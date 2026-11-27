"""Quota: burst rate limiting, daily budgets and snapshots."""

from __future__ import annotations

from pathlib import Path

import pytest
from mem_guard.contracts import Scope
from mem_guard.quota import QuotaExceeded, QuotaManager, RateLimiter, UsageLedger

SCOPE = Scope(tenant_id="tenant-a", user_id="user-1")


def test_rate_limiter_allows_burst_then_refills() -> None:
    limiter = RateLimiter(per_minute=2)
    assert limiter.allow(SCOPE)[0] is True
    assert limiter.allow(SCOPE)[0] is True
    allowed, retry_after = limiter.allow(SCOPE)
    assert allowed is False
    assert retry_after > 0


def test_rate_limiter_is_per_tenant_and_user() -> None:
    limiter = RateLimiter(per_minute=1)
    assert limiter.allow(SCOPE)[0] is True
    other = Scope(tenant_id="tenant-b", user_id="user-1")
    assert limiter.allow(other)[0] is True


def test_ledger_accumulates_per_day(tmp_path: Path) -> None:
    ledger = UsageLedger(tmp_path / "usage.db")
    try:
        assert ledger.used(SCOPE, "embedding_tokens") == 0
        ledger.charge(SCOPE, "embedding_tokens", 120)
        ledger.charge(SCOPE, "embedding_tokens", 30)
        assert ledger.used(SCOPE, "embedding_tokens") == 150
        assert ledger.used(SCOPE, "embedding_tokens", day="1999-01-01") == 0
    finally:
        ledger.close()


def test_daily_budget_is_enforced(tmp_path: Path) -> None:
    ledger = UsageLedger(tmp_path / "usage.db")
    try:
        quota = QuotaManager(ledger=ledger, daily_embedding_tokens=100, per_minute=100)
        quota.check_budget(SCOPE, "embedding_tokens", 60)
        quota.charge(SCOPE, "embedding_tokens", 60)
        with pytest.raises(QuotaExceeded) as excinfo:
            quota.check_budget(SCOPE, "embedding_tokens", 60)
        assert excinfo.value.code == "quota_exceeded"
        assert excinfo.value.details["limit"] == 100
    finally:
        ledger.close()


def test_rate_limit_raises_with_retry_after(tmp_path: Path) -> None:
    ledger = UsageLedger(tmp_path / "usage.db")
    try:
        quota = QuotaManager(ledger=ledger, per_minute=1)
        quota.check_request(SCOPE)
        with pytest.raises(QuotaExceeded) as excinfo:
            quota.check_request(SCOPE)
        assert excinfo.value.code == "rate_limit_exceeded"
        assert excinfo.value.retry_after > 0
    finally:
        ledger.close()


def test_snapshot_reports_remaining(tmp_path: Path) -> None:
    ledger = UsageLedger(tmp_path / "usage.db")
    try:
        quota = QuotaManager(ledger=ledger, daily_writes=10)
        quota.charge(SCOPE, "writes", 3)
        snapshot = quota.snapshot(SCOPE)
        assert snapshot.used["writes"] == 3
        assert snapshot.remaining["writes"] == 7
    finally:
        ledger.close()
