"""Rate limiting and daily budgets: the cost-governance half of the gateway.

Two mechanisms, two different questions:

* token bucket (in-memory, per tenant+user): "is this caller making requests too fast?"
  -> 429 with Retry-After, before any model or vector work happens.
* daily ledger (SQLite): "has this tenant already spent its embedding/retrieval budget today?"
  -> 429 with a budget reason, which is a business limit, not an abuse signal.

In-memory buckets are per process.  With several gateway replicas the effective rate is
replicas x limit; the ledger is shared through SQLite in the single-node product, and the
limitation is stated in the health payload instead of being hidden.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mem_guard.contracts import QuotaSnapshot, Scope

METRICS = ("writes", "embedding_tokens", "retrieval_tokens", "searches")


class QuotaExceeded(Exception):
    """Raised before work is done; the server maps it to 429."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        retry_after: float = 0.0,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retry_after = retry_after
        self.details = details or {}


@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated_at: float


class RateLimiter:
    """Token bucket: capacity = per_minute, refill = per_minute / 60 per second."""

    def __init__(self, *, per_minute: int, enabled: bool = True) -> None:
        self.per_minute = max(1, per_minute)
        self.enabled = enabled
        self._buckets: dict[tuple[str, str], _Bucket] = {}
        self._lock = threading.Lock()

    def _refill(self, key: tuple[str, str], now: float) -> _Bucket:
        bucket = self._buckets.get(key)
        rate = self.per_minute / 60.0
        if bucket is None:
            return _Bucket(tokens=float(self.per_minute), updated_at=now)
        elapsed = max(0.0, now - bucket.updated_at)
        tokens = min(float(self.per_minute), bucket.tokens + elapsed * rate)
        return _Bucket(tokens=tokens, updated_at=now)

    def allow(self, scope: Scope, *, cost: float = 1.0) -> tuple[bool, float]:
        if not self.enabled:
            return True, 0.0
        key = (scope.tenant_id, scope.user_id)
        now = time.monotonic()
        with self._lock:
            bucket = self._refill(key, now)
            if bucket.tokens >= cost:
                bucket.tokens -= cost
                self._buckets[key] = bucket
                return True, 0.0
            deficit = cost - bucket.tokens
            retry_after = deficit / (self.per_minute / 60.0)
            self._buckets[key] = bucket
            return False, round(retry_after, 3)

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


class UsageLedger:
    """Daily per-tenant/user counters persisted in SQLite."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self.path), check_same_thread=False, isolation_level=None, timeout=10.0
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS usage (
                day TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                metric TEXT NOT NULL,
                amount INTEGER NOT NULL,
                PRIMARY KEY (day, tenant_id, user_id, metric)
            );
            """
        )

    @staticmethod
    def today() -> str:
        return datetime.now(UTC).strftime("%Y-%m-%d")

    def used(self, scope: Scope, metric: str, *, day: str | None = None) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT amount FROM usage WHERE day = ? AND tenant_id = ? AND user_id = ? "
                "AND metric = ?",
                (day or self.today(), scope.tenant_id, scope.user_id, metric),
            ).fetchone()
        return int(row["amount"]) if row else 0

    def charge(self, scope: Scope, metric: str, amount: int, *, day: str | None = None) -> int:
        if amount <= 0:
            return self.used(scope, metric, day=day)
        with self._lock:
            self._conn.execute(
                "INSERT INTO usage (day, tenant_id, user_id, metric, amount) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT(day, tenant_id, user_id, metric) "
                "DO UPDATE SET amount = amount + excluded.amount",
                (day or self.today(), scope.tenant_id, scope.user_id, metric, amount),
            )
            row = self._conn.execute(
                "SELECT amount FROM usage WHERE day = ? AND tenant_id = ? AND user_id = ? "
                "AND metric = ?",
                (day or self.today(), scope.tenant_id, scope.user_id, metric),
            ).fetchone()
        return int(row["amount"]) if row else amount

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class QuotaManager:
    """Policy facade: rate limit + budget check + charge + snapshot."""

    def __init__(
        self,
        *,
        ledger: UsageLedger,
        per_minute: int = 120,
        daily_embedding_tokens: int = 200_000,
        daily_retrieval_tokens: int = 500_000,
        daily_writes: int = 20_000,
        daily_searches: int = 50_000,
        enabled: bool = True,
    ) -> None:
        self.ledger = ledger
        self.limiter = RateLimiter(per_minute=per_minute, enabled=enabled)
        self.enabled = enabled
        self.limits = {
            "writes": daily_writes,
            "searches": daily_searches,
            "embedding_tokens": daily_embedding_tokens,
            "retrieval_tokens": daily_retrieval_tokens,
        }

    def check_request(self, scope: Scope) -> None:
        allowed, retry_after = self.limiter.allow(scope)
        if not allowed:
            raise QuotaExceeded(
                "rate_limit_exceeded",
                "Too many requests for this tenant/user; retry shortly.",
                retry_after=retry_after,
                details={"limit_per_minute": self.limiter.per_minute},
            )

    def check_budget(self, scope: Scope, metric: str, amount: int = 1) -> None:
        if not self.enabled:
            return
        limit = self.limits.get(metric, 0)
        if limit <= 0:
            return
        used = self.ledger.used(scope, metric)
        if used + amount > limit:
            raise QuotaExceeded(
                "quota_exceeded",
                f"Daily {metric} budget exhausted for this tenant/user.",
                details={"metric": metric, "limit": limit, "used": used},
            )

    def charge(self, scope: Scope, metric: str, amount: int) -> int:
        if not self.enabled or amount <= 0:
            return self.ledger.used(scope, metric)
        return self.ledger.charge(scope, metric, amount)

    def snapshot(self, scope: Scope) -> QuotaSnapshot:
        used = {metric: self.ledger.used(scope, metric) for metric in METRICS}
        remaining = {
            metric: max(0, self.limits.get(metric, 0) - used.get(metric, 0)) for metric in METRICS
        }
        return QuotaSnapshot(
            tenant_id=scope.tenant_id,
            user_id=scope.user_id,
            day=self.ledger.today(),
            limits=dict(self.limits),
            used=used,
            remaining=remaining,
        )


__all__ = [
    "METRICS",
    "QuotaExceeded",
    "QuotaManager",
    "RateLimiter",
    "UsageLedger",
]
