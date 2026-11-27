"""Content safety: detection, redaction and block mode."""

from __future__ import annotations

from mem_guard.safety import ContentSafety


def test_phone_is_redacted() -> None:
    report = ContentSafety(mode="redact").scan("客户电话 13800001234，请联系。")
    assert report.action == "redact"
    assert "13800001234" not in report.redacted_text
    assert "[REDACTED:cn_phone]" in report.redacted_text
    assert report.kinds == ["cn_phone"]


def test_email_and_secret_are_detected() -> None:
    # Build the fake key at runtime: a literal would look like a leaked credential to
    # secret scanners while testing exactly the same rule.
    fake_key = "sk-" + "a" * 24
    report = ContentSafety(mode="redact").scan(
        f"mail me at ops@example.com and use {fake_key}"
    )
    assert report.action == "redact"
    assert "ops@example.com" not in report.redacted_text
    assert fake_key not in report.redacted_text
    assert report.has_secrets is True


def test_block_mode_rejects_secrets_and_pii() -> None:
    report = ContentSafety(mode="block").scan("card 6222020200112233445")
    assert report.action == "block"


def test_clean_text_is_untouched() -> None:
    text = "订单 A1001 已由顺丰发出，预计 10 月 15 日送达。"
    report = ContentSafety(mode="redact").scan(text)
    assert report.action == "allow"
    assert report.findings == []
    assert report.redacted_text == text


def test_no_overlapping_findings_for_a_card_number() -> None:
    report = ContentSafety(mode="redact").scan("6222 0202 0011 2233 445")
    assert len(report.findings) == 1
    assert report.findings[0].kind == "bank_card"


def test_redaction_is_idempotent_enough_for_audit() -> None:
    text = "联系 13800001234"
    once = ContentSafety(mode="redact").scan(text).redacted_text
    twice = ContentSafety(mode="redact").scan(once).redacted_text
    assert once == twice
