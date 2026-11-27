"""Audit log: hash chain and tamper evidence."""

from __future__ import annotations

from pathlib import Path

from mem_guard.audit import AuditLog


def test_chain_verifies(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    first = log.append("memory.remember", tenant_id="t", user_id="u", trace_id="tr-1")
    second = log.append("memory.recall", tenant_id="t", user_id="u", trace_id="tr-2")
    assert second.prev_hash == first.hash
    result = log.verify()
    assert result.valid is True
    assert result.entries == 2


def test_tampering_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("memory.remember", tenant_id="t", user_id="u")
    log.append("memory.recall", tenant_id="t", user_id="u")
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace('"outcome": "ok"', '"outcome": "blocked"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = log.verify()
    assert result.valid is False
    assert result.broken_at == 1


def test_deleted_line_breaks_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("a", tenant_id="t", user_id="u")
    log.append("b", tenant_id="t", user_id="u")
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(lines[1] + "\n", encoding="utf-8")
    result = log.verify()
    assert result.valid is False
    assert result.broken_at == 1
