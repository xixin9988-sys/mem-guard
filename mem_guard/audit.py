"""Hash-chained audit log.

Every allow/redact/block decision is appended to a JSONL file where each entry hashes the
previous entry's hash.  Deleting or editing a line breaks the chain from that point on, which is
what makes "we logged it" a checkable statement rather than a promise.  verify() reports the
first broken link with its line number.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


@dataclass(slots=True)
class AuditEntry:
    audit_id: str
    at: str
    event: str
    tenant_id: str
    user_id: str
    trace_id: str | None
    outcome: str
    details: dict[str, Any]
    prev_hash: str
    hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "at": self.at,
            "event": self.event,
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "trace_id": self.trace_id,
            "outcome": self.outcome,
            "details": self.details,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }


@dataclass(slots=True)
class VerifyResult:
    valid: bool
    entries: int
    broken_at: int | None = None
    reason: str | None = None


def _digest(entry: dict[str, Any]) -> str:
    payload = {key: value for key, value in entry.items() if key != "hash"}
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _last_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS
        last = ""
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last = line
        if not last:
            return GENESIS
        try:
            return str(json.loads(last).get("hash") or GENESIS)
        except json.JSONDecodeError:
            return GENESIS

    def append(
        self,
        event: str,
        *,
        tenant_id: str,
        user_id: str,
        trace_id: str | None = None,
        outcome: str = "ok",
        details: dict[str, Any] | None = None,
    ) -> AuditEntry:
        with self._lock:
            entry = {
                "audit_id": f"aud-{uuid.uuid4().hex[:16]}",
                "at": datetime.now(UTC).isoformat(),
                "event": event,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "trace_id": trace_id,
                "outcome": outcome,
                "details": details or {},
                "prev_hash": self._last_hash(),
            }
            entry["hash"] = _digest(entry)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
                handle.flush()
        return AuditEntry(**entry)

    def tail(self, limit: int = 20) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        rows: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    rows.append(json.loads(line))
        return rows[-max(0, limit) :]

    def verify(self) -> VerifyResult:
        if not self.path.exists():
            return VerifyResult(valid=True, entries=0)
        previous = GENESIS
        count = 0
        with self.path.open("r", encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return VerifyResult(False, count, number, "line is not valid JSON")
                count += 1
                if entry.get("prev_hash") != previous:
                    return VerifyResult(False, count, number, "prev_hash does not match")
                if entry.get("hash") != _digest(entry):
                    return VerifyResult(False, count, number, "entry hash does not match")
                previous = entry["hash"]
        return VerifyResult(valid=True, entries=count)


__all__ = ["GENESIS", "AuditEntry", "AuditLog", "VerifyResult"]
