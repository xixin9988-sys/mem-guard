"""Feedback ledger: 👍/👎 bound to a trace id.

The gateway stores feedback locally (so the audit trail survives a NanoMemory outage) and
forwards it to NanoMemory (which owns the trace and its badcase export).  A feedback row that
NanoMemory rejected is still stored locally with @@forwarded=false@@ -- losing the user's signal
would be worse than storing it without the join.
"""

from __future__ import annotations

import sqlite3
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

from mem_guard.contracts import FeedbackRecord, FeedbackRequest, Scope


class FeedbackStore:
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
            CREATE TABLE IF NOT EXISTS feedback (
                feedback_id TEXT PRIMARY KEY,
                trace_id TEXT NOT NULL,
                verdict TEXT NOT NULL,
                reason TEXT,
                comment TEXT,
                tenant_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                forwarded INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_feedback_tenant ON feedback (tenant_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_feedback_trace ON feedback (trace_id);
            """
        )

    def record(
        self,
        scope: Scope,
        request: FeedbackRequest,
        *,
        forwarded: bool,
    ) -> FeedbackRecord:
        record = FeedbackRecord(
            feedback_id=f"fb-{uuid.uuid4().hex[:16]}",
            trace_id=request.trace_id,
            verdict=request.verdict,
            reason=request.reason,
            comment=request.comment,
            tenant_id=scope.tenant_id,
            user_id=scope.user_id,
            forwarded=forwarded,
            created_at=datetime.now(UTC).isoformat(),
        )
        with self._lock:
            self._conn.execute(
                "INSERT INTO feedback (feedback_id, trace_id, verdict, reason, comment, "
                "tenant_id, user_id, forwarded, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record.feedback_id,
                    record.trace_id,
                    record.verdict,
                    record.reason,
                    record.comment,
                    record.tenant_id,
                    record.user_id,
                    int(record.forwarded),
                    record.created_at,
                ),
            )
        return record

    def list(self, scope: Scope, *, limit: int = 100) -> list[FeedbackRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM feedback WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?",
                (scope.tenant_id, max(0, limit)),
            ).fetchall()
        return [
            FeedbackRecord(
                feedback_id=row["feedback_id"],
                trace_id=row["trace_id"],
                verdict=row["verdict"],
                reason=row["reason"],
                comment=row["comment"],
                tenant_id=row["tenant_id"],
                user_id=row["user_id"],
                forwarded=bool(row["forwarded"]),
                created_at=row["created_at"],
            )
            for row in rows
        ]

    def stats(self, scope: Scope) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT verdict, COUNT(*) AS total FROM feedback WHERE tenant_id = ? "
                "GROUP BY verdict",
                (scope.tenant_id,),
            ).fetchall()
        return {row["verdict"]: int(row["total"]) for row in rows}

    def close(self) -> None:
        with self._lock:
            self._conn.close()


__all__ = ["FeedbackStore"]
