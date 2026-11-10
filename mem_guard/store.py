"""Persistence: a tiny store protocol plus an atomic JSON-file implementation.

State is not just memory content: trust labels, partitions, state, supersede links and the
audit log survive a restart. The interface is deliberately small so other backends (SQLite,
Mem0, LangChain) can be dropped in without touching governance logic.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Protocol


class Store(Protocol):
    """Minimal persistence contract."""

    def load(self) -> dict[str, Any]: ...

    def save(self, state: dict[str, Any]) -> None: ...


class InMemoryStore:
    """Default store: process lifetime only (explicitly non-durable)."""

    durable = False

    def __init__(self) -> None:
        self._state: dict[str, Any] = {}

    def load(self) -> dict[str, Any]:
        return json.loads(json.dumps(self._state))

    def save(self, state: dict[str, Any]) -> None:
        self._state = json.loads(json.dumps(state))


class JsonFileStore:
    """Atomic JSON file store: temp file → flush → fsync → replace."""

    durable = True

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            # A corrupt store must not silently look empty to governance code.
            raise ValueError(f"corrupt store: {self.path}") from None

    def save(self, state: dict[str, Any]) -> None:
        payload = json.dumps(state, ensure_ascii=False, indent=2) + "\n"
        descriptor, temp_name = tempfile.mkstemp(
            prefix=".memguard-", suffix=".tmp", dir=str(self.path.parent)
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
