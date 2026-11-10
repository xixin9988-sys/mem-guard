"""mem-guard — Memory Reliability & Governance Middleware.

Memory belongs to the user, not the model. mem-guard is the layer that keeps that promise
enforceable: every memory carries provenance, a governed state, a precompiled trust policy
and a partition, so retrieval can be filtered *before* it reaches the model.

Quick start::

    from mem_guard import Guard

    guard = Guard()
    memory = guard.add("用户喜欢深色模式", source="user_statement", confidence=0.9)
    hits = guard.search("UI偏好", require_trust_level="user_verified")
"""

from __future__ import annotations

from mem_guard.guard import Guard, SearchHit
from mem_guard.models import (
    Memory,
    MemoryState,
    Partition,
    Policy,
    Provenance,
    SourceKind,
    TrustLevel,
)

__all__ = [
    "Guard",
    "Memory",
    "MemoryState",
    "Partition",
    "Policy",
    "Provenance",
    "SearchHit",
    "SourceKind",
    "TrustLevel",
    "__version__",
]

__version__ = "0.1.0"
