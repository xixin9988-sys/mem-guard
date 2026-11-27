"""mem-guard — Memory Reliability & Governance Middleware.

Two layers ship in one package:

* the original in-process governance library (Guard: provenance, trust, state, partitions,
  consolidation rules) — still the right tool when memory lives inside your process;
* the v2 gateway (MemoryGateway + FastAPI app) that sits in front of NanoMemory's vector store:
  signed tenant scope, prompt-injection and PII screening, per-tenant rate limits and budgets,
  hash-chained audit, feedback loop and a grounded-answer guard.

Quick start (library)::

    from mem_guard import Guard

    guard = Guard()
    guard.add("用户喜欢深色模式", source="user_statement", confidence=0.9)
    hits = guard.search("UI偏好", require_trust_level="user_verified")

Quick start (gateway)::

    uvicorn mem_guard.server:app --port 8080
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

__version__ = "2.0.0"
