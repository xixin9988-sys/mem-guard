"""Memory State Governance: legal transitions, supersede history and explainability.

The state machine is small on purpose. Everything that changes a memory's status must go
through :meth:`Governance.transition`, so the history is always complete and auditable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from mem_guard.models import Memory, MemoryState, utc_now

ALLOWED_TRANSITIONS: dict[MemoryState, frozenset[MemoryState]] = {
    MemoryState.ACTIVE: frozenset(
        {
            MemoryState.SUPERSEDED,
            MemoryState.CONFLICT,
            MemoryState.ARCHIVED,
            MemoryState.QUARANTINED,
        }
    ),
    MemoryState.PENDING_REVIEW: frozenset(
        {MemoryState.ACTIVE, MemoryState.CONFLICT, MemoryState.ARCHIVED, MemoryState.QUARANTINED}
    ),
    MemoryState.CONFLICT: frozenset(
        {MemoryState.ACTIVE, MemoryState.SUPERSEDED, MemoryState.ARCHIVED}
    ),
    MemoryState.QUARANTINED: frozenset({MemoryState.ACTIVE, MemoryState.ARCHIVED}),
    MemoryState.SUPERSEDED: frozenset({MemoryState.ARCHIVED}),
    MemoryState.ARCHIVED: frozenset(),
}


class GovernanceError(ValueError):
    """Raised when a transition or lookup is not allowed."""


@dataclass(slots=True)
class Governance:
    """In-memory governed store; persistence is intentionally out of scope for 0.1."""

    memories: dict[str, Memory] = field(default_factory=dict)

    # ------------------------------------------------------------------ read
    def get(self, memory_id: str) -> Memory:
        try:
            return self.memories[memory_id]
        except KeyError as error:
            raise GovernanceError(f"unknown memory: {memory_id}") from error

    def active(self) -> list[Memory]:
        return [memory for memory in self.memories.values() if memory.state is MemoryState.ACTIVE]

    def by_tag(self, tag: str) -> list[Memory]:
        normalised = tag.strip().lower()
        return [memory for memory in self.memories.values() if normalised in memory.tags]

    # ------------------------------------------------------------------ write
    def register(self, memory: Memory) -> Memory:
        if memory.id in self.memories:
            raise GovernanceError(f"duplicate memory id: {memory.id}")
        self.memories[memory.id] = memory
        return memory

    def transition(self, memory: Memory, target: MemoryState, *, reason: str, actor: str) -> Memory:
        if memory.state is target:
            return memory
        if target not in ALLOWED_TRANSITIONS[memory.state]:
            raise GovernanceError(
                f"illegal transition {memory.state.value} -> {target.value} for {memory.id}"
            )
        memory.record_transition(target, reason, actor)
        return memory

    def supersede(
        self, old_id: str, new_id: str, *, reason: str = "superseded by newer statement"
    ) -> Memory:
        old = self.get(old_id)
        new = self.get(new_id)
        if old.id == new.id:
            raise GovernanceError("a memory cannot supersede itself")
        self.transition(old, MemoryState.SUPERSEDED, reason=reason, actor="governance")
        old.superseded_by = new.id
        old.valid_until = utc_now()
        if old.id not in new.supersedes:
            new.supersedes.append(old.id)
        return old

    def confirm(self, memory_id: str, *, reason: str = "human confirmed") -> Memory:
        memory = self.get(memory_id)
        if memory.state not in {
            MemoryState.PENDING_REVIEW,
            MemoryState.CONFLICT,
            MemoryState.QUARANTINED,
        }:
            raise GovernanceError(f"memory {memory_id} is not awaiting review")
        return self.transition(memory, MemoryState.ACTIVE, reason=reason, actor="human")

    def archive(self, memory_id: str, *, reason: str = "archived") -> Memory:
        memory = self.get(memory_id)
        return self.transition(memory, MemoryState.ARCHIVED, reason=reason, actor="human")

    # ------------------------------------------------------------------ explain
    def explain(self, memory_id: str) -> dict[str, Any]:
        memory = self.get(memory_id)
        chain: list[dict[str, Any]] = []
        current = memory
        seen = {memory.id}
        while current.superseded_by and current.superseded_by not in seen:
            seen.add(current.superseded_by)
            successor = self.memories.get(current.superseded_by)
            if successor is None:
                break
            chain.append(
                {
                    "id": successor.id,
                    "state": successor.state.value,
                    "observed_at": successor.observed_at,
                }
            )
            current = successor
        return {
            "memory": memory.to_dict(),
            "provenance": memory.provenance.to_dict(),
            "supersedes": list(memory.supersedes),
            "superseded_by": memory.superseded_by,
            "supersede_chain": chain,
            "history": list(memory.history),
        }

    # ------------------------------------------------------------------ stats
    def stats(self) -> dict[str, Any]:
        by_state: dict[str, int] = {}
        by_partition: dict[str, int] = {}
        for memory in self.memories.values():
            by_state[memory.state.value] = by_state.get(memory.state.value, 0) + 1
            by_partition[memory.partition.value] = by_partition.get(memory.partition.value, 0) + 1
        return {
            "total": len(self.memories),
            "by_state": by_state,
            "by_partition": by_partition,
            "generated_at": datetime.now(UTC).isoformat(),
        }
