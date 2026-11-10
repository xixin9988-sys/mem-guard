"""Guard: the small public surface.

    guard = Guard()
    memory = guard.add("用户喜欢深色模式", source="user_statement", confidence=0.9)
    hits = guard.search("UI偏好", require_trust_level="user_verified")

Writing goes through provenance validation, state governance, trust partitioning and the
consolidation gate. Reading selects partitions first, then ranks — it never runs per-item
policy checks.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from mem_guard.consolidation import Candidate, ConsolidationGate, GateAction, GateDecision
from mem_guard.governance import Governance
from mem_guard.models import (
    Memory,
    MemoryState,
    Partition,
    Provenance,
    SourceKind,
    TrustLevel,
    trust_rank,
)
from mem_guard.provenance import ProvenanceValidator, ValidationResult
from mem_guard.rules import Decision, Rule, RuleAction, RuleCompiler
from mem_guard.trust import PolicyEngine

_WORD = re.compile(r"[A-Za-z0-9_]{2,}")


def tokens(text: str) -> set[str]:
    lowered = text.lower()
    found = {token for token in _WORD.findall(lowered)}
    for phrase in re.findall(r"[\u4e00-\u9fff]{2,}", lowered):
        for index in range(len(phrase) - 1):
            found.add(phrase[index : index + 2])
    return found


def similarity(left: str, right: str) -> float:
    first, second = tokens(left), tokens(right)
    if not first or not second:
        return 0.0
    return len(first & second) / len(first | second)


@dataclass(slots=True)
class SearchHit:
    memory: Memory
    score: float
    reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.memory.id,
            "content": self.memory.content,
            "score": round(self.score, 4),
            "trust": self.memory.trust.value,
            "partition": self.memory.partition.value,
            "tags": list(self.memory.tags),
            "reasons": list(self.reasons),
        }


@dataclass(slots=True)
class AddResult:
    memory: Memory
    validation: ValidationResult
    gate: GateDecision
    conflicts: list[str] = field(default_factory=list)
    superseded: list[str] = field(default_factory=list)
    accepted: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "memory": self.memory.to_dict(),
            "validation": {
                "ok": self.validation.ok,
                "trust": self.validation.trust.value,
                "reasons": list(self.validation.reasons),
                "quarantine": self.validation.quarantine,
            },
            "gate": self.gate.to_dict(),
            "conflicts": self.conflicts,
            "superseded": self.superseded,
            "accepted": self.accepted,
        }


class Guard:
    """Memory Reliability & Governance middleware with a two-method happy path."""

    def __init__(self, *, consolidate: bool = True) -> None:
        self.governance = Governance()
        self.validator = ProvenanceValidator()
        self.policy = PolicyEngine()
        self.gate = ConsolidationGate()
        self.rules = RuleCompiler()
        self.consolidate = consolidate

    # ------------------------------------------------------------------ write
    def add(
        self,
        content: str,
        *,
        source: str | SourceKind = "user_statement",
        confidence: float = 0.8,
        tags: tuple[str, ...] = (),
        valid_until: str | None = None,
        evidence: tuple[str, ...] = (),
        reference: str | None = None,
        is_preference: bool = False,
        decision_weight: float = 0.0,
        repetitions: int = 1,
    ) -> AddResult:
        validation = self.validator.validate(
            content, source, confidence=confidence, evidence=evidence
        )
        compiled = self.policy.compile(
            validation.trust,
            confidence=confidence,
            quarantine=validation.quarantine or not validation.ok,
            verified=validation.source is SourceKind.USER_VERIFIED,
        )
        memory = Memory(
            content=content.strip(),
            provenance=Provenance(kind=validation.source, reference=reference, evidence=evidence),
            trust=validation.trust,
            confidence=confidence,
            tags=tags,
            state=MemoryState.ACTIVE,
            partition=compiled.partition,
            valid_until=valid_until,
            policy=compiled.policy,
        )

        conflicts: list[str] = []
        superseded: list[str] = []
        if memory.state is MemoryState.ACTIVE:
            conflicts, superseded = self._reconcile(memory)

        gate = self._gate(
            memory,
            is_preference=is_preference,
            decision_weight=decision_weight,
            repetitions=repetitions,
        )
        if not validation.ok:
            memory.record_transition(MemoryState.QUARANTINED, "provenance rejected", "validator")
            memory.partition = Partition.QUARANTINE
        elif gate.action is GateAction.QUARANTINE:
            memory.record_transition(
                MemoryState.QUARANTINED, "consolidation gate quarantined", "gate"
            )
            memory.partition = Partition.QUARANTINE
        elif conflicts:
            memory.record_transition(
                MemoryState.CONFLICT, "contradicts an existing memory", "governance"
            )
        elif (
            gate.action is GateAction.PROMOTE
            or not self.consolidate
            or memory.trust in {TrustLevel.USER_STATED, TrustLevel.USER_VERIFIED}
        ):
            memory.state = MemoryState.ACTIVE
        else:
            memory.record_transition(
                MemoryState.PENDING_REVIEW, f"gate: {gate.action.value}", "gate"
            )

        self.governance.register(memory)
        for old_id in superseded:
            self.governance.supersede(old_id, memory.id)
        return AddResult(
            memory=memory,
            validation=validation,
            gate=gate,
            conflicts=conflicts,
            superseded=superseded,
            accepted=memory.state is MemoryState.ACTIVE,
        )

    def _reconcile(self, memory: Memory) -> tuple[list[str], list[str]]:
        conflicts: list[str] = []
        superseded: list[str] = []
        for existing in self.governance.active():
            if existing.id == memory.id:
                continue
            if not set(existing.tags) & set(memory.tags):
                continue
            score = similarity(existing.content, memory.content)
            if score < 0.45:
                continue
            same_trust = trust_rank(memory.trust) == trust_rank(existing.trust)
            newer = trust_rank(memory.trust) > trust_rank(existing.trust) or (
                same_trust and memory.observed_at >= existing.observed_at
            )
            if newer and score >= 0.6:
                superseded.append(existing.id)
            elif score >= 0.45:
                conflicts.append(existing.id)
        return conflicts, superseded

    def _gate(
        self,
        memory: Memory,
        *,
        is_preference: bool,
        decision_weight: float,
        repetitions: int,
    ) -> GateDecision:
        if not self.consolidate:
            from mem_guard.consolidation import GateAction as _Action

            return GateDecision(_Action.PROMOTE, 1.0, ("consolidation disabled",))
        best = 0.0
        for existing in self.governance.active():
            best = max(best, similarity(existing.content, memory.content))
        return self.gate.evaluate(
            Candidate(
                content=memory.content,
                trust=memory.trust,
                repetitions=repetitions,
                is_preference=is_preference,
                decision_weight=decision_weight,
                similarity_to_existing=best,
                evidence_count=len(memory.provenance.evidence),
            )
        )

    # ------------------------------------------------------------------ read
    def search(
        self,
        query: str,
        *,
        require_trust_level: str | TrustLevel = TrustLevel.USER_STATED,
        limit: int = 5,
        tags: tuple[str, ...] = (),
    ) -> list[SearchHit]:
        required = TrustLevel(require_trust_level)
        partitions = self.policy.partitions_for(required)
        required_rank = trust_rank(required)
        query_tokens = tokens(query)
        wanted = {tag.lower() for tag in tags}
        hits: list[SearchHit] = []
        now = datetime.now(UTC)
        for memory in self.governance.memories.values():
            allowed_states = {MemoryState.ACTIVE}
            if required is TrustLevel.UNTRUSTED:
                # An explicit inspector may read what was quarantined, never a normal agent.
                allowed_states.add(MemoryState.QUARANTINED)
            if memory.state not in allowed_states or memory.partition not in partitions:
                continue
            if trust_rank(memory.trust) < required_rank or memory.is_expired(now=now):
                continue
            if wanted and not wanted <= set(memory.tags):
                continue
            overlap = query_tokens & tokens(f"{memory.content} {' '.join(memory.tags)}")
            keyword = min(1.0, len(overlap) / max(1, min(len(query_tokens), 6)))
            recency = self._recency(memory.observed_at, now)
            score = 0.65 * keyword + 0.20 * recency + 0.15 * memory.confidence
            if score <= 0.05:
                continue
            reasons = []
            if overlap:
                reasons.append(f"keywords: {', '.join(sorted(overlap)[:4])}")
            reasons.append(f"trust {memory.trust.value}")
            hits.append(SearchHit(memory=memory, score=score, reasons=tuple(reasons)))
        hits.sort(key=lambda hit: hit.score, reverse=True)
        return hits[:limit]

    @staticmethod
    def _recency(stamp: str, now: datetime) -> float:
        try:
            parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError:
            return 0.5
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        age_days = max(0.0, (now - parsed).total_seconds() / 86400)
        return math.exp(-age_days / 120.0)

    # ------------------------------------------------------------------ governance ops
    def supersede(self, old_id: str, new_id: str) -> Memory:
        return self.governance.supersede(old_id, new_id)

    def confirm(self, memory_id: str) -> Memory:
        return self.governance.confirm(memory_id)

    def archive(self, memory_id: str) -> Memory:
        return self.governance.archive(memory_id)

    def explain(self, memory_id: str) -> dict[str, Any]:
        return self.governance.explain(memory_id)

    def stats(self) -> dict[str, Any]:
        return self.governance.stats()

    # ------------------------------------------------------------------ rules
    def add_rule(self, rule: Rule) -> Rule:
        return self.rules.add(rule)

    def evaluate_rule(self, text: str, *, scope: str = "*") -> Decision:
        return self.rules.evaluate(text, scope=scope)

    # ------------------------------------------------------------------ demo helpers
    def reset(self) -> None:
        self.governance = Governance()


__all__ = ["AddResult", "Guard", "Rule", "RuleAction", "SearchHit", "similarity", "tokens"]
