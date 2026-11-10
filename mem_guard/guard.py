"""Guard: the small public surface.

    guard = Guard(path="mem.json")          # durable, survives a restart
    guard = Guard()                          # in-memory, for tests and demos

    guard.register_issuer(Issuer("chat", frozenset({SourceKind.USER_STATEMENT})))
    guard.add("I prefer dark mode", source="user_statement", issuer="chat")
    guard.search("UI preference", require_trust_level="user_stated", consumer="agent")

Trust is minted by an **attested issuer**, never by the string a caller passes. Conflicts are
resolved atomically: a memory that becomes ``CONFLICT`` never supersedes anything. Retrieval
filters by partition, trust rank and consumer policy.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from mem_guard.consolidation import Candidate, ConsolidationGate, GateAction, GateDecision
from mem_guard.governance import Governance, GovernanceError
from mem_guard.models import (
    Memory,
    MemoryState,
    Partition,
    Policy,
    Provenance,
    SourceKind,
    TrustLevel,
    memory_from_dict,
    trust_rank,
    utc_now,
)
from mem_guard.provenance import Issuer, IssuerRegistry, ProvenanceValidator, ValidationResult
from mem_guard.rules import Decision, Rule, RuleAction, RuleCompiler
from mem_guard.store import InMemoryStore, JsonFileStore, Store
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
                "attested": self.validation.attested,
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

    def __init__(
        self,
        *,
        store: Store | None = None,
        path: str | None = None,
        consolidate: bool = True,
    ) -> None:
        self.store: Store = store or (JsonFileStore(path) if path else InMemoryStore())
        self.validator = ProvenanceValidator()
        self.policy = PolicyEngine()
        self.gate = ConsolidationGate()
        self.rules = RuleCompiler()
        self.governance = Governance()
        self.consolidate = consolidate
        self.audit_log: list[dict[str, Any]] = []
        self._load()

    # ------------------------------------------------------------------ persistence
    @property
    def durable(self) -> bool:
        return bool(getattr(self.store, "durable", False))

    def _load(self) -> None:
        state = self.store.load()
        for payload in state.get("memories", []):
            memory = memory_from_dict(payload)
            self.governance.register(memory)
        self.audit_log = list(state.get("audit", []))

    def _persist(self) -> None:
        self.store.save(
            {
                "schema_version": 1,
                "saved_at": utc_now(),
                "memories": [memory.to_dict() for memory in self.governance.memories.values()],
                "audit": self.audit_log,
            }
        )

    def _audit(self, event: str, memory_id: str, detail: str) -> None:
        self.audit_log.append(
            {"at": utc_now(), "event": event, "memory_id": memory_id, "detail": detail}
        )

    def audit(self) -> tuple[dict[str, Any], ...]:
        return tuple(dict(entry) for entry in self.audit_log)

    # ------------------------------------------------------------------ trust roots
    def register_issuer(self, issuer: Issuer) -> Issuer:
        """Register a trusted adapter; only these may assert beyond ``untrusted``."""
        return self.validator.issuers.register(issuer)

    def issuers(self) -> tuple[str, ...]:
        return self.validator.issuers.names()

    # ------------------------------------------------------------------ write
    def add(
        self,
        content: str,
        *,
        source: str | SourceKind = "user_statement",
        issuer: str | None = None,
        confidence: float = 0.8,
        tags: tuple[str, ...] = (),
        valid_until: str | None = None,
        evidence: tuple[str, ...] = (),
        reference: str | None = None,
        is_preference: bool = False,
        decision_weight: float = 0.0,
        repetitions: int = 1,
        allowed_consumers: frozenset[str] | None = None,
    ) -> AddResult:
        validation = self.validator.validate(
            content, source, issuer=issuer, confidence=confidence, evidence=evidence
        )
        compiled = self.policy.compile(
            validation.trust,
            confidence=confidence,
            quarantine=validation.quarantine or not validation.ok,
            verified=validation.trust is TrustLevel.USER_VERIFIED,
        )
        policy = compiled.policy
        if allowed_consumers is not None:
            policy = Policy(
                allowed_consumers=frozenset(allowed_consumers),
                min_trust=policy.min_trust,
                retention=policy.retention,
                note=policy.note,
            )
        memory = Memory(
            content=content.strip(),
            provenance=Provenance(
                kind=validation.source,
                reference=reference,
                issuer=issuer,
                evidence=evidence,
            ),
            trust=validation.trust,
            confidence=confidence,
            tags=tags,
            state=MemoryState.ACTIVE,
            partition=compiled.partition,
            valid_until=valid_until,
            policy=policy,
        )

        conflicts: list[str] = []
        supersede_candidates: list[str] = []
        gate = self._gate(
            memory,
            is_preference=is_preference,
            decision_weight=decision_weight,
            repetitions=repetitions,
        )
        if validation.ok and gate.action is not GateAction.QUARANTINE:
            conflicts, supersede_candidates = self._reconcile(memory)

        if not validation.ok:
            memory.record_transition(MemoryState.QUARANTINED, "provenance rejected", "validator")
            memory.partition = Partition.QUARANTINE
        elif gate.action is GateAction.QUARANTINE:
            memory.record_transition(
                MemoryState.QUARANTINED, "consolidation gate quarantined", "gate"
            )
            memory.partition = Partition.QUARANTINE
        elif conflicts:
            # Atomicity: a conflicting memory must not displace the older one.
            memory.record_transition(
                MemoryState.CONFLICT, "contradicts an existing memory", "governance"
            )
        elif gate.action is GateAction.PROMOTE or (
            validation.trust in {TrustLevel.USER_STATED, TrustLevel.USER_VERIFIED}
        ):
            memory.state = MemoryState.ACTIVE
        else:
            memory.record_transition(MemoryState.PENDING_REVIEW, f"gate: {gate.action.value}", "gate")

        self.governance.register(memory)
        applied_supersede: list[str] = []
        if memory.state is MemoryState.ACTIVE and not conflicts:
            for old_id in supersede_candidates:
                self.governance.supersede(old_id, memory.id)
                applied_supersede.append(old_id)
                self._audit("superseded", old_id, f"by {memory.id}")

        self._audit(
            "added",
            memory.id,
            f"trust={memory.trust.value} state={memory.state.value} attested={validation.attested}",
        )
        self._persist()
        return AddResult(
            memory=memory,
            validation=validation,
            gate=gate,
            conflicts=conflicts,
            superseded=applied_supersede,
            accepted=memory.state is MemoryState.ACTIVE,
        )

    def _reconcile(self, memory: Memory) -> tuple[list[str], list[str]]:
        conflicts: list[str] = []
        supersede: list[str] = []
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
                supersede.append(existing.id)
            elif score >= 0.45:
                conflicts.append(existing.id)
        return conflicts, supersede

    def _gate(
        self,
        memory: Memory,
        *,
        is_preference: bool,
        decision_weight: float,
        repetitions: int,
    ) -> GateDecision:
        if not self.consolidate:
            return GateDecision(GateAction.PROMOTE, 1.0, ("consolidation disabled",))
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
                confidence=memory.confidence,
            )
        )

    # ------------------------------------------------------------------ read
    def search(
        self,
        query: str,
        *,
        require_trust_level: str | TrustLevel = TrustLevel.USER_STATED,
        consumer: str = "agent",
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
                allowed_states.add(MemoryState.QUARANTINED)
            if memory.state not in allowed_states or memory.partition not in partitions:
                continue
            if trust_rank(memory.trust) < required_rank or memory.is_expired(now=now):
                continue
            # Consumer authorization comes from the precompiled policy. An explicit
            # inspector (require_trust_level=untrusted) bypasses consumer gating.
            if required is not TrustLevel.UNTRUSTED and not memory.policy.permits(consumer):
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
        old = self.governance.supersede(old_id, new_id)
        self._audit("superseded", old_id, f"by {new_id} (explicit)")
        self._persist()
        return old

    def confirm(self, memory_id: str) -> Memory:
        memory = self.governance.confirm(memory_id)
        self._audit("confirmed", memory_id, "human confirmation")
        self._persist()
        return memory

    def archive(self, memory_id: str) -> Memory:
        memory = self.governance.archive(memory_id)
        self._audit("archived", memory_id, "archived")
        self._persist()
        return memory

    def explain(self, memory_id: str) -> dict[str, Any]:
        explained = self.governance.explain(memory_id)
        explained["audit"] = [
            dict(entry) for entry in self.audit_log if entry["memory_id"] == memory_id
        ]
        return explained

    def stats(self) -> dict[str, Any]:
        stats = self.governance.stats()
        stats["durable"] = self.durable
        stats["audit_events"] = len(self.audit_log)
        return stats

    # ------------------------------------------------------------------ rules
    def add_rule(self, rule: Rule) -> Rule:
        return self.rules.add(rule)

    def evaluate_rule(self, text: str, *, scope: str = "*") -> Decision:
        return self.rules.evaluate(text, scope=scope)


__all__ = ["AddResult", "Guard", "SearchHit", "Rule", "RuleAction", "similarity", "tokens"]
