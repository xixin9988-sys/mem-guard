"""Consolidation Gate: heuristics decide what may become durable memory.

An LLM may propose candidates, but admission is deterministic: repetition, preference weight,
decision weight, similarity to what is already stored and evidence count. Model inferences
without evidence are quarantined rather than "summarised into truth".
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from mem_guard.models import TrustLevel

WEIGHTS = {
    "repetition": 0.30,
    "preference": 0.25,
    "decision": 0.20,
    "similarity": 0.15,
    "evidence": 0.10,
}
PROMOTE_THRESHOLD = 0.60
DEFER_THRESHOLD = 0.35


class GateAction(StrEnum):
    PROMOTE = "promote"
    DEFER = "defer"
    QUARANTINE = "quarantine"
    REJECT = "reject"


@dataclass(frozen=True, slots=True)
class Candidate:
    content: str
    trust: TrustLevel
    repetitions: int = 1
    is_preference: bool = False
    decision_weight: float = 0.0
    similarity_to_existing: float = 0.0
    evidence_count: int = 0
    confidence: float = 0.8


@dataclass(frozen=True, slots=True)
class GateDecision:
    action: GateAction
    score: float
    reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action.value,
            "score": round(self.score, 4),
            "reasons": list(self.reasons),
        }


class ConsolidationGate:
    """Deterministic admission policy for long-term memory."""

    def evaluate(self, candidate: Candidate) -> GateDecision:
        if candidate.trust is TrustLevel.MODEL_INFERRED and candidate.evidence_count == 0:
            return GateDecision(
                action=GateAction.QUARANTINE,
                score=0.0,
                reasons=("model inference without evidence cannot be consolidated",),
            )
        # Trusted, confident statements are admissible by construction; the gate exists to
        # stop weak, inferred or unverified material from becoming durable memory.
        if candidate.trust in {TrustLevel.USER_STATED, TrustLevel.USER_VERIFIED} and (
            candidate.confidence >= 0.7 or candidate.is_preference or candidate.evidence_count > 0
        ):
            return GateDecision(
                action=GateAction.PROMOTE,
                score=0.7,
                reasons=("trusted source with sufficient confidence",),
            )
        repetition = min(candidate.repetitions / 3.0, 1.0)
        preference = 1.0 if candidate.is_preference else 0.0
        decision = max(0.0, min(1.0, candidate.decision_weight))
        similarity = max(0.0, min(1.0, candidate.similarity_to_existing))
        evidence = min(candidate.evidence_count / 2.0, 1.0)
        score = (
            WEIGHTS["repetition"] * repetition
            + WEIGHTS["preference"] * preference
            + WEIGHTS["decision"] * decision
            + WEIGHTS["similarity"] * similarity
            + WEIGHTS["evidence"] * evidence
        )
        reasons = [
            f"repetition {repetition:.2f}",
            f"preference {preference:.2f}",
            f"decision {decision:.2f}",
            f"similarity {similarity:.2f}",
            f"evidence {evidence:.2f}",
        ]
        if score >= PROMOTE_THRESHOLD:
            return GateDecision(GateAction.PROMOTE, score, tuple(reasons))
        if score >= DEFER_THRESHOLD:
            return GateDecision(
                GateAction.DEFER, score, tuple([*reasons, "below promotion threshold"])
            )
        return GateDecision(GateAction.REJECT, score, tuple([*reasons, "too weak to keep"]))
