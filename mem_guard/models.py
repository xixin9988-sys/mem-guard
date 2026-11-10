"""Core data model: provenance, trust, state, partition and memory records."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


class TrustLevel(StrEnum):
    """How much the system may rely on a memory, derived from provenance only."""

    UNTRUSTED = "untrusted"
    MODEL_INFERRED = "model_inferred"
    USER_STATED = "user_stated"
    USER_VERIFIED = "user_verified"


TRUST_ORDER: dict[TrustLevel, int] = {
    TrustLevel.UNTRUSTED: 0,
    TrustLevel.MODEL_INFERRED: 1,
    TrustLevel.USER_STATED: 2,
    TrustLevel.USER_VERIFIED: 3,
}


def trust_rank(level: TrustLevel | str) -> int:
    return TRUST_ORDER[TrustLevel(level)]


class MemoryState(StrEnum):
    """Governed lifecycle states; retrieval only serves ``ACTIVE``."""

    ACTIVE = "active"
    PENDING_REVIEW = "pending_review"
    CONFLICT = "conflict"
    QUARANTINED = "quarantined"
    SUPERSEDED = "superseded"
    ARCHIVED = "archived"


class Partition(StrEnum):
    """Physical partition: retrieval selects partitions, never per-item ACLs."""

    PRIVATE = "private"
    SHARED = "shared"
    QUARANTINE = "quarantine"


class SourceKind(StrEnum):
    """Where a statement came from; the only input to the trust label."""

    USER_STATEMENT = "user_statement"
    USER_VERIFIED = "user_verified"
    MODEL_INFERENCE = "model_inference"
    TOOL_OUTPUT = "tool_output"
    EXTERNAL_DOCUMENT = "external_document"
    IMPORT = "import"


SOURCE_TRUST: dict[SourceKind, TrustLevel] = {
    SourceKind.USER_STATEMENT: TrustLevel.USER_STATED,
    SourceKind.USER_VERIFIED: TrustLevel.USER_VERIFIED,
    SourceKind.MODEL_INFERENCE: TrustLevel.MODEL_INFERRED,
    SourceKind.TOOL_OUTPUT: TrustLevel.UNTRUSTED,
    SourceKind.EXTERNAL_DOCUMENT: TrustLevel.UNTRUSTED,
    SourceKind.IMPORT: TrustLevel.UNTRUSTED,
}


@dataclass(slots=True)
class Provenance:
    """Immutable record of where a memory came from."""

    kind: SourceKind
    reference: str | None = None
    issuer: str | None = None
    captured_at: str = field(default_factory=utc_now)
    evidence: tuple[str, ...] = ()
    integrity: str = ""

    def __post_init__(self) -> None:
        if not self.integrity:
            payload = f"{self.kind.value}|{self.issuer or ''}|{self.reference or ''}|{self.captured_at}"
            self.integrity = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "reference": self.reference,
            "issuer": self.issuer,
            "captured_at": self.captured_at,
            "evidence": list(self.evidence),
            "integrity": self.integrity,
        }


@dataclass(slots=True)
class Policy:
    """Precompiled at write time so retrieval never re-evaluates policy per item."""

    allowed_consumers: frozenset[str] = frozenset({"*"})
    min_trust: TrustLevel = TrustLevel.UNTRUSTED
    retention: str = "standard"
    note: str | None = None

    def permits(self, consumer: str) -> bool:
        return "*" in self.allowed_consumers or consumer in self.allowed_consumers

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_consumers": sorted(self.allowed_consumers),
            "min_trust": self.min_trust.value,
            "retention": self.retention,
            "note": self.note,
        }


@dataclass(slots=True)
class Memory:
    """One governed memory record."""

    content: str
    provenance: Provenance
    trust: TrustLevel
    confidence: float = 0.8
    tags: tuple[str, ...] = ()
    id: str = field(default_factory=lambda: f"mem-{uuid.uuid4().hex[:12]}")
    state: MemoryState = MemoryState.ACTIVE
    partition: Partition = Partition.PRIVATE
    observed_at: str = field(default_factory=utc_now)
    valid_until: str | None = None
    supersedes: list[str] = field(default_factory=list)
    superseded_by: str | None = None
    version: int = 1
    policy: Policy = field(default_factory=Policy)
    history: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        self.tags = tuple(sorted({tag.strip().lower() for tag in self.tags if tag.strip()}))
        if not self.history:
            self.history.append(
                {
                    "at": self.observed_at,
                    "state": self.state.value,
                    "reason": "created",
                    "actor": self.provenance.kind.value,
                }
            )

    def record_transition(self, state: MemoryState, reason: str, actor: str) -> None:
        self.state = state
        self.version += 1
        self.history.append(
            {"at": utc_now(), "state": state.value, "reason": reason, "actor": actor}
        )

    def is_expired(self, *, now: datetime | None = None) -> bool:
        if not self.valid_until:
            return False
        moment = now or datetime.now(UTC)
        try:
            deadline = datetime.fromisoformat(self.valid_until.replace("Z", "+00:00"))
        except ValueError:
            return False
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=UTC)
        return deadline <= moment

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "content": self.content,
            "trust": self.trust.value,
            "confidence": round(self.confidence, 4),
            "state": self.state.value,
            "partition": self.partition.value,
            "tags": list(self.tags),
            "observed_at": self.observed_at,
            "valid_until": self.valid_until,
            "supersedes": list(self.supersedes),
            "superseded_by": self.superseded_by,
            "version": self.version,
            "provenance": self.provenance.to_dict(),
            "policy": self.policy.to_dict(),
            "history": list(self.history),
        }
def memory_from_dict(data: dict[str, Any]) -> Memory:
    """Rebuild a memory from its serialised form (persistence round-trip)."""
    provenance = Provenance(
        kind=SourceKind(data["provenance"]["kind"]),
        reference=data["provenance"].get("reference"),
        issuer=data["provenance"].get("issuer"),
        captured_at=data["provenance"]["captured_at"],
        evidence=tuple(data["provenance"].get("evidence", ())),
        integrity=data["provenance"].get("integrity", ""),
    )
    policy_data = data.get("policy", {})
    policy = Policy(
        allowed_consumers=frozenset(policy_data.get("allowed_consumers", ["*"])),
        min_trust=TrustLevel(policy_data.get("min_trust", "untrusted")),
        retention=policy_data.get("retention", "standard"),
        note=policy_data.get("note"),
    )
    return Memory(
        id=data["id"],
        content=data["content"],
        provenance=provenance,
        trust=TrustLevel(data["trust"]),
        confidence=float(data.get("confidence", 0.8)),
        tags=tuple(data.get("tags", ())),
        state=MemoryState(data.get("state", "active")),
        partition=Partition(data.get("partition", "private")),
        observed_at=data.get("observed_at", utc_now()),
        valid_until=data.get("valid_until"),
        supersedes=list(data.get("supersedes", [])),
        superseded_by=data.get("superseded_by"),
        version=int(data.get("version", 1)),
        policy=policy,
        history=list(data.get("history", [])),
    )