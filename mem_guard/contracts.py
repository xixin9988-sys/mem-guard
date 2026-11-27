"""Wire contracts for the mem-guard gateway.

Every request and response that crosses the HTTP boundary is one of these models, so a client
cannot smuggle a field the gateway ignores and the gateway cannot answer with a shape the
client does not understand.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

GUARD_VERSION = "2.0.0"

Decision = Literal["allow", "redact", "block", "insufficient_evidence"]


class Scope(BaseModel):
    """Authenticated caller identity.  Produced by tenancy resolution, never by a client body."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_.:-]+$")
    user_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_.:-]+$")
    roles: tuple[str, ...] = Field(default_factory=tuple, max_length=20)
    acl_tags: tuple[str, ...] = Field(default_factory=tuple, max_length=50)
    request_id: str | None = Field(default=None, max_length=80)

    def to_headers(self) -> dict[str, str]:
        return {
            "X-Guard-Tenant": self.tenant_id,
            "X-Guard-User": self.user_id,
            "X-Guard-Roles": ",".join(self.roles),
            "X-Guard-Acl": ",".join(self.acl_tags),
        }


class RememberRequest(BaseModel):
    """Write a memory through the guard."""

    model_config = ConfigDict(extra="forbid")

    content: str = Field(min_length=1, max_length=20_000)
    category: str = Field(default="general", min_length=1, max_length=80)
    tags: list[str] = Field(default_factory=list, max_length=30)
    memory_type: Literal[
        "fact", "preference", "event", "procedure", "relationship", "autobiographical"
    ] = "fact"
    importance: int = Field(default=3, ge=1, le=5)
    confidence: Literal["low", "medium", "high"] = "medium"
    source_kind: Literal["user", "model", "tool", "file", "composed", "import", "unknown"] = "user"
    source_ref: str | None = Field(default=None, max_length=500)
    valid_until: str | None = Field(default=None, max_length=40)
    acl_tags: list[str] = Field(default_factory=list, max_length=50)
    attributes: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    idempotency_key: str | None = Field(default=None, max_length=120)

    @field_validator("tags", "acl_tags")
    @classmethod
    def _slug_list(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for item in value:
            normalised = item.strip().lower()
            if not normalised:
                continue
            if not normalised.replace("-", "").replace("_", "").isalnum():
                raise ValueError("tags must be slugs")
            if normalised not in cleaned:
                cleaned.append(normalised)
        return cleaned


class RecallRequest(BaseModel):
    """Ask the guard for evidence, not for an answer."""

    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=4000)
    limit: int = Field(default=6, ge=1, le=20)
    categories: list[str] = Field(default_factory=list, max_length=20)
    memory_types: list[str] = Field(default_factory=list, max_length=10)
    tags: list[str] = Field(default_factory=list, max_length=20)
    min_trust: Literal["untrusted", "unknown", "user_provided", "verified"] = "unknown"


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    content: str
    score: float = 0.0
    signals: dict[str, float] = Field(default_factory=dict)
    trust_level: str = "unknown"
    metadata: dict[str, Any] = Field(default_factory=dict)


class SafetyFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str
    severity: Literal["low", "medium", "high"]
    start: int
    end: int
    snippet: str


class InjectionFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule: str
    weight: float
    snippet: str


class GuardReport(BaseModel):
    """What the guard did and why — returned with every recall/write response."""

    model_config = ConfigDict(extra="forbid")

    decision: Decision = "allow"
    reasons: list[str] = Field(default_factory=list)
    safety: list[SafetyFinding] = Field(default_factory=list)
    injection: list[InjectionFinding] = Field(default_factory=list)
    injection_score: float = 0.0
    redacted: bool = False
    trust_filtered: int = 0
    quota_remaining: dict[str, int] = Field(default_factory=dict)
    latency_ms: float = 0.0
    audit_id: str | None = None


class RecallResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trace_id: str
    items: list[Evidence] = Field(default_factory=list)
    insufficient_context: bool = False
    degraded: bool = False
    fallback_reason: str | None = None
    guard: GuardReport = Field(default_factory=GuardReport)


class RememberResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    record: dict[str, Any]
    trace_id: str
    guard: GuardReport = Field(default_factory=GuardReport)


class FeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trace_id: str = Field(min_length=4, max_length=80)
    verdict: Literal["up", "down"]
    reason: str | None = Field(default=None, max_length=80)
    comment: str | None = Field(default=None, max_length=1000)


class FeedbackRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    feedback_id: str
    trace_id: str
    verdict: Literal["up", "down"]
    reason: str | None = None
    comment: str | None = None
    tenant_id: str
    user_id: str
    forwarded: bool = False
    created_at: str


class GroundingRequest(BaseModel):
    """Check a generated answer against the evidence it claims to use."""

    model_config = ConfigDict(extra="forbid")

    question: str = Field(default="", max_length=4000)
    answer: str = Field(min_length=1, max_length=20_000)
    evidence: list[str] = Field(default_factory=list, max_length=20)
    trace_id: str | None = Field(default=None, max_length=80)
    min_question_coverage: float = Field(default=0.34, ge=0.0, le=1.0)


class GroundingDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["allow", "repair", "block", "insufficient_evidence"]
    reasons: list[str] = Field(default_factory=list)
    unsupported_entities: list[str] = Field(default_factory=list)
    missing_question_entities: list[str] = Field(default_factory=list)
    question_coverage: float = 0.0
    audit_id: str | None = None


class QuotaSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    user_id: str
    day: str
    limits: dict[str, int]
    used: dict[str, int]
    remaining: dict[str, int]
    retry_after_seconds: float = 0.0


class ErrorEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    request_id: str | None = None


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ok", "degraded"]
    version: str
    nanomemory: dict[str, Any]
    checks: dict[str, bool]


__all__ = [
    "GUARD_VERSION",
    "Decision",
    "ErrorEnvelope",
    "Evidence",
    "FeedbackRecord",
    "FeedbackRequest",
    "GroundingDecision",
    "GroundingRequest",
    "GuardReport",
    "HealthResponse",
    "InjectionFinding",
    "QuotaSnapshot",
    "RecallRequest",
    "RecallResponse",
    "RememberRequest",
    "RememberResponse",
    "SafetyFinding",
    "Scope",
]
