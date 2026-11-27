"""MemoryGateway: the only path from a client to memory.

Write path: auth -> rate limit -> injection scan -> PII/secret scan -> budget -> NanoMemory
            (signed scope) -> charge -> audit.
Read path:  auth -> rate limit -> injection scan -> budget -> NanoMemory search -> trust gate
            -> charge -> audit.

Every branch that refuses still writes an audit entry, so "the guard blocked it" is
reconstructible with a timestamp and a reason, not just a 422.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from mem_guard.audit import AuditLog
from mem_guard.config import GatewaySettings
from mem_guard.contracts import (
    Evidence,
    FeedbackRecord,
    FeedbackRequest,
    GroundingDecision,
    GroundingRequest,
    GuardReport,
    QuotaSnapshot,
    RecallRequest,
    RecallResponse,
    RememberRequest,
    RememberResponse,
    Scope,
)
from mem_guard.feedback import FeedbackStore
from mem_guard.grounding import GroundingGuard
from mem_guard.injection import InjectionDetector
from mem_guard.nanomemory_client import NanoMemoryClient, NanoMemoryError
from mem_guard.quota import QuotaExceeded, QuotaManager, UsageLedger
from mem_guard.safety import ContentSafety

TRUST_ORDER = {"untrusted": 0, "unknown": 1, "user_provided": 2, "verified": 3}

_SOURCE_TRUST = {
    "user": "user_provided",
    "model": "unknown",
    "tool": "untrusted",
    "file": "untrusted",
    "composed": "unknown",
    "import": "untrusted",
    "unknown": "unknown",
}


class GuardRejection(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        status: int = 422,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.details = details or {}


@dataclass(slots=True)
class GatewayHealth:
    status: str
    checks: dict[str, bool] = field(default_factory=dict)
    nanomemory: dict[str, Any] = field(default_factory=dict)


def estimate_tokens(text: str) -> int:
    if not text:
        return 0
    cjk = sum(1 for char in text if "\u4e00" <= char <= "\u9fff")
    return max(1, round(cjk / 1.7 + (len(text) - cjk) / 4.0))


class MemoryGateway:
    def __init__(
        self,
        settings: GatewaySettings,
        *,
        client: NanoMemoryClient | None = None,
        quota: QuotaManager | None = None,
        audit: AuditLog | None = None,
        feedback: FeedbackStore | None = None,
        safety: ContentSafety | None = None,
        injection: InjectionDetector | None = None,
        grounding: GroundingGuard | None = None,
    ) -> None:
        self.settings = settings
        self.client = client or NanoMemoryClient(
            base_url=settings.nanomemory_base_url,
            signing_key=settings.context_signing_key,
            timeout=settings.nanomemory_timeout,
            admin_token=settings.nanomemory_admin_token,
        )
        self.quota = quota or QuotaManager(
            ledger=UsageLedger(settings.quota_db),
            per_minute=settings.rate_limit_per_minute,
            daily_embedding_tokens=settings.daily_embedding_tokens,
            daily_retrieval_tokens=settings.daily_retrieval_tokens,
            daily_writes=settings.daily_writes,
            daily_searches=settings.daily_searches,
            enabled=settings.quota_enabled,
        )
        self.audit = audit or AuditLog(settings.audit_log)
        self.feedback = feedback or FeedbackStore(settings.feedback_db)
        self.safety = safety or ContentSafety(mode=settings.safety_mode)
        self.injection = injection or InjectionDetector(threshold=settings.injection_threshold)
        self.grounding = grounding or GroundingGuard()

    # ------------------------------------------------------------------ write
    async def remember(self, scope: Scope, request: RememberRequest) -> RememberResponse:
        started = time.perf_counter()
        self.quota.check_request(scope)
        self.quota.check_budget(scope, "writes", 1)

        injection = self.injection.scan(request.content)
        if injection.blocked(self.settings.injection_threshold):
            self._audit(
                "memory.remember.blocked",
                scope,
                outcome="blocked",
                details={"reason": "prompt_injection", "rules": injection.rules},
            )
            raise GuardRejection(
                "prompt_injection_detected",
                "Content looks like a prompt-injection attempt and was not stored.",
                details={"score": injection.score, "rules": injection.rules},
            )

        safety = self.safety.scan(request.content)
        if safety.action == "block":
            self._audit(
                "memory.remember.blocked",
                scope,
                outcome="blocked",
                details={"reason": "sensitive_content", "kinds": safety.kinds},
            )
            raise GuardRejection(
                "sensitive_content_blocked",
                "Content contains secrets or high-risk PII and was not stored.",
                details={"kinds": safety.kinds},
            )

        content = safety.redacted_text
        estimated = estimate_tokens(content)
        self.quota.check_budget(scope, "embedding_tokens", estimated)

        payload = {
            "content": content,
            "category": request.category,
            "tags": request.tags,
            "memory_type": request.memory_type,
            "importance": request.importance,
            "confidence": request.confidence,
            "source": f"mem-guard:{request.source_kind}",
            "source_type": "user" if request.source_kind == "user" else "tool",
            "trust_level": _SOURCE_TRUST.get(request.source_kind, "unknown"),
            "valid_until": request.valid_until,
            "attributes": {
                **request.attributes,
                "guard_source_kind": request.source_kind,
                "guard_redacted": safety.action == "redact",
            },
            "acl_tags": request.acl_tags,
            "provenance": {
                "source_kind": request.source_kind,
                "source_ref": request.source_ref,
                "created_by": "mem-guard",
            },
        }
        if request.idempotency_key:
            payload["idempotency_key"] = request.idempotency_key
        try:
            response = await self.client.remember(scope, payload)
        except NanoMemoryError as exc:
            self._audit(
                "memory.remember.failed",
                scope,
                outcome="error",
                details={"code": exc.code, "status": exc.status},
            )
            raise

        record = dict(response.get("record") or {})
        trace_id = str(response.get("trace_id") or "")
        tokens = int((response.get("embedding") or {}).get("tokens") or estimated)
        self.quota.charge(scope, "writes", 1)
        self.quota.charge(scope, "embedding_tokens", tokens)
        snapshot = self.quota.snapshot(scope)
        audit = self._audit(
            "memory.remember",
            scope,
            trace_id=trace_id,
            outcome="redacted" if safety.action == "redact" else "ok",
            details={
                "memory_id": record.get("id"),
                "tokens": tokens,
                "injection_score": injection.score,
                "safety_kinds": safety.kinds,
            },
        )
        report = GuardReport(
            decision="redact" if safety.action == "redact" else "allow",
            reasons=["sensitive_content_redacted"] if safety.action == "redact" else [],
            safety=safety.findings,
            injection=injection.findings,
            injection_score=injection.score,
            redacted=safety.action == "redact",
            quota_remaining=snapshot.remaining,
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
            audit_id=audit.audit_id,
        )
        return RememberResponse(record=record, trace_id=trace_id, guard=report)

    # ------------------------------------------------------------------ read
    async def recall(self, scope: Scope, request: RecallRequest) -> RecallResponse:
        started = time.perf_counter()
        self.quota.check_request(scope)
        self.quota.check_budget(scope, "searches", 1)
        self.quota.check_budget(scope, "retrieval_tokens", estimate_tokens(request.query))

        injection = self.injection.scan(request.query)
        if injection.blocked(self.settings.injection_threshold):
            self._audit(
                "memory.recall.blocked",
                scope,
                outcome="blocked",
                details={"reason": "prompt_injection", "rules": injection.rules},
            )
            raise GuardRejection(
                "prompt_injection_detected",
                "Query looks like a prompt-injection attempt.",
                details={"score": injection.score, "rules": injection.rules},
            )

        payload = {
            "query": request.query,
            "limit": request.limit,
            "categories": request.categories,
            "memory_types": request.memory_types,
            "tags": request.tags,
        }
        response = await self.client.search(scope, payload)
        items = [_evidence(item) for item in response.get("items", [])]
        allowed, dropped = self._trust_gate(items, request.min_trust)

        used_tokens = estimate_tokens(request.query) + sum(
            estimate_tokens(item.content) for item in allowed
        )
        self.quota.charge(scope, "searches", 1)
        self.quota.charge(scope, "retrieval_tokens", used_tokens)
        snapshot = self.quota.snapshot(scope)
        trace_id = str(response.get("trace_id") or "")
        audit = self._audit(
            "memory.recall",
            scope,
            trace_id=trace_id,
            outcome="ok",
            details={
                "items": len(allowed),
                "trust_filtered": dropped,
                "insufficient_context": bool(response.get("insufficient_context")),
                "injection_score": injection.score,
            },
        )
        report = GuardReport(
            decision="allow",
            injection=injection.findings,
            injection_score=injection.score,
            trust_filtered=dropped,
            quota_remaining=snapshot.remaining,
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
            audit_id=audit.audit_id,
        )
        return RecallResponse(
            trace_id=trace_id,
            items=allowed,
            insufficient_context=bool(response.get("insufficient_context")),
            degraded=bool(response.get("degraded")),
            fallback_reason=response.get("fallback_reason"),
            guard=report,
        )

    @staticmethod
    def _trust_gate(items: list[Evidence], min_trust: str) -> tuple[list[Evidence], int]:
        required = TRUST_ORDER.get(min_trust, 1)
        kept: list[Evidence] = []
        dropped = 0
        for item in items:
            if TRUST_ORDER.get(item.trust_level, 0) < required:
                dropped += 1
                continue
            kept.append(item)
        return kept, dropped

    # ------------------------------------------------------------------ feedback
    async def submit_feedback(self, scope: Scope, request: FeedbackRequest) -> FeedbackRecord:
        forwarded = True
        try:
            await self.client.feedback(
                scope,
                trace_id=request.trace_id,
                verdict=request.verdict,
                reason=request.reason,
                comment=request.comment,
            )
        except NanoMemoryError as exc:
            if exc.status == 404:
                raise GuardRejection(
                    "trace_not_found",
                    "No trace with this id exists for this tenant.",
                    status=404,
                    details={"trace_id": request.trace_id},
                ) from exc
            if exc.status == 0 or exc.status >= 500:
                forwarded = False
            else:
                raise
        record = self.feedback.record(scope, request, forwarded=forwarded)
        self._audit(
            "memory.feedback",
            scope,
            trace_id=request.trace_id,
            outcome="ok" if forwarded else "degraded",
            details={"verdict": request.verdict, "forwarded": forwarded},
        )
        return record

    # ------------------------------------------------------------------ grounding
    def check_grounding(self, scope: Scope, request: GroundingRequest) -> GroundingDecision:
        decision = self.grounding.check(
            question=request.question,
            answer=request.answer,
            evidence=request.evidence,
            min_question_coverage=request.min_question_coverage,
        )
        audit = self._audit(
            "answer.grounded",
            scope,
            trace_id=request.trace_id,
            outcome=decision.action,
            details={
                "unsupported": decision.unsupported_entities,
                "missing_question_entities": decision.missing_question_entities,
                "coverage": decision.question_coverage,
            },
        )
        decision.audit_id = audit.audit_id
        return decision

    # ------------------------------------------------------------------ ops
    def quota_snapshot(self, scope: Scope) -> QuotaSnapshot:
        return self.quota.snapshot(scope)

    async def export_badcases(self, scope: Scope) -> dict[str, Any]:
        response = await self.client.export_badcases(scope)
        self._audit(
            "feedback.export",
            scope,
            outcome="ok",
            details={"exported": response.get("exported")},
        )
        return response

    async def health(self) -> GatewayHealth:
        checks: dict[str, bool] = {}
        nanomemory: dict[str, Any] = {}
        try:
            payload = await self.client.health()
            nanomemory = {
                "status": payload.get("status"),
                "version": payload.get("version"),
            }
            checks["nanomemory"] = str(payload.get("status")) == "ok"
        except NanoMemoryError as exc:
            nanomemory = {"status": "unavailable", "error": exc.code}
            checks["nanomemory"] = False
        checks["audit_chain"] = self.audit.verify().valid
        checks["quota"] = self.settings.quota_enabled
        return GatewayHealth(
            status="ok" if all(checks.values()) else "degraded",
            checks=checks,
            nanomemory=nanomemory,
        )

    async def aclose(self) -> None:
        await self.client.aclose()
        self.feedback.close()
        self.quota.ledger.close()

    # ------------------------------------------------------------------ internals
    def _audit(
        self,
        event: str,
        scope: Scope,
        *,
        trace_id: str | None = None,
        outcome: str = "ok",
        details: dict[str, Any] | None = None,
    ):
        return self.audit.append(
            event,
            tenant_id=scope.tenant_id,
            user_id=scope.user_id,
            trace_id=trace_id,
            outcome=outcome,
            details=details,
        )


def _evidence(item: dict[str, Any]) -> Evidence:
    metadata = dict(item.get("metadata") or {})
    return Evidence(
        id=str(item.get("id") or ""),
        content=str(item.get("content") or ""),
        score=float(item.get("score") or 0.0),
        signals={key: float(value) for key, value in (item.get("signals") or {}).items()},
        trust_level=str(metadata.get("trust_level") or "unknown"),
        metadata=metadata,
    )


__all__ = ["GuardRejection", "MemoryGateway", "QuotaExceeded", "estimate_tokens"]
