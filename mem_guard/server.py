"""FastAPI front door for the guard.

    POST /v1/guard/remember            write through the guard
    POST /v1/guard/recall              retrieve evidence through the guard
    POST /v1/guard/feedback            👍/👎 bound to a trace id
    POST /v1/guard/grounding/check     verify an answer against its evidence
    GET  /v1/guard/quota               today's usage and remaining budgets
    GET  /v1/guard/feedback/export     admin: push badcases into NanoMemory's eval file
    GET  /healthz                      dependency + audit-chain health

The service key authenticates the *calling service* (OmniCare's BFF), not an end user.  End
users never hold this key: they authenticate to OmniCare, which then asserts tenant/user.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from mem_guard.config import GatewaySettings
from mem_guard.contracts import (
    GUARD_VERSION,
    FeedbackRecord,
    FeedbackRequest,
    GroundingDecision,
    GroundingRequest,
    QuotaSnapshot,
    RecallRequest,
    RecallResponse,
    RememberRequest,
    RememberResponse,
    Scope,
)
from mem_guard.gateway import GuardRejection, MemoryGateway
from mem_guard.nanomemory_client import NanoMemoryError
from mem_guard.quota import QuotaExceeded
from mem_guard.tenancy import ContextError, resolve_scope


def get_gateway(request: Request) -> MemoryGateway:
    """Create the gateway on first use so importing the module has no filesystem side effect."""
    gateway = request.app.state.gateway
    if gateway is None:
        gateway = MemoryGateway(request.app.state.settings)
        request.app.state.gateway = gateway
    return gateway


def get_scope(request: Request) -> Scope:
    settings: GatewaySettings = request.app.state.settings
    return resolve_scope(
        request.headers,
        service_key=settings.service_api_key,
        allow_default=settings.allow_default_scope,
    )


def _error(
    code: str,
    message: str,
    status: int,
    *,
    details: dict[str, Any] | None = None,
    request_id: str | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={
            "code": code,
            "message": message,
            "details": details or {},
            "request_id": request_id,
        },
    )


def create_app(
    settings: GatewaySettings | None = None,
    *,
    gateway: MemoryGateway | None = None,
) -> FastAPI:
    settings = settings or GatewaySettings.from_env()

    @asynccontextmanager
    async def lifespan(instance: FastAPI):
        yield
        gateway = instance.state.gateway
        if gateway is not None:
            await gateway.aclose()

    app = FastAPI(
        title="mem-guard gateway",
        description="Memory security, governance and cost gateway in front of NanoMemory.",
        version=GUARD_VERSION,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.gateway = gateway

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    @app.exception_handler(ContextError)
    async def context_error(request: Request, exc: ContextError) -> JSONResponse:
        status = 401 if exc.code.startswith("guard_auth") else 400
        return _error(
            exc.code,
            exc.message,
            status,
            details=exc.details,
            request_id=getattr(request.state, "request_id", None),
        )

    @app.exception_handler(GuardRejection)
    async def guard_rejection(request: Request, exc: GuardRejection) -> JSONResponse:
        return _error(
            exc.code,
            exc.message,
            exc.status,
            details=exc.details,
            request_id=getattr(request.state, "request_id", None),
        )

    @app.exception_handler(QuotaExceeded)
    async def quota_exceeded(request: Request, exc: QuotaExceeded) -> JSONResponse:
        response = _error(
            exc.code,
            exc.message,
            429,
            details=exc.details,
            request_id=getattr(request.state, "request_id", None),
        )
        response.headers["Retry-After"] = str(max(0.0, float(exc.retry_after)))
        return response

    @app.exception_handler(NanoMemoryError)
    async def nanomemory_error(request: Request, exc: NanoMemoryError) -> JSONResponse:
        status = exc.status if exc.status >= 400 else 502
        return _error(
            exc.code,
            exc.message,
            status,
            details=exc.details,
            request_id=getattr(request.state, "request_id", None),
        )

    # ------------------------------------------------------------------ endpoints
    @app.post("/v1/guard/remember", response_model=RememberResponse)
    async def remember(
        body: RememberRequest,
        scope: Scope = Depends(get_scope),
        gw: MemoryGateway = Depends(get_gateway),
    ) -> RememberResponse:
        return await gw.remember(scope, body)

    @app.post("/v1/guard/recall", response_model=RecallResponse)
    async def recall(
        body: RecallRequest,
        scope: Scope = Depends(get_scope),
        gw: MemoryGateway = Depends(get_gateway),
    ) -> RecallResponse:
        return await gw.recall(scope, body)

    @app.post("/v1/guard/feedback", response_model=FeedbackRecord)
    async def feedback(
        body: FeedbackRequest,
        scope: Scope = Depends(get_scope),
        gw: MemoryGateway = Depends(get_gateway),
    ) -> FeedbackRecord:
        return await gw.submit_feedback(scope, body)

    @app.post("/v1/guard/grounding/check", response_model=GroundingDecision)
    def grounding(
        body: GroundingRequest,
        scope: Scope = Depends(get_scope),
        gw: MemoryGateway = Depends(get_gateway),
    ) -> GroundingDecision:
        return gw.check_grounding(scope, body)

    @app.get("/v1/guard/quota", response_model=QuotaSnapshot)
    def quota(
        scope: Scope = Depends(get_scope),
        gw: MemoryGateway = Depends(get_gateway),
    ) -> QuotaSnapshot:
        return gw.quota_snapshot(scope)

    @app.get("/v1/guard/feedback/export")
    async def export_badcases(
        scope: Scope = Depends(get_scope),
        gw: MemoryGateway = Depends(get_gateway),
    ) -> dict[str, Any]:
        return await gw.export_badcases(scope)

    @app.get("/healthz")
    async def health(gw: MemoryGateway = Depends(get_gateway)) -> dict[str, Any]:
        report = await gw.health()
        return {
            "status": report.status,
            "version": GUARD_VERSION,
            "nanomemory": report.nanomemory,
            "checks": report.checks,
        }

    @app.get("/")
    def index() -> dict[str, str]:
        return {"service": "mem-guard", "version": GUARD_VERSION, "docs": "/docs"}

    return app


app = create_app()


__all__ = ["app", "create_app", "get_gateway", "get_scope"]
