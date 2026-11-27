"""HTTP client for NanoMemory v2.

Every request is signed with the shared context key, so NanoMemory's SQL pre-filter is built
from a tenant that the gateway proved, not from a value a caller supplied.  The signature
includes a timestamp (fresh per request) and the body is never trusted for scope.
"""

from __future__ import annotations

from typing import Any

import httpx

from mem_guard.contracts import Scope
from mem_guard.tenancy import nm_headers


class NanoMemoryError(Exception):
    """A typed upstream failure; 0 means the request never reached NanoMemory."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status: int = 0,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.details = details or {}


class NanoMemoryClient:
    def __init__(
        self,
        *,
        base_url: str,
        signing_key: str,
        timeout: float = 8.0,
        admin_token: str = "",
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.signing_key = signing_key
        self.admin_token = admin_token
        self._client = httpx.AsyncClient(
            base_url=self.base_url, timeout=timeout, transport=transport
        )
        self.last_request_headers: dict[str, str] | None = None

    def _headers(self, scope: Scope, *, admin: bool = False) -> dict[str, str]:
        headers = nm_headers(scope, secret=self.signing_key)
        if admin and self.admin_token:
            headers["Authorization"] = f"Bearer {self.admin_token}"
        self.last_request_headers = dict(headers)
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        *,
        scope: Scope,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        admin: bool = False,
    ) -> dict[str, Any]:
        try:
            response = await self._client.request(
                method,
                path,
                headers=self._headers(scope, admin=admin),
                json=json,
                params=params,
            )
        except httpx.HTTPError as exc:
            raise NanoMemoryError(
                "nanomemory_unavailable",
                "NanoMemory is unreachable.",
                status=0,
                details={"reason": type(exc).__name__},
            ) from exc
        if response.status_code >= 400:
            try:
                body = response.json()
            except ValueError:
                body = {}
            raise NanoMemoryError(
                str(body.get("code") or "nanomemory_error"),
                str(body.get("message") or f"NanoMemory returned {response.status_code}."),
                status=response.status_code,
                details=dict(body.get("details") or {}),
            )
        try:
            return response.json()
        except ValueError as exc:
            raise NanoMemoryError(
                "nanomemory_invalid_response",
                "NanoMemory returned a non-JSON body.",
                status=502,
            ) from exc

    async def remember(self, scope: Scope, payload: dict[str, Any]) -> dict[str, Any]:
        headers = self._headers(scope)
        key = payload.get("idempotency_key")
        if key:
            headers["Idempotency-Key"] = str(key)
        try:
            response = await self._client.post(
                "/api/v1/memory/vectors", headers=headers, json=payload
            )
        except httpx.HTTPError as exc:
            raise NanoMemoryError(
                "nanomemory_unavailable", "NanoMemory is unreachable.", status=0
            ) from exc
        if response.status_code >= 400:
            body = _safe_json(response)
            raise NanoMemoryError(
                str(body.get("code") or "nanomemory_error"),
                str(body.get("message") or "NanoMemory rejected the write."),
                status=response.status_code,
                details=dict(body.get("details") or {}),
            )
        return _safe_json(response)

    async def search(self, scope: Scope, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._request(
            "POST", "/api/v1/memory/vectors/search", scope=scope, json=payload
        )

    async def trace(self, scope: Scope, trace_id: str) -> dict[str, Any]:
        return await self._request("GET", f"/api/v1/traces/{trace_id}", scope=scope)

    async def feedback(
        self, scope: Scope, *, trace_id: str, verdict: str, reason: str | None, comment: str | None
    ) -> dict[str, Any]:
        return await self._request(
            "POST",
            "/api/v1/feedback",
            scope=scope,
            json={
                "trace_id": trace_id,
                "verdict": verdict,
                "reason": reason,
                "comment": comment,
            },
        )

    async def export_badcases(self, scope: Scope) -> dict[str, Any]:
        return await self._request("GET", "/api/v1/feedback/export", scope=scope, admin=True)

    async def health(self) -> dict[str, Any]:
        try:
            response = await self._client.get("/health")
        except httpx.HTTPError as exc:
            raise NanoMemoryError(
                "nanomemory_unavailable", "NanoMemory is unreachable.", status=0
            ) from exc
        return _safe_json(response)

    async def aclose(self) -> None:
        await self._client.aclose()


def _safe_json(response: httpx.Response) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError:
        return {}
    return payload if isinstance(payload, dict) else {}


__all__ = ["NanoMemoryClient", "NanoMemoryError"]
