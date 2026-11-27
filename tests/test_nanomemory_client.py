"""NanoMemory client: signed scope headers, idempotency and error mapping."""

from __future__ import annotations

import asyncio
import hashlib
import hmac

import httpx
import pytest
from mem_guard.contracts import Scope
from mem_guard.nanomemory_client import NanoMemoryClient, NanoMemoryError

SCOPE = Scope(tenant_id="tenant-a", user_id="user-1", roles=("agent",), acl_tags=("team",))


def test_requests_are_signed_and_scoped() -> None:
    captured: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"trace_id": "tr-1", "items": []})

    async def run() -> None:
        client = NanoMemoryClient(
            base_url="http://nm", signing_key="secret", transport=httpx.MockTransport(handler)
        )
        try:
            await client.search(SCOPE, {"query": "x"})
        finally:
            await client.aclose()

    asyncio.run(run())
    request = captured[0]
    tenant = request.headers["X-NM-Tenant"]
    user = request.headers["X-NM-User"]
    roles = request.headers["X-NM-Roles"]
    acl = request.headers["X-NM-Acl"]
    stamp = request.headers["X-NM-Timestamp"]
    assert (tenant, user, roles, acl) == ("tenant-a", "user-1", "agent", "team")
    expected = hmac.new(
        b"secret",
        "\n".join([tenant, user, roles, acl, stamp]).encode(),
        hashlib.sha256,
    ).hexdigest()
    assert request.headers["X-NM-Signature"] == expected


def test_idempotency_key_is_forwarded() -> None:
    captured: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(201, json={"record": {"id": "vec-1"}, "trace_id": "tr-1"})

    async def run() -> None:
        client = NanoMemoryClient(
            base_url="http://nm", signing_key="secret", transport=httpx.MockTransport(handler)
        )
        try:
            await client.remember(SCOPE, {"content": "x", "idempotency_key": "abc"})
        finally:
            await client.aclose()

    asyncio.run(run())
    assert captured[0].headers["Idempotency-Key"] == "abc"


def test_upstream_error_is_mapped() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            404, json={"code": "not_found", "message": "Trace not found.", "details": {}}
        )

    async def run() -> None:
        client = NanoMemoryClient(
            base_url="http://nm", signing_key="secret", transport=httpx.MockTransport(handler)
        )
        try:
            with pytest.raises(NanoMemoryError) as excinfo:
                await client.trace(SCOPE, "tr-missing")
            assert excinfo.value.status == 404
            assert excinfo.value.code == "not_found"
        finally:
            await client.aclose()

    asyncio.run(run())


def test_connection_failure_is_typed() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    async def run() -> None:
        client = NanoMemoryClient(
            base_url="http://nm", signing_key="secret", transport=httpx.MockTransport(handler)
        )
        try:
            with pytest.raises(NanoMemoryError) as excinfo:
                await client.search(SCOPE, {"query": "x"})
            assert excinfo.value.status == 0
            assert excinfo.value.code == "nanomemory_unavailable"
        finally:
            await client.aclose()

    asyncio.run(run())
