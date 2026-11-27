"""Scope resolution and the signature contract shared with NanoMemory."""

from __future__ import annotations

import pytest
from mem_guard.contracts import Scope
from mem_guard.tenancy import (
    ContextError,
    nm_headers,
    nm_signature,
    resolve_scope,
)

# Golden vector: NanoMemory's test-suite asserts the same digest for the same tuple, so a
# change in either implementation breaks one of the two tests instead of silently diverging.
GOLDEN = "41d2b50c74c62438b2d973ba5862f2191dfc372989798f9f0d67da98e82355fe"


def test_golden_signature_matches_nanomemory() -> None:
    scope = Scope(tenant_id="tenant-a", user_id="user-1")
    assert nm_signature(scope, "shared-secret", "1700000000") == GOLDEN
    headers = nm_headers(scope, secret="shared-secret", timestamp=1700000000)
    assert headers["X-NM-Signature"] == GOLDEN
    assert headers["X-NM-Tenant"] == "tenant-a"
    assert headers["X-NM-Timestamp"] == "1700000000"


def test_roles_and_acl_participate_in_the_signature() -> None:
    plain = Scope(tenant_id="t", user_id="u")
    privileged = Scope(tenant_id="t", user_id="u", roles=("admin",), acl_tags=("team",))
    assert nm_signature(plain, "k", "1") != nm_signature(privileged, "k", "1")


def test_scope_headers_are_read_and_normalised() -> None:
    scope = resolve_scope(
        {
            "X-Guard-Tenant": "tenant-a",
            "X-Guard-User": "user-1",
            "X-Guard-Roles": "agent, auditor",
            "X-Guard-Acl": "team-a",
        }
    )
    assert scope.tenant_id == "tenant-a"
    assert scope.roles == ("agent", "auditor")
    assert scope.acl_tags == ("team-a",)


def test_missing_scope_falls_back_only_when_allowed() -> None:
    assert resolve_scope({}).tenant_id == "local"
    with pytest.raises(ContextError) as excinfo:
        resolve_scope({}, allow_default=False)
    assert excinfo.value.code == "guard_scope_required"


def test_service_key_is_enforced() -> None:
    headers = {"Authorization": "Bearer secret", "X-Guard-Tenant": "t", "X-Guard-User": "u"}
    assert resolve_scope(headers, service_key="secret").tenant_id == "t"
    with pytest.raises(ContextError) as missing:
        resolve_scope({"X-Guard-Tenant": "t", "X-Guard-User": "u"}, service_key="secret")
    assert missing.value.code == "guard_auth_required"
    with pytest.raises(ContextError) as wrong:
        resolve_scope({**headers, "Authorization": "Bearer nope"}, service_key="secret")
    assert wrong.value.code == "guard_auth_invalid"


def test_invalid_scope_is_rejected() -> None:
    with pytest.raises(ContextError) as excinfo:
        resolve_scope({"X-Guard-Tenant": "bad tenant!", "X-Guard-User": "u"})
    assert excinfo.value.code == "guard_scope_invalid"
