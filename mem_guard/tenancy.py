"""Scope resolution and the signed envelope mem-guard presents to NanoMemory.

Two directions, two different trust problems:

* inbound: a caller must not pick its own tenant.  The gateway is an internal service that is
  authenticated with a service key; the scope headers it forwards are the claims the calling
  BFF already authenticated.  End users never talk to mem-guard directly.
* outbound: NanoMemory must not trust a scope that a random process could mint.  mem-guard signs
  tenant/user/roles/ACL/timestamp with the shared key and NanoMemory verifies it before building
  a SQL WHERE clause.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from collections.abc import Mapping

from mem_guard.contracts import Scope

TENANT_HEADER = "X-Guard-Tenant"
USER_HEADER = "X-Guard-User"
ROLES_HEADER = "X-Guard-Roles"
ACL_HEADER = "X-Guard-Acl"

NM_TENANT_HEADER = "X-NM-Tenant"
NM_USER_HEADER = "X-NM-User"
NM_ROLES_HEADER = "X-NM-Roles"
NM_ACL_HEADER = "X-NM-Acl"
NM_TIMESTAMP_HEADER = "X-NM-Timestamp"
NM_SIGNATURE_HEADER = "X-NM-Signature"

DEFAULT_TENANT = "local"
DEFAULT_USER = "local"


class ContextError(Exception):
    """Raised when a scope cannot be established; maps to a 401/403 envelope."""

    def __init__(self, code: str, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


def _split(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(item.strip() for item in value.split(",") if item.strip())


def resolve_scope(
    headers: Mapping[str, str],
    *,
    service_key: str = "",
    allow_default: bool = True,
) -> Scope:
    """Authenticate the service and read the scope it asserts."""
    if service_key:
        header = headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise ContextError(
                "guard_auth_required",
                "A service bearer token is required.",
                {"header": "Authorization"},
            )
        if not hmac.compare_digest(token.strip(), service_key):
            raise ContextError("guard_auth_invalid", "The service token is invalid.")
    tenant = (headers.get(TENANT_HEADER) or "").strip()
    user = (headers.get(USER_HEADER) or "").strip()
    if not tenant or not user:
        if not allow_default:
            raise ContextError(
                "guard_scope_required",
                f"{TENANT_HEADER} and {USER_HEADER} are required.",
            )
        tenant = tenant or DEFAULT_TENANT
        user = user or DEFAULT_USER
    try:
        return Scope(
            tenant_id=tenant,
            user_id=user,
            roles=_split(headers.get(ROLES_HEADER)),
            acl_tags=_split(headers.get(ACL_HEADER)),
            request_id=headers.get("X-Request-ID"),
        )
    except ValueError as exc:
        raise ContextError(
            "guard_scope_invalid", "The asserted scope is invalid.", {"reason": str(exc)}
        ) from exc


def nm_signature(scope: Scope, secret: str, timestamp: str) -> str:
    payload = "\n".join(
        [
            scope.tenant_id,
            scope.user_id,
            ",".join(scope.roles),
            ",".join(scope.acl_tags),
            timestamp,
        ]
    )
    return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def nm_headers(scope: Scope, *, secret: str, timestamp: int | None = None) -> dict[str, str]:
    """The exact envelope NanoMemory verifies (format shared by contract tests)."""
    stamp = str(timestamp if timestamp is not None else int(time.time()))
    signature = nm_signature(scope, secret, stamp)
    return {
        NM_TENANT_HEADER: scope.tenant_id,
        NM_USER_HEADER: scope.user_id,
        NM_ROLES_HEADER: ",".join(scope.roles),
        NM_ACL_HEADER: ",".join(scope.acl_tags),
        NM_TIMESTAMP_HEADER: stamp,
        NM_SIGNATURE_HEADER: signature,
    }


__all__ = [
    "ACL_HEADER",
    "DEFAULT_TENANT",
    "DEFAULT_USER",
    "NM_ACL_HEADER",
    "NM_ROLES_HEADER",
    "NM_SIGNATURE_HEADER",
    "NM_TENANT_HEADER",
    "NM_TIMESTAMP_HEADER",
    "NM_USER_HEADER",
    "ROLES_HEADER",
    "TENANT_HEADER",
    "USER_HEADER",
    "ContextError",
    "nm_headers",
    "nm_signature",
    "resolve_scope",
]
