"""Gateway configuration from MEM_GUARD_* environment variables.

Secrets are read once and never logged.  The production guard rails are fail-closed:

* @@environment=production@@ requires both the inbound service key and the outbound
  NanoMemory signing key; otherwise the gateway refuses to start.
* unsafe defaults (allow a missing scope) are rejected in production.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True, slots=True)
class GatewaySettings:
    environment: str = "development"
    nanomemory_base_url: str = "http://127.0.0.1:8000"
    nanomemory_timeout: float = 8.0
    nanomemory_admin_token: str = field(default="", repr=False)
    context_signing_key: str = field(default="", repr=False)
    service_api_key: str = field(default="", repr=False)
    allow_default_scope: bool = True
    safety_mode: Literal["block", "redact"] = "redact"
    injection_threshold: Literal["low", "medium", "high"] = "high"
    max_content_chars: int = 20_000
    rate_limit_per_minute: int = 120
    daily_embedding_tokens: int = 200_000
    daily_retrieval_tokens: int = 500_000
    daily_writes: int = 20_000
    daily_searches: int = 50_000
    quota_enabled: bool = True
    state_dir: Path = PROJECT_ROOT / ".memguard"

    @property
    def quota_db(self) -> Path:
        return self.state_dir / "usage.db"

    @property
    def feedback_db(self) -> Path:
        return self.state_dir / "feedback.db"

    @property
    def audit_log(self) -> Path:
        return self.state_dir / "audit.jsonl"

    def validate(self) -> None:
        if self.environment == "production":
            missing = []
            if not self.service_api_key:
                missing.append("MEM_GUARD_SERVICE_API_KEY")
            if not self.context_signing_key:
                missing.append("MEM_GUARD_CONTEXT_SIGNING_KEY")
            if self.allow_default_scope:
                missing.append("MEM_GUARD_ALLOW_DEFAULT_SCOPE=false")
            if missing:
                raise ValueError(
                    "mem-guard production configuration is unsafe; missing: " + ", ".join(missing)
                )

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> GatewaySettings:
        source = env if env is not None else os.environ

        def get(name: str, default: str = "") -> str:
            return str(source.get(name, default) or default)

        def number(name: str, default: float) -> float:
            raw = get(name)
            try:
                return float(raw) if raw else default
            except ValueError as exc:
                raise ValueError(f"{name} must be a number") from exc

        def flag(name: str, default: bool) -> bool:
            raw = get(name).strip().lower()
            if not raw:
                return default
            return raw in {"1", "true", "yes", "on"}

        settings = cls(
            environment=get("MEM_GUARD_ENVIRONMENT", "development"),
            nanomemory_base_url=get("MEM_GUARD_NANOMEMORY_URL", "http://127.0.0.1:8000"),
            nanomemory_timeout=number("MEM_GUARD_NANOMEMORY_TIMEOUT", 8.0),
            nanomemory_admin_token=get("MEM_GUARD_NANOMEMORY_ADMIN_TOKEN"),
            context_signing_key=get("MEM_GUARD_CONTEXT_SIGNING_KEY"),
            service_api_key=get("MEM_GUARD_SERVICE_API_KEY"),
            allow_default_scope=flag("MEM_GUARD_ALLOW_DEFAULT_SCOPE", True),
            safety_mode=get("MEM_GUARD_SAFETY_MODE", "redact").lower(),  # type: ignore[arg-type]
            injection_threshold=get("MEM_GUARD_INJECTION_THRESHOLD", "high").lower(),  # type: ignore[arg-type]
            max_content_chars=int(number("MEM_GUARD_MAX_CONTENT_CHARS", 20_000)),
            rate_limit_per_minute=int(number("MEM_GUARD_RATE_LIMIT_PER_MINUTE", 120)),
            daily_embedding_tokens=int(number("MEM_GUARD_DAILY_EMBEDDING_TOKENS", 200_000)),
            daily_retrieval_tokens=int(number("MEM_GUARD_DAILY_RETRIEVAL_TOKENS", 500_000)),
            daily_writes=int(number("MEM_GUARD_DAILY_WRITES", 20_000)),
            daily_searches=int(number("MEM_GUARD_DAILY_SEARCHES", 50_000)),
            quota_enabled=flag("MEM_GUARD_QUOTA_ENABLED", True),
            state_dir=Path(get("MEM_GUARD_STATE_DIR", str(PROJECT_ROOT / ".memguard"))),
        )
        settings.validate()
        return settings


__all__ = ["PROJECT_ROOT", "GatewaySettings"]
