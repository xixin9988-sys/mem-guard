"""Provenance validation with issuer attestation.

A caller cannot mint trust by writing ``source="user_verified"``. A source claim is only
honoured when it arrives through a **registered issuer** (a trusted adapter: user input
channel, verified runbook, tool bridge). Unattested claims are downgraded to ``untrusted`` and
quarantined, so trust reflects *where the bytes came from*, not what the caller typed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from mem_guard.models import SOURCE_TRUST, SourceKind, TrustLevel

MIN_CONTENT_LENGTH = 8
INJECTION_PATTERNS = (
    re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.I),
    re.compile(r"(reveal|print|show)\s+(the\s+)?system\s+prompt", re.I),
    re.compile(r"you\s+are\s+now\s+(a|an|the)\s+", re.I),
    re.compile(r"<\s*script", re.I),
)
UNVERIFIED_SOURCES = {
    SourceKind.TOOL_OUTPUT,
    SourceKind.EXTERNAL_DOCUMENT,
    SourceKind.IMPORT,
}
SOURCE_ALIASES = {
    "user_stated": "user_statement",
    "user": "user_statement",
    "verified": "user_verified",
    "model": "model_inference",
    "llm": "model_inference",
    "tool": "tool_output",
    "document": "external_document",
    "imported": "import",
}


@dataclass(frozen=True, slots=True)
class Issuer:
    """A trusted adapter allowed to assert a set of source kinds."""

    name: str
    kinds: frozenset[SourceKind]
    require_evidence: bool = False

    def allows(self, kind: SourceKind) -> bool:
        return kind in self.kinds


class IssuerRegistry:
    """Allowlist of trusted issuers; empty by default (nothing is self-assertable)."""

    def __init__(self) -> None:
        self._issuers: dict[str, Issuer] = {}

    def register(self, issuer: Issuer) -> Issuer:
        if not issuer.name.strip():
            raise ValueError("issuer name must not be empty")
        self._issuers[issuer.name] = issuer
        return issuer

    def get(self, name: str | None) -> Issuer | None:
        return self._issuers.get(name or "")

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._issuers))


@dataclass(frozen=True, slots=True)
class ValidationResult:
    ok: bool
    trust: TrustLevel
    source: SourceKind
    reasons: tuple[str, ...] = ()
    quarantine: bool = False
    attested: bool = False


@dataclass(slots=True)
class ProvenanceValidator:
    issuers: IssuerRegistry = field(default_factory=IssuerRegistry)

    def validate(
        self,
        content: str,
        source: str | SourceKind,
        *,
        issuer: str | None = None,
        confidence: float = 0.8,
        evidence: tuple[str, ...] = (),
    ) -> ValidationResult:
        if isinstance(source, SourceKind):
            kind = source
        else:
            raw = str(source).strip().lower()
            kind = SourceKind(SOURCE_ALIASES.get(raw, raw))

        trust = SOURCE_TRUST[kind]
        reasons: list[str] = []
        quarantine = False
        attested = False

        text = content.strip()
        if len(text) < MIN_CONTENT_LENGTH:
            return ValidationResult(
                ok=False,
                trust=TrustLevel.UNTRUSTED,
                source=kind,
                reasons=("content too short to be a memory",),
                quarantine=True,
            )

        trusted_issuer = self.issuers.get(issuer)
        if trusted_issuer is not None and trusted_issuer.allows(kind):
            attested = True
        else:
            # The claim is not attested: never let it mint a higher trust level.
            reasons.append("unattested source claim (no registered issuer)")
            quarantine = True
            trust = TrustLevel.UNTRUSTED
            if kind in UNVERIFIED_SOURCES:
                reasons.append("unverified external content")

        if attested and kind in UNVERIFIED_SOURCES and not evidence:
            reasons.append("unverified external content")
            quarantine = True
        if kind is SourceKind.MODEL_INFERENCE and not evidence:
            reasons.append("model inference without evidence")
            quarantine = True
        if kind is SourceKind.MODEL_INFERENCE and confidence < 0.6:
            reasons.append("low-confidence inference")
            quarantine = True
        if not 0.0 <= confidence <= 1.0:
            reasons.append("confidence clamped to [0, 1]")
        for pattern in INJECTION_PATTERNS:
            if pattern.search(text):
                reasons.append("prompt-injection markers detected")
                quarantine = True
                trust = TrustLevel.UNTRUSTED
                attested = False
                break

        return ValidationResult(
            ok=not quarantine,
            trust=trust,
            source=kind,
            reasons=tuple(reasons),
            quarantine=quarantine,
            attested=attested,
        )
