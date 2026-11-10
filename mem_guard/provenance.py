"""Provenance validation: the only thing allowed to set a trust label.

A model inference is never promoted to a user statement, and untrusted content is quarantined
before it can reach retrieval. Trust is computed **once, at write time**.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from mem_guard.models import SOURCE_TRUST, SourceKind, TrustLevel

MIN_CONTENT_LENGTH = 8
INJECTION_PATTERNS = (
    re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.I),
    re.compile(r"(reveal|print|show)\s+(the\s+)?system\s+prompt", re.I),
    re.compile(r"you\s+are\s+now\s+(a|an|the)\s+", re.I),
    re.compile(r"<\s*script", re.I),
)
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

UNVERIFIED_SOURCES = {
    SourceKind.TOOL_OUTPUT,
    SourceKind.EXTERNAL_DOCUMENT,
    SourceKind.IMPORT,
}


@dataclass(frozen=True, slots=True)
class ValidationResult:
    ok: bool
    trust: TrustLevel
    source: SourceKind
    reasons: tuple[str, ...] = ()
    quarantine: bool = False


class ProvenanceValidator:
    """Validate content and derive the trust label from the declared source."""

    def validate(
        self,
        content: str,
        source: str | SourceKind,
        *,
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

        text = content.strip()
        if len(text) < MIN_CONTENT_LENGTH:
            return ValidationResult(
                ok=False,
                trust=TrustLevel.UNTRUSTED,
                source=kind,
                reasons=("content too short to be a memory",),
                quarantine=True,
            )

        for pattern in INJECTION_PATTERNS:
            if pattern.search(text):
                reasons.append("prompt-injection markers detected")
                quarantine = True
                trust = TrustLevel.UNTRUSTED
                break

        if kind is SourceKind.MODEL_INFERENCE and not evidence:
            reasons.append("model inference without evidence")
            quarantine = True
        if kind in UNVERIFIED_SOURCES and not evidence:
            reasons.append("unverified external content")
            quarantine = True
        if not 0.0 <= confidence <= 1.0:
            reasons.append("confidence clamped to [0, 1]")
            confidence = max(0.0, min(1.0, confidence))
        if kind is SourceKind.MODEL_INFERENCE and confidence < 0.6:
            reasons.append("low-confidence inference")
            quarantine = True

        return ValidationResult(
            ok=not quarantine,
            trust=trust,
            source=kind,
            reasons=tuple(reasons),
            quarantine=quarantine,
        )
