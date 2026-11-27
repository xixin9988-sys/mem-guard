"""Content safety: secrets and PII detected *before* a memory is embedded.

Order matters: secrets are rejected or redacted before the text reaches the embedding provider,
so a leaked API key never becomes a vector, a trace payload or a third-party request.

The scanner is deliberately explainable: every finding carries a kind, a severity and the exact
span, and redaction is a pure function of the text, so the same input always yields the same
output (testable and diffable).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

from mem_guard.contracts import SafetyFinding

Severity = Literal["low", "medium", "high"]


@dataclass(frozen=True, slots=True)
class _Rule:
    kind: str
    pattern: re.Pattern[str]
    severity: Severity
    group: int = 0


_RULES: tuple[_Rule, ...] = (
    _Rule(
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
            r"[\s\S]{0,4000}?-----END[^-]*-----"
        ),
        "high",
    ),
    _Rule("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), "high"),
    _Rule("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    _Rule("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"), "high"),
    _Rule(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "high",
    ),
    _Rule(
        "password_assignment",
        re.compile(r"(?i)\b(?:password|passwd|pwd|secret|token)\s*[:=]\s*[^\s,;]{6,}"),
        "high",
    ),
    _Rule("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "medium"),
    _Rule("cn_phone", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"), "medium"),
    _Rule("cn_phone_dashed", re.compile(r"(?<!\d)1[3-9]\d-\d{4}-\d{4}(?!\d)"), "medium"),
    _Rule("cn_id", re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)"), "high"),
    _Rule("bank_card", re.compile(r"(?<!\d)(?:\d[ -]?){15,18}\d(?!\d)"), "high"),
)

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


@dataclass(slots=True)
class SafetyReport:
    findings: list[SafetyFinding] = field(default_factory=list)
    redacted_text: str = ""
    action: Literal["allow", "redact", "block"] = "allow"

    @property
    def has_secrets(self) -> bool:
        return any(finding.severity == "high" for finding in self.findings)

    @property
    def kinds(self) -> list[str]:
        return [finding.kind for finding in self.findings]


class ContentSafety:
    """Scan and optionally redact; policy is explicit per deployment."""

    def __init__(self, *, mode: Literal["block", "redact"] = "redact") -> None:
        if mode not in {"block", "redact"}:
            raise ValueError("mode must be 'block' or 'redact'")
        self.mode = mode

    def scan(self, text: str) -> SafetyReport:
        findings: list[SafetyFinding] = []
        for rule in _RULES:
            for match in rule.pattern.finditer(text):
                start, end = match.span(rule.group)
                snippet = text[start:end]
                findings.append(
                    SafetyFinding(
                        kind=rule.kind,
                        severity=rule.severity,
                        start=start,
                        end=end,
                        snippet=_mask(snippet),
                    )
                )
        findings.sort(key=lambda item: (item.start, item.end))
        findings = _deduplicate(findings)
        if not findings:
            return SafetyReport(findings=[], redacted_text=text, action="allow")

        highest = max(_SEVERITY_RANK[finding.severity] for finding in findings)
        if self.mode == "block" and highest >= _SEVERITY_RANK["medium"]:
            return SafetyReport(findings=findings, redacted_text=text, action="block")

        redacted = text
        for finding in sorted(findings, key=lambda item: item.start, reverse=True):
            redacted = (
                redacted[: finding.start] + f"[REDACTED:{finding.kind}]" + redacted[finding.end :]
            )
        action: Literal["redact", "block"] = "redact"
        return SafetyReport(findings=findings, redacted_text=redacted, action=action)


def _mask(snippet: str) -> str:
    if len(snippet) <= 4:
        return "***"
    return f"{snippet[:2]}***{snippet[-2:]}"


def _deduplicate(findings: list[SafetyFinding]) -> list[SafetyFinding]:
    """Drop findings fully contained in an earlier, higher-severity span (bank card vs phone)."""
    kept: list[SafetyFinding] = []
    for finding in sorted(findings, key=lambda item: (item.start, -_SEVERITY_RANK[item.severity])):
        if any(item.start <= finding.start and finding.end <= item.end for item in kept):
            continue
        kept.append(finding)
    return kept


__all__ = ["ContentSafety", "SafetyReport"]
