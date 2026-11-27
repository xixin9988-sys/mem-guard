"""Grounded-answer guard: stop fabricated identifiers, dates and amounts.

Retrieval cannot tell "this order does not exist" from "this order is relevant": both look like
a topical match.  The generation step is where a model turns that ambiguity into a confident
wrong answer, so the gateway checks the answer against the evidence it was given.

Checked classes (high precision, low noise):

* hard identifiers -- A1001, R1002, X1, Z9, C9999, emails, phone numbers
* dates            -- 2026-10-01, 10月15日
* amounts          -- 199 元, ¥500, 50 块

Bare integers are *not* checked; they appear in too many legitimate contexts.

Outcomes:

* @@block@@                -- the answer asserts an entity that no evidence contains
* @@insufficient_evidence@@ -- the question's entity is absent from evidence, or the answer is a
                          refusal, or the question's terms are largely unmatched
* @@repair@@            -- reserved for future span-level rewrites; not emitted today
* @@allow@@                -- every checked claim is grounded
"""

from __future__ import annotations

import re

from mem_guard.contracts import GroundingDecision
from mem_guard.guard import tokens

_IDENTIFIER = re.compile(r"\b[A-Za-z]{1,8}[-_]?\d{1,6}\b")
_DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}\s*月\s*\d{1,2}\s*日\b")
_AMOUNT = re.compile(
    r"(?:[¥$]\s*\d[\d,]*(?:\.\d{1,2})?)"
    r"|(?:\b\d[\d,]*(?:\.\d{1,2})?\s*(?:元|块|美元|USD|CNY))"
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")

#: Interrogatives and fillers do not make an answer more or less grounded.
_NOISE_TERMS = frozenset(
    {
        "什么",
        "么时",
        "时候",
        "怎么",
        "多少",
        "哪里",
        "哪个",
        "是否",
        "可以",
        "能不",
        "不能",
        "为什",
        "如何",
        "请问",
        "我的",
        "你们",
        "这个",
        "一下",
    }
)

_REFUSAL_MARKERS = (
    "没有找到",
    "未找到",
    "无法确认",
    "不清楚",
    "不确定",
    "未知",
    "没有相关",
    "没有记录",
    "暂无",
    "not found",
    "no record",
    "unknown",
    "cannot confirm",
    "i don't know",
    "i do not know",
)


def _normalise(value: str) -> str:
    return re.sub(r"[\s_]", "", value).upper()


def entities(text: str) -> set[str]:
    found: set[str] = set()
    for pattern in (_IDENTIFIER, _DATE, _AMOUNT, _EMAIL, _PHONE):
        for match in pattern.finditer(text):
            found.add(_normalise(match.group(0)))
    return found


def _is_refusal(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _REFUSAL_MARKERS)


class GroundingGuard:
    """Deterministic answer-vs-evidence check."""

    def __init__(self, *, min_question_coverage: float = 0.34) -> None:
        self.min_question_coverage = min_question_coverage

    def check(
        self,
        *,
        question: str,
        answer: str,
        evidence: list[str],
        min_question_coverage: float | None = None,
    ) -> GroundingDecision:
        threshold = (
            self.min_question_coverage if min_question_coverage is None else min_question_coverage
        )
        evidence_text = "\n".join(evidence)
        if not evidence_text.strip():
            return GroundingDecision(
                action="insufficient_evidence",
                reasons=["no_evidence"],
            )

        evidence_entities = entities(evidence_text)
        question_entities = entities(question)
        answer_entities = entities(answer)

        missing_question = sorted(question_entities - evidence_entities)
        if missing_question:
            return GroundingDecision(
                action="insufficient_evidence",
                reasons=["question_entity_not_in_evidence"],
                missing_question_entities=missing_question,
                question_coverage=0.0,
            )

        unsupported = sorted(answer_entities - evidence_entities)
        question_terms = tokens(question) - _NOISE_TERMS
        evidence_terms = tokens(evidence_text)
        coverage = (
            len(question_terms & evidence_terms) / len(question_terms) if question_terms else 0.0
        )
        # A hard identifier that is present in the evidence anchors the question: "A1001 什么
        # 时候发出" is grounded even though the interrogative dominates the token coverage.
        entity_anchored = bool(question_entities) and not missing_question

        if unsupported:
            if _is_refusal(answer):
                return GroundingDecision(
                    action="insufficient_evidence",
                    reasons=["answer_refuses_unknown_entity"],
                    unsupported_entities=unsupported,
                    question_coverage=round(coverage, 4),
                )
            return GroundingDecision(
                action="block",
                reasons=["answer_entity_not_in_evidence"],
                unsupported_entities=unsupported,
                question_coverage=round(coverage, 4),
            )

        if not entity_anchored and coverage < threshold:
            return GroundingDecision(
                action="insufficient_evidence",
                reasons=["question_terms_not_covered_by_evidence"],
                question_coverage=round(coverage, 4),
            )

        return GroundingDecision(
            action="allow",
            reasons=["grounded"],
            question_coverage=round(coverage, 4),
        )


__all__ = ["GroundingGuard", "entities"]
