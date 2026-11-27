"""Grounded-answer guard: the answer may only assert what the evidence contains."""

from __future__ import annotations

from mem_guard.grounding import GroundingGuard, entities

EVIDENCE = [
    "Order A1001 于 2026-10-01 由顺丰发出，运单号 SF7788990011，客户已签收。",
    "退款政策：签收后 7 天内可无理由退款。",
]


def test_grounded_answer_is_allowed() -> None:
    decision = GroundingGuard().check(
        question="A1001 什么时候发出的？",
        answer="Order A1001 于 2026-10-01 由顺丰发出。",
        evidence=EVIDENCE,
    )
    assert decision.action == "allow", decision
    assert decision.question_coverage >= 0.34


def test_fabricated_identifier_is_blocked() -> None:
    decision = GroundingGuard().check(
        question="Order C9999 的物流状态？",
        answer="Order C9999 已于 2026-10-01 由顺丰发出。",
        evidence=EVIDENCE,
    )
    assert decision.action in {"block", "insufficient_evidence"}
    assert "C9999" in decision.unsupported_entities or "C9999" in decision.missing_question_entities


def test_refusal_mentioning_the_unknown_entity_is_not_a_block() -> None:
    decision = GroundingGuard().check(
        question="Order C9999 的物流状态？",
        answer="没有找到 Order C9999 的记录。",
        evidence=EVIDENCE,
    )
    assert decision.action == "insufficient_evidence"


def test_question_entity_missing_from_evidence() -> None:
    decision = GroundingGuard().check(
        question="商品 Z9 的库存还有多少？",
        answer="商品 Z9 有现货。",
        evidence=EVIDENCE,
    )
    assert decision.action == "insufficient_evidence"
    assert "Z9" in decision.missing_question_entities


def test_unrelated_question_is_insufficient_even_with_relevant_text() -> None:
    decision = GroundingGuard().check(
        question="会员积分怎么兑换？",
        answer="会员积分可以兑换礼品。",
        evidence=["该客户为 VIP 金卡会员，享受优先客服。"],
    )
    assert decision.action == "insufficient_evidence"


def test_fabricated_amount_is_blocked() -> None:
    decision = GroundingGuard().check(
        question="退款金额是多少？",
        answer="退款金额为 899 元。",
        evidence=EVIDENCE,
    )
    assert decision.action == "block"
    assert any("899" in item for item in decision.unsupported_entities)


def test_no_evidence_is_insufficient() -> None:
    decision = GroundingGuard().check(question="退款政策？", answer="7 天。", evidence=[])
    assert decision.action == "insufficient_evidence"
    assert decision.reasons == ["no_evidence"]


def test_entity_extraction_covers_ids_dates_amounts() -> None:
    found = entities("A1001 2026-10-01 ¥500 199 元 ops@example.com 13800001234")
    assert any("A1001" in item for item in found)
    assert any("2026-10-01" in item for item in found)
    assert any("500" in item for item in found)
    assert any("199" in item for item in found)
    assert any("OPS@EXAMPLE.COM" in item for item in found)
