"""Behavioral rule compiler and consolidation gate."""

from __future__ import annotations

import pytest
from mem_guard.consolidation import Candidate, ConsolidationGate, GateAction
from mem_guard.models import TrustLevel
from mem_guard.rules import (
    Decision,
    Rule,
    RuleAction,
    RuleCompiler,
    RuleConflictError,
)


def _compiler() -> RuleCompiler:
    compiler = RuleCompiler()
    compiler.add(
        Rule(
            id="preserve-files",
            name="Preserve Original Files",
            action=RuleAction.DENY,
            scope="file_write",
            trigger=r"overwrite|rm -rf",
            priority=80,
            rationale="never destroy user files",
        )
    )
    return compiler


def test_no_matching_rule_allows() -> None:
    decision = _compiler().evaluate("read the config", scope="file_write")
    assert decision.action is RuleAction.ALLOW
    assert decision.human_required is False


def test_rule_matches_on_scope_and_trigger() -> None:
    decision = _compiler().evaluate("rm -rf ./data", scope="file_write")
    assert decision.action is RuleAction.DENY
    assert "preserve-files" in decision.matched


def test_scope_is_enforced() -> None:
    decision = _compiler().evaluate("rm -rf ./data", scope="memory_write")
    assert decision.action is RuleAction.ALLOW


def test_conflicting_rules_escalate_to_human() -> None:
    compiler = RuleCompiler()
    compiler.add(
        Rule(
            id="a",
            name="deny",
            action=RuleAction.DENY,
            scope="file_write",
            trigger="overwrite",
            priority=60,
        )
    )
    compiler.add(
        Rule(
            id="b",
            name="allow",
            action=RuleAction.ALLOW,
            scope="file_write",
            trigger="overwrite",
            priority=60,
        )
    )
    decision = compiler.evaluate("overwrite the report", scope="file_write")
    assert decision.action is RuleAction.REQUIRE_CONFIRM
    assert decision.human_required is True
    assert set(decision.conflicts) == {"a", "b"}


def test_higher_priority_wins_without_conflict() -> None:
    compiler = RuleCompiler()
    compiler.add(
        Rule(id="low", name="allow", action=RuleAction.ALLOW, scope="file_write", priority=20)
    )
    compiler.add(
        Rule(
            id="high",
            name="confirm",
            action=RuleAction.REQUIRE_CONFIRM,
            scope="file_write",
            priority=90,
        )
    )
    decision = compiler.evaluate("anything", scope="file_write")
    assert decision.action is RuleAction.REQUIRE_CONFIRM
    assert decision.human_required is False


def test_duplicate_ids_and_bad_regex_are_rejected() -> None:
    compiler = RuleCompiler()
    compiler.add(Rule(id="r1", name="x", action=RuleAction.ALLOW))
    with pytest.raises(RuleConflictError):
        compiler.add(Rule(id="r1", name="y", action=RuleAction.DENY))
    with pytest.raises(RuleConflictError):
        compiler.add(Rule(id="r2", name="bad", action=RuleAction.DENY, trigger="(["))


def test_decision_serialises() -> None:
    decision = Decision(action=RuleAction.DENY, matched=("r1",))
    assert decision.to_dict()["action"] == "deny"


def test_gate_promotes_repeated_preference() -> None:
    decision = ConsolidationGate().evaluate(
        Candidate(
            content="I prefer dark mode",
            trust=TrustLevel.USER_STATED,
            repetitions=3,
            is_preference=True,
            similarity_to_existing=0.5,
            evidence_count=1,
        )
    )
    assert decision.action is GateAction.PROMOTE
    assert decision.score >= 0.6


def test_gate_rejects_weak_signal() -> None:
    decision = ConsolidationGate().evaluate(
        Candidate(content="random chatter", trust=TrustLevel.UNTRUSTED, repetitions=1)
    )
    assert decision.action is GateAction.REJECT


def test_gate_quarantines_unsupported_model_inference() -> None:
    decision = ConsolidationGate().evaluate(
        Candidate(
            content="The user is a backend engineer.",
            trust=TrustLevel.MODEL_INFERRED,
            repetitions=3,
            decision_weight=1.0,
            evidence_count=0,
        )
    )
    assert decision.action is GateAction.QUARANTINE


def test_gate_defers_mid_signal() -> None:
    decision = ConsolidationGate().evaluate(
        Candidate(
            content="The API is rate limited.",
            trust=TrustLevel.USER_STATED,
            repetitions=3,
            decision_weight=0.5,
            similarity_to_existing=0.6,
            confidence=0.5,
        )
    )
    assert decision.action is GateAction.DEFER
