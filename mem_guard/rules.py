"""Behavioral Rule Compiler: layered rules with scope, trigger, priority and conflicts.

Rules are not a flat list of sentences. Each rule declares a ``scope`` (where it applies), an
optional ``trigger`` regex (when), a ``priority`` and an ``action``. Compilation resolves
precedence; when two equally specific rules disagree the compiler refuses to guess and asks
for a human (``human_required=True``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum


class RuleAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_CONFIRM = "require_confirm"
    REWRITE = "rewrite"


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    name: str
    action: RuleAction
    scope: str = "*"
    trigger: str | None = None
    priority: int = 50
    rationale: str = ""

    def matches_scope(self, scope: str) -> bool:
        return self.scope == "*" or self.scope == scope

    def matches_text(self, text: str) -> bool:
        return self.trigger is None or re.search(self.trigger, text, re.I) is not None

    @property
    def specificity(self) -> tuple[int, int, int]:
        """Higher wins: explicit scope > regex trigger > declared priority."""
        return (self.priority, int(self.scope != "*"), int(self.trigger is not None))


@dataclass(frozen=True, slots=True)
class ConflictReport:
    """Structured escalation payload: what conflicted, and a suggested resolution."""

    rule_ids: tuple[str, ...]
    scopes: tuple[str, ...]
    triggers: tuple[str, ...]
    priorities: tuple[int, ...]
    suggested_resolution: str

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_ids": list(self.rule_ids),
            "scopes": list(self.scopes),
            "triggers": list(self.triggers),
            "priorities": list(self.priorities),
            "suggested_resolution": self.suggested_resolution,
        }


@dataclass(frozen=True, slots=True)
class Decision:
    action: RuleAction
    matched: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()
    human_required: bool = False
    reasons: tuple[str, ...] = ()
    report: ConflictReport | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action.value,
            "matched": list(self.matched),
            "conflicts": list(self.conflicts),
            "human_required": self.human_required,
            "reasons": list(self.reasons),
            "report": self.report.to_dict() if self.report else None,
        }


class RuleConflictError(ValueError):
    pass


@dataclass(slots=True)
class RuleCompiler:
    rules: list[Rule] = field(default_factory=list)

    def add(self, rule: Rule) -> Rule:
        if any(existing.id == rule.id for existing in self.rules):
            raise RuleConflictError(f"duplicate rule id: {rule.id}")
        if rule.trigger:
            try:
                re.compile(rule.trigger)
            except re.error as error:
                raise RuleConflictError(f"invalid trigger regex in {rule.id}: {error}") from error
        if not 0 <= rule.priority <= 100:
            raise RuleConflictError("priority must be within [0, 100]")
        self.rules.append(rule)
        return rule

    def evaluate(self, text: str, *, scope: str = "*") -> Decision:
        matched = [
            rule for rule in self.rules if rule.matches_scope(scope) and rule.matches_text(text)
        ]
        if not matched:
            return Decision(action=RuleAction.ALLOW, reasons=("no rule matched",))

        best = max(rule.specificity for rule in matched)
        top = [rule for rule in matched if rule.specificity == best]
        actions = {rule.action for rule in top}
        if len(actions) > 1:
            ids = tuple(rule.id for rule in top)
            report = ConflictReport(
                rule_ids=ids,
                scopes=tuple(sorted({rule.scope for rule in top})),
                triggers=tuple(sorted({rule.trigger or "*" for rule in top})),
                priorities=tuple(sorted({rule.priority for rule in top})),
                suggested_resolution=(
                    "ask a human to pick one rule, or raise the priority of the intended one"
                ),
            )
            return Decision(
                action=RuleAction.REQUIRE_CONFIRM,
                matched=tuple(rule.id for rule in matched),
                conflicts=ids,
                human_required=True,
                reasons=(f"conflicting equally specific rules: {', '.join(ids)}",),
                report=report,
            )
        winner = top[0]
        return Decision(
            action=winner.action,
            matched=tuple(rule.id for rule in matched),
            reasons=(winner.rationale or winner.name,),
        )
