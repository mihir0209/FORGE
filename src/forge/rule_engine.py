"""Adaptive Anti-Fraud Rule Engine and Policy Synthesis DSL.

Evaluates declarative business rules over streaming transaction signals,
handles priority conflict resolution, and supports dynamic threshold tuning.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable


class RuleAction(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    CHALLENGE = "CHALLENGE"
    BLOCK = "BLOCK"


_ACTION_SEVERITY: dict[RuleAction, int] = {
    RuleAction.ALLOW: 0,
    RuleAction.CHALLENGE: 1,
    RuleAction.REVIEW: 2,
    RuleAction.BLOCK: 3,
}


@dataclass
class Condition:
    field: str
    operator: str  # '>', '<', '>=', '<=', '==', '!=', 'in', 'contains'
    value: Any

    def evaluate(self, context: dict[str, Any]) -> bool:
        if self.field not in context:
            return False
        val = context[self.field]
        if val is None:
            return False

        op = self.operator
        try:
            if op == ">":
                return float(val) > float(self.value)
            elif op == "<":
                return float(val) < float(self.value)
            elif op == ">=":
                return float(val) >= float(self.value)
            elif op == "<=":
                return float(val) <= float(self.value)
            elif op == "==":
                return val == self.value
            elif op == "!=":
                return val != self.value
            elif op == "in":
                return val in self.value
            elif op == "contains":
                return self.value in val
        except (ValueError, TypeError):
            return False
        return False


@dataclass
class Rule:
    id: str
    name: str
    conditions: list[Condition]
    action: RuleAction
    priority: int = 100  # Lower number = higher priority
    combinator: str = "ALL"  # 'ALL' (AND) or 'ANY' (OR)
    reason: str = ""
    enabled: bool = True
    hit_count: int = 0

    def evaluate(self, context: dict[str, Any]) -> bool:
        if not self.enabled or not self.conditions:
            return False

        results = [cond.evaluate(context) for cond in self.conditions]
        matched = all(results) if self.combinator == "ALL" else any(results)
        if matched:
            self.hit_count += 1
        return matched


@dataclass
class RuleEvaluationResult:
    action: RuleAction
    decision_reason: str
    matched_rules: list[dict[str, Any]]
    context_snapshot: dict[str, Any]


class AdaptiveRuleEngine:
    """Evaluates rules over transaction contexts and adaptively calibrates thresholds."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules: list[Rule] = rules or []

    def add_rule(self, rule: Rule) -> None:
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority)

    def remove_rule(self, rule_id: str) -> bool:
        initial_len = len(self.rules)
        self.rules = [r for r in self.rules if r.id != rule_id]
        return len(self.rules) < initial_len

    def evaluate(self, context: dict[str, Any]) -> RuleEvaluationResult:
        """Evaluate context against all active rules, resolving actions by highest severity."""
        matched: list[Rule] = []

        for rule in self.rules:
            if rule.evaluate(context):
                matched.append(rule)

        if not matched:
            return RuleEvaluationResult(
                action=RuleAction.ALLOW,
                decision_reason="No fraud rules triggered",
                matched_rules=[],
                context_snapshot=context,
            )

        # Conflict resolution: select the highest severity action
        highest_rule = max(
            matched,
            key=lambda r: (_ACTION_SEVERITY.get(r.action, 0), -r.priority),
        )

        matched_summaries = [
            {
                "rule_id": r.id,
                "name": r.name,
                "action": r.action.value,
                "reason": r.reason,
                "priority": r.priority,
            }
            for r in matched
        ]

        return RuleEvaluationResult(
            action=highest_rule.action,
            decision_reason=f"Triggered rule '{highest_rule.name}': {highest_rule.reason}",
            matched_rules=matched_summaries,
            context_snapshot=context,
        )

    def calibrate_threshold(
        self,
        rule_id: str,
        condition_field: str,
        labeled_samples: list[tuple[dict[str, Any], bool]],  # (features, is_actual_fraud)
        max_acceptable_fpr: float = 0.05,
    ) -> float | None:
        """Calibrates a numeric rule threshold so false positive rate <= max_acceptable_fpr."""
        target_rule = next((r for r in self.rules if r.id == rule_id), None)
        if not target_rule:
            return None

        target_cond = next((c for c in target_rule.conditions if c.field == condition_field), None)
        if not target_cond or target_cond.operator not in (">", ">="):
            return None

        legitimate_values = [
            ctx[condition_field]
            for ctx, is_fraud in labeled_samples
            if not is_fraud and condition_field in ctx and ctx[condition_field] is not None
        ]

        if not legitimate_values:
            return None

        # Sort legitimate values to find percentile corresponding to 1 - max_acceptable_fpr
        legitimate_values.sort()
        idx = int(len(legitimate_values) * (1.0 - max_acceptable_fpr))
        idx = min(idx, len(legitimate_values) - 1)
        new_threshold = round(float(legitimate_values[idx]), 3)

        target_cond.value = new_threshold
        return new_threshold

    def to_json(self) -> str:
        data = []
        for r in self.rules:
            data.append({
                "id": r.id,
                "name": r.name,
                "action": r.action.value,
                "priority": r.priority,
                "combinator": r.combinator,
                "reason": r.reason,
                "enabled": r.enabled,
                "conditions": [asdict(c) for c in r.conditions],
            })
        return json.dumps(data, indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> AdaptiveRuleEngine:
        data = json.loads(json_str)
        rules = []
        for d in data:
            conditions = [
                Condition(field=c["field"], operator=c["operator"], value=c["value"])
                for c in d.get("conditions", [])
            ]
            rules.append(
                Rule(
                    id=d["id"],
                    name=d["name"],
                    action=RuleAction(d["action"]),
                    priority=d.get("priority", 100),
                    combinator=d.get("combinator", "ALL"),
                    reason=d.get("reason", ""),
                    enabled=d.get("enabled", True),
                    conditions=conditions,
                )
            )
        return cls(rules=rules)
