"""Tests for FORGE Adaptive Rule Engine & Policy Synthesis DSL."""

from __future__ import annotations

import pytest
from forge.rule_engine import (
    AdaptiveRuleEngine,
    Condition,
    Rule,
    RuleAction,
)


def test_rule_condition_operators():
    # Numeric comparison
    c_gt = Condition("velocity_60s", ">", 5)
    assert c_gt.evaluate({"velocity_60s": 6}) is True
    assert c_gt.evaluate({"velocity_60s": 5}) is False
    assert c_gt.evaluate({"velocity_60s": 4}) is False
    assert c_gt.evaluate({}) is False

    # String contains / in
    c_in = Condition("country", "in", ["NG", "RU", "IR"])
    assert c_in.evaluate({"country": "NG"}) is True
    assert c_in.evaluate({"country": "US"}) is False

    # Equals
    c_eq = Condition("device_type", "==", "emulator")
    assert c_eq.evaluate({"device_type": "emulator"}) is True
    assert c_eq.evaluate({"device_type": "mobile"}) is False


def test_rule_evaluation_and_combinator():
    # Rule triggers ONLY IF all conditions match
    rule = Rule(
        id="R101",
        name="High Velocity & Mule Ring Risk",
        conditions=[
            Condition("velocity_60s", ">=", 5),
            Condition("mule_risk", ">", 0.7),
        ],
        action=RuleAction.BLOCK,
        combinator="ALL",
        reason="Rapid burst with graph mule cycle membership",
    )

    # 1. Partial match (only velocity) -> False
    assert rule.evaluate({"velocity_60s": 5, "mule_risk": 0.4}) is False
    assert rule.hit_count == 0

    # 2. Both match -> True
    assert rule.evaluate({"velocity_60s": 6, "mule_risk": 0.85}) is True
    assert rule.hit_count == 1


def test_rule_engine_severity_conflict_resolution():
    engine = AdaptiveRuleEngine()

    # Rule 1: Review for velocity
    engine.add_rule(
        Rule(
            id="R_REV",
            name="Velocity Review",
            conditions=[Condition("velocity_60s", ">=", 3)],
            action=RuleAction.REVIEW,
            priority=50,
            reason="Elevated velocity",
        )
    )

    # Rule 2: Hard Block for mule risk
    engine.add_rule(
        Rule(
            id="R_BLK",
            name="Mule Ring Block",
            conditions=[Condition("mule_risk", ">=", 0.9)],
            action=RuleAction.BLOCK,
            priority=100,  # Lower priority number, but higher severity action
            reason="Confirmed mule ring cycle",
        )
    )

    context = {"velocity_60s": 4, "mule_risk": 0.95}
    result = engine.evaluate(context)

    # Severity resolution: BLOCK overrides REVIEW
    assert result.action == RuleAction.BLOCK
    assert "Mule Ring Block" in result.decision_reason
    assert len(result.matched_rules) == 2


def test_engine_adaptive_threshold_calibration():
    engine = AdaptiveRuleEngine()
    rule = Rule(
        id="R_ADAPTIVE",
        name="Adaptive Velocity Cap",
        conditions=[Condition("velocity_60s", ">=", 3.0)],
        action=RuleAction.BLOCK,
    )
    engine.add_rule(rule)

    # Historical labeled samples: 20 legitimate transactions with velocity between 1 and 6
    legitimate_samples = [({"velocity_60s": float(v)}, False) for v in range(1, 21)]

    # Calibrate so FPR <= 10% (i.e. only top 10% of legitimate transactions would trigger)
    new_thresh = engine.calibrate_threshold("R_ADAPTIVE", "velocity_60s", legitimate_samples, max_acceptable_fpr=0.10)
    assert new_thresh is not None
    assert new_thresh >= 18.0
    assert rule.conditions[0].value == new_thresh


def test_rule_engine_json_serialization_roundtrip():
    engine = AdaptiveRuleEngine()
    engine.add_rule(
        Rule(
            id="R_SERIAL",
            name="Serialization Test",
            conditions=[Condition("amount", ">", 10000)],
            action=RuleAction.CHALLENGE,
            priority=10,
            reason="Large transfer challenge",
        )
    )

    json_str = engine.to_json()
    reloaded = AdaptiveRuleEngine.from_json(json_str)

    assert len(reloaded.rules) == 1
    assert reloaded.rules[0].id == "R_SERIAL"
    assert reloaded.rules[0].action == RuleAction.CHALLENGE

    # Test evaluation on reloaded engine
    res = reloaded.evaluate({"amount": 15000})
    assert res.action == RuleAction.CHALLENGE
