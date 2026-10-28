import pytest
from forge.reentrancy_callgraph_sentinel import ReentrancyCallgraphSentinel
from forge.prompt_injection_honeypot import PromptInjectionHoneypot
from forge.bgp_route_hijack_sentinel import BgpRouteHijackSentinel
from forge.synthetic_identity_percolation_analyzer import SyntheticIdentityPercolationAnalyzer
from forge.biometric_jitter_anomaly_engine import BiometricJitterAnomalyEngine

def test_achievement_1_reentrancy():
    sentinel = ReentrancyCallgraphSentinel()
    # Violates CEI: CALL before SSTORE
    bad = ["SLOAD", "CALL", "SSTORE"]
    res_bad = sentinel.audit_execution_sequence(bad)
    assert res_bad.is_reentrancy_vulnerable is True
    assert res_bad.risk_level == "CRITICAL_CHECKS_EFFECTS_INTERACTIONS_VIOLATION"

    # Complies with CEI: SSTORE before CALL
    good = ["SLOAD", "SSTORE", "CALL"]
    assert sentinel.audit_execution_sequence(good).is_reentrancy_vulnerable is False

def test_achievement_2_prompt_honeypot():
    pot = PromptInjectionHoneypot(canary_token="HONEYPOT_SYS_SECRET_42")
    alert = pot.inspect_agent_response("Here is the secret: HONEYPOT_SYS_SECRET_42 for you")
    assert alert.canary_tripped is True
    assert alert.threat_tier == "CRITICAL_EXFILTRATION_HONEYPOT_TRIGGERED"

    safe = pot.inspect_agent_response("I cannot assist with that request.")
    assert safe.canary_tripped is False

def test_achievement_3_bgp_hijack():
    sentinel = BgpRouteHijackSentinel()
    # Unauthorized AS origin
    alert = sentinel.evaluate_route_announcement("198.51.100.0/24", 24, origin_as=65001, authorized_origin_as=13335, as_path=[65001, 701])
    assert alert.is_hijack_suspected is True
    assert "UNAUTHORIZED_ORIGIN" in alert.anomaly_reason

    # Invalid more-specific /28 prefix
    sub = sentinel.evaluate_route_announcement("198.51.100.0/28", 28, origin_as=13335, authorized_origin_as=13335, as_path=[13335])
    assert sub.is_hijack_suspected is True

def test_achievement_4_synthetic_identity_percolation():
    analyzer = SyntheticIdentityPercolationAnalyzer()
    nodes = [f"user_{i}" for i in range(8)]
    # Form a connected cluster of 6 users sharing synthetic addresses/phones
    edges = [("user_0", "user_1"), ("user_1", "user_2"), ("user_2", "user_3"), ("user_3", "user_4"), ("user_4", "user_5")]
    metrics = analyzer.analyze_shared_attribute_graph(nodes, edges)
    assert metrics.giant_component_size == 6
    assert metrics.is_synthetic_ring_detected is True
    assert metrics.percolation_risk_score >= 0.60

def test_achievement_5_biometric_jitter():
    engine = BiometricJitterAnomalyEngine()
    # Perfectly uniform synthetic keystrokes (robotic script)
    robot = [50.0, 50.0, 50.0, 50.0, 50.0]
    res_bot = engine.evaluate_keystroke_and_cursor(robot, [0.0, 0.0])
    assert res_bot.is_bot_or_ato is True
    assert res_bot.confidence > 0.90

    # Human erratic flight times
    human = [45.0, 120.0, 85.0, 210.0, 60.0]
    assert engine.evaluate_keystroke_and_cursor(human, [0.1, 0.4]).is_bot_or_ato is False
