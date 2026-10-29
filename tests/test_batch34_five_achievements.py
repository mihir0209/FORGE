import pytest
from forge.erc4337_paymaster_gas_griefing_sentinel import Erc4337PaymasterGasGriefingSentinel
from forge.cross_l2_bridge_challenge_sentinel import CrossL2BridgeChallengeSentinel
from forge.bgp_origin_validation_failure_sentinel import BgpOriginValidationFailureSentinel
from forge.readonly_reentrancy_curve_auditor import ReadOnlyReentrancyCurveAuditor
from forge.graph_anomaly_centrality_evasion_predictor import GraphAnomalyCentralityEvasionPredictor

def test_achievement_1_paymaster_gas_griefing():
    sentinel = Erc4337PaymasterGasGriefingSentinel()
    # Inflated verification gas limit (400k > 150k limit) -> griefing alert
    grief = sentinel.audit_paymaster_user_op(verification_gas_limit=400_000, call_gas_limit=100_000, postop_gas_limit=50_000)
    assert grief.is_gas_griefing_risk is True
    assert "REJECT" in grief.action

    # Compliant gas limit (80k verification, 30k postop)
    safe = sentinel.audit_paymaster_user_op(80_000, 100_000, 30_000)
    assert safe.is_gas_griefing_risk is False

def test_achievement_2_cross_l2_bridge_challenge():
    sentinel = CrossL2BridgeChallengeSentinel()
    claimed = "0x" + "a" * 64
    verified = "0x" + "b" * 64
    # Dishonest root submitted with 50 blocks remaining in dispute window -> challenge & slash
    alert = sentinel.verify_optimistic_withdrawal_assertion("assert_01", claimed, verified, dispute_window_blocks_remaining=50, staked_bond_eth=10.0)
    assert alert.is_dispute_challenge_triggered is True
    assert alert.challenge_bond_slashed_eth == 10.0
    assert "SLASH_DISHONEST" in alert.dispute_verdict

    # Correct root -> clean
    assert sentinel.verify_optimistic_withdrawal_assertion("assert_02", verified, verified, 50).is_dispute_challenge_triggered is False

def test_achievement_3_bgp_rpki_ovf():
    sentinel = BgpOriginValidationFailureSentinel()
    # Hijack: announced by AS65001 when ROA says AS13335
    res_bad = sentinel.validate_rpki_route("198.51.100.0/24", 24, origin_asn=65001, roa_authorized_asn=13335, roa_max_length=24)
    assert res_bad.rpki_status == "INVALID"
    assert res_bad.is_route_leak_dropped is True

    # Valid route
    res_good = sentinel.validate_rpki_route("198.51.100.0/24", 24, origin_asn=13335, roa_authorized_asn=13335, roa_max_length=24)
    assert res_good.rpki_status == "VALID"
    assert res_good.is_route_leak_dropped is False

def test_achievement_4_readonly_reentrancy_curve():
    auditor = ReadOnlyReentrancyCurveAuditor()
    # Read-only caller queries during remove_liquidity when virtual price dropped from 1.05 to 0.85 (1900 bps drop)
    attack = auditor.inspect_transient_pool_state(is_inside_remove_liquidity_hook=True, nominal_virtual_price=1.05, transient_virtual_price=0.85)
    assert attack.is_transient_price_manipulated is True
    assert attack.virtual_price_drop_bps > 1000
    assert "READONLY_REENTRANCY" in attack.exploit_risk_tier

    # Outside callback: nominal synced state
    safe = auditor.inspect_transient_pool_state(False, 1.05, 1.05)
    assert safe.is_transient_price_manipulated is False

def test_achievement_5_graph_centrality_evasion():
    predictor = GraphAnomalyCentralityEvasionPredictor()
    # Synthetic peel chain: 8 transactions each with degree exactly (1 in, 1 out) -> uniform variance = 0
    in_deg = [1] * 8
    out_deg = [1] * 8
    alert = predictor.evaluate_node_centrality(in_deg, out_deg)
    assert alert.is_evasion_detected is True
    assert alert.degree_dispersion_ratio <= 0.05
    assert alert.centrality_flattening_score > 0.90
