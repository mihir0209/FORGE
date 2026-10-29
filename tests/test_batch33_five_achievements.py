import pytest
from forge.pbs_mevboost_censorship_sentinel import PbsMevboostCensorshipSentinel
from forge.stark_fri_soundness_verifier import StarkFriSoundnessVerifier
from forge.solana_pda_canonical_bump_enforcer import SolanaPdaCanonicalBumpEnforcer
from forge.bgp_rfd_parameter_misconfiguration_sentinel import BgpRfdParameterSentinel
from forge.amm_fee_tier_arbitrage_drain_predictor import AmmFeeTierArbitrageDrainPredictor

def test_achievement_1_mevboost_censorship():
    sentinel = PbsMevboostCensorshipSentinel()
    sanctioned = "0x1111111111111111111111111111111111111111"
    # Systematically omitted for 5 consecutive blocks
    alert = sentinel.audit_block_bids("censoring-relay-flashbots", [sanctioned], ["0xSafeUser"], consecutive_blocks_omitted=5)
    assert alert.is_censorship_detected is True
    assert alert.threat_tier == "CRITICAL_PROPOSER_BUILDER_OFAC_CENSORSHIP"

    # Neutral inclusion
    neutral = sentinel.audit_block_bids("neutral-relay", [sanctioned], [sanctioned], consecutive_blocks_omitted=0)
    assert neutral.is_censorship_detected is False

def test_achievement_2_stark_fri_soundness():
    verifier = StarkFriSoundnessVerifier()
    # Blowup factor 8 (rate 1/8 -> delta = 1 - 1/sqrt(8) ~ 0.646), 80 queries -> >110 bits security
    metrics_secure = verifier.evaluate_fri_parameters(blowup_factor=8, num_queries=80)
    assert metrics_secure.is_sound is True
    assert metrics_secure.soundness_error_bits >= 96.0

    # Inadequate queries (only 10 queries) -> low bits
    metrics_weak = verifier.evaluate_fri_parameters(blowup_factor=4, num_queries=10)
    assert metrics_weak.is_sound is False

def test_achievement_3_solana_pda_canonical_bump():
    enforcer = SolanaPdaCanonicalBumpEnforcer()
    # Canonical bump is 255
    assert enforcer.verify_pda_bump(255, 255).is_canonical is True

    # Attacker passes non-canonical bump 254 -> collision attack
    collision = enforcer.verify_pda_bump(254, 255)
    assert collision.is_canonical is False
    assert "REVERT" in collision.security_action

def test_achievement_4_bgp_rfd_flapping():
    sentinel = BgpRfdParameterSentinel()
    # 3 flaps -> 3000 penalty points >= 2000 suppress threshold
    damped = sentinel.evaluate_route_flaps(flap_count=3, suppress_threshold=2000.0)
    assert damped.is_flapping_route_suppressed is True
    assert damped.accumulated_penalty == 3000.0
    assert damped.current_status == "ROUTE_SUPPRESSED_FLAP_DAMPED"

    # 1 flap -> 1000 points < 2000 threshold
    assert sentinel.evaluate_route_flaps(1, 2000.0).is_flapping_route_suppressed is False

def test_achievement_5_amm_fee_tier_arbitrage():
    predictor = AmmFeeTierArbitrageDrainPredictor()
    # Low pool price $1000, high pool price $1008 (80 bps discrepancy > 35 bps fee)
    arb = predictor.evaluate_cross_tier_discrepancy(1000.0, 1008.0, trade_volume_usd=100000.0, estimated_gas_cost_usd=25.0)
    assert arb.is_arbitrage_profitable is True
    assert arb.net_profit_usd > 300.0
    assert arb.action == "EXECUTE_MEV_JIT_LIQUIDITY_REBALANCE"

    # Minimal discrepancy (5 bps discrepancy < 35 bps fee)
    no_arb = predictor.evaluate_cross_tier_discrepancy(1000.0, 1000.5, trade_volume_usd=100000.0, estimated_gas_cost_usd=25.0)
    assert no_arb.is_arbitrage_profitable is False
