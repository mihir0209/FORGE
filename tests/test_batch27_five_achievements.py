import pytest
from forge.zk_proof_soundness_sentinel import ZkProofSoundnessSentinel
from forge.doh_tunneling_sentinel import DohTunnelingSentinel
from forge.ecdsa_signature_malleability_sentinel import EcdsaSignatureMalleabilitySentinel
from forge.reorg_finality_arbitrage_watchdog import ReorgFinalityArbitrageWatchdog
from forge.credit_bustout_velocity_engine import CreditBustOutVelocityEngine

def test_achievement_1_zk_soundness():
    sentinel = ZkProofSoundnessSentinel()
    # Missing constraint on public signal
    flawed = sentinel.audit_circuit_constraints(["in_a", "in_b", "out_c"], {"in_a", "in_b"}, division_remainder_check_enforced=True)
    assert flawed.is_sound is False
    assert "out_c" in flawed.underconstrained_signals

    # Fully constrained circuit
    sound = sentinel.audit_circuit_constraints(["in_a", "out_c"], {"in_a", "out_c"}, division_remainder_check_enforced=True)
    assert sound.is_sound is True

def test_achievement_2_doh_tunneling():
    sentinel = DohTunnelingSentinel()
    # Long high-entropy base32 exfiltration subdomain
    tunnel = sentinel.evaluate_doh_traffic_pattern(
        subdomain_label="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
        upstream_bytes=50000,
        downstream_bytes=2000
    )
    assert tunnel.is_tunneling is True
    assert tunnel.threat_tier == "CRITICAL_DOH_DATA_EXFILTRATION"

    # Standard query
    standard = sentinel.evaluate_doh_traffic_pattern("google", 200, 1500)
    assert standard.is_tunneling is False

def test_achievement_3_ecdsa_malleability():
    sentinel = EcdsaSignatureMalleabilitySentinel()
    # Malicious high-S value (> n/2)
    high_s = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140"
    res = sentinel.check_and_normalize_s(high_s)
    assert res.is_malleable is True
    assert res.remediation_required is True
    # Normalized S is low
    assert int(res.normalized_s, 16) <= sentinel.HALF_N

def test_achievement_4_reorg_finality():
    watchdog = ReorgFinalityArbitrageWatchdog()
    # High value transaction on PoW Nakamoto with only 3 confirmations
    high_val = watchdog.evaluate_block_finality("POW_NAKAMOTO", current_confirmations=3, transaction_amount_usd=250_000.0)
    assert high_val.is_reorg_vulnerable is True
    assert high_val.required_safe_depth == 12
    assert high_val.action == "WAIT_FOR_DEEPER_FINALITY"

    # Tendermint instant finality
    bft = watchdog.evaluate_block_finality("BFT_TENDERMINT", current_confirmations=1, transaction_amount_usd=1_000_000.0)
    assert bft.is_reorg_vulnerable is False
    assert bft.action == "PROCEED_IMMEDIATELY"

def test_achievement_5_credit_bustout():
    engine = CreditBustOutVelocityEngine()
    # Average $3000/mo ($100/day), suddenly spends $1200 in 48h ($600/day = 6x spike), 60% cash advance on $1500 limit (80% utilization)
    alert = engine.evaluate_utilization_acceleration(
        historical_monthly_spend_usd=3000.0,
        last_48h_spend_usd=1200.0,
        cash_advance_ratio=0.60,
        credit_limit_usd=1500.0
    )
    assert alert.is_bustout_risk is True
    assert alert.velocity_spike_ratio == 6.0
    assert alert.mitigation == "FREEZE_CREDIT_LINE_IMMEDIATELY"
