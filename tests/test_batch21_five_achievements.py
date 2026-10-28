import pytest
from forge.deepfake_liveness_sentinel import DeepfakeBiometricsLivenessSentinel
from forge.ransomware_cluster_tracer import RansomwareBtcClusterTracer
from forge.zeroday_drain_sentinel import ZeroDayContractDrainSentinel
from forge.card_testing_governor import CardTestingVelocityGovernor
from forge.did_sybil_score import DecentralizedIdentitySybilScore

def test_achievement_1_deepfake_liveness():
    sentinel = DeepfakeBiometricsLivenessSentinel()
    # Authentic human (15 blinks/min, low artifact score)
    res_real = sentinel.evaluate_video_stream(150, [1.0, 3.0], 0.2)
    assert res_real.is_live is True

    # Deepfake (zero blinks + high frequency artifacts)
    res_fake = sentinel.evaluate_video_stream(150, [], 0.85)
    assert res_fake.is_live is False
    assert res_fake.flag == "DEEPFAKE_ARTIFACT_DETECTED"

def test_achievement_2_ransomware_cluster_tracer():
    tracer = RansomwareBtcClusterTracer(
        known_ransomware_seeds={"1LockBitSeedWalletX"},
        known_mixers={"1TornadoCashMixerY"}
    )
    path = [
        {"from": "1LockBitSeedWalletX", "to": "1IntermediaryMule", "btc": 5.0},
        {"from": "1IntermediaryMule", "to": "1TornadoCashMixerY", "btc": 4.98},
    ]
    trace = tracer.trace_utxo_lineage(path)
    assert trace.is_ransomware_taint is True
    assert trace.hop_count == 2
    assert trace.mixer_interaction is True

def test_achievement_3_zeroday_drain():
    drain = ZeroDayContractDrainSentinel()
    alert = drain.evaluate_contract_outflow("0xVaultContract", 1000000.0, 450000.0) # 45% drain
    assert alert.is_drain is True
    assert alert.recommended_action == "PAUSE_CONTRACT_EMERGENCY"

def test_achievement_4_card_testing_governor():
    gov = CardTestingVelocityGovernor()
    res = gov.evaluate_terminal_attempts(total_attempts=50, declined_attempts=40) # 80% decline
    assert res.quarantine_terminal is True
    assert res.action == "TRIP_TERMINAL_QUARANTINE"

def test_achievement_5_did_sybil_score():
    scorer = DecentralizedIdentitySybilScore()
    assessment = scorer.compute_trust_score(attestation_count=10, unique_verifiers=5, age_in_days=300)
    assert assessment.sybil_resistance_score >= 80.0
    assert assessment.trust_tier == "VERIFIED_HUMAN"
