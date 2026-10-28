import pytest
from forge.audio_deepfake_voiceprint_sentinel import AudioDeepfakeVoiceprintSentinel
from forge.gas_griefing_call_sentinel import GasGriefingCallSentinel
from forge.sybil_louvain_modularity_optimizer import SybilLouvainModularityOptimizer
from forge.bin_attack_quarantine_governor import BinAttackQuarantineGovernor
from forge.jito_subslot_sandwich_tracer import JitoSubslotSandwichTracer

def test_achievement_1_audio_deepfake():
    sentinel = AudioDeepfakeVoiceprintSentinel()
    # Unnatural flat pitch variance + synthetic phase discontinuity -> Deepfake
    fake = sentinel.evaluate_voice_audio(spectral_centroid_hz=1500.0, pitch_variance_semitones=0.8, synthetic_phase_discontinuity_score=0.85)
    assert fake.is_deepfake_voice is True
    assert fake.threat_tier == "CRITICAL_AI_VOICE_CLONE"

    # Human voice
    human = sentinel.evaluate_voice_audio(spectral_centroid_hz=1400.0, pitch_variance_semitones=3.5, synthetic_phase_discontinuity_score=0.2)
    assert human.is_deepfake_voice is False

def test_achievement_2_gas_griefing():
    sentinel = GasGriefingCallSentinel()
    # High gas forward + 95% consumed -> Gas griefing
    alert = sentinel.evaluate_low_level_call("0xTargetContract", forwarded_gas=1_000_000, consumed_gas=950_000, revert_data_bytes_len=100)
    assert alert.is_griefing_attack is True
    assert alert.severity == "CRITICAL_GAS_DRAIN"

def test_achievement_3_sybil_louvain_modularity():
    optimizer = SybilLouvainModularityOptimizer()
    graph = {
        "A": {"B", "C"},
        "B": {"A", "C"},
        "C": {"A", "B"},
        "X": set(),
    }
    res = optimizer.partition_account_graph(graph, min_cluster_size=3)
    assert res.detected_clique_count == 1
    assert res.modularity_q_score > 0.0

def test_achievement_4_bin_attack_governor():
    gov = BinAttackQuarantineGovernor(velocity_threshold=20, max_failure_rate_pct=70.0)
    # 50 attempts with 45 fails (90% fail rate) -> Quarantine
    res = gov.evaluate_bin_stream("411111", total_attempts_60s=50, failed_attempts_60s=45)
    assert res.quarantine_bin_prefix is True
    assert res.action == "QUARANTINE_BIN_RANGE_60M"

def test_achievement_5_jito_sandwich_tracer():
    tracer = JitoSubslotSandwichTracer()
    # 3-tx atomic bundle with tip -> Jito sandwich detected
    res = tracer.evaluate_bundle_ordering("jito_bundle_001", ["sig1", "sig2", "sig3"], tip_amount_lamports=5_000_000, target_swap_account="RaydiumPool")
    assert res.is_jito_sandwich is True
    assert res.risk_level == "CRITICAL_MEV_PREDATION"
    assert res.victim_slippage_extracted_sol > 0
