import pytest
from forge.keystroke_dwell_time_verifier import KeystrokeDwellTimeVerifier
from forge.mixer_hop_proximity_scorer import MixerHopProximityScorer
from forge.ecommerce_return_wardrobing_sentinel import EcommerceReturnWardrobingSentinel
from forge.fast_flux_dns_sentinel import FastFluxDnsSentinel
from forge.storage_slot_manipulation_sentinel import StorageSlotManipulationSentinel

def test_achievement_1_keystroke_biometric_cadence():
    verifier = KeystrokeDwellTimeVerifier(max_distance_threshold=30.0)
    baseline = [85.0, 92.0, 110.0, 78.0, 95.0]
    # Identical cadence -> match
    match = verifier.evaluate_typing_cadence(baseline, [86.0, 90.0, 108.0, 80.0, 94.0])
    assert match.is_biometric_match is True
    assert match.threat_tier == "AUTHORIZED_BIOMETRIC_PROFILE"

    # Drastic bot injection divergence
    bot = verifier.evaluate_typing_cadence(baseline, [20.0, 20.0, 20.0, 20.0, 20.0])
    assert bot.is_biometric_match is False
    assert bot.threat_tier == "SUSPECTED_ATO_BOT_INJECTION"

def test_achievement_2_mixer_hop_proximity_scorer():
    scorer = MixerHopProximityScorer(sanctioned_clusters={"0xTornadoCash01"}, max_flagged_hops=3)
    graph = {
        "0xUserWallet": {"0xMule1"},
        "0xMule1": {"0xMule2"},
        "0xMule2": {"0xTornadoCash01"},
    }
    # 3 hops away from Tornado Cash
    res = scorer.compute_proximity("0xUserWallet", graph)
    assert res.is_high_sanction_risk is True
    assert res.shortest_hop_distance == 3

    # Clean wallet
    clean = scorer.compute_proximity("0xCleanWallet", {})
    assert clean.is_high_sanction_risk is False

def test_achievement_3_wardrobing_return_fraud():
    sentinel = EcommerceReturnWardrobingSentinel()
    purchases = [500.0, 600.0, 450.0, 50.0]
    returns = [500.0, 600.0, 450.0] # 75% return rate, 3 high value
    alert = sentinel.evaluate_account_history(purchases, returns, account_age_days=10)
    assert alert.is_wardrobing_fraud is True
    assert alert.account_action == "RESTRICT_RETURN_PRIVILEGES"

def test_achievement_4_fast_flux_dns_sentinel():
    sentinel = FastFluxDnsSentinel(max_ip_churn=4, min_ttl_threshold_sec=120)
    ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"]
    ttls = [60, 60, 60, 60, 60]
    flux = sentinel.evaluate_dns_resolutions(ips, ttls)
    assert flux.is_fast_flux is True
    assert flux.threat_classification == "FAST_FLUX_BOTNET_C2"

def test_achievement_5_storage_slot_manipulation():
    sentinel = StorageSlotManipulationSentinel()
    writes = {
        "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc": "0xRogueImplementation",
    }
    alert = sentinel.inspect_state_diff(writes, {"0x0", "0x1"})
    assert alert.is_storage_collision is True
    assert alert.implementation_slot_mutated is True
    assert alert.action == "TRIGGER_CIRCUIT_BREAKER_UPGRADE_ATTACK"
