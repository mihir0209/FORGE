import pytest
from forge.phishing_domain_typo_sentinel import PhishingDomainTypoSentinel
from forge.gas_price_spike_sentinel import GasPriceSpikeSentinel
from forge.ato_login_velocity_sentinel import AtoLoginVelocitySentinel
from forge.face_morphing_detector import FaceMorphingDetector
from forge.cross_chain_nonce_sentinel import CrossChainNonceSentinel

def test_achievement_1_phishing_typosquat():
    sentinel = PhishingDomainTypoSentinel(protected_brands={"coinbase", "binance", "metamask"})
    # Substitution / omission (1 edit distance)
    res = sentinel.evaluate_domain("conbase.com")
    assert res.is_impersonation is True
    assert res.target_brand == "coinbase"
    assert res.edit_distance == 1
    assert res.risk_level == "CRITICAL_TYPOSQUAT"

    # Official domain passes
    assert sentinel.evaluate_domain("coinbase.com").is_impersonation is False

def test_achievement_2_gas_spike_sentinel():
    sentinel = GasPriceSpikeSentinel(spike_multiplier_threshold=3.0)
    # 50 Gwei avg -> spiked to 200 Gwei (4x) with 98% gas usage -> Surge attack
    alert = sentinel.evaluate_block_gas(50.0, 200.0, 98.0)
    assert alert.is_surge_attack is True
    assert alert.mempool_exhaustion_detected is True

    # Normal gas flow
    normal = sentinel.evaluate_block_gas(50.0, 60.0, 60.0)
    assert normal.is_surge_attack is False

def test_achievement_3_ato_login_velocity():
    sentinel = AtoLoginVelocitySentinel(failure_threshold=5)
    # 6 failed attempts -> triggers lockout backoff
    res = sentinel.evaluate_account_attempts(6, unique_ip_count=1)
    assert res.is_credential_stuffing is True
    assert res.lockout_seconds >= 60

def test_achievement_4_face_morphing_detector():
    detector = FaceMorphingDetector()
    # High edge discontinuity + ghost score -> flagged
    res = detector.evaluate_biometric_facial_mesh(0.75, 0.50, 0.40)
    assert res.is_morphed_image is True
    assert res.decision == "FLAG_FOR_MANUAL_KYC_AUDIT"

    # Authentic face scan passes
    auth = detector.evaluate_biometric_facial_mesh(0.20, 0.10, 0.10)
    assert auth.is_morphed_image is False

def test_achievement_5_cross_chain_nonce_replay():
    sentinel = CrossChainNonceSentinel()
    # First delivery succeeds
    first = sentinel.process_message_delivery(src_chain=1, target_chain=137, nonce=1001)
    assert first.is_replay_attack is False
    assert first.action == "EXECUTE_RELAY_PAYLOAD"

    # Replay of same nonce is dropped
    replay = sentinel.process_message_delivery(src_chain=1, target_chain=137, nonce=1001)
    assert replay.is_replay_attack is True
    assert replay.action == "DROP_REPLAY_MESSAGE"
