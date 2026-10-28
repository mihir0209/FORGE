import pytest
from forge.flash_loan_reentrancy_guard import FlashLoanReentrancyGuard
from forge.subnet_poisoning_sentinel import SubnetPoisoningSentinel
from forge.triangulation_fraud_sentinel import TriangulationFraudSentinel
from forge.l2_sequencer_frontrun_sentinel import L2SequencerFrontrunSentinel
from forge.micro_structuring_mule_sentinel import MicroStructuringMuleSentinel

def test_achievement_1_flash_loan_reentrancy():
    guard = FlashLoanReentrancyGuard(max_allowed_depth=1)
    pool = "0xLendingPoolAlpha"
    res1 = guard.enter_pool_callback(pool)
    assert res1.is_reentrancy_attack is False
    assert res1.call_depth == 1

    # Malicious recursive re-entry
    res2 = guard.enter_pool_callback(pool)
    assert res2.is_reentrancy_attack is True
    assert res2.call_depth == 2
    assert res2.threat_severity == "CRITICAL"

    guard.exit_pool_callback(pool)
    guard.exit_pool_callback(pool)

def test_achievement_2_subnet_poisoning():
    sentinel = SubnetPoisoningSentinel(max_asns_per_subnet=2, churn_threshold=4)
    # Same /24 subnet rotated across 3 different ASNs (BGP routing anomaly / proxy network)
    sentinel.register_connection("198.51.100.10", asn=100)
    sentinel.register_connection("198.51.100.15", asn=200)
    alert = sentinel.register_connection("198.51.100.20", asn=300)
    assert alert.is_poisoned is True
    assert alert.unique_asns_seen == 3
    assert alert.risk_level in ("HIGH", "CRITICAL")

def test_achievement_3_triangulation_fraud():
    sentinel = TriangulationFraudSentinel()
    alert = sentinel.evaluate_order(
        buyer_card_hash="card_hash_xyz",
        shipping_address_hash="ship_hash_123",
        matched_marketplace_listing="LISTING-EBAY-999",
        cardholder_name="Alice Smith",
        shipping_recipient_name="Bob Stranger",
        order_to_listing_delta_seconds=1200.0 # 20 minutes
    )
    assert alert.is_triangulation_fraud is True
    assert alert.confidence_score >= 0.90

def test_achievement_4_l2_sequencer_mev():
    sentinel = L2SequencerFrontrunSentinel()
    alert = sentinel.evaluate_batch(
        sequencer_addr="0xSequencerNode01",
        sub_millisecond_ordering=True,
        miner_extractable_value_usd=15000.0,
        block_latency_ms=25.0
    )
    assert alert.is_sequencer_mev is True
    assert alert.risk_tier == "CRITICAL_SEQUENCER_CORRUPTION"

def test_achievement_5_micro_structuring_mules():
    sentinel = MicroStructuringMuleSentinel()
    # 5 uniform deposits of ~$490 across 5 wallets in 20 min
    deposits = [490.0, 492.0, 489.0, 491.0, 490.5]
    wallets = {"0xW1", "0xW2", "0xW3", "0xW4", "0xW5"}
    alert = sentinel.evaluate_deposit_fan_out(deposits, wallets, window_minutes=20.0)
    assert alert.is_smurfing_mule is True
    assert alert.action == "LOCK_CHAIN_DISPERSION"
