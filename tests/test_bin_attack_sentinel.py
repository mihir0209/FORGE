import pytest
from forge.bin_attack_sentinel import BINAttackSentinel, BINAttackAlert


def test_bin_attack_sentinel_normal_traffic_clean():
    sentinel = BINAttackSentinel(window_seconds=60.0)
    bin_num = "411111"
    mid = "merchant_nike"

    # 3 legitimate approvals with different cards
    for i in range(3):
        alert = sentinel.record_auth_attempt(
            bin_number=bin_num,
            merchant_id=mid,
            card_hash=f"card_hash_{i}",
            approved=True,
            timestamp_epoch=1000.0 + i,
        )

    assert not alert.is_attack_detected
    assert alert.failure_rate == 0.0
    assert alert.recommended_mitigation == "NONE"


def test_bin_attack_sentinel_detects_card_testing_burst():
    sentinel = BINAttackSentinel(window_seconds=60.0)
    bin_num = "542418"
    mid = "merchant_shopify_target"

    # Bot runs 7 card auth attempts in 10 seconds: 5 failures, 2 successes across 6 cards
    for i in range(7):
        approved = (i == 0)  # 1 approval, 6 failures (6/7 failures = 85.7%)
        alert = sentinel.record_auth_attempt(
            bin_number=bin_num,
            merchant_id=mid,
            card_hash=f"stolen_card_{i}",
            approved=approved,
            timestamp_epoch=2000.0 + i,
        )

    assert alert.is_attack_detected
    assert alert.failure_rate >= 0.70
    assert alert.unique_cards >= 6
    assert alert.recommended_mitigation == "BLOCK_BIN"


def test_bin_attack_sliding_window_prunes_stale_attempts():
    sentinel = BINAttackSentinel(window_seconds=30.0)
    bin_num = "400000"
    mid = "merchant_digital_goods"

    # 6 failed attempts at t=100
    for i in range(6):
        sentinel.record_auth_attempt(
            bin_number=bin_num,
            merchant_id=mid,
            card_hash=f"probe_{i}",
            approved=False,
            timestamp_epoch=100.0 + i,
        )

    # Fast forward to t=150 (50s later, beyond 30s window) with 1 normal approved attempt
    alert = sentinel.record_auth_attempt(
        bin_number=bin_num,
        merchant_id=mid,
        card_hash="clean_card",
        approved=True,
        timestamp_epoch=150.0,
    )

    # Window should only have the 1 recent attempt
    assert alert.total_attempts_in_window == 1
    assert alert.failure_rate == 0.0
    assert not alert.is_attack_detected
