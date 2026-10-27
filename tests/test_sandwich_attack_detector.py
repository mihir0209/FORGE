import pytest
from forge.sandwich_attack_detector import (
    SandwichAttackDetector,
    DexSwapTransaction,
    SandwichAttackAlert,
)


@pytest.fixture
def detector():
    return SandwichAttackDetector(min_profit_threshold=0.0)


def test_clean_sandwich_attack_detection(detector):
    # Attacker frontruns victim on WETH/USDC pool
    pool = "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640"
    attacker = "0xAttackerMEVBot000000000000000000000001"
    victim = "0xRetailVictimTrader00000000000000000002"

    swaps = [
        # Frontrun: Buy 100 USDC with 10 WETH, high gas
        DexSwapTransaction(
            tx_hash="0xfront",
            sender_address=attacker,
            block_number=19000000,
            tx_index=1,
            pool_address=pool,
            token_in="WETH",
            token_out="USDC",
            amount_in=10.0,
            amount_out=25000.0,
            effective_gas_price_gwei=120.0,
        ),
        # Victim: Buy USDC with 50 WETH, normal gas
        DexSwapTransaction(
            tx_hash="0xvictim",
            sender_address=victim,
            block_number=19000000,
            tx_index=2,
            pool_address=pool,
            token_in="WETH",
            token_out="USDC",
            amount_in=50.0,
            amount_out=115000.0,
            effective_gas_price_gwei=40.0,
        ),
        # Backrun: Sell 25000 USDC back for 11.5 WETH (+1.5 WETH profit)
        DexSwapTransaction(
            tx_hash="0xback",
            sender_address=attacker,
            block_number=19000000,
            tx_index=3,
            pool_address=pool,
            token_in="USDC",
            token_out="WETH",
            amount_in=25000.0,
            amount_out=11.5,
            effective_gas_price_gwei=120.0,
        ),
    ]

    alerts = detector.analyze_block_swaps(swaps)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.is_sandwich_attack
    assert a.attacker_address == attacker
    assert a.victim_address == victim
    assert a.attacker_gross_profit_token_in == 1.5
    assert a.confidence_score >= 0.85


def test_independent_unrelated_swaps_not_flagged(detector):
    # Two different traders trading in same pool
    pool = "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640"
    user_a = "0xUserA00000000000000000000000000000000001"
    user_b = "0xUserB00000000000000000000000000000000002"

    swaps = [
        DexSwapTransaction("0x1", user_a, 19000000, 1, pool, "WETH", "USDC", 5.0, 12500.0, 50.0),
        DexSwapTransaction("0x2", user_b, 19000000, 2, pool, "WETH", "USDC", 2.0, 5000.0, 50.0),
    ]

    alerts = detector.analyze_block_swaps(swaps)
    assert len(alerts) == 0


def test_unprofitable_or_loss_making_sequence_ignored(detector):
    pool = "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640"
    trader = "0xTrader0000000000000000000000000000000003"
    victim = "0xVictim0000000000000000000000000000000004"

    swaps = [
        DexSwapTransaction("0xfront", trader, 19000000, 1, pool, "WETH", "USDC", 10.0, 25000.0, 50.0),
        DexSwapTransaction("0xvic", victim, 19000000, 2, pool, "WETH", "USDC", 5.0, 12000.0, 40.0),
        # Backrun received less WETH than put in (9.0 < 10.0 => gross profit -1.0)
        DexSwapTransaction("0xback", trader, 19000000, 3, pool, "USDC", "WETH", 25000.0, 9.0, 50.0),
    ]

    alerts = detector.analyze_block_swaps(swaps)
    assert len(alerts) == 0


def test_different_pools_not_grouped(detector):
    attacker = "0xAttacker00000000000000000000000000000005"
    victim = "0xVictim0000000000000000000000000000000006"

    swaps = [
        DexSwapTransaction("0x1", attacker, 19000000, 1, "0xPoolA", "WETH", "USDC", 10.0, 25000.0, 100.0),
        DexSwapTransaction("0x2", victim, 19000000, 2, "0xPoolB", "WETH", "USDC", 10.0, 25000.0, 50.0),
        DexSwapTransaction("0x3", attacker, 19000000, 3, "0xPoolA", "USDC", "WETH", 25000.0, 12.0, 100.0),
    ]

    alerts = detector.analyze_block_swaps(swaps)
    assert len(alerts) == 0
