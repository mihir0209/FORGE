import pytest
from forge.oracle_manipulation_sentinel import (
    OracleManipulationSentinel,
    OraclePriceObservation,
    OracleManipulationAlert,
)


@pytest.fixture
def sentinel():
    return OracleManipulationSentinel(deviation_threshold_pct=8.0, flash_loan_threshold_usd=50000.0)


def test_benign_stable_price_passes(sentinel):
    obs = OraclePriceObservation(
        timestamp_sec=1000.0,
        block_number=19000000,
        asset_pair="ETH/USDC",
        spot_price=3005.0,
        reference_twap_price=3000.0,
        dex_source="UniswapV3",
        reserve_in=5000.0,
        reserve_out=15000000.0,
    )
    alert = sentinel.evaluate_observation(obs)
    assert alert is None


def test_detects_flash_loan_oracle_manipulation_critical(sentinel):
    # Attacker borrows 2,000,000 USDC flash loan and dumps into pool, driving spot down by 25%
    obs = OraclePriceObservation(
        timestamp_sec=1010.0,
        block_number=19000001,
        asset_pair="ETH/USDC",
        spot_price=2250.0,
        reference_twap_price=3000.0,
        dex_source="UniswapV2",
        reserve_in=1000.0,
        reserve_out=2250000.0,
        tx_hash="0xflash_attack_tx",
        flash_loan_amount=2000000.0,
    )
    alert = sentinel.evaluate_observation(obs)
    assert alert is not None
    assert alert.is_manipulation
    assert alert.severity == "CRITICAL"
    assert alert.has_flash_loan is True
    assert alert.price_deviation_pct == 25.0
    assert alert.mitigation_action == "HALT_LENDING_ORACLE"
    assert alert.confidence_score >= 0.95


def test_detects_extreme_deviation_without_flash_loan(sentinel):
    # Thin pool manipulated by 30% without explicit flash loan
    obs = OraclePriceObservation(
        timestamp_sec=1020.0,
        block_number=19000002,
        asset_pair="XYZ/WETH",
        spot_price=1.30,
        reference_twap_price=1.00,
        dex_source="Sushiswap",
        reserve_in=500.0,
        reserve_out=650.0,
        flash_loan_amount=None,
    )
    alert = sentinel.evaluate_observation(obs)
    assert alert is not None
    assert alert.severity == "HIGH"
    assert alert.has_flash_loan is False
    assert alert.price_deviation_pct == 30.0
    assert alert.mitigation_action == "FALLBACK_TO_TWAP"


def test_batch_analysis_filters_clean_and_flags_bad(sentinel):
    batch = [
        OraclePriceObservation(1000.0, 19000000, "ETH/USDC", 3010.0, 3000.0, "UniV3", 5000, 15000000),
        OraclePriceObservation(1001.0, 19000001, "ETH/USDC", 3500.0, 3000.0, "UniV2", 2000, 7000000, flash_loan_amount=100000.0),
    ]
    alerts = sentinel.analyze_batch(batch)
    assert len(alerts) == 1
    assert alerts[0].asset_pair == "ETH/USDC"
    assert alerts[0].block_number == 19000001
