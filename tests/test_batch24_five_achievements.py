import pytest
from forge.dex_sandbagging_sentinel import DexSandbaggingSentinel
from forge.sim_swap_risk_engine import SimSwapRiskEngine
from forge.mev_bundle_arbitrage_tracer import MevBundleArbitrageTracer
from forge.synthetic_id_inquiry_sentinel import SyntheticIdInquirySentinel
from forge.bridge_collateral_drain_watchdog import BridgeCollateralDrainWatchdog

def test_achievement_1_dex_sandbagging():
    sentinel = DexSandbaggingSentinel(imbalance_threshold=3.0)
    # Huge single-sided injection into 1,000 token reserve
    alert = sentinel.evaluate_pool_injection(
        pool_address="0xPoolBeta",
        reserve_token_a=1000.0,
        reserve_token_b=10000.0,
        injected_token_a=5000.0, # 5x reserve A
        injected_token_b=0.0
    )
    assert alert.is_sandbagging is True
    assert alert.manipulation_vector == "ONE_SIDED_TWAP_SKEW_INJECTION"

def test_achievement_2_sim_swap_risk():
    engine = SimSwapRiskEngine()
    # SIM change 6h ago + password reset + high wire -> High risk
    assessment = engine.evaluate_phone_change(6.0, True, True)
    assert assessment.is_high_risk is True
    assert assessment.risk_score >= 0.8
    assert assessment.recommendation == "STEP_UP_OUT_OF_BAND_AUTH"

def test_achievement_3_mev_bundle_tracer():
    tracer = MevBundleArbitrageTracer()
    bundle = tracer.evaluate_block_transaction_group(
        tx_hashes=["0xtx1", "0xtx2"],
        gas_price_spread_gwei=65.0,
        is_routed_via_flashbots_or_builder=True
    )
    assert bundle.is_private_builder_bundle is True
    assert bundle.classification == "MEV_BOOST_ATOMIC_BUNDLE"

def test_achievement_4_synthetic_id_inquiry():
    sentinel = SyntheticIdInquirySentinel()
    recent = [
        {"id": "app1", "phone": "p1", "addr": "a1"},
        {"id": "app2", "phone": "p1", "addr": "a2"},
        {"id": "app3", "phone": "p2", "addr": "a1"},
    ]
    res = sentinel.check_application_attribute_sharing("app4", "p1", "a1", recent)
    assert res.is_synthetic_ring is True
    assert res.cluster_size == 4

def test_achievement_5_bridge_collateral_watchdog():
    watchdog = BridgeCollateralDrainWatchdog()
    # Undercollateralized: $8M locked vs $10M minted -> 80% backing
    insolvent = watchdog.verify_bridge_backing(8_000_000.0, 10_000_000.0)
    assert insolvent.is_solvent is False
    assert insolvent.deficit_usd == 2_000_000.0
    assert insolvent.action == "HALT_SYNTHETIC_MINTING"

    # Solvent bridge
    solvent = watchdog.verify_bridge_backing(10_000_000.0, 10_000_000.0)
    assert solvent.is_solvent is True
