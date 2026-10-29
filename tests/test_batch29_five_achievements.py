import pytest
from forge.evm_storage_collision_analyzer import EvmStorageCollisionAnalyzer
from forge.temporal_edge_decay_fraud_classifier import TemporalEdgeDecayFraudClassifier
from forge.flashloan_twap_sandwich_guard import FlashLoanTwapSandwichGuard
from forge.wasm_fuel_metering_sentinel import WasmFuelMeteringSentinel
from forge.tls_session_ticket_sentinel import TlsSessionTicketSentinel

def test_achievement_1_storage_collision():
    analyzer = EvmStorageCollisionAnalyzer()
    # Bad proxy: defines _admin at slot 0 and _impl at slot 1
    # Implementation defines owner at slot 0 -> COLLISION
    proxy_bad = {"_admin": 0, "_impl": 1}
    impl = {"owner": 0, "token_balance": 1}
    alert = analyzer.check_proxy_implementation_layout(proxy_bad, impl)
    assert alert.has_collision is True
    assert 0 in alert.colliding_slots
    assert alert.risk_level == "CRITICAL_STORAGE_OVERWRITE_COLLISION"

    # EIP-1967 clean proxy uses high hashed slots
    proxy_clean = {"_admin": 99999999, "_impl": 88888888}
    assert analyzer.check_proxy_implementation_layout(proxy_clean, impl).has_collision is False

def test_achievement_2_temporal_edge_decay():
    classifier = TemporalEdgeDecayFraudClassifier(half_life_hours=24.0)
    # Initial weight 1.0, after 24h should decay to exactly 0.50
    score_24h = classifier.evaluate_transaction_edge(1.0, 24.0)
    assert score_24h.decayed_weight == 0.50
    assert score_24h.is_active_fraud_risk is True

    # After 72h (3 half-lives), weight decays to ~0.125 < 0.50 -> risk subsided
    score_72h = classifier.evaluate_transaction_edge(1.0, 72.0)
    assert score_72h.decayed_weight < 0.20
    assert score_72h.is_active_fraud_risk is False

def test_achievement_3_flashloan_twap_sandwich():
    guard = FlashLoanTwapSandwichGuard()
    # Normal trading: spot $100.50, TWAP $100.00 -> 50 bps deviation <= 150 bps allowed
    calm = guard.inspect_oracle_deviation(100.50, 100.00, 150)
    assert calm.manipulation_detected is False
    assert calm.spot_to_twap_deviation_bps == 50
    assert calm.action == "ALLOW_EXECUTION"

    # Flash loan pump: spot $110.00, TWAP $100.00 -> 1000 bps deviation (10%)
    pumped = guard.inspect_oracle_deviation(110.00, 100.00, 150)
    assert pumped.manipulation_detected is True
    assert pumped.spot_to_twap_deviation_bps == 1000
    assert "REVERT" in pumped.action

def test_achievement_4_wasm_fuel_metering():
    meter = WasmFuelMeteringSentinel(initial_fuel=100)
    res1 = meter.consume_instruction_fuel(40)
    assert res1.remaining_fuel == 60
    assert res1.trapped is False

    # Out of gas trap
    res2 = meter.consume_instruction_fuel(70)
    assert res2.fuel_exhausted is True
    assert res2.trapped is True
    assert res2.remaining_fuel == 0

def test_achievement_5_tls_session_ticket():
    sentinel = TlsSessionTicketSentinel()
    # Stale key (48 hours old > 24 hours allowed)
    stale = sentinel.audit_session_ticket_rotation(48.0, 24.0, forward_secrecy_enabled=True)
    assert stale.is_compromised_risk is True
    assert stale.rotation_overdue is True
    assert "ROTATE" in stale.recommendation

    # Fresh key (4 hours old) with PFS
    fresh = sentinel.audit_session_ticket_rotation(4.0, 24.0, forward_secrecy_enabled=True)
    assert fresh.is_compromised_risk is False
