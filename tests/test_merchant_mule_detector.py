import pytest
from forge.merchant_mule_detector import MerchantMuleDetector


def test_merchant_mule_detector_clean_linear_flow():
    detector = MerchantMuleDetector()
    detector.record_transfer("customer_1", "merchant_walmart", 150.0, 1000.0)
    detector.record_transfer("customer_2", "merchant_target", 200.0, 1001.0)
    detector.record_transfer("merchant_walmart", "supplier_acme", 5000.0, 1002.0)

    alert = detector.analyze_network()
    assert not alert.network_flagged
    assert len(alert.cycles_detected) == 0
    assert alert.alert_severity == "NONE"


def test_merchant_mule_detector_identifies_triangular_cycle():
    detector = MerchantMuleDetector(cycle_max_length=4)
    # Circular money flow: Shell Merchant A -> Shell Merchant B -> Mule C -> Shell Merchant A
    detector.record_transfer("merchant_shell_A", "merchant_shell_B", 4500.0, 100.0)
    detector.record_transfer("merchant_shell_B", "mule_crypto_C", 4400.0, 110.0)
    detector.record_transfer("mule_crypto_C", "merchant_shell_A", 4300.0, 120.0)

    alert = detector.analyze_network()
    assert alert.network_flagged
    assert len(alert.cycles_detected) >= 1
    assert "merchant_shell_A" in alert.high_risk_entities
    assert "merchant_shell_B" in alert.high_risk_entities
    assert "mule_crypto_C" in alert.high_risk_entities
    assert alert.alert_severity in ("HIGH", "CRITICAL")
