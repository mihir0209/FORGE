"""Unit and Regression Tests for Multi-Hop Structured Smurfing & AML Sentinel."""

import pytest
from forge.smurfing_detector import (
    SmurfingDetector,
    TransactionRecord,
)


def test_smurfing_detector_identifies_structured_fan_in():
    # 4 transactions of $9,500 each sent to MuleAccount1 within 6 hours (Total $38,000 > $10,000 threshold)
    base_time = 1700000000.0
    transactions = [
        TransactionRecord("tx_1", "SenderA", "MuleAccount1", 9500.0, base_time),
        TransactionRecord("tx_2", "SenderB", "MuleAccount1", 9400.0, base_time + 3600),
        TransactionRecord("tx_3", "SenderC", "MuleAccount1", 9600.0, base_time + 7200),
        TransactionRecord("tx_4", "SenderD", "MuleAccount1", 9550.0, base_time + 10800),
    ]

    detector = SmurfingDetector(reporting_threshold=10000.0, smurfing_band_lower=8000.0)
    alerts = detector.analyze_transactions(transactions)

    assert len(alerts) >= 1
    alert = next(a for a in alerts if a.account_id == "MuleAccount1")
    assert alert.is_smurfing is True
    assert alert.direction == "FAN_IN"
    assert alert.total_volume == 38050.0
    assert alert.transaction_count == 4
    assert alert.smurfing_score >= 0.70


def test_smurfing_detector_ignores_normal_diverse_spending():
    # Normal consumer transactions with high variance and lower values
    base_time = 1700000000.0
    transactions = [
        TransactionRecord("tx_1", "Alice", "MerchantA", 45.0, base_time),
        TransactionRecord("tx_2", "Alice", "MerchantB", 120.0, base_time + 1000),
        TransactionRecord("tx_3", "Alice", "MerchantC", 2500.0, base_time + 2000),
    ]

    detector = SmurfingDetector()
    alerts = detector.analyze_transactions(transactions)
    assert len(alerts) == 0


def test_smurfing_detector_catches_fan_out_dispersion():
    # Central account dispersing structured $9,200 chunks to 3 different cash-out mules
    base_time = 1700000000.0
    transactions = [
        TransactionRecord("tx_10", "MasterAccount", "Mule1", 9200.0, base_time),
        TransactionRecord("tx_11", "MasterAccount", "Mule2", 9100.0, base_time + 1800),
        TransactionRecord("tx_12", "MasterAccount", "Mule3", 9300.0, base_time + 3600),
    ]

    detector = SmurfingDetector()
    alerts = detector.analyze_transactions(transactions)
    alert = next(a for a in alerts if a.account_id == "MasterAccount")
    assert alert.is_smurfing is True
    assert alert.direction == "FAN_OUT"
    assert alert.total_volume == 27600.0
