"""Unit and regression tests for Merchant Collusion & Cartel Churn Sentinel."""

import pytest
from forge.merchant_collusion import (
    MerchantCollusionSentinel,
    MerchantTransaction,
)


def test_diversified_healthy_merchant_approved():
    sentinel = MerchantCollusionSentinel()

    # Healthy merchant with diversified buyer pool
    txs = [
        MerchantTransaction(tx_id="tx-1", merchant_id="m-good", buyer_id="b-1", amount=100.0),
        MerchantTransaction(tx_id="tx-2", merchant_id="m-good", buyer_id="b-2", amount=120.0),
        MerchantTransaction(tx_id="tx-3", merchant_id="m-good", buyer_id="b-3", amount=90.0),
        MerchantTransaction(tx_id="tx-4", merchant_id="m-good", buyer_id="b-4", amount=110.0),
        MerchantTransaction(tx_id="tx-5", merchant_id="m-good", buyer_id="b-5", amount=80.0),
    ]

    report = sentinel.audit_merchant("m-good", txs)
    assert report.is_collusive is False
    assert report.recommendation == "APPROVE"
    assert report.hhi_concentration < 0.3
    assert report.risk_score < 0.2


def test_single_buyer_cartel_detected():
    sentinel = MerchantCollusionSentinel()

    # Suspicious merchant where one buyer represents 95% of $10,000 volume
    txs = [
        MerchantTransaction(tx_id="tx-1", merchant_id="m-shady", buyer_id="b-confederate", amount=4500.0),
        MerchantTransaction(tx_id="tx-2", merchant_id="m-shady", buyer_id="b-confederate", amount=5000.0),
        MerchantTransaction(tx_id="tx-3", merchant_id="m-shady", buyer_id="b-random", amount=100.0),
    ]

    report = sentinel.audit_merchant("m-shady", txs)
    assert report.is_collusive is True
    assert report.hhi_concentration > 0.8
    assert report.recommendation in ("HOLD_SETTLEMENT", "FREEZE_MERCHANT")
    assert any("cartel concentration" in r for r in report.flagged_reasons)


def test_refund_churn_and_cashback_arbitrage():
    sentinel = MerchantCollusionSentinel()

    # Merchant churning purchases and refunds to harvest promotional cashbacks
    txs = [
        MerchantTransaction(tx_id="tx-1", merchant_id="m-churn", buyer_id="b-1", amount=1000.0, cashback_claimed=80.0),
        MerchantTransaction(tx_id="tx-2", merchant_id="m-churn", buyer_id="b-1", amount=800.0, is_refund=True),
        MerchantTransaction(tx_id="tx-3", merchant_id="m-churn", buyer_id="b-2", amount=1000.0, cashback_claimed=80.0),
        MerchantTransaction(tx_id="tx-4", merchant_id="m-churn", buyer_id="b-2", amount=800.0, is_refund=True),
    ]

    report = sentinel.audit_merchant("m-churn", txs)
    assert report.refund_rate >= 0.40
    assert report.cashback_churn_ratio > 0.05
    assert report.risk_score >= 0.50
    assert report.recommendation in ("HOLD_SETTLEMENT", "FREEZE_MERCHANT")


def test_empty_transaction_history_safe():
    sentinel = MerchantCollusionSentinel()
    report = sentinel.audit_merchant("m-empty", [])
    assert report.is_collusive is False
    assert report.total_transactions == 0
    assert report.recommendation == "APPROVE"
