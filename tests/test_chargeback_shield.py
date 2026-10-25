"""Tests for Decentralized Chargeback Predictor & Merchant Friendly-Fraud Shield."""

import pytest
from forge.chargeback_shield import (
    TransactionContext,
    ChargebackShieldEngine,
    FriendlyFraudRisk,
    DisputeRebuttalPacket,
)


def test_low_risk_established_customer_chargeback_profile():
    engine = ChargebackShieldEngine()
    ctx = TransactionContext(
        transaction_id="TX-LOW-01",
        account_id="ACC-TRUSTED-1",
        amount=45.0,
        mcc="5411",  # Grocery
        card_present=True,
        billing_country="US",
        shipping_country="US",
        account_age_days=450,
        prior_dispute_count=0,
        prior_successful_tx_count=28,
        delivery_signed=True,
        delivery_carrier_hash="fedex_sig_valid_hash_abc",
    )

    res = engine.evaluate(ctx)
    assert res.chargeback_probability < 0.20
    assert res.risk_level == FriendlyFraudRisk.LOW
    assert res.dispute_shield_action == "APPROVE"
    assert res.rebuttal_packet is not None
    assert res.rebuttal_packet.ce30_qualifying is True
    assert "Compelling Evidence 3.0" in res.rebuttal_packet.rebuttal_strategy


def test_high_risk_friendly_fraud_cross_border_new_account():
    engine = ChargebackShieldEngine()
    ctx = TransactionContext(
        transaction_id="TX-HIGH-01",
        account_id="ACC-NEW-SUSPECT",
        amount=1450.0,
        mcc="7995",  # Gambling / high risk
        card_present=False,
        billing_country="US",
        shipping_country="NG",  # Cross-border mismatch
        account_age_days=1,     # Brand new account
        prior_dispute_count=3,  # Serial disputer
        prior_successful_tx_count=1,
        delivery_signed=False,
    )

    res = engine.evaluate(ctx)
    assert res.chargeback_probability > 0.70
    assert res.risk_level in {
        FriendlyFraudRisk.HIGH_RISK_CHARGEBACK,
        FriendlyFraudRisk.CRITICAL_FIRST_PARTY_FRAUD,
    }
    assert res.dispute_shield_action in {"FLAG_PRE_DISPUTE", "FORCE_3DS"}
    assert any("Cross-border" in f for f in res.risk_factors)
    assert any("High-dispute merchant category" in f for f in res.risk_factors)


def test_carrier_delivery_signature_mitigates_chargeback_risk():
    engine = ChargebackShieldEngine()
    ctx_without_sig = TransactionContext(
        transaction_id="TX-NO-SIG",
        account_id="ACC-02",
        amount=300.0,
        mcc="5734",
        card_present=False,
        billing_country="CA",
        shipping_country="CA",
        account_age_days=30,
        prior_dispute_count=0,
        prior_successful_tx_count=2,
        delivery_signed=False,
    )
    prob_no_sig, _ = engine.calculate_chargeback_probability(ctx_without_sig)

    ctx_with_sig = TransactionContext(
        transaction_id="TX-WITH-SIG",
        account_id="ACC-02",
        amount=300.0,
        mcc="5734",
        card_present=False,
        billing_country="CA",
        shipping_country="CA",
        account_age_days=30,
        prior_dispute_count=0,
        prior_successful_tx_count=2,
        delivery_signed=True,
        delivery_carrier_hash="ups_sig_verified_xyz",
    )
    prob_with_sig, factors = engine.calculate_chargeback_probability(ctx_with_sig)

    assert prob_with_sig < prob_no_sig
    assert any("Mitigation: Carrier-verified" in f for f in factors)
