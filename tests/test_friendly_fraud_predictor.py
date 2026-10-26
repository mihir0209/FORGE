import pytest
from forge.friendly_fraud_predictor import FriendlyFraudPredictor, DisputeEvidence

def test_legitimate_customer_dispute():
    predictor = FriendlyFraudPredictor()
    evidence = DisputeEvidence(
        dispute_id="disp_001",
        account_id="acc_good_1",
        transaction_amount_usd=45.0,
        account_age_days=180,
        historical_disputes=0,
        total_completed_orders=25,
        delivery_confirmed=False,
        delivery_address_matches_billing=True,
        device_ip_matches_delivery_geo=False,
        photo_signature_confirmed=False,
        dispute_reason="ITEM_NOT_RECEIVED"
    )
    result = predictor.evaluate(evidence)
    assert result.verdict == "LEGITIMATE_DISPUTE"
    assert result.recommended_action == "ACCEPT_DISPUTE"
    assert result.risk_score < 0.40

def test_high_risk_friendly_fraud_photo_inr():
    predictor = FriendlyFraudPredictor()
    evidence = DisputeEvidence(
        dispute_id="disp_002",
        account_id="acc_fraud_1",
        transaction_amount_usd=850.0,
        account_age_days=12,
        historical_disputes=4,
        total_completed_orders=5,
        delivery_confirmed=True,
        delivery_address_matches_billing=True,
        device_ip_matches_delivery_geo=True,
        photo_signature_confirmed=True,
        dispute_reason="ITEM_NOT_RECEIVED"
    )
    result = predictor.evaluate(evidence)
    assert result.verdict == "HIGH_RISK_FIRST_PARTY_FRAUD"
    assert result.recommended_action == "BLOCK_AND_REPRESENT"
    assert result.risk_score >= 0.70
    assert any("Carrier confirmed delivery" in f for f in result.contributing_factors)

def test_suspected_friendly_fraud_unauthorized_from_home():
    predictor = FriendlyFraudPredictor()
    evidence = DisputeEvidence(
        dispute_id="disp_003",
        account_id="acc_doubt_1",
        transaction_amount_usd=120.0,
        account_age_days=90,
        historical_disputes=1,
        total_completed_orders=8,
        delivery_confirmed=True,
        delivery_address_matches_billing=True,
        device_ip_matches_delivery_geo=True,
        photo_signature_confirmed=False,
        dispute_reason="UNAUTHORIZED_TRANSACTION"
    )
    result = predictor.evaluate(evidence)
    assert result.verdict == "SUSPECTED_FRIENDLY_FRAUD"
    assert result.recommended_action == "REPRESENTMENT_CHALLENGE"
    assert 0.40 <= result.risk_score < 0.70
