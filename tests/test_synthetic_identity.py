"""Unit & Adversarial Tests for Synthetic Identity & Bust-Out Predictor."""

import pytest
from forge.synthetic_identity import (
    SyntheticIdentityProfile,
    BustOutFeatureVector,
    SyntheticIdentityEngine,
)


def test_detects_high_confidence_synthetic_identity():
    engine = SyntheticIdentityEngine()

    synth_profile = SyntheticIdentityProfile(
        ssn_age_days=45,  # newly issued
        address_link_count=5,  # multiple names linked to single drop address
        phone_recycled=True,
        credit_bureau_depth=1,
        identity_discrepancy_score=0.85,
    )

    res = engine.evaluate_synthetic_identity(synth_profile)
    assert res.is_synthetic
    assert res.risk_score >= 0.90
    assert any("SYNTHETIC" in f for f in res.flags)


def test_allows_legitimate_established_identity():
    engine = SyntheticIdentityEngine()

    legit_profile = SyntheticIdentityProfile(
        ssn_age_days=3650,  # 10 years old
        address_link_count=1,
        phone_recycled=False,
        credit_bureau_depth=8,
        identity_discrepancy_score=0.05,
    )

    res = engine.evaluate_synthetic_identity(legit_profile)
    assert not res.is_synthetic
    assert res.risk_score <= 0.20
    assert len(res.flags) == 0


def test_predicts_critical_bust_out_pattern():
    engine = SyntheticIdentityEngine()

    # Dormant account suddenly ramps up spending, maxes out credit, makes no payments
    bust_out_features = BustOutFeatureVector(
        dormancy_days=90.0,
        recent_spend_velocity=1200.0,  # $1,200/day
        historical_spend_velocity=50.0,  # $50/day (24x ramp)
        credit_limit_utilization=0.98,  # 98% maxed
        disbursement_ratio=0.85,  # 85% cash advance
        repayment_rate=0.01,  # 1% minimum payment
    )

    prediction = engine.predict_bust_out(bust_out_features)
    assert prediction.is_bust_out_risk
    assert prediction.bust_out_probability >= 0.95
    assert prediction.recommended_action == "FREEZE_LINE"
    assert any("CRITICAL_BUST_OUT_PATTERN_MATCH" in f for f in prediction.flags)


def test_preserves_healthy_active_credit_behavior():
    engine = SyntheticIdentityEngine()

    healthy_features = BustOutFeatureVector(
        dormancy_days=0.0,
        recent_spend_velocity=80.0,
        historical_spend_velocity=75.0,
        credit_limit_utilization=0.30,  # 30% utilization
        disbursement_ratio=0.0,
        repayment_rate=0.90,  # Pays balance in full
    )

    prediction = engine.predict_bust_out(healthy_features)
    assert not prediction.is_bust_out_risk
    assert prediction.bust_out_probability <= 0.20
    assert prediction.recommended_action == "ALLOW"
    assert len(prediction.flags) == 0
