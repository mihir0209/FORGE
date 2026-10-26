import pytest
from forge.app_scam_shield import APPScamShield, APPScamDecision


def test_app_scam_allows_routine_transfer_to_existing_payee():
    shield = APPScamShield()
    decision = shield.evaluate_transfer(
        account_id="acc_user_1",
        beneficiary_id="beneficiary_landlord",
        is_new_beneficiary=False,
        minutes_since_added=14400.0,  # Added 10 days ago
        amount=1200.0,
        user_average_transfer=1100.0,
        session_duration_seconds=180.0,
        high_urgency_flag=False,
    )

    assert decision.action == "ALLOW"
    assert decision.risk_score < 0.3
    assert len(decision.friction_triggers) == 0


def test_app_scam_holds_urgent_transfer_to_fresh_payee():
    shield = APPScamShield()
    # Scenario: Victim on call with scammer impersonating bank fraud team.
    # Added beneficiary 3 minutes ago, transferring $5,000 (avg is $200), hasty 20s session
    decision = shield.evaluate_transfer(
        account_id="acc_victim_1",
        beneficiary_id="safe_account_scammer",
        is_new_beneficiary=True,
        minutes_since_added=3.0,
        amount=5000.0,
        user_average_transfer=200.0,
        session_duration_seconds=20.0,
        high_urgency_flag=True,
    )

    assert decision.action == "HOLD_FOR_COOLING_OFF"
    assert decision.risk_score >= 0.70
    assert any("cooling off threshold" in t for t in decision.friction_triggers)
    assert any("rushed session" in t for t in decision.friction_triggers)


def test_app_scam_step_up_challenge_for_elevated_volume():
    shield = APPScamShield()
    # Scenario: New beneficiary added 45 minutes ago, but 4x normal volume
    decision = shield.evaluate_transfer(
        account_id="acc_user_2",
        beneficiary_id="contractor_1",
        is_new_beneficiary=True,
        minutes_since_added=45.0,
        amount=1500.0,
        user_average_transfer=300.0,
        session_duration_seconds=120.0,
        high_urgency_flag=False,
    )

    assert decision.action == "STEP_UP_CHALLENGE"
    assert decision.risk_score >= 0.50


def test_app_scam_rejects_non_positive_amount():
    shield = APPScamShield()
    with pytest.raises(ValueError, match="strictly positive"):
        shield.evaluate_transfer(
            account_id="acc_err",
            beneficiary_id="payee",
            is_new_beneficiary=False,
            minutes_since_added=100.0,
            amount=-50.0,
            user_average_transfer=100.0,
            session_duration_seconds=60.0,
        )
