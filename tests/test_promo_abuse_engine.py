import pytest
from forge.promo_abuse_engine import PromoAbuseEngine, PromoRedemption, canonicalize_email


def test_canonicalize_email_strips_gmail_dots_and_plus():
    assert canonicalize_email("m.i.h.i.r.patil@gmail.com") == "mihirpatil@gmail.com"
    assert canonicalize_email("user+free_voucher_10@gmail.com") == "user@gmail.com"
    assert canonicalize_email("john.doe+promo@corporate.org") == "john.doe@corporate.org"


def test_promo_abuse_engine_blocks_email_aliasing_farm():
    engine = PromoAbuseEngine()

    # User 1 registers with base email
    r1 = PromoRedemption(
        redemption_id="red_1",
        user_id="user_001",
        email="shopper@gmail.com",
        phone_number="+15551234567",
        card_fingerprint="card_visa_9988",
        promo_code="WELCOME50",
        timestamp_epoch=1000.0,
    )
    v1 = engine.evaluate_redemption(r1)
    assert not v1.is_abusive
    assert v1.abuse_type == "NONE"

    # User 2 attempts to use dotted alias of same email with new user ID
    r2 = PromoRedemption(
        redemption_id="red_2",
        user_id="user_002",
        email="s.h.o.p.p.e.r+bonus@gmail.com",
        phone_number="+15559876543",
        card_fingerprint="card_mc_1122",
        promo_code="WELCOME50",
        timestamp_epoch=1010.0,
    )
    v2 = engine.evaluate_redemption(r2)
    assert v2.is_abusive
    assert v2.abuse_type == "EMAIL_ALIASING"
    assert v2.canonical_email == "shopper@gmail.com"
    assert v2.associated_user_count >= 2


def test_promo_abuse_engine_blocks_reused_payment_method():
    engine = PromoAbuseEngine()

    # User A redeems with Card X
    engine.evaluate_redemption(PromoRedemption(
        redemption_id="red_A",
        user_id="user_A",
        email="personA@yahoo.com",
        phone_number="+15551112222",
        card_fingerprint="shared_credit_card_4242",
        promo_code="FALL20",
        timestamp_epoch=2000.0,
    ))

    # User B (different email, different phone) reuses Card X for first-time sign-up discount
    vB = engine.evaluate_redemption(PromoRedemption(
        redemption_id="red_B",
        user_id="user_B",
        email="personB@proton.me",
        phone_number="+15553334444",
        card_fingerprint="shared_credit_card_4242",
        promo_code="FALL20",
        timestamp_epoch=2010.0,
    ))
    assert vB.is_abusive
    assert vB.abuse_type == "REUSED_PAYMENT_METHOD"
