import pytest
from forge.synthetic_identity_detector import (
    SyntheticIdentityDetector,
    SyntheticIdentityResult,
)


def test_synthetic_identity_allows_normal_applicant():
    detector = SyntheticIdentityDetector()
    res = detector.assess_applicant(
        application_id="app_001",
        name="James Wilson",
        ssn_fragment="9876",
        phone="555-0100",
        address="100 Main St, Austin, TX",
        credit_line_age_months=48,
        authorized_user_count=0,
    )

    assert not res.is_synthetic
    assert res.risk_score < 0.3
    assert res.cluster_size == 1


def test_synthetic_identity_detects_ssn_name_collision():
    detector = SyntheticIdentityDetector()

    # First applicant with SSN 1234
    detector.assess_applicant(
        application_id="app_real_1",
        name="Robert Green",
        ssn_fragment="1234",
        phone="555-0101",
        address="200 Elm St, Chicago, IL",
        credit_line_age_months=24,
        authorized_user_count=0,
    )

    # Second applicant with same SSN 1234 but completely different name
    res2 = detector.assess_applicant(
        application_id="app_synth_2",
        name="Marcus Vance",
        ssn_fragment="1234",
        phone="555-0102",
        address="300 Oak St, Dallas, TX",
        credit_line_age_months=12,
        authorized_user_count=0,
    )

    assert res2.risk_score >= 0.45
    assert any("associated with 2 distinct applicant names" in r for r in res2.reasons)


def test_synthetic_identity_flags_tradeline_piggybacking():
    detector = SyntheticIdentityDetector()
    # Applicant has very young file (2 months) but 3 authorized user tradelines
    res = detector.assess_applicant(
        application_id="app_piggy_1",
        name="Arthur Pendelton",
        ssn_fragment="5544",
        phone="555-0200",
        address="404 Ghost Way, Miami, FL",
        credit_line_age_months=2,
        authorized_user_count=3,
    )

    assert res.risk_score >= 0.35
    assert any("tradeline piggybacking" in r for r in res.reasons)


def test_synthetic_identity_dense_pii_cluster():
    detector = SyntheticIdentityDetector()
    shared_phone = "555-9999"

    for i in range(4):
        detector.assess_applicant(
            application_id=f"app_ring_{i}",
            name=f"Applicant {i}",
            ssn_fragment=f"100{i}",
            phone=shared_phone,
            address=f"{i} Pine St, Seattle, WA",
            credit_line_age_months=1,
            authorized_user_count=2,
        )

    # 4th applicant should be flagged as synthetic with dense entity cluster
    res = detector.assess_applicant(
        application_id="app_ring_final",
        name="Final Mule",
        ssn_fragment="9999",
        phone=shared_phone,
        address="555 Drop St, Seattle, WA",
        credit_line_age_months=2,
        authorized_user_count=2,
    )

    assert res.is_synthetic
    assert res.cluster_size >= 4
    assert res.risk_score >= 0.65
