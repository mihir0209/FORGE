import pytest
from forge.ato_session_sentinel import ATOSessionSentinel, SessionFingerprint


def test_ato_session_clean_progression():
    sentinel = ATOSessionSentinel()
    initial = SessionFingerprint(
        session_id="sess_100",
        user_id="user_alice",
        ja3_hash="ja3_hash_chrome_v1",
        canvas_hash="canvas_hash_v1",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
        ip_address="198.51.100.10",
        asn=15169,
        latitude=37.7749,
        longitude=-122.4194,  # San Francisco
        timestamp_epoch=1700000000.0,
    )

    assessment1 = sentinel.evaluate_session_activity(initial)
    assert assessment1.action == "ALLOW"
    assert assessment1.risk_score == 0.0
    assert not assessment1.drift_detected

    # Next request 5 minutes later from same location and device
    subsequent = SessionFingerprint(
        session_id="sess_100",
        user_id="user_alice",
        ja3_hash="ja3_hash_chrome_v1",
        canvas_hash="canvas_hash_v1",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
        ip_address="198.51.100.12",  # Minor DHCP IP shift within same ASN
        asn=15169,
        latitude=37.7750,
        longitude=-122.4190,
        timestamp_epoch=1700000300.0,
    )

    assessment2 = sentinel.evaluate_session_activity(subsequent)
    assert assessment2.action == "ALLOW"
    assert assessment2.risk_score == 0.0


def test_ato_session_detects_impossible_travel_and_ja3_drift():
    sentinel = ATOSessionSentinel(max_travel_velocity_kmh=800.0)
    initial = SessionFingerprint(
        session_id="sess_200",
        user_id="user_bob",
        ja3_hash="ja3_mac_safari",
        canvas_hash="canvas_mac_retina",
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
        ip_address="203.0.113.5",
        asn=7922,
        latitude=40.7128,
        longitude=-74.0060,  # New York City
        timestamp_epoch=1700000000.0,
    )
    sentinel.evaluate_session_activity(initial)

    # 15 minutes later, same session cookie is used from Frankfurt, Germany (6200 km away!) with a curl/Python JA3
    hijacked = SessionFingerprint(
        session_id="sess_200",
        user_id="user_bob",
        ja3_hash="ja3_python_requests_hijacker",
        canvas_hash="canvas_headless_linux",
        user_agent="Mozilla/5.0 (X11; Linux x86_64) Firefox/115.0",
        ip_address="194.25.0.1",
        asn=3320,
        latitude=50.1109,
        longitude=8.6821,  # Frankfurt (~6200 km from NYC)
        timestamp_epoch=1700000900.0,  # 15 mins later -> velocity > 24,000 km/h!
    )

    assessment = sentinel.evaluate_session_activity(hijacked)
    assert assessment.action == "REVOKE_SESSION"
    assert assessment.risk_score >= 0.70
    assert assessment.drift_detected
    assert any("Impossible travel velocity" in r for r in assessment.reasons)
