"""Comprehensive Unit & Adversarial Tests for Device Fingerprinting & Botnet Defense."""

import pytest
import time
from forge.device_fingerprint import (
    DeviceFingerprint,
    DeviceFingerprintEngine,
)


@pytest.fixture
def clean_fingerprint() -> DeviceFingerprint:
    return DeviceFingerprint(
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        accept_language="en-US,en;q=0.9",
        screen_resolution="2560x1440",
        timezone_offset=-300,
        canvas_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        webgl_vendor="Apple Inc.",
        webgl_renderer="Apple M2 Max",
        ip_address="73.189.45.12",
        asn=7922,
        is_headless=False,
    )


def test_deterministic_device_hashing(clean_fingerprint: DeviceFingerprint):
    engine = DeviceFingerprintEngine()
    hash1 = engine.compute_device_hash(clean_fingerprint)
    hash2 = engine.compute_device_hash(clean_fingerprint)
    assert hash1 == hash2
    assert len(hash1) == 64

    # Minor change in resolution alters hash
    altered_fp = DeviceFingerprint(
        user_agent=clean_fingerprint.user_agent,
        accept_language=clean_fingerprint.accept_language,
        screen_resolution="1920x1080",
        timezone_offset=clean_fingerprint.timezone_offset,
        canvas_hash=clean_fingerprint.canvas_hash,
        webgl_vendor=clean_fingerprint.webgl_vendor,
        webgl_renderer=clean_fingerprint.webgl_renderer,
        ip_address=clean_fingerprint.ip_address,
    )
    assert engine.compute_device_hash(altered_fp) != hash1


def test_headless_botnet_detection(clean_fingerprint: DeviceFingerprint):
    engine = DeviceFingerprintEngine()

    # Clean browser
    clean_res = engine.detect_headless_browser(clean_fingerprint)
    assert not clean_res.is_bot
    assert clean_res.risk_score == 0.0
    assert len(clean_res.flags) == 0

    # Headless Chrome with SwiftShader
    bot_fp = DeviceFingerprint(
        user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/118.0.5993.88 Safari/537.36",
        accept_language="en-US",
        screen_resolution="800x600",
        timezone_offset=0,
        canvas_hash="c1a4b44298fc1c149afbf4c8996fb924",
        webgl_vendor="Google Inc. (Google)",
        webgl_renderer="Google SwiftShader",
        ip_address="198.51.100.25",
        is_headless=True,
    )

    bot_res = engine.detect_headless_browser(bot_fp)
    assert bot_res.is_bot
    assert bot_res.risk_score >= 0.85
    assert any("HEADLESS" in f for f in bot_res.flags)
    assert any("SWIFTSHADER" in f for f in bot_res.flags)
    assert "ANOMALOUS_HEADLESS_RESOLUTION" in bot_res.flags


def test_session_drift_and_hijack_detection(clean_fingerprint: DeviceFingerprint):
    engine = DeviceFingerprintEngine()

    # 1. Identical device and IP -> Normal session
    res_normal = engine.assess_session_drift(clean_fingerprint, clean_fingerprint)
    assert not res_normal.is_hijacked
    assert res_normal.risk_score == 0.0

    # 2. Same hardware, roaming IP (e.g. mobile to Wi-Fi) -> Benign drift
    roaming_fp = DeviceFingerprint(
        user_agent=clean_fingerprint.user_agent,
        accept_language=clean_fingerprint.accept_language,
        screen_resolution=clean_fingerprint.screen_resolution,
        timezone_offset=clean_fingerprint.timezone_offset,
        canvas_hash=clean_fingerprint.canvas_hash,
        webgl_vendor=clean_fingerprint.webgl_vendor,
        webgl_renderer=clean_fingerprint.webgl_renderer,
        ip_address="172.56.21.89",  # different IP
        asn=21928,  # T-Mobile
    )
    res_roaming = engine.assess_session_drift(clean_fingerprint, roaming_fp)
    assert not res_roaming.is_hijacked
    assert res_roaming.is_benign_ip_shift
    assert res_roaming.risk_score <= 0.20

    # 3. Disparate hardware, different IP -> Critical Session Hijack
    hijacked_fp = DeviceFingerprint(
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/121.0",
        accept_language="ru-RU,ru;q=0.9",
        screen_resolution="1366x768",
        timezone_offset=180,
        canvas_hash="99999999999999999999999999999999",
        webgl_vendor="Mesa/X.org",
        webgl_renderer="llvmpipe",
        ip_address="185.220.101.5",
        asn=9009,
    )
    res_hijack = engine.assess_session_drift(clean_fingerprint, hijacked_fp)
    assert res_hijack.is_hijacked
    assert res_hijack.risk_score >= 0.90
    assert any("CRITICAL_SESSION_HIJACK" in r for r in res_hijack.reasons)


def test_device_velocity_clustering_and_takeover():
    engine = DeviceFingerprintEngine()
    now = time.time()
    bot_device = "device_botnet_alpha_99"

    # 1 device attacking multiple accounts within 10 minutes
    engine.track_device_velocity(bot_device, "user_101", timestamp=now)
    engine.track_device_velocity(bot_device, "user_102", timestamp=now + 30)
    res3 = engine.track_device_velocity(bot_device, "user_103", timestamp=now + 60)

    assert res3.is_suspicious
    assert res3.associated_accounts_count == 3
    assert res3.risk_score >= 0.90
    assert any("DEVICE_CLUSTERING" in f for f in res3.flags)

    # 1 account accessed rapidly by multiple distinct devices (Distributed ATO)
    victim_account = "user_victim_88"
    engine.track_device_velocity("device_node_1", victim_account, timestamp=now)
    engine.track_device_velocity("device_node_2", victim_account, timestamp=now + 20)
    res_ato = engine.track_device_velocity("device_node_3", victim_account, timestamp=now + 40)

    assert res_ato.is_suspicious
    assert res_ato.rapid_device_switches_count == 3
    assert res_ato.risk_score >= 0.85
    assert any("DISTRIBUTED_TAKEOVER" in f for f in res_ato.flags)
