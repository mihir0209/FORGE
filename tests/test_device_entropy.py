"""Unit and Regression Tests for Device Fingerprint Entropy & Anti-Detect Browser Sentinel."""

import pytest
from forge.device_entropy import (
    DeviceEntropyClassifier,
    DeviceProfile,
)


def test_device_entropy_identifies_clean_authentic_profile():
    profile = DeviceProfile(
        device_id="dev_real_user",
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        platform="MacIntel",
        hardware_concurrency=8,
        device_memory_gb=16.0,
        webgl_vendor="Apple Inc.",
        webgl_renderer="Apple M2 Pro",
        canvas_hash="9f8e7d6c5b4a3210",
        audio_jitter_ms=0.0384,
    )

    classifier = DeviceEntropyClassifier()
    report = classifier.evaluate_profile(profile)

    assert report.spoofing_detected is False
    assert report.entropy_score >= 0.8
    assert report.risk_level == "LOW"
    assert len(report.anomalies) == 0


def test_device_entropy_detects_anti_detect_os_mismatch():
    # Anti-detect browser spoofing Windows User-Agent while running inside Linux container
    profile = DeviceProfile(
        device_id="dev_stealth_bot",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        platform="Linux x86_64",  # Mismatch!
        hardware_concurrency=8,
        device_memory_gb=8.0,
        webgl_vendor="Google Inc. (NVIDIA)",
        webgl_renderer="ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0)",
        canvas_hash="0000000000000000",  # Fake canvas hash!
        audio_jitter_ms=0.0,  # Zero jitter mock!
    )

    classifier = DeviceEntropyClassifier()
    report = classifier.evaluate_profile(profile)

    assert report.spoofing_detected is True
    assert report.risk_level in {"HIGH", "CRITICAL"}
    assert any("OS mismatch" in a for a in report.anomalies)
    assert any("canvas" in a for a in report.anomalies)
    assert any("audio" in a for a in report.anomalies)


def test_device_entropy_flags_impossible_hardware_cores():
    profile = DeviceProfile(
        device_id="dev_fake_cores",
        user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
        platform="iPhone",
        hardware_concurrency=128,  # Impossible on iPhone
        device_memory_gb=4.0,
        webgl_vendor="Apple Inc.",
        webgl_renderer="Apple GPU",
        canvas_hash="a1b2c3d4e5f67890",
        audio_jitter_ms=0.042,
    )

    classifier = DeviceEntropyClassifier()
    report = classifier.evaluate_profile(profile)

    assert any("hardware concurrency" in a for a in report.anomalies)
