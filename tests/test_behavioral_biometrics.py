"""Unit and regression tests for Behavioral Biometrics & Keystroke Dynamics."""

import pytest
from forge.behavioral_biometrics import (
    KeyEvent,
    KeystrokeDynamicsClassifier,
)


def test_robotic_script_detected_with_constant_timing():
    classifier = KeystrokeDynamicsClassifier()

    # Synthetic script: exactly 50ms dwell and 100ms flight every time
    events = [
        KeyEvent(key="a", down_ms=1000.0, up_ms=1050.0),
        KeyEvent(key="b", down_ms=1150.0, up_ms=1200.0),
        KeyEvent(key="c", down_ms=1300.0, up_ms=1350.0),
        KeyEvent(key="d", down_ms=1450.0, up_ms=1500.0),
        KeyEvent(key="e", down_ms=1600.0, up_ms=1650.0),
    ]

    res = classifier.evaluate(events)
    assert res.is_bot is True
    assert res.classification == "SCRIPTED_AUTOMATION_BOT"
    assert res.bot_probability >= 0.9
    assert res.dwell_variance == 0.0
    assert any("dwell consistency" in a for a in res.anomaly_details)


def test_organic_human_typing_verified():
    classifier = KeystrokeDynamicsClassifier()

    # Authentic human cadence with natural variance (80ms - 130ms dwell, 120ms - 250ms flight)
    events = [
        KeyEvent(key="t", down_ms=100.0, up_ms=195.0),  # 95ms
        KeyEvent(key="e", down_ms=310.0, up_ms=420.0),  # 110ms, flight 115ms
        KeyEvent(key="s", down_ms=560.0, up_ms=640.0),  # 80ms, flight 140ms
        KeyEvent(key="t", down_ms=880.0, up_ms=1010.0), # 130ms, flight 240ms
        KeyEvent(key="i", down_ms=1150.0, up_ms=1245.0), # 95ms, flight 140ms
        KeyEvent(key="n", down_ms=1380.0, up_ms=1485.0), # 105ms, flight 135ms
        KeyEvent(key="g", down_ms=1610.0, up_ms=1725.0), # 115ms, flight 125ms
    ]

    res = classifier.evaluate(events)
    assert res.is_bot is False
    assert res.classification == "AUTHENTIC_HUMAN"
    assert res.bot_probability < 0.3
    assert res.dwell_variance > 100.0
    assert res.dwell_cv > 0.1


def test_superhuman_speed_detected():
    classifier = KeystrokeDynamicsClassifier()

    # Superhuman typing script: 2ms dwell time
    events = [
        KeyEvent(key="h", down_ms=10.0, up_ms=12.0),
        KeyEvent(key="a", down_ms=15.0, up_ms=17.0),
        KeyEvent(key="c", down_ms=20.0, up_ms=22.0),
        KeyEvent(key="k", down_ms=25.0, up_ms=27.0),
    ]

    res = classifier.evaluate(events)
    assert res.is_bot is True
    assert res.bot_probability == 1.0
    assert any("Superhuman" in a for a in res.anomaly_details)


def test_insufficient_samples_boundary():
    classifier = KeystrokeDynamicsClassifier()
    events = [KeyEvent(key="x", down_ms=100.0, up_ms=180.0)]
    res = classifier.evaluate(events)
    assert res.is_bot is False
    assert res.classification == "INSUFFICIENT_DATA"
