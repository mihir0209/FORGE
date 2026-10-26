import pytest
from forge.keystroke_biometrics_verifier import (
    KeystrokeBiometricsVerifier, KeystrokeEvent, PointerEvent
)

def test_genuine_human_dynamics():
    verifier = KeystrokeBiometricsVerifier()
    # Natural human variance in typing speed and dwell
    keystrokes = [
        KeystrokeEvent("KeyA", 1000.0, 1085.0),
        KeystrokeEvent("KeyB", 1220.0, 1310.0),
        KeystrokeEvent("KeyC", 1450.0, 1515.0),
        KeystrokeEvent("KeyD", 1680.0, 1790.0),
    ]
    # Curved human pointer trajectory
    pointers = [
        PointerEvent(10.0, 20.0, 100.0),
        PointerEvent(15.0, 35.0, 120.0),
        PointerEvent(28.0, 52.0, 140.0),
        PointerEvent(50.0, 60.0, 160.0),
    ]
    res = verifier.analyze("sess_human", keystrokes, pointers)
    assert res.verdict == "GENUINE_HUMAN"
    assert not res.is_synthetic_automation
    assert res.recommended_action == "ALLOW"

def test_synthetic_bot_automation_detection():
    verifier = KeystrokeBiometricsVerifier()
    # Programmatic typing: identical 5ms dwell times, exact 50ms intervals
    keystrokes = [
        KeystrokeEvent("KeyA", 1000.0, 1005.0),
        KeystrokeEvent("KeyB", 1050.0, 1055.0),
        KeystrokeEvent("KeyC", 1100.0, 1105.0),
        KeystrokeEvent("KeyD", 1150.0, 1155.0),
    ]
    # Perfectly straight horizontal vector (delta_y = 0)
    pointers = [
        PointerEvent(10.0, 50.0, 100.0),
        PointerEvent(20.0, 50.0, 120.0),
        PointerEvent(30.0, 50.0, 140.0),
        PointerEvent(40.0, 50.0, 160.0),
    ]
    res = verifier.analyze("sess_bot", keystrokes, pointers)
    assert res.verdict == "SUSPECTED_BOT"
    assert res.is_synthetic_automation
    assert res.recommended_action == "BLOCK_SESSION"
    assert res.bot_probability >= 0.65
