"""Unit and Regression Tests for Adaptive Velocity Risk Governor."""

import math
import pytest
from forge.adaptive_velocity_governor import (
    AdaptiveVelocityGovernor,
)


def test_velocity_governor_computes_exact_half_life_decay():
    # 3600 seconds half life
    gov = AdaptiveVelocityGovernor(half_life_seconds=3600.0)
    t0 = 10000.0
    gov.record_transaction("acc_1", 1000.0, t0)

    # Exactly 1 half-life later (t0 + 3600s), volume should be 500.0 (50% decay)
    m = gov.get_velocity("acc_1", t0 + 3600.0)
    assert math.isclose(m.current_volume_velocity, 500.0, abs_tol=1.0)
    assert math.isclose(m.current_count_velocity, 0.5, abs_tol=0.05)


def test_velocity_governor_detects_burst_attacks():
    gov = AdaptiveVelocityGovernor(
        half_life_seconds=3600.0,
        burst_volume_threshold=5000.0,
        burst_count_threshold=5.0,
    )
    t0 = 20000.0
    # Rapid burst of 6 transactions within 10 seconds
    for i in range(6):
        gov.record_transaction("acc_burst", 900.0, t0 + i * 2)

    m = gov.get_velocity("acc_burst", t0 + 15)
    assert m.is_bursting is True
    assert m.current_volume_velocity > 5000.0
    assert m.risk_score == 1.0


def test_velocity_governor_throttles_excessive_admission():
    gov = AdaptiveVelocityGovernor(
        half_life_seconds=3600.0,
        burst_volume_threshold=2000.0,
        burst_count_threshold=4.0,
    )
    t0 = 30000.0
    gov.record_transaction("acc_throttle", 2500.0, t0)

    # Next large transaction right away should be throttled
    allowed, reason = gov.evaluate_transaction_admission("acc_throttle", 2000.0, t0 + 5)
    assert allowed is False
    assert "Velocity throttle" in reason
