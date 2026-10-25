"""Tests for FORGE Behavioral Profiling & Anomaly Scoring Engine."""

from __future__ import annotations

from datetime import datetime
import pytest
from forge.behavioral_engine import (
    AnomalyScoreResult,
    BehavioralProfiler,
    UserBehavioralProfile,
)


def test_welford_online_mean_and_variance():
    profiler = BehavioralProfiler()
    user_id = "user_welford_01"

    # Feed numbers: 10, 20, 30
    profiler.update_profile(user_id, 10.0, 1000.0)
    profiler.update_profile(user_id, 20.0, 2000.0)
    profiler.update_profile(user_id, 30.0, 3000.0)

    p = profiler.profiles[user_id]
    assert p.count == 3
    assert p.mean_amount == 20.0
    # Sample variance of [10, 20, 30] is 100.0, std is 10.0
    assert p.variance_amount == 100.0
    assert p.std_amount == 10.0


def test_cold_start_profile_returns_baseline_low_risk():
    profiler = BehavioralProfiler()
    user_id = "new_user_cold_start"

    # Only 1 transaction: insufficient for standard deviation
    profiler.update_profile(user_id, 50.0, 1000.0)
    res = profiler.score_transaction(user_id, 10000.0, 2000.0)

    assert res.risk_level == "LOW"
    assert "warmup phase" in res.reasons[0]


def test_extreme_amount_zscore_triggers_anomaly():
    profiler = BehavioralProfiler(z_score_threshold=3.0)
    user_id = "regular_spender"

    # User typically spends around $50 (std ~$5)
    for _ in range(20):
        profiler.update_profile(user_id, 50.0, 1700000000.0, beneficiary_id="local_grocery")

    # Inbound transaction of $5,000 (enormous spike)
    res = profiler.score_transaction(user_id, 5000.0, 1700000000.0, beneficiary_id="local_grocery")

    assert res.z_score >= 3.0
    assert res.anomaly_score >= 0.5
    assert any("exceeds" in r for r in res.reasons)


def test_compound_anomalies_escalate_risk_level():
    profiler = BehavioralProfiler(z_score_threshold=3.0)
    user_id = "corporate_account"

    # Profile established at 14:00 (2 PM) with known vendors
    base_ts = datetime(2026, 10, 25, 14, 0, 0).timestamp()
    for _ in range(10):
        profiler.update_profile(user_id, 100.0, base_ts, beneficiary_id="vendor_corp_a")

    # Transaction occurs at 03:00 AM (off-hours) to an unknown foreign account
    off_hours_ts = datetime(2026, 10, 26, 3, 0, 0).timestamp()
    res = profiler.score_transaction(
        user_id,
        amount=120.0,  # normal amount
        timestamp=off_hours_ts,
        beneficiary_id="unknown_overseas_wallet",
    )

    assert res.is_off_hours is True
    assert res.is_novel_beneficiary is True
    assert res.anomaly_score >= 0.40
    assert any("0:00" in r or "First-time transfer" in r for r in res.reasons)
