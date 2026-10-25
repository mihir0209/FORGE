"""Behavioral Profiling and Anomaly Scoring Engine.

Tracks user transaction behavior baselines using online Welford updates (mean and variance),
evaluates hourly activity entropy and beneficiary novelty, and generates anomaly risk scores.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class UserBehavioralProfile:
    user_id: str
    count: int = 0
    mean_amount: float = 0.0
    m2_amount: float = 0.0  # Sum of squared deviations for Welford algorithm
    hourly_histogram: dict[int, int] = field(default_factory=lambda: {h: 0 for h in range(24)})
    known_beneficiaries: set[str] = field(default_factory=set)
    last_timestamp: float = 0.0

    @property
    def variance_amount(self) -> float:
        if self.count < 2:
            return 0.0
        return self.m2_amount / (self.count - 1)

    @property
    def std_amount(self) -> float:
        return math.sqrt(self.variance_amount)


@dataclass
class AnomalyScoreResult:
    user_id: str
    amount: float
    z_score: float
    is_off_hours: bool
    is_novel_beneficiary: bool
    anomaly_score: float  # Normalized 0.0 to 1.0
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    reasons: list[str]


class BehavioralProfiler:
    """Maintains user behavioral models and flags statistical outliers."""

    def __init__(self, z_score_threshold: float = 3.0) -> None:
        self.profiles: dict[str, UserBehavioralProfile] = {}
        self.z_score_threshold = z_score_threshold

    def get_or_create_profile(self, user_id: str) -> UserBehavioralProfile:
        if user_id not in self.profiles:
            self.profiles[user_id] = UserBehavioralProfile(user_id=user_id)
        return self.profiles[user_id]

    def update_profile(
        self,
        user_id: str,
        amount: float,
        timestamp: float | datetime,
        beneficiary_id: str | None = None,
    ) -> None:
        """Online update of user profile via Welford algorithm."""
        profile = self.get_or_create_profile(user_id)
        ts_float = timestamp.timestamp() if isinstance(timestamp, datetime) else float(timestamp)
        hour = datetime.fromtimestamp(ts_float).hour

        profile.count += 1
        delta = amount - profile.mean_amount
        profile.mean_amount += delta / profile.count
        delta2 = amount - profile.mean_amount
        profile.m2_amount += delta * delta2

        profile.hourly_histogram[hour] = profile.hourly_histogram.get(hour, 0) + 1
        if beneficiary_id:
            profile.known_beneficiaries.add(beneficiary_id)
        profile.last_timestamp = ts_float

    def score_transaction(
        self,
        user_id: str,
        amount: float,
        timestamp: float | datetime,
        beneficiary_id: str | None = None,
    ) -> AnomalyScoreResult:
        """Evaluates an inbound transaction against historical baseline profile."""
        profile = self.profiles.get(user_id)
        ts_float = timestamp.timestamp() if isinstance(timestamp, datetime) else float(timestamp)
        hour = datetime.fromtimestamp(ts_float).hour

        # Cold start (insufficient history): return baseline
        if not profile or profile.count < 3:
            return AnomalyScoreResult(
                user_id=user_id,
                amount=amount,
                z_score=0.0,
                is_off_hours=False,
                is_novel_beneficiary=False,
                anomaly_score=0.05,
                risk_level="LOW",
                reasons=["Insufficient baseline history (warmup phase)"],
            )

        # 1. Amount Z-score
        std = profile.std_amount
        # Use variance floor to avoid division by zero on identical recurring transactions
        effective_std = max(std, max(1.0, profile.mean_amount * 0.05)) if std == 0 else std
        z_score = max(0.0, (amount - profile.mean_amount) / effective_std)

        reasons = []
        score_components = []

        # Amount deviation penalty
        amount_penalty = min(1.0, z_score / (self.z_score_threshold * 1.5))
        score_components.append(amount_penalty * 0.6)
        if z_score >= self.z_score_threshold:
            reasons.append(f"Amount {amount:.2f} exceeds {z_score:.1f} standard deviations from mean {profile.mean_amount:.2f}")

        # 2. Hourly distribution check
        total_hour_txns = profile.hourly_histogram.get(hour, 0)
        is_off_hours = total_hour_txns == 0
        if is_off_hours:
            score_components.append(0.2)
            reasons.append(f"Transaction at hour {hour}:00 has 0 historical occurrences for user")

        # 3. Beneficiary novelty
        is_novel = False
        if beneficiary_id and beneficiary_id not in profile.known_beneficiaries:
            is_novel = True
            score_components.append(0.2)
            reasons.append(f"First-time transfer to beneficiary '{beneficiary_id}'")

        composite_score = round(min(1.0, sum(score_components)), 3)

        if composite_score >= 0.75:
            risk = "CRITICAL"
        elif composite_score >= 0.50:
            risk = "HIGH"
        elif composite_score >= 0.25:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        if not reasons:
            reasons.append("Transaction matches historical behavioral patterns")

        return AnomalyScoreResult(
            user_id=user_id,
            amount=amount,
            z_score=round(z_score, 2),
            is_off_hours=is_off_hours,
            is_novel_beneficiary=is_novel,
            anomaly_score=composite_score,
            risk_level=risk,
            reasons=reasons,
        )
