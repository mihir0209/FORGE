"""Adaptive Velocity Risk Governor with Exponential Decay Windows.

Calculates real-time continuous transaction velocity and burst rates using half-life
exponential decay weighting, eliminating tumbling-window boundary vulnerabilities.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class VelocityEvent:
    amount: float
    timestamp: float


@dataclass
class VelocityMetrics:
    account_id: str
    current_volume_velocity: float
    current_count_velocity: float
    is_bursting: bool
    risk_score: float  # 0.0 to 1.0


class AdaptiveVelocityGovernor:
    """Computes continuous exponentially decayed velocity metrics over transaction streams."""

    def __init__(
        self,
        half_life_seconds: float = 3600.0,  # 1 hour half-life
        burst_volume_threshold: float = 5000.0,
        burst_count_threshold: float = 5.0,
    ) -> None:
        self.half_life_seconds = half_life_seconds
        self.decay_lambda = math.log(2.0) / half_life_seconds
        self.burst_volume_threshold = burst_volume_threshold
        self.burst_count_threshold = burst_count_threshold
        self._history: Dict[str, List[VelocityEvent]] = {}

    def record_transaction(self, account_id: str, amount: float, timestamp: float) -> None:
        if amount < 0:
            raise ValueError("Transaction amount must be non-negative")
        self._history.setdefault(account_id, []).append(VelocityEvent(amount=amount, timestamp=timestamp))

    def get_velocity(self, account_id: str, current_time: float) -> VelocityMetrics:
        events = self._history.get(account_id, [])
        if not events:
            return VelocityMetrics(
                account_id=account_id,
                current_volume_velocity=0.0,
                current_count_velocity=0.0,
                is_bursting=False,
                risk_score=0.0,
            )

        decayed_vol = 0.0
        decayed_cnt = 0.0

        for ev in events:
            delta_t = current_time - ev.timestamp
            if delta_t < 0:
                delta_t = 0.0
            # Exp decay factor: e^(-lambda * dt)
            weight = math.exp(-self.decay_lambda * delta_t)
            decayed_vol += ev.amount * weight
            decayed_cnt += 1.0 * weight

        is_bursting = (
            decayed_vol >= self.burst_volume_threshold or decayed_cnt >= self.burst_count_threshold
        )

        vol_ratio = min(1.0, decayed_vol / self.burst_volume_threshold)
        cnt_ratio = min(1.0, decayed_cnt / self.burst_count_threshold)
        risk_score = round(max(vol_ratio, cnt_ratio), 3)

        return VelocityMetrics(
            account_id=account_id,
            current_volume_velocity=round(decayed_vol, 2),
            current_count_velocity=round(decayed_cnt, 2),
            is_bursting=is_bursting,
            risk_score=risk_score,
        )

    def evaluate_transaction_admission(
        self,
        account_id: str,
        amount: float,
        current_time: float,
    ) -> Tuple[bool, str]:
        """Evaluates whether an incoming transaction should be accepted or velocity-throttled."""
        metrics = self.get_velocity(account_id, current_time)
        projected_vol = metrics.current_volume_velocity + amount
        projected_cnt = metrics.current_count_velocity + 1.0

        if projected_vol > (self.burst_volume_threshold * 1.5) or projected_cnt > (
            self.burst_count_threshold * 1.5
        ):
            return False, f"Velocity throttle: projected volume ${projected_vol:,.2f} exceeds threshold."

        return True, "Approved"
