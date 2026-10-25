"""Behavioral Biometrics & Keystroke Dynamics Classifier for FORGE."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

# Thresholds for automated robotic scripts vs authentic human typing
MIN_SAMPLES_FOR_EVALUATION = 4
BOT_VARIANCE_CEILING = 15.0  # Milliseconds squared variance under which bot is detected
HUMAN_CV_LOWER_BOUND = 0.12  # Coefficient of variation lower threshold for human organic typing


@dataclass
class KeyEvent:
    key: str
    down_ms: float
    up_ms: float

    @property
    def dwell_time_ms(self) -> float:
        return max(0.0, self.up_ms - self.down_ms)


@dataclass
class BiometricProfileResult:
    is_bot: bool
    bot_probability: float
    mean_dwell_ms: float
    dwell_variance: float
    dwell_cv: float
    mean_flight_ms: float
    flight_variance: float
    sample_size: int
    classification: str
    anomaly_details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_bot": self.is_bot,
            "bot_probability": round(self.bot_probability, 4),
            "mean_dwell_ms": round(self.mean_dwell_ms, 2),
            "dwell_variance": round(self.dwell_variance, 2),
            "dwell_cv": round(self.dwell_cv, 4),
            "mean_flight_ms": round(self.mean_flight_ms, 2),
            "flight_variance": round(self.flight_variance, 2),
            "sample_size": self.sample_size,
            "classification": self.classification,
            "anomaly_details": self.anomaly_details,
        }


def _calculate_variance(values: list[float], mean: float) -> float:
    if len(values) < 2:
        return 0.0
    return sum((x - mean) ** 2 for x in values) / (len(values) - 1)


class KeystrokeDynamicsClassifier:
    """Classifies keystroke stream timing to differentiate scripted bots from human users."""

    def __init__(self, bot_variance_threshold: float = BOT_VARIANCE_CEILING) -> None:
        self.bot_variance_threshold = bot_variance_threshold

    def evaluate(self, key_events: list[KeyEvent]) -> BiometricProfileResult:
        if len(key_events) < MIN_SAMPLES_FOR_EVALUATION:
            return BiometricProfileResult(
                is_bot=False,
                bot_probability=0.1,
                mean_dwell_ms=0.0,
                dwell_variance=0.0,
                dwell_cv=0.0,
                mean_flight_ms=0.0,
                flight_variance=0.0,
                sample_size=len(key_events),
                classification="INSUFFICIENT_DATA",
                anomaly_details=["Input string too short for confident biometric profiling."],
            )

        # 1. Dwell Times (key down to key up)
        dwell_times = [k.dwell_time_ms for k in key_events]
        mean_dwell = sum(dwell_times) / len(dwell_times)
        dwell_var = _calculate_variance(dwell_times, mean_dwell)
        dwell_std = math.sqrt(dwell_var)
        dwell_cv = (dwell_std / mean_dwell) if mean_dwell > 0 else 0.0

        # 2. Flight Times (time between key release and next key press)
        flight_times: list[float] = []
        for i in range(len(key_events) - 1):
            flight = key_events[i + 1].down_ms - key_events[i].up_ms
            flight_times.append(flight)

        mean_flight = (sum(flight_times) / len(flight_times)) if flight_times else 0.0
        flight_var = _calculate_variance(flight_times, mean_flight) if flight_times else 0.0

        anomalies: list[str] = []
        is_bot = False
        bot_prob = 0.0

        # Check for Robotic Script Indicators:
        # A. Unnaturally constant dwell times (e.g. headless browser script with fixed sleep)
        if dwell_var < self.bot_variance_threshold or dwell_cv < 0.05:
            is_bot = True
            bot_prob = max(bot_prob, 0.95)
            anomalies.append(
                f"Synthetic keystroke dwell consistency detected (variance: {dwell_var:.2f} ms², CV: {dwell_cv:.4f})."
            )

        # B. Unnaturally constant flight times
        if flight_times and (flight_var < self.bot_variance_threshold or (math.sqrt(flight_var) / max(1.0, mean_flight)) < 0.05):
            is_bot = True
            bot_prob = max(bot_prob, 0.92)
            anomalies.append(
                f"Fixed flight intervals detected across key transitions (variance: {flight_var:.2f} ms²)."
            )

        # C. Superhuman typing speed (average dwell < 15ms or average flight < 10ms)
        if mean_dwell < 15.0 or (mean_flight > 0 and mean_flight < 10.0):
            is_bot = True
            bot_prob = 1.0
            anomalies.append(
                f"Superhuman typing cadence: mean dwell {mean_dwell:.1f}ms, mean flight {mean_flight:.1f}ms."
            )

        # D. Zero flight or identical timestamps (instant programmatic field paste)
        if any(f <= 0.0 for f in flight_times) and len([f for f in flight_times if f <= 0.0]) > len(flight_times) * 0.5:
            is_bot = True
            bot_prob = 0.98
            anomalies.append("Immediate bulk DOM value injection / automated paste event detected.")

        if not is_bot:
            classification = "AUTHENTIC_HUMAN"
            bot_prob = max(0.02, min(0.25, 1.0 - dwell_cv))
        else:
            classification = "SCRIPTED_AUTOMATION_BOT"

        return BiometricProfileResult(
            is_bot=is_bot,
            bot_probability=bot_prob,
            mean_dwell_ms=mean_dwell,
            dwell_variance=dwell_var,
            dwell_cv=dwell_cv,
            mean_flight_ms=mean_flight,
            flight_variance=flight_var,
            sample_size=len(key_events),
            classification=classification,
            anomaly_details=anomalies,
        )
