from dataclasses import dataclass
from typing import List
import math

@dataclass
class BiometricJitterResult:
    is_bot_or_ato: bool
    flight_time_variance: float
    trajectory_curvature: float
    confidence: float

class BiometricJitterAnomalyEngine:
    def evaluate_keystroke_and_cursor(
        self,
        keystroke_flight_times_ms: List[float],
        cursor_trajectory_angles_rad: List[float]
    ) -> BiometricJitterResult:
        if len(keystroke_flight_times_ms) < 2:
            return BiometricJitterResult(False, 0.0, 0.0, 0.0)

        mean_flight = sum(keystroke_flight_times_ms) / len(keystroke_flight_times_ms)
        var_flight = sum((x - mean_flight) ** 2 for x in keystroke_flight_times_ms) / len(keystroke_flight_times_ms)

        # Bot signature: zero or near-zero variance (< 1.0 ms^2) in flight times
        is_synthetic = var_flight < 2.0
        conf = 0.95 if is_synthetic else 0.10

        return BiometricJitterResult(
            is_bot_or_ato=is_synthetic,
            flight_time_variance=round(var_flight, 2),
            trajectory_curvature=round(sum(cursor_trajectory_angles_rad), 2),
            confidence=conf
        )
