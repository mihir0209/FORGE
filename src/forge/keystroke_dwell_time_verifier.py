from dataclasses import dataclass
from typing import List
import math

@dataclass
class KeystrokeBiometricMatch:
    is_biometric_match: bool
    euclidean_distance: float
    confidence_score: float
    threat_tier: str

class KeystrokeDwellTimeVerifier:
    def __init__(self, max_distance_threshold: float = 35.0):
        self.max_distance_threshold = max_distance_threshold

    def evaluate_typing_cadence(
        self,
        baseline_dwell_times_ms: List[float],
        observed_dwell_times_ms: List[float]
    ) -> KeystrokeBiometricMatch:
        if len(baseline_dwell_times_ms) != len(observed_dwell_times_ms) or len(baseline_dwell_times_ms) < 4:
            return KeystrokeBiometricMatch(False, 999.0, 0.0, "INSUFFICIENT_TELEMETRY")

        # Compute Euclidean distance across dwell times
        squared_diff = sum((b - o) ** 2 for b, o in zip(baseline_dwell_times_ms, observed_dwell_times_ms))
        distance = math.sqrt(squared_diff)
        is_match = distance <= self.max_distance_threshold
        confidence = max(0.0, min(1.0, 1.0 - (distance / (self.max_distance_threshold * 2.0))))

        tier = "AUTHORIZED_BIOMETRIC_PROFILE" if is_match else "SUSPECTED_ATO_BOT_INJECTION"

        return KeystrokeBiometricMatch(
            is_biometric_match=is_match,
            euclidean_distance=round(distance, 2),
            confidence_score=round(confidence, 2),
            threat_tier=tier
        )
