from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import math

@dataclass
class KeystrokeEvent:
    key_code: str
    press_time_ms: float
    release_time_ms: float

@dataclass
class PointerEvent:
    x: float
    y: float
    timestamp_ms: float

@dataclass
class BiometricAssessment:
    session_id: str
    bot_probability: float
    imposter_probability: float
    entropy_score: float
    is_synthetic_automation: bool
    verdict: str
    recommended_action: str

class KeystrokeBiometricsVerifier:
    # Analyzes human behavioral dynamics vs programmatic synthetic click/typing automation.

    def __init__(self, bot_threshold: float = 0.65):
        self.bot_threshold = bot_threshold

    def analyze(self, session_id: str, keystrokes: List[KeystrokeEvent], pointers: List[PointerEvent]) -> BiometricAssessment:
        bot_score = 0.0

        # 1. Analyze Keystroke Dwell Times (duration key is pressed)
        dwell_times = [k.release_time_ms - k.press_time_ms for k in keystrokes if k.release_time_ms >= k.press_time_ms]
        if dwell_times:
            mean_dwell = sum(dwell_times) / len(dwell_times)
            variance_dwell = sum((d - mean_dwell) ** 2 for d in dwell_times) / len(dwell_times)
            std_dwell = math.sqrt(variance_dwell)

            # Robots/scripts usually have identical dwell times (std < 2ms) or inhumanly fast (< 10ms)
            if std_dwell < 2.0 or mean_dwell < 10.0:
                bot_score += 0.50

        # 2. Analyze Flight Times (interval between successive key presses)
        if len(keystrokes) >= 2:
            flight_times = [
                keystrokes[i].press_time_ms - keystrokes[i-1].release_time_ms
                for i in range(1, len(keystrokes))
            ]
            mean_flight = sum(flight_times) / len(flight_times)
            variance_flight = sum((f - mean_flight) ** 2 for f in flight_times) / len(flight_times)
            std_flight = math.sqrt(variance_flight)

            if std_flight < 2.0 or mean_flight < 5.0:
                bot_score += 0.35

        # 3. Analyze Pointer Movements (Curvature entropy vs linear telemetry)
        entropy = 1.0
        if len(pointers) >= 3:
            # Check for perfectly linear movements (synthetic bots jump straight across coordinates)
            angles = []
            for i in range(1, len(pointers) - 1):
                dx1 = pointers[i].x - pointers[i-1].x
                dy1 = pointers[i].y - pointers[i-1].y
                dx2 = pointers[i+1].x - pointers[i].x
                dy2 = pointers[i+1].y - pointers[i].y
                theta1 = math.atan2(dy1, dx1)
                theta2 = math.atan2(dy2, dx2)
                angles.append(abs(theta2 - theta1))

            if angles:
                variance_angles = sum(a ** 2 for a in angles) / len(angles)
                entropy = round(min(1.0, math.sqrt(variance_angles)), 4)
                if entropy < 0.05:  # Perfectly straight lines
                    bot_score += 0.30

        bot_prob = min(1.0, round(bot_score, 4))
        is_synthetic = bot_prob >= self.bot_threshold

        if is_synthetic:
            verdict = "SUSPECTED_BOT"
            action = "BLOCK_SESSION"
        elif bot_prob >= 0.35:
            verdict = "CREDENTIAL_IMPOSTER"
            action = "CHALLENGE_CAPTCHA"
        else:
            verdict = "GENUINE_HUMAN"
            action = "ALLOW"

        return BiometricAssessment(
            session_id=session_id,
            bot_probability=bot_prob,
            imposter_probability=round(min(1.0, bot_prob * 0.8), 4),
            entropy_score=entropy,
            is_synthetic_automation=is_synthetic,
            verdict=verdict,
            recommended_action=action
        )
