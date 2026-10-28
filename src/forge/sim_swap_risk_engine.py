from dataclasses import dataclass
from typing import Optional

@dataclass
class SimSwapRiskAssessment:
    is_high_risk: bool
    risk_score: float
    recommendation: str

class SimSwapRiskEngine:
    def evaluate_phone_change(
        self,
        hours_since_last_sim_change: float,
        recent_password_reset: bool,
        high_value_wire_attempt: bool
    ) -> SimSwapRiskAssessment:
        score = 0.0
        # If SIM change happened in last 48 hours
        if hours_since_last_sim_change <= 48.0:
            score += 0.50
        if recent_password_reset:
            score += 0.35
        if high_value_wire_attempt:
            score += 0.25

        score = min(1.0, round(score, 2))
        is_high = score >= 0.70
        rec = "STEP_UP_OUT_OF_BAND_AUTH" if is_high else "ALLOW"

        return SimSwapRiskAssessment(
            is_high_risk=is_high,
            risk_score=score,
            recommendation=rec
        )
