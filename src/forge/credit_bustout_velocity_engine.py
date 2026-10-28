from dataclasses import dataclass
from typing import List

@dataclass
class BustOutAlert:
    is_bustout_risk: bool
    velocity_spike_ratio: float
    risk_score: float
    mitigation: str

class CreditBustOutVelocityEngine:
    def evaluate_utilization_acceleration(
        self,
        historical_monthly_spend_usd: float,
        last_48h_spend_usd: float,
        cash_advance_ratio: float,
        credit_limit_usd: float
    ) -> BustOutAlert:
        if historical_monthly_spend_usd <= 0 or credit_limit_usd <= 0:
            return BustOutAlert(False, 1.0, 0.0, "ALLOW")

        daily_baseline = historical_monthly_spend_usd / 30.0
        recent_daily_rate = last_48h_spend_usd / 2.0
        spike_ratio = recent_daily_rate / daily_baseline

        utilization_pct = (last_48h_spend_usd / credit_limit_usd) * 100.0
        # Bust-out signature: sudden 5x+ velocity spike with high cash advances and >80% credit limit utilization
        is_bustout = spike_ratio >= 4.0 and cash_advance_ratio >= 0.40 and utilization_pct >= 75.0
        score = min(1.0, (spike_ratio / 6.0) * 0.5 + cash_advance_ratio * 0.3 + (utilization_pct / 100.0) * 0.2)

        return BustOutAlert(
            is_bustout_risk=is_bustout,
            velocity_spike_ratio=round(spike_ratio, 2),
            risk_score=round(score, 2),
            mitigation="FREEZE_CREDIT_LINE_IMMEDIATELY" if is_bustout else "MONITOR"
        )
