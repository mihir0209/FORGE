"""Authorized Push Payment (APP) Scam & Social Engineering Velocity Shield.

Detects social engineering, impersonation scams, and coerced fast transfers
where victims are manipulated into sending large payments to newly added fraudster accounts.
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class APPScamDecision:
    account_id: str
    beneficiary_id: str
    action: str  # ALLOW, STEP_UP_CHALLENGE, HOLD_FOR_COOLING_OFF, BLOCK
    risk_score: float
    friction_triggers: List[str]


class APPScamShield:
    def __init__(self, high_risk_multiplier: float = 3.0, cooling_off_minutes: float = 15.0):
        self.high_risk_multiplier = high_risk_multiplier
        self.cooling_off_minutes = cooling_off_minutes

    def evaluate_transfer(
        self,
        account_id: str,
        beneficiary_id: str,
        is_new_beneficiary: bool,
        minutes_since_added: float,
        amount: float,
        user_average_transfer: float,
        session_duration_seconds: float,
        high_urgency_flag: bool = False,
    ) -> APPScamDecision:
        triggers: List[str] = []
        score = 0.0

        if amount <= 0:
            raise ValueError("Transfer amount must be strictly positive")

        baseline_avg = max(10.0, user_average_transfer)
        ratio = amount / baseline_avg

        # 1. New Beneficiary Recency Risk
        if is_new_beneficiary:
            if minutes_since_added <= self.cooling_off_minutes:
                score += 0.40
                triggers.append(
                    f"Beneficiary created only {minutes_since_added:.1f}m ago (under {self.cooling_off_minutes}m cooling off threshold)"
                )
            else:
                score += 0.15
                triggers.append(f"Recent beneficiary added {minutes_since_added:.1f}m ago")

        # 2. Volume Spike Anomaly
        if ratio >= self.high_risk_multiplier:
            volume_score = min(0.40, (ratio - 1.0) * 0.1)
            score += volume_score
            triggers.append(
                f"Amount ${amount:.2f} is {ratio:.1f}x higher than typical user average ${baseline_avg:.2f}"
            )

        # 3. Behavioral Coercion / Panic Signals (Very short hasty session or explicit urgency override)
        if session_duration_seconds < 45.0:
            score += 0.20
            triggers.append(
                f"Extremely rushed session ({session_duration_seconds:.1f}s) indicates active phone call coercion"
            )

        if high_urgency_flag:
            score += 0.25
            triggers.append("Urgent fast-transfer override invoked by sender")

        final_score = min(1.0, round(score, 3))

        # Decision matrix
        if final_score >= 0.70 and is_new_beneficiary and minutes_since_added <= self.cooling_off_minutes:
            action = "HOLD_FOR_COOLING_OFF"
        elif final_score >= 0.50:
            action = "STEP_UP_CHALLENGE"
        elif final_score >= 0.85:
            action = "BLOCK"
        else:
            action = "ALLOW"

        return APPScamDecision(
            account_id=account_id,
            beneficiary_id=beneficiary_id,
            action=action,
            risk_score=final_score,
            friction_triggers=triggers,
        )
