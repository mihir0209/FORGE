"""Synthetic Identity Fraud & Credit Bust-Out Predictor.

Detects synthetic identities constructed from fragmented/recycled records
and predicts credit bust-out abandonment patterns using dynamic ramp velocity modeling.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class SyntheticIdentityProfile:
    ssn_age_days: int
    address_link_count: int
    phone_recycled: bool
    credit_bureau_depth: int
    identity_discrepancy_score: float  # 0.0 to 1.0


@dataclass
class BustOutFeatureVector:
    dormancy_days: float
    recent_spend_velocity: float  # $/day over past 7 days
    historical_spend_velocity: float  # $/day baseline
    credit_limit_utilization: float  # e.g., 0.95 for 95%
    disbursement_ratio: float  # cash advance / total line
    repayment_rate: float  # payment / balance ratio over past 30 days


@dataclass
class SyntheticIdentityResult:
    is_synthetic: bool
    risk_score: float  # 0.0 to 1.0
    flags: List[str]


@dataclass
class BustOutPredictionResult:
    is_bust_out_risk: bool
    bust_out_probability: float  # 0.0 to 1.0
    flags: List[str]
    recommended_action: str  # "FREEZE_LINE", "STEP_UP_VERIFICATION", "ALLOW"


class SyntheticIdentityEngine:
    """Predicts synthetic identities and credit bust-out exploitation."""

    @staticmethod
    def evaluate_synthetic_identity(profile: SyntheticIdentityProfile) -> SyntheticIdentityResult:
        flags: List[str] = []
        score = 0.0

        # 1. Newly issued SSN with excessive name linkages
        if profile.ssn_age_days < 180 and profile.address_link_count >= 3:
            flags.append("NEW_SSN_ADDRESS_LINKAGE_CLUSTER")
            score += 0.45

        if profile.ssn_age_days < 90 and profile.address_link_count >= 4:
            flags.append("HIGH_CONFIDENCE_SYNTHETIC_ID")
            score = max(score, 0.95)

        # 2. Recycled phone + high discrepancy
        if profile.phone_recycled and profile.identity_discrepancy_score >= 0.60:
            flags.append("RECYCLED_PHONE_DISCREPANCY")
            score += 0.35

        # 3. Thin file anomaly
        if profile.credit_bureau_depth <= 1 and profile.ssn_age_days < 365:
            flags.append("THIN_FILE_NEW_IDENTITY")
            score += 0.20

        # Cap score
        score = min(1.0, max(score, profile.identity_discrepancy_score * 0.8))
        is_synthetic = score >= 0.70 or "HIGH_CONFIDENCE_SYNTHETIC_ID" in flags

        return SyntheticIdentityResult(
            is_synthetic=is_synthetic,
            risk_score=score,
            flags=flags,
        )

    @staticmethod
    def predict_bust_out(features: BustOutFeatureVector) -> BustOutPredictionResult:
        flags: List[str] = []
        prob = 0.0

        # Ramp ratio
        baseline = max(1.0, features.historical_spend_velocity)
        ramp_ratio = features.recent_spend_velocity / baseline

        if ramp_ratio >= 8.0 and features.credit_limit_utilization >= 0.85:
            flags.append(f"ACCELERATED_RAMP_SLOPE_{ramp_ratio:.1f}X")
            prob += 0.45

        # Sleeper account awakening
        if features.dormancy_days >= 45 and ramp_ratio >= 5.0:
            flags.append("DORMANT_ACCOUNT_AWAKENING")
            prob += 0.30

        # Cash drain / Max disbursement
        if features.disbursement_ratio >= 0.75:
            flags.append(f"HIGH_CASH_DISBURSEMENT_{features.disbursement_ratio:.0%}")
            prob += 0.35

        # Low repayment rate under high balance
        if features.credit_limit_utilization >= 0.90 and features.repayment_rate <= 0.05:
            flags.append("MINIMAL_REPAYMENT_UNDER_MAX_UTILIZATION")
            prob += 0.35

        # Critical bust-out pattern combo
        if (
            features.dormancy_days >= 45
            and ramp_ratio >= 8.0
            and features.credit_limit_utilization >= 0.90
            and features.repayment_rate <= 0.05
        ):
            flags.append("CRITICAL_BUST_OUT_PATTERN_MATCH")
            prob = max(prob, 0.98)

        prob = min(1.0, prob)
        is_risk = prob >= 0.70

        if prob >= 0.85:
            action = "FREEZE_LINE"
        elif prob >= 0.60:
            action = "STEP_UP_VERIFICATION"
        else:
            action = "ALLOW"

        return BustOutPredictionResult(
            is_bust_out_risk=is_risk,
            bust_out_probability=prob,
            flags=flags,
            recommended_action=action,
        )
