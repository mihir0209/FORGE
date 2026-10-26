from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class DisputeEvidence:
    dispute_id: str
    account_id: str
    transaction_amount_usd: float
    account_age_days: int
    historical_disputes: int
    total_completed_orders: int
    delivery_confirmed: bool
    delivery_address_matches_billing: bool
    device_ip_matches_delivery_geo: bool
    photo_signature_confirmed: bool
    dispute_reason: str
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class FriendlyFraudAssessment:
    dispute_id: str
    account_id: str
    risk_score: float
    confidence: float
    verdict: str
    contributing_factors: List[str]
    recommended_action: str

class FriendlyFraudPredictor:
    def __init__(self, high_risk_threshold: float = 0.70, medium_risk_threshold: float = 0.40):
        self.high_risk_threshold = high_risk_threshold
        self.medium_risk_threshold = medium_risk_threshold

    def evaluate(self, evidence: DisputeEvidence) -> FriendlyFraudAssessment:
        score = 0.0
        factors = []

        if evidence.delivery_confirmed and evidence.photo_signature_confirmed:
            if evidence.dispute_reason == "ITEM_NOT_RECEIVED":
                score += 0.45
                factors.append("Carrier confirmed delivery with photo/signature against INR claim")
        
        if evidence.device_ip_matches_delivery_geo and evidence.dispute_reason == "UNAUTHORIZED_TRANSACTION":
            score += 0.35
            factors.append("Dispute filed from same physical geolocation and subnet as delivery address")

        dispute_ratio = (
            evidence.historical_disputes / max(1, evidence.total_completed_orders)
        )
        if dispute_ratio > 0.20:
            score += 0.25
            factors.append(f"High historical dispute ratio ({dispute_ratio:.1%})")
        elif dispute_ratio > 0.10:
            score += 0.15
            factors.append(f"Elevated historical dispute ratio ({dispute_ratio:.1%})")

        if evidence.account_age_days < 30 and evidence.transaction_amount_usd > 500.0:
            score += 0.20
            factors.append("High-value dispute on account under 30 days old")

        if evidence.delivery_address_matches_billing and evidence.dispute_reason == "UNAUTHORIZED_TRANSACTION":
            score += 0.15
            factors.append("Billing and shipping address match on alleged unauthorized transaction")

        risk_score = min(1.0, round(score, 4))
        confidence = min(0.99, round(0.55 + 0.1 * len(factors), 2))

        if risk_score >= self.high_risk_threshold:
            verdict = "HIGH_RISK_FIRST_PARTY_FRAUD"
            recommended_action = "BLOCK_AND_REPRESENT"
        elif risk_score >= self.medium_risk_threshold:
            verdict = "SUSPECTED_FRIENDLY_FRAUD"
            recommended_action = "REPRESENTMENT_CHALLENGE"
        else:
            verdict = "LEGITIMATE_DISPUTE"
            recommended_action = "ACCEPT_DISPUTE"

        return FriendlyFraudAssessment(
            dispute_id=evidence.dispute_id,
            account_id=evidence.account_id,
            risk_score=risk_score,
            confidence=confidence,
            verdict=verdict,
            contributing_factors=factors,
            recommended_action=recommended_action,
        )
