"""Merchant Collusion & Triangular Arbitrage Fraud Sentinel for FORGE."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

HHI_COLLUSION_THRESHOLD = 0.55  # Herfindahl-Hirschman index > 0.55 flags excessive buyer cartel concentration
REFUND_CHURN_RATIO_THRESHOLD = 0.40  # Over 40% refund rate paired with rapid velocity


@dataclass
class MerchantTransaction:
    tx_id: str
    merchant_id: str
    buyer_id: str
    amount: float
    is_refund: bool = False
    timestamp: datetime | None = None
    cashback_claimed: float = 0.0


@dataclass
class MerchantRiskReport:
    merchant_id: str
    is_collusive: bool
    risk_score: float  # 0.0 to 1.0
    hhi_concentration: float
    total_volume: float
    total_transactions: int
    top_buyer_ratio: float
    refund_rate: float
    cashback_churn_ratio: float
    recommendation: str  # "APPROVE" | "HOLD_SETTLEMENT" | "FREEZE_MERCHANT"
    flagged_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "merchant_id": self.merchant_id,
            "is_collusive": self.is_collusive,
            "risk_score": round(self.risk_score, 4),
            "hhi_concentration": round(self.hhi_concentration, 4),
            "total_volume": round(self.total_volume, 2),
            "total_transactions": self.total_transactions,
            "top_buyer_ratio": round(self.top_buyer_ratio, 4),
            "refund_rate": round(self.refund_rate, 4),
            "cashback_churn_ratio": round(self.cashback_churn_ratio, 4),
            "recommendation": self.recommendation,
            "flagged_reasons": self.flagged_reasons,
        }


class MerchantCollusionSentinel:
    """Analyzes merchant transaction history to detect collusion, buyer cartels, and reward churn."""

    def __init__(self, hhi_threshold: float = HHI_COLLUSION_THRESHOLD) -> None:
        self.hhi_threshold = hhi_threshold

    def audit_merchant(self, merchant_id: str, transactions: list[MerchantTransaction]) -> MerchantRiskReport:
        if not transactions:
            return MerchantRiskReport(
                merchant_id=merchant_id,
                is_collusive=False,
                risk_score=0.0,
                hhi_concentration=0.0,
                total_volume=0.0,
                total_transactions=0,
                top_buyer_ratio=0.0,
                refund_rate=0.0,
                cashback_churn_ratio=0.0,
                recommendation="APPROVE",
                flagged_reasons=["No transaction history to evaluate."],
            )

        total_volume = 0.0
        buyer_volumes: dict[str, float] = defaultdict(float)
        refund_volume = 0.0
        total_cashback = 0.0

        for tx in transactions:
            if tx.is_refund:
                refund_volume += tx.amount
            else:
                total_volume += tx.amount
                buyer_volumes[tx.buyer_id] += tx.amount
                total_cashback += tx.cashback_claimed

        if total_volume <= 0.0:
            return MerchantRiskReport(
                merchant_id=merchant_id,
                is_collusive=False,
                risk_score=0.1,
                hhi_concentration=0.0,
                total_volume=0.0,
                total_transactions=len(transactions),
                top_buyer_ratio=0.0,
                refund_rate=1.0 if refund_volume > 0 else 0.0,
                cashback_churn_ratio=0.0,
                recommendation="APPROVE",
                flagged_reasons=["Zero net purchase volume."],
            )

        # Calculate Herfindahl-Hirschman Index (HHI)
        # HHI = sum((buyer_volume / total_volume) ** 2)
        shares = [(vol / total_volume) for vol in buyer_volumes.values()]
        hhi = sum(s ** 2 for s in shares)
        top_buyer_ratio = max(shares) if shares else 0.0

        # Refund rate
        refund_rate = refund_volume / (total_volume + refund_volume) if (total_volume + refund_volume) > 0 else 0.0

        # Cashback churn ratio (cashback collected relative to volume)
        cashback_ratio = total_cashback / total_volume if total_volume > 0 else 0.0

        reasons: list[str] = []
        collusive_indicators = 0

        # Check 1: Buyer Concentration (Small Cartel Churn)
        if len(buyer_volumes) >= 2 and hhi > self.hhi_threshold:
            collusive_indicators += 2
            reasons.append(
                f"Severe buyer cartel concentration: HHI {hhi:.3f} exceeds threshold {self.hhi_threshold:.2f} (Top buyer controls {top_buyer_ratio * 100:.1f}% volume)."
            )
        elif len(buyer_volumes) == 1 and len(transactions) >= 3:
            collusive_indicators += 2
            reasons.append(
                f"100% single-buyer dependency across {len(transactions)} transactions indicating synthetic merchant-buyer loop."
            )

        # Check 2: Refund Churn Exploitation
        if refund_rate > REFUND_CHURN_RATIO_THRESHOLD and len(transactions) >= 4:
            collusive_indicators += 2
            reasons.append(
                f"Abnormal refund rate ({refund_rate * 100:.1f}%) indicating round-trip cashback churning."
            )

        # Check 3: Disproportionate Cashback Harvesting
        if cashback_ratio > 0.05:  # Over 5% average cashback extraction
            collusive_indicators += 1
            reasons.append(
                f"Elevated cashback harvesting ratio ({cashback_ratio * 100:.2f}% of gross volume)."
            )

        risk_score = min(collusive_indicators * 0.28, 1.0)
        is_collusive = risk_score >= 0.50

        if risk_score >= 0.75:
            recommendation = "FREEZE_MERCHANT"
        elif risk_score >= 0.45:
            recommendation = "HOLD_SETTLEMENT"
        else:
            recommendation = "APPROVE"

        return MerchantRiskReport(
            merchant_id=merchant_id,
            is_collusive=is_collusive,
            risk_score=risk_score,
            hhi_concentration=hhi,
            total_volume=total_volume,
            total_transactions=len(transactions),
            top_buyer_ratio=top_buyer_ratio,
            refund_rate=refund_rate,
            cashback_churn_ratio=cashback_ratio,
            recommendation=recommendation,
            flagged_reasons=reasons,
        )
