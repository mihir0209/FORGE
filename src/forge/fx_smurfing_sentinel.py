from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class FxTransaction:
    transaction_id: str
    entity_id: str
    amount_usd: float
    source_currency: str
    target_currency: str
    timestamp_epoch: int
    is_pegged_stablecoin: bool = False

@dataclass
class SmurfingAssessment:
    entity_id: str
    structuring_detected: bool
    smurfing_score: float
    total_volume_usd: float
    suspicious_transaction_ids: List[str]
    risk_tier: str
    recommended_action: str

class FxSmurfingSentinel:
    # Monitors high-velocity cross-border FX structuring, smurfing, and currency-hopping patterns.

    def __init__(self, reporting_threshold: float = 10000.0, smurf_window_seconds: int = 86400):
        self.reporting_threshold = reporting_threshold
        self.smurf_window_seconds = smurf_window_seconds

    def analyze(self, entity_id: str, transactions: List[FxTransaction]) -> SmurfingAssessment:
        if not transactions:
            return SmurfingAssessment(
                entity_id=entity_id,
                structuring_detected=False,
                smurfing_score=0.0,
                total_volume_usd=0.0,
                suspicious_transaction_ids=[],
                risk_tier="NORMAL",
                recommended_action="ALLOW"
            )

        sorted_txs = sorted(transactions, key=lambda t: t.timestamp_epoch)
        total_vol = sum(t.amount_usd for t in sorted_txs)
        
        structuring_txs = [
            t.transaction_id for t in sorted_txs
            if (self.reporting_threshold * 0.85) <= t.amount_usd < self.reporting_threshold
        ]

        currencies_touched = set()
        for t in sorted_txs:
            currencies_touched.add(t.source_currency.upper())
            currencies_touched.add(t.target_currency.upper())

        window_start = sorted_txs[0].timestamp_epoch
        window_end = sorted_txs[-1].timestamp_epoch
        duration = max(1, window_end - window_start)

        score = 0.0
        if len(structuring_txs) >= 3:
            score += 0.50
        elif len(structuring_txs) >= 1:
            score += 0.25

        if len(sorted_txs) >= 4 and total_vol >= self.reporting_threshold:
            score += 0.30

        if len(currencies_touched) >= 4 and duration <= self.smurf_window_seconds:
            score += 0.20

        smurfing_score = min(1.0, round(score, 4))
        structuring_detected = len(structuring_txs) >= 2 or (len(structuring_txs) >= 1 and total_vol > self.reporting_threshold)

        if smurfing_score >= 0.70:
            risk_tier = "CRITICAL_AML_FLAG"
            recommended_action = "FILE_SAR_AND_FREEZE"
        elif smurfing_score >= 0.35:
            risk_tier = "ELEVATED"
            recommended_action = "ENHANCED_DUE_DILIGENCE"
        else:
            risk_tier = "NORMAL"
            recommended_action = "ALLOW"

        return SmurfingAssessment(
            entity_id=entity_id,
            structuring_detected=structuring_detected,
            smurfing_score=smurfing_score,
            total_volume_usd=round(total_vol, 2),
            suspicious_transaction_ids=structuring_txs,
            risk_tier=risk_tier,
            recommended_action=recommended_action
        )
