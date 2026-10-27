"""
FORGE Remittance Smurfing & Velocity Decay Sentinel.
Flags structured micro-transfers just below statutory reporting thresholds.
"""
from dataclasses import dataclass
from typing import List, Dict

@dataclass
class SmurfingAlert:
    is_smurfing: bool
    sender_address: str
    transaction_count: int
    total_amount: float
    risk_score: float

class RemittanceSmurfingSentinel:
    def __init__(self, threshold: float = 10000.0, smurf_band: float = 0.2):
        self.threshold = threshold
        self.lower_bound = threshold * (1 - smurf_band)

    def analyze_transactions(self, sender: str, amounts: List[float]) -> SmurfingAlert:
        near_threshold = [a for a in amounts if self.lower_bound <= a < self.threshold]
        count = len(near_threshold)
        total = sum(near_threshold)
        is_smurf = count >= 3 or total >= (self.threshold * 2)
        score = min(1.0, count * 0.25 + (total / (self.threshold * 2)) * 0.5)
        return SmurfingAlert(
            is_smurfing=is_smurf,
            sender_address=sender,
            transaction_count=count,
            total_amount=round(total, 2),
            risk_score=round(score, 2),
        )
