"""Multi-Hop Structured Micro-Deposit (Smurfing) & AML Sentinel.

Detects structured financial transactions designed to evade statutory anti-money laundering (AML)
currency transaction reporting thresholds (e.g., structuring multiple $9,000–$9,990 transfers).
Analyzes fan-in, fan-out, amount clustering, and aggregate flow over sliding time windows.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class TransactionRecord:
    tx_id: str
    sender: str
    receiver: str
    amount: float
    timestamp: float  # unix epoch in seconds


@dataclass
class SmurfingAlert:
    cluster_id: str
    direction: str  # "FAN_IN" or "FAN_OUT"
    account_id: str
    total_volume: float
    transaction_count: int
    mean_amount: float
    amount_std_dev: float
    smurfing_score: float  # 0.0 to 1.0
    is_smurfing: bool
    description: str


class SmurfingDetector:
    """Detects structured AML smurfing rings and micro-deposit evasion patterns."""

    def __init__(
        self,
        reporting_threshold: float = 10000.0,
        smurfing_band_lower: float = 8000.0,
        window_seconds: float = 86400.0,  # 24 hours
        min_transactions: int = 3,
    ) -> None:
        self.reporting_threshold = reporting_threshold
        self.smurfing_band_lower = smurfing_band_lower
        self.window_seconds = window_seconds
        self.min_transactions = min_transactions

    def analyze_transactions(self, transactions: List[TransactionRecord]) -> List[SmurfingAlert]:
        alerts: List[SmurfingAlert] = []
        if not transactions:
            return alerts

        # Group by receiver (Fan-In smurfing) and sender (Fan-Out smurfing)
        fan_in: Dict[str, List[TransactionRecord]] = {}
        fan_out: Dict[str, List[TransactionRecord]] = {}

        for tx in transactions:
            fan_in.setdefault(tx.receiver, []).append(tx)
            fan_out.setdefault(tx.sender, []).append(tx)

        # Inspect Fan-In
        for receiver, tx_list in fan_in.items():
            alert = self._evaluate_cluster(receiver, tx_list, direction="FAN_IN")
            if alert and alert.is_smurfing:
                alerts.append(alert)

        # Inspect Fan-Out
        for sender, tx_list in fan_out.items():
            alert = self._evaluate_cluster(sender, tx_list, direction="FAN_OUT")
            if alert and alert.is_smurfing:
                alerts.append(alert)

        return alerts

    def _evaluate_cluster(
        self,
        account_id: str,
        tx_list: List[TransactionRecord],
        direction: str,
    ) -> Optional[SmurfingAlert]:
        if len(tx_list) < self.min_transactions:
            return None

        # Sort by timestamp
        sorted_tx = sorted(tx_list, key=lambda x: x.timestamp)
        earliest = sorted_tx[0].timestamp
        latest = sorted_tx[-1].timestamp

        if (latest - earliest) > self.window_seconds:
            # Filter to transactions within sliding window
            sorted_tx = [t for t in sorted_tx if (latest - t.timestamp) <= self.window_seconds]
            if len(sorted_tx) < self.min_transactions:
                return None

        amounts = [t.amount for t in sorted_tx]
        total_vol = sum(amounts)
        n = len(amounts)
        mean_amt = total_vol / n

        # Standard deviation
        variance = sum((x - mean_amt) ** 2 for x in amounts) / n
        std_dev = math.sqrt(variance)

        # Smurfing criteria:
        # 1. Total volume exceeds reporting threshold
        # 2. Individual transactions are just below threshold (within smurfing_band)
        # 3. High transaction count with low variance (structured amounts)
        band_hits = sum(1 for a in amounts if self.smurfing_band_lower <= a < self.reporting_threshold)
        band_ratio = band_hits / n

        # Smurfing score formula
        volume_factor = min(1.0, total_vol / (self.reporting_threshold * 2))
        clustering_factor = band_ratio
        regularity_factor = max(0.0, 1.0 - (std_dev / (mean_amt + 1e-5)))

        smurfing_score = (volume_factor * 0.4) + (clustering_factor * 0.4) + (regularity_factor * 0.2)
        is_smurfing = total_vol >= self.reporting_threshold and band_hits >= 2 and smurfing_score >= 0.60

        return SmurfingAlert(
            cluster_id=f"AML-{direction}-{account_id}",
            direction=direction,
            account_id=account_id,
            total_volume=round(total_vol, 2),
            transaction_count=n,
            mean_amount=round(mean_amt, 2),
            amount_std_dev=round(std_dev, 2),
            smurfing_score=round(smurfing_score, 3),
            is_smurfing=is_smurfing,
            description=f"Structured {direction} smurfing detected on {account_id}: {n} txs totaling ${total_vol:,.2f} evading reporting ceiling.",
        )
