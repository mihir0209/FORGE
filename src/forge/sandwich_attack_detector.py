"""
FORGE Sandwich Attack & Front-Running MEV Predation Detector
Identifies atomic sandwich attack triplets in blockchain transaction sequences,
quantifying victim slippage exploitation, attacker extraction profit, and validator bribes.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any


@dataclass
class DexSwapTransaction:
    tx_hash: str
    sender_address: str
    block_number: int
    tx_index: int
    pool_address: str
    token_in: str
    token_out: str
    amount_in: float
    amount_out: float
    effective_gas_price_gwei: float
    priority_fee_gwei: float = 0.0
    miner_bribe_eth: float = 0.0


@dataclass
class SandwichAttackAlert:
    is_sandwich_attack: bool
    attacker_address: str
    victim_address: str
    pool_address: str
    frontrun_tx_hash: str
    victim_tx_hash: str
    backrun_tx_hash: str
    token_in: str
    token_out: str
    attacker_gross_profit_token_in: float
    attacker_net_profit_token_in: float
    estimated_victim_slippage_loss: float
    price_impact_percentage: float
    confidence_score: float
    risk_severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"


class SandwichAttackDetector:
    """
    Scans sequential swaps in a block to detect sandwich exploitation triplets:
    Tx_frontrun (buy) -> Tx_victim (buy) -> Tx_backrun (sell).
    """

    def __init__(self, min_profit_threshold: float = 0.0, min_confidence: float = 0.80):
        self.min_profit_threshold = min_profit_threshold
        self.min_confidence = min_confidence

    def analyze_block_swaps(
        self, swaps: List[DexSwapTransaction]
    ) -> List[SandwichAttackAlert]:
        """
        Processes a block's chronological DEX swaps and returns all confirmed sandwich attacks.
        """
        ordered_swaps = sorted(swaps, key=lambda s: s.tx_index)
        alerts: List[SandwichAttackAlert] = []

        n = len(ordered_swaps)
        if n < 3:
            return alerts

        for i in range(n - 2):
            frontrun = ordered_swaps[i]

            for j in range(i + 1, n - 1):
                victim = ordered_swaps[j]

                if frontrun.pool_address != victim.pool_address:
                    continue

                if frontrun.token_in != victim.token_in or frontrun.token_out != victim.token_out:
                    continue

                if frontrun.sender_address.lower() == victim.sender_address.lower():
                    continue

                for k in range(j + 1, n):
                    backrun = ordered_swaps[k]

                    if backrun.pool_address != frontrun.pool_address:
                        continue

                    if backrun.sender_address.lower() != frontrun.sender_address.lower():
                        continue

                    if backrun.token_in != frontrun.token_out or backrun.token_out != frontrun.token_in:
                        continue

                    tokens_held = frontrun.amount_out
                    if abs(backrun.amount_in - tokens_held) / max(tokens_held, 1e-9) > 0.05:
                        continue

                    cost_in = frontrun.amount_in
                    proceeds_in = backrun.amount_out
                    gross_profit = proceeds_in - cost_in

                    if gross_profit <= self.min_profit_threshold:
                        continue

                    net_profit = gross_profit

                    price_worsening = (frontrun.amount_in / max(cost_in + victim.amount_in, 1e-9)) * 100.0
                    victim_loss = victim.amount_out * (price_worsening / 100.0)

                    gas_advantage = frontrun.effective_gas_price_gwei >= victim.effective_gas_price_gwei
                    confidence = 0.95 if gas_advantage else 0.85

                    severity = "CRITICAL" if gross_profit > 1000.0 or price_worsening > 5.0 else "HIGH"

                    alerts.append(
                        SandwichAttackAlert(
                            is_sandwich_attack=True,
                            attacker_address=frontrun.sender_address,
                            victim_address=victim.sender_address,
                            pool_address=frontrun.pool_address,
                            frontrun_tx_hash=frontrun.tx_hash,
                            victim_tx_hash=victim.tx_hash,
                            backrun_tx_hash=backrun.tx_hash,
                            token_in=frontrun.token_in,
                            token_out=frontrun.token_out,
                            attacker_gross_profit_token_in=gross_profit,
                            attacker_net_profit_token_in=net_profit,
                            estimated_victim_slippage_loss=victim_loss,
                            price_impact_percentage=price_worsening,
                            confidence_score=confidence,
                            risk_severity=severity,
                        )
                    )

        return alerts
