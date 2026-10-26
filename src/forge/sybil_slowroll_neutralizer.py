from typing import List, Dict, Any, Tuple
import math
import numpy as np

class SybilSlowRollNeutralizer:
    """
    Detects high-frequency distributed botnets and slow-roll Sybil swarms
    that evade simple rate-limits by dilating micro-transactions across
    hundreds of rotating residential subnets.
    """

    def __init__(self, time_dilation_window_hours: float = 72.0, entropy_threshold: float = 1.2):
        self.time_dilation_window_hours = time_dilation_window_hours
        self.entropy_threshold = entropy_threshold

    def calculate_subnet_entropy(self, ip_addresses: List[str]) -> float:
        if not ip_addresses:
            return 0.0
        subnets = {}
        for ip in ip_addresses:
            parts = ip.split(".")
            subnet = ".".join(parts[:3]) if len(parts) >= 3 else ip
            subnets[subnet] = subnets.get(subnet, 0) + 1

        total = len(ip_addresses)
        entropy = 0.0
        for count in subnets.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return float(round(entropy, 4))

    def calculate_cadence_variance(self, timestamps: List[float]) -> float:
        if len(timestamps) < 3:
            return 999.0
        sorted_ts = sorted(timestamps)
        deltas = [sorted_ts[i] - sorted_ts[i - 1] for i in range(1, len(sorted_ts))]
        return float(round(float(np.var(deltas)), 4))

    def evaluate_cluster(self, transactions: List[Dict[str, Any]]) -> Dict[str, Any]:
        if len(transactions) < 5:
            return {
                "is_sybil_botnet": False,
                "risk_score": 0.1,
                "confidence": 0.5,
                "reason": "Insufficient transaction volume for Sybil cluster detection"
            }

        ips = [tx.get("ip", "0.0.0.0") for tx in transactions]
        timestamps = [tx.get("timestamp", 0.0) for tx in transactions]
        amounts = [tx.get("amount", 0.0) for tx in transactions]

        entropy = self.calculate_subnet_entropy(ips)
        cadence_var = self.calculate_cadence_variance(timestamps)
        amount_std = float(np.std(amounts))

        # Synthetic botnet signature: unnaturally regular cadences (low variance)
        # coupled with micro-amounts and coordinated subnet clusters
        is_synthetic_timing = cadence_var < 5.0
        is_uniform_amounts = amount_std < 0.5
        is_subnet_clustering = entropy < self.entropy_threshold

        sybil_signals = sum([is_synthetic_timing, is_uniform_amounts, is_subnet_clustering])
        risk_score = round(min(1.0, (sybil_signals * 0.35) + (0.2 if len(transactions) > 20 else 0.0)), 2)
        is_botnet = risk_score >= 0.70

        return {
            "is_sybil_botnet": is_botnet,
            "risk_score": risk_score,
            "entropy": entropy,
            "cadence_variance": cadence_var,
            "amount_std": round(amount_std, 4),
            "cluster_size": len(transactions),
            "action": "QUARANTINE_CLUSTER" if is_botnet else "ALLOW"
        }
