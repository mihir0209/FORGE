from dataclasses import dataclass
from typing import Dict, List, Set

@dataclass
class MicroStructuringAlert:
    is_smurfing_mule: bool
    cluster_account_count: int
    variance_ratio: float
    action: str

class MicroStructuringMuleSentinel:
    def evaluate_deposit_fan_out(
        self,
        deposit_amounts: List[float],
        distinct_destination_accounts: Set[str],
        window_minutes: float
    ) -> MicroStructuringAlert:
        if len(deposit_amounts) < 4:
            return MicroStructuringAlert(False, len(distinct_destination_accounts), 0.0, "ALLOW")

        avg = sum(deposit_amounts) / len(deposit_amounts)
        # Check standard deviation or coefficient of variation
        variance = sum((x - avg) ** 2 for x in deposit_amounts) / len(deposit_amounts)
        std_dev = variance ** 0.5
        cv = std_dev / max(0.01, avg)

        # Uniform low amounts (e.g. $490, $495, $492 across 5+ wallets in < 30m)
        is_smurfing = cv < 0.15 and len(distinct_destination_accounts) >= 4 and window_minutes <= 60.0
        return MicroStructuringAlert(
            is_smurfing_mule=is_smurfing,
            cluster_account_count=len(distinct_destination_accounts),
            variance_ratio=round(cv, 3),
            action="LOCK_CHAIN_DISPERSION" if is_smurfing else "ALLOW"
        )
