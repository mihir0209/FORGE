from dataclasses import dataclass
from typing import List, Optional

@dataclass
class JitoSandwichAlert:
    is_jito_sandwich: bool
    leader_bundle_id: str
    victim_slippage_extracted_sol: float
    risk_level: str

class JitoSubslotSandwichTracer:
    def evaluate_bundle_ordering(
        self,
        bundle_id: str,
        transaction_signatures: List[str],
        tip_amount_lamports: int,
        target_swap_account: str
    ) -> JitoSandwichAlert:
        # Canonical Jito 3-tx sandwich inside a single auction bundle
        is_sandwich = len(transaction_signatures) == 3 and tip_amount_lamports >= 1_000_000 # >= 0.001 SOL tip
        extracted_sol = (tip_amount_lamports / 1_000_000_000.0) * 4.0 if is_sandwich else 0.0

        return JitoSandwichAlert(
            is_jito_sandwich=is_sandwich,
            leader_bundle_id=bundle_id,
            victim_slippage_extracted_sol=round(extracted_sol, 4),
            risk_level="CRITICAL_MEV_PREDATION" if is_sandwich else "BENIGN"
        )
