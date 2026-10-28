from dataclasses import dataclass
from typing import Dict, List

@dataclass
class ZeroDayDrainAlert:
    is_drain: bool
    contract_address: str
    depleted_pct: float
    recommended_action: str

class ZeroDayContractDrainSentinel:
    def evaluate_contract_outflow(
        self,
        contract: str,
        initial_balance_usd: float,
        outflows_last_10m_usd: float
    ) -> ZeroDayDrainAlert:
        depleted_pct = (outflows_last_10m_usd / max(1.0, initial_balance_usd)) * 100.0
        is_drain = depleted_pct >= 35.0
        return ZeroDayDrainAlert(
            is_drain=is_drain,
            contract_address=contract,
            depleted_pct=round(depleted_pct, 2),
            recommended_action="PAUSE_CONTRACT_EMERGENCY" if is_drain else "MONITOR"
        )
