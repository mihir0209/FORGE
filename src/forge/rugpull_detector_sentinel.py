"""
FORGE Automated Liquidity Pool Rug-Pull & Lock Removal Sentinel.
Detects sudden removal of LP tokens by project deployers.
"""
from dataclasses import dataclass

@dataclass
class RugpullAlert:
    is_rugpull: bool
    pool_address: str
    removed_lp_pct: float
    action: str

class RugpullDetectorSentinel:
    def check_liquidity_removal(self, pool: str, initial_lp: float, removed_lp: float, is_deployer: bool) -> RugpullAlert:
        removal_pct = (removed_lp / max(1.0, initial_lp)) * 100.0
        is_rug = is_deployer and removal_pct >= 50.0
        return RugpullAlert(
            is_rugpull=is_rug,
            pool_address=pool,
            removed_lp_pct=round(removal_pct, 2),
            action="EMERGENCY_FREEZE_POOL" if is_rug else "ALLOW",
        )
