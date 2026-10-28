from dataclasses import dataclass

@dataclass
class BridgeSolvencyAssessment:
    is_solvent: bool
    collateralization_ratio_pct: float
    deficit_usd: float
    action: str

class BridgeCollateralDrainWatchdog:
    def verify_bridge_backing(
        self,
        l1_locked_collateral_usd: float,
        l2_minted_synthetic_usd: float,
        min_collateral_ratio_pct: float = 100.0
    ) -> BridgeSolvencyAssessment:
        if l2_minted_synthetic_usd <= 0:
            return BridgeSolvencyAssessment(True, 100.0, 0.0, "SOLVENT")

        ratio = (l1_locked_collateral_usd / l2_minted_synthetic_usd) * 100.0
        ratio = round(ratio, 2)
        deficit = max(0.0, l2_minted_synthetic_usd - l1_locked_collateral_usd)
        is_solvent = ratio >= 99.0 # Within 1% oracle rounding

        action = "HALT_SYNTHETIC_MINTING" if not is_solvent else "SOLVENT"

        return BridgeSolvencyAssessment(
            is_solvent=is_solvent,
            collateralization_ratio_pct=ratio,
            deficit_usd=round(deficit, 2),
            action=action
        )
