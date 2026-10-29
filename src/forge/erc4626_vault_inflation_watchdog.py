from dataclasses import dataclass

@dataclass
class VaultInflationAlert:
    is_inflation_attack_suspected: bool
    assets_per_share_ratio: float
    threat_level: str

class Erc4626VaultInflationWatchdog:
    def inspect_share_ratio(
        self,
        total_vault_assets: int,
        total_vault_shares: int
    ) -> VaultInflationAlert:
        if total_vault_shares <= 0:
            return VaultInflationAlert(False, 1.0, "INITIAL_EMPTY_VAULT")

        # In standard ERC-4626: assets_per_share = total_assets / total_shares
        ratio = total_vault_assets / total_vault_shares
        # If attacker donates massive assets while shares == 1 (e.g. 1 share backed by 1e18 assets)
        is_attack = ratio >= 1_000_000.0 and total_vault_shares <= 10

        return VaultInflationAlert(
            is_inflation_attack_suspected=is_attack,
            assets_per_share_ratio=round(ratio, 2),
            threat_level="CRITICAL_ERC4626_SHARE_INFLATION_ATTACK" if is_attack else "HEALTHY_SHARE_RATIO"
        )
