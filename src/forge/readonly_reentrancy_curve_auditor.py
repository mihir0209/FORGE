from dataclasses import dataclass

@dataclass
class ReadOnlyReentrancyAlert:
    is_transient_price_manipulated: bool
    virtual_price_drop_bps: int
    exploit_risk_tier: str

class ReadOnlyReentrancyCurveAuditor:
    def inspect_transient_pool_state(
        self,
        is_inside_remove_liquidity_hook: bool,
        nominal_virtual_price: float,
        transient_virtual_price: float
    ) -> ReadOnlyReentrancyAlert:
        # Read-only reentrancy attack occurs when an external view caller reads virtual_price
        # while inside remove_liquidity before balances are synced (transient virtual_price crashes)
        drop_bps = int(round(abs(nominal_virtual_price - transient_virtual_price) / nominal_virtual_price * 10000.0))
        is_manipulated = is_inside_remove_liquidity_hook and drop_bps >= 50

        tier = "CRITICAL_READONLY_REENTRANCY_LENDING_ORACLE_DRAIN" if is_manipulated else "SAFE_SYNCED_VIRTUAL_PRICE"

        return ReadOnlyReentrancyAlert(
            is_transient_price_manipulated=is_manipulated,
            virtual_price_drop_bps=drop_bps,
            exploit_risk_tier=tier
        )
