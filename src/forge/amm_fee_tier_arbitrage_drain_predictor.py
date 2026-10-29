from dataclasses import dataclass

@dataclass
class FeeTierArbitrageFinding:
    is_arbitrage_profitable: bool
    net_profit_usd: float
    effective_spread_bps: int
    action: str

class AmmFeeTierArbitrageDrainPredictor:
    def evaluate_cross_tier_discrepancy(
        self,
        price_tier_low_bps: float,  # e.g. 5 bps pool price $1000.00
        price_tier_high_bps: float, # e.g. 30 bps pool price $1005.00
        trade_volume_usd: float = 100_000.0,
        estimated_gas_cost_usd: float = 25.0
    ) -> FeeTierArbitrageFinding:
        discrepancy_bps = int(round(abs(price_tier_low_bps - price_tier_high_bps) / price_tier_low_bps * 10000.0))
        # Total fee to cross both pools: 5 bps + 30 bps = 35 bps
        total_fee_bps = 35
        gross_profit_usd = (discrepancy_bps / 10000.0) * trade_volume_usd
        fee_cost_usd = (total_fee_bps / 10000.0) * trade_volume_usd
        net_profit = gross_profit_usd - fee_cost_usd - estimated_gas_cost_usd

        is_profitable = net_profit > 10.0 # Meaningful profit
        action = "EXECUTE_MEV_JIT_LIQUIDITY_REBALANCE" if is_profitable else "HOLD_NO_PROFIT"

        return FeeTierArbitrageFinding(
            is_arbitrage_profitable=is_profitable,
            net_profit_usd=round(net_profit, 2),
            effective_spread_bps=discrepancy_bps,
            action=action
        )
