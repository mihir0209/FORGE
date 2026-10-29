from dataclasses import dataclass

@dataclass
class FlashLoanTwapAlert:
    manipulation_detected: bool
    spot_to_twap_deviation_bps: int
    action: str

class FlashLoanTwapSandwichGuard:
    def inspect_oracle_deviation(
        self,
        spot_price: float,
        twap_price: float,
        max_allowed_deviation_bps: int = 150 # 1.5% max tolerance
    ) -> FlashLoanTwapAlert:
        if spot_price <= 0 or twap_price <= 0:
            return FlashLoanTwapAlert(True, 9999, "REVERT_TRANSACTION_INVALID_ORACLE")

        deviation = abs(spot_price - twap_price) / twap_price
        deviation_bps = int(round(deviation * 10000.0))

        is_manipulated = deviation_bps > max_allowed_deviation_bps
        action = "REVERT_TRANSACTION_FLASHLOAN_ORACLE_MANIPULATION" if is_manipulated else "ALLOW_EXECUTION"

        return FlashLoanTwapAlert(
            manipulation_detected=is_manipulated,
            spot_to_twap_deviation_bps=deviation_bps,
            action=action
        )
