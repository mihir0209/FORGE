from dataclasses import dataclass
from typing import List

@dataclass
class WardrobingRiskAssessment:
    is_wardrobing_fraud: bool
    return_rate_pct: float
    high_value_return_count: int
    account_action: str

class EcommerceReturnWardrobingSentinel:
    def __init__(self, high_value_threshold_usd: float = 300.0, return_rate_ceiling_pct: float = 65.0):
        self.high_value_threshold_usd = high_value_threshold_usd
        self.return_rate_ceiling_pct = return_rate_ceiling_pct

    def evaluate_account_history(
        self,
        purchased_item_prices: List[float],
        returned_item_prices: List[float],
        account_age_days: int
    ) -> WardrobingRiskAssessment:
        if len(purchased_item_prices) == 0:
            return WardrobingRiskAssessment(False, 0.0, 0, "ALLOW")

        return_rate = (len(returned_item_prices) / len(purchased_item_prices)) * 100.0
        high_value_returns = sum(1 for p in returned_item_prices if p >= self.high_value_threshold_usd)

        # Wardrobing signature: returning >= 65% of orders with multiple high-value items within new account
        is_fraud = return_rate >= self.return_rate_ceiling_pct and high_value_returns >= 2
        action = "RESTRICT_RETURN_PRIVILEGES" if is_fraud else "ALLOW"

        return WardrobingRiskAssessment(
            is_wardrobing_fraud=is_fraud,
            return_rate_pct=round(return_rate, 1),
            high_value_return_count=high_value_returns,
            account_action=action
        )
