from dataclasses import dataclass
from typing import Dict, List, Optional

@dataclass
class SandbaggingAlert:
    is_sandbagging: bool
    pool_address: str
    reserve_imbalance_ratio: float
    manipulation_vector: str

class DexSandbaggingSentinel:
    def __init__(self, imbalance_threshold: float = 3.5):
        self.imbalance_threshold = imbalance_threshold

    def evaluate_pool_injection(
        self,
        pool_address: str,
        reserve_token_a: float,
        reserve_token_b: float,
        injected_token_a: float,
        injected_token_b: float
    ) -> SandbaggingAlert:
        if reserve_token_a <= 0 or reserve_token_b <= 0:
            return SandbaggingAlert(False, pool_address, 1.0, "INVALID_RESERVES")

        # Check one-sided single-token massive injection
        ratio_a = injected_token_a / reserve_token_a
        ratio_b = injected_token_b / reserve_token_b if reserve_token_b > 0 else 0

        imbalance_delta = abs(ratio_a - ratio_b)
        is_attack = imbalance_delta >= self.imbalance_threshold and (ratio_a > 1.0 or ratio_b > 1.0)
        vector = "ONE_SIDED_TWAP_SKEW_INJECTION" if is_attack else "BALANCED_OR_BENIGN"

        return SandbaggingAlert(
            is_sandbagging=is_attack,
            pool_address=pool_address,
            reserve_imbalance_ratio=round(imbalance_delta, 2),
            manipulation_vector=vector
        )
