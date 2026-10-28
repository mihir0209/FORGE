from dataclasses import dataclass
from typing import List

@dataclass
class GasSurgeAlert:
    is_surge_attack: bool
    base_fee_gwei: float
    spike_ratio: float
    mempool_exhaustion_detected: bool

class GasPriceSpikeSentinel:
    def __init__(self, spike_multiplier_threshold: float = 3.0):
        self.spike_multiplier_threshold = spike_multiplier_threshold

    def evaluate_block_gas(
        self,
        recent_average_base_fee: float,
        current_base_fee: float,
        gas_used_pct: float
    ) -> GasSurgeAlert:
        if recent_average_base_fee <= 0:
            return GasSurgeAlert(False, current_base_fee, 1.0, False)

        ratio = current_base_fee / recent_average_base_fee
        is_exhaustion = gas_used_pct >= 95.0
        is_surge = ratio >= self.spike_multiplier_threshold and is_exhaustion

        return GasSurgeAlert(
            is_surge_attack=is_surge,
            base_fee_gwei=round(current_base_fee, 1),
            spike_ratio=round(ratio, 2),
            mempool_exhaustion_detected=is_exhaustion
        )
