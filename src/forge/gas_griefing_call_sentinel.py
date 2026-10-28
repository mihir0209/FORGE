from dataclasses import dataclass
from typing import Optional

@dataclass
class GasGriefingAlert:
    is_griefing_attack: bool
    forwarded_gas_units: int
    unconsumed_gas_burned: int
    severity: str

class GasGriefingCallSentinel:
    def evaluate_low_level_call(
        self,
        target_contract: str,
        forwarded_gas: int,
        consumed_gas: int,
        revert_data_bytes_len: int
    ) -> GasGriefingAlert:
        # EIP-150 63/64th gas rule exploitation: contract forces parent call into OOM or Burns 95%+ of gas
        burn_ratio = consumed_gas / max(1, forwarded_gas)
        # Griefing signature: forwarding 500k+ gas, burning >= 90% without productive state transition, or large return bomb
        is_grief = (forwarded_gas >= 500_000 and burn_ratio >= 0.90) or revert_data_bytes_len >= 50_000
        severity = "CRITICAL_GAS_DRAIN" if is_grief else "NORMAL"

        return GasGriefingAlert(
            is_griefing_attack=is_grief,
            forwarded_gas_units=forwarded_gas,
            unconsumed_gas_burned=consumed_gas,
            severity=severity
        )
