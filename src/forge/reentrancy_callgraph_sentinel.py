from dataclasses import dataclass
from typing import List

@dataclass
class ReentrancyFinding:
    is_reentrancy_vulnerable: bool
    state_update_after_external_call: bool
    risk_level: str

class ReentrancyCallgraphSentinel:
    def audit_execution_sequence(self, instructions: List[str]) -> ReentrancyFinding:
        has_ext_call = False
        vulnerable = False

        for inst in instructions:
            if "CALL" in inst or "DELEGATECALL" in inst or "RAW_CALL" in inst:
                has_ext_call = True
            elif ("SSTORE" in inst or "WRITE_BALANCE" in inst) and has_ext_call:
                vulnerable = True

        return ReentrancyFinding(
            is_reentrancy_vulnerable=vulnerable,
            state_update_after_external_call=vulnerable,
            risk_level="CRITICAL_CHECKS_EFFECTS_INTERACTIONS_VIOLATION" if vulnerable else "SAFE"
        )
