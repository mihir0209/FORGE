from dataclasses import dataclass
from typing import List

@dataclass
class CrossCpiReentrancyAlert:
    is_cpi_reentrancy_detected: bool
    reentrant_program_id: str
    call_depth: int
    security_action: str

class SolanaCrossCpiReentrancyWatchdog:
    def inspect_cpi_stack(
        self,
        current_program_id: str,
        execution_call_stack: List[str] # ["prog_a", "prog_b", "prog_a"]
    ) -> CrossCpiReentrancyAlert:
        # Cross-CPI reentrancy occurs when a program appears multiple times in the active execution call stack
        occurrences = execution_call_stack.count(current_program_id)
        is_reentrant = occurrences >= 2
        depth = len(execution_call_stack)

        action = "ABORT_TRANSACTION_CPI_REENTRANCY_TRAP" if is_reentrant else "PERMIT_SAFE_CPI"

        return CrossCpiReentrancyAlert(
            is_cpi_reentrancy_detected=is_reentrant,
            reentrant_program_id=current_program_id if is_reentrant else "NONE",
            call_depth=depth,
            security_action=action
        )
