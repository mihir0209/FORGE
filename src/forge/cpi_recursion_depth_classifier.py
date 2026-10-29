from dataclasses import dataclass

@dataclass
class CpiDepthAlert:
    is_cpi_limit_exceeded: bool
    current_depth: int
    action: str

class CpiRecursionDepthClassifier:
    MAX_SOLANA_CPI_DEPTH = 4

    def check_call_chain_depth(self, current_cpi_depth: int) -> CpiDepthAlert:
        is_exceeded = current_cpi_depth > self.MAX_SOLANA_CPI_DEPTH
        action = "TRAP_CPI_CALL_DEPTH_EXHAUSTION" if is_exceeded else "PERMIT_CPI_INVOCATION"

        return CpiDepthAlert(
            is_cpi_limit_exceeded=is_exceeded,
            current_depth=current_cpi_depth,
            action=action
        )
