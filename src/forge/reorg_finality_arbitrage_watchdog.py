from dataclasses import dataclass

@dataclass
class ReorgFinalityAssessment:
    is_reorg_vulnerable: bool
    confirmation_depth: int
    required_safe_depth: int
    action: str

class ReorgFinalityArbitrageWatchdog:
    def evaluate_block_finality(
        self,
        chain_consensus_type: str, # "POW_NAKAMOTO" or "BFT_TENDERMINT" or "POS_GASPER"
        current_confirmations: int,
        transaction_amount_usd: float
    ) -> ReorgFinalityAssessment:
        if chain_consensus_type == "BFT_TENDERMINT":
            # Instant single-slot finality
            return ReorgFinalityAssessment(False, current_confirmations, 1, "PROCEED_IMMEDIATELY")

        # Nakamoto PoW or PoS probabilistic finality: higher value requires deeper confirmations
        required_depth = 6
        if transaction_amount_usd >= 1_000_000.0:
            required_depth = 32
        elif transaction_amount_usd >= 100_000.0:
            required_depth = 12

        is_vulnerable = current_confirmations < required_depth
        action = "WAIT_FOR_DEEPER_FINALITY" if is_vulnerable else "PROCEED"

        return ReorgFinalityAssessment(
            is_reorg_vulnerable=is_vulnerable,
            confirmation_depth=current_confirmations,
            required_safe_depth=required_depth,
            action=action
        )
