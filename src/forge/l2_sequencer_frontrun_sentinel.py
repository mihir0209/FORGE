from dataclasses import dataclass
from typing import Dict, List

@dataclass
class SequencerFrontrunAlert:
    is_sequencer_mev: bool
    sequencer_address: str
    block_latency_ms: float
    extracted_profit_usd: float
    risk_tier: str

class L2SequencerFrontrunSentinel:
    def evaluate_batch(
        self,
        sequencer_addr: str,
        sub_millisecond_ordering: bool,
        miner_extractable_value_usd: float,
        block_latency_ms: float
    ) -> SequencerFrontrunAlert:
        # Sequencers with private mempool advantage reordering transactions in < 50ms
        is_frontrun = sub_millisecond_ordering and miner_extractable_value_usd >= 1000.0 and block_latency_ms < 50.0
        risk = "CRITICAL_SEQUENCER_CORRUPTION" if is_frontrun else "NORMAL"
        return SequencerFrontrunAlert(
            is_sequencer_mev=is_frontrun,
            sequencer_address=sequencer_addr,
            block_latency_ms=block_latency_ms,
            extracted_profit_usd=miner_extractable_value_usd,
            risk_tier=risk
        )
