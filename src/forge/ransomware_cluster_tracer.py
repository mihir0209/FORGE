from dataclasses import dataclass
from typing import Dict, List, Set

@dataclass
class RansomwareTraceResult:
    is_ransomware_taint: bool
    hop_count: int
    mixer_interaction: bool
    tainted_amount_btc: float

class RansomwareBtcClusterTracer:
    def __init__(self, known_ransomware_seeds: Set[str], known_mixers: Set[str]):
        self.seeds = {s.lower() for s in known_ransomware_seeds}
        self.mixers = {m.lower() for m in known_mixers}

    def trace_utxo_lineage(
        self,
        transaction_path: List[Dict[str, any]] # [{'from': str, 'to': str, 'btc': float}]
    ) -> RansomwareTraceResult:
        current_tainted = False
        hop_count = 0
        mixer_seen = False
        amount = 0.0

        for hop in transaction_path:
            src = hop["from"].lower()
            dst = hop["to"].lower()
            if src in self.seeds or current_tainted:
                current_tainted = True
                hop_count += 1
                amount = hop.get("btc", 0.0)
                if dst in self.mixers:
                    mixer_seen = True
                    break

        return RansomwareTraceResult(
            is_ransomware_taint=current_tainted,
            hop_count=hop_count,
            mixer_interaction=mixer_seen,
            tainted_amount_btc=round(amount, 4)
        )
