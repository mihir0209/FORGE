from dataclasses import dataclass
from typing import Dict, List, Set

@dataclass
class MixerProximityResult:
    is_high_sanction_risk: bool
    shortest_hop_distance: int
    risk_score: float
    action: str

class MixerHopProximityScorer:
    def __init__(self, sanctioned_clusters: Set[str], max_flagged_hops: int = 3):
        self.sanctioned_clusters = {a.lower() for a in sanctioned_clusters}
        self.max_flagged_hops = max_flagged_hops

    def compute_proximity(
        self,
        source_address: str,
        transaction_graph: Dict[str, Set[str]] # addr -> set of outgoing recipient addrs
    ) -> MixerProximityResult:
        src = source_address.lower()
        if src in self.sanctioned_clusters:
            return MixerProximityResult(True, 0, 1.0, "BLOCK_IMMEDIATE_OFAC_HIT")

        # Breadth-first search for shortest path to any sanctioned address
        norm_graph = {k.lower(): {v.lower() for v in vals} for k, vals in transaction_graph.items()}
        queue = [(src, 0)]
        visited = {src}

        while queue:
            curr, hops = queue.pop(0)
            if hops >= self.max_flagged_hops:
                continue

            for neighbor in norm_graph.get(curr, set()):
                n_lower = neighbor.lower()
                if n_lower in self.sanctioned_clusters:
                    hop_dist = hops + 1
                    risk = max(0.2, 1.0 - (hop_dist - 1) * 0.25)
                    action = "FREEZE_DEPOSIT_REVIEW" if hop_dist <= 2 else "FLAG_MONITORING"
                    return MixerProximityResult(True, hop_dist, round(risk, 2), action)
                if n_lower not in visited:
                    visited.add(n_lower)
                    queue.append((n_lower, hops + 1))

        return MixerProximityResult(False, 999, 0.05, "ALLOW")
