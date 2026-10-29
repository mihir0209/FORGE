from dataclasses import dataclass
from typing import List

@dataclass
class CentralityEvasionMetrics:
    is_evasion_detected: bool
    degree_dispersion_ratio: float
    centrality_flattening_score: float

class GraphAnomalyCentralityEvasionPredictor:
    def evaluate_node_centrality(
        self,
        in_degrees: List[int],
        out_degrees: List[int]
    ) -> CentralityEvasionMetrics:
        if not in_degrees or not out_degrees:
            return CentralityEvasionMetrics(False, 0.0, 0.0)

        # Money laundering ring dispersion: Sybil peel chains disperse high volume through uniform 1-to-1 hops
        # Mean degree ~ 1, variance ~ 0
        total_deg = [a + b for a, b in zip(in_degrees, out_degrees)]
        mean_deg = sum(total_deg) / len(total_deg)
        var_deg = sum((d - mean_deg) ** 2 for d in total_deg) / len(total_deg)

        # Uniform peeling chain has very low variance (< 0.20) with multiple hops
        is_evasion = var_deg <= 0.25 and len(total_deg) >= 6
        flattening = round(1.0 / (1.0 + var_deg), 3)

        return CentralityEvasionMetrics(
            is_evasion_detected=is_evasion,
            degree_dispersion_ratio=round(var_deg, 3),
            centrality_flattening_score=flattening
        )
