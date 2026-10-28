from dataclasses import dataclass
from typing import List, Dict, Set

@dataclass
class PercolationMetrics:
    giant_component_size: int
    is_synthetic_ring_detected: bool
    percolation_risk_score: float

class SyntheticIdentityPercolationAnalyzer:
    def analyze_shared_attribute_graph(
        self,
        identity_nodes: List[str],
        shared_attribute_edges: List[tuple] # [("id1", "id2"), ("id2", "id3")]
    ) -> PercolationMetrics:
        # Build adjacency
        adj: Dict[str, Set[str]] = {n: set() for n in identity_nodes}
        for u, v in shared_attribute_edges:
            if u in adj and v in adj:
                adj[u].add(v)
                adj[v].add(u)

        # Find connected components
        visited = set()
        max_comp = 0

        for node in identity_nodes:
            if node not in visited:
                comp_size = 0
                q = [node]
                visited.add(node)
                while q:
                    curr = q.pop()
                    comp_size += 1
                    for neighbor in adj[curr]:
                        if neighbor not in visited:
                            visited.add(neighbor)
                            q.append(neighbor)
                if comp_size > max_comp:
                    max_comp = comp_size

        is_ring = max_comp >= 5
        score = min(1.0, max_comp / 10.0)

        return PercolationMetrics(
            giant_component_size=max_comp,
            is_synthetic_ring_detected=is_ring,
            percolation_risk_score=round(score, 2)
        )
