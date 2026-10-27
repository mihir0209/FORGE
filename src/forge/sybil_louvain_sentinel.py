"""
FORGE Sybil Cluster Graph Community Detection Sentinel.
Detects synchronized clusters of accounts transferring micro-funds among dense cliques.
"""
from dataclasses import dataclass
from typing import Dict, List, Set

@dataclass
class SybilClusterFinding:
    cluster_id: str
    member_addresses: List[str]
    inter_cluster_density: float
    is_sybil_cluster: bool

class SybilLouvainSentinel:
    def __init__(self, min_cluster_size: int = 3, density_threshold: float = 0.6):
        self.min_cluster_size = min_cluster_size
        self.density_threshold = density_threshold

    def analyze_graph(self, adjacency: Dict[str, Set[str]]) -> List[SybilClusterFinding]:
        findings = []
        visited = set()
        for node, neighbors in adjacency.items():
            if node in visited:
                continue
            component = {node} | neighbors
            visited.update(component)
            if len(component) >= self.min_cluster_size:
                # Compute edge density
                n = len(component)
                possible_edges = n * (n - 1) / 2
                actual_edges = sum(len(adjacency.get(m, set()) & component) for m in component) / 2
                density = actual_edges / max(1.0, possible_edges)
                if density >= self.density_threshold:
                    findings.append(SybilClusterFinding(
                        cluster_id=f"sybil_{node[:8]}",
                        member_addresses=sorted(list(component)),
                        inter_cluster_density=round(density, 2),
                        is_sybil_cluster=True,
                    ))
        return findings
