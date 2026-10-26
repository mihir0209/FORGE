"""Merchant Collusion & Triangular Money Mule Network Graph Detector.

Identifies collusive merchant clusters and circular fund flows designed to
launder stolen card proceeds or execute fraudulent chargeback bust-outs.
"""

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple


@dataclass
class TransactionEdge:
    source_entity: str
    target_entity: str
    amount: float
    timestamp_epoch: float


@dataclass
class MuleNetworkAlert:
    network_flagged: bool
    cycles_detected: List[List[str]]
    total_laundered_volume: float
    high_risk_entities: Set[str]
    alert_severity: str  # NONE, MEDIUM, HIGH, CRITICAL


class MerchantMuleDetector:
    def __init__(self, cycle_max_length: int = 4, volume_velocity_threshold: float = 10000.0):
        self.cycle_max_length = cycle_max_length
        self.volume_velocity_threshold = volume_velocity_threshold
        # Adjacency list: source -> List of TransactionEdge
        self.graph: Dict[str, List[TransactionEdge]] = defaultdict(list)

    def record_transfer(self, source: str, target: str, amount: float, timestamp: float) -> None:
        self.graph[source].append(TransactionEdge(source, target, amount, timestamp))

    def detect_cycles(self) -> List[List[str]]:
        """Finds circular payment paths up to cycle_max_length."""
        all_cycles: List[List[str]] = []
        visited_globally: Set[str] = set()

        def dfs(current: str, start: str, path: List[str], depth: int):
            if depth > self.cycle_max_length:
                return
            for edge in self.graph.get(current, []):
                next_node = edge.target_entity
                if next_node == start and len(path) >= 2:
                    all_cycles.append(path + [start])
                elif next_node not in path and len(path) < self.cycle_max_length:
                    dfs(next_node, start, path + [next_node], depth + 1)

        nodes = list(self.graph.keys())
        for node in nodes:
            dfs(node, node, [node], 1)

        # Canonicalize cycles to remove duplicates
        unique_cycles: List[List[str]] = []
        seen = set()
        for cycle in all_cycles:
            nodes_tuple = tuple(sorted(cycle[:-1]))
            if nodes_tuple not in seen:
                seen.add(nodes_tuple)
                unique_cycles.append(cycle)

        return unique_cycles

    def analyze_network(self) -> MuleNetworkAlert:
        cycles = self.detect_cycles()
        high_risk_entities: Set[str] = set()
        total_volume = 0.0

        for cycle in cycles:
            for entity in cycle[:-1]:
                high_risk_entities.add(entity)

        # Sum volume across high-risk edges
        for source, edges in self.graph.items():
            for edge in edges:
                if edge.source_entity in high_risk_entities or edge.target_entity in high_risk_entities:
                    total_volume += edge.amount

        flagged = len(cycles) > 0 or total_volume >= self.volume_velocity_threshold

        if len(cycles) >= 2 or (len(cycles) >= 1 and total_volume >= self.volume_velocity_threshold):
            severity = "CRITICAL"
        elif len(cycles) == 1:
            severity = "HIGH"
        elif total_volume >= self.volume_velocity_threshold:
            severity = "MEDIUM"
        else:
            severity = "NONE"

        return MuleNetworkAlert(
            network_flagged=flagged,
            cycles_detected=cycles,
            total_laundered_volume=total_volume,
            high_risk_entities=high_risk_entities,
            alert_severity=severity,
        )
