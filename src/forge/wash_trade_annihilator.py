"""
Temporal Graph Flow Correlation & Circular Wash-Trading Annihilator.

Detects cyclic wash-trading topologies where synthetic accounts route volume circularly
(e.g., A -> B -> C -> A) within a dynamic temporal window Delta t, conserving >= 90%
of aggregate liquidity to fabricate artificial market depth or harvest incentives.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional
import time


@dataclass
class TransactionFlow:
    flow_id: str
    sender: str
    receiver: str
    amount: float
    timestamp: float


@dataclass
class WashCycleReport:
    cycle_nodes: List[str]
    flow_ids: List[str]
    total_volume: float
    volume_conservation_ratio: float
    duration_seconds: float
    is_wash_trade: bool


class WashTradeAnnihilator:
    def __init__(
        self,
        max_cycle_length: int = 6,
        time_window_seconds: float = 3600.0,
        min_conservation_ratio: float = 0.90,
    ):
        self.max_cycle_length = max_cycle_length
        self.time_window_seconds = time_window_seconds
        self.min_conservation_ratio = min_conservation_ratio

    def find_simple_cycles(
        self,
        adj: Dict[str, List[Tuple[str, TransactionFlow]]],
        start_node: str,
    ) -> List[List[Tuple[str, TransactionFlow]]]:
        """Finds elementary cycles starting at start_node up to max_cycle_length using DFS."""
        cycles = []

        def dfs(
            current: str,
            path: List[Tuple[str, TransactionFlow]],
            visited: Set[str],
        ):
            if len(path) > self.max_cycle_length:
                return

            for neighbor, flow in adj.get(current, []):
                if neighbor == start_node and len(path) >= 2:
                    cycles.append(path + [(neighbor, flow)])
                elif neighbor not in visited and len(path) < self.max_cycle_length:
                    visited.add(neighbor)
                    dfs(neighbor, path + [(neighbor, flow)], visited)
                    visited.remove(neighbor)

        dfs(start_node, [], {start_node})
        return cycles

    def analyze_transactions(
        self, flows: List[TransactionFlow]
    ) -> List[WashCycleReport]:
        """Analyzes a stream of transaction flows and quarantines circular wash-trading loops."""
        if not flows:
            return []

        # Build adjacency graph
        adj: Dict[str, List[Tuple[str, TransactionFlow]]] = {}
        all_nodes: Set[str] = set()

        for f in flows:
            adj.setdefault(f.sender, []).append((f.receiver, f))
            all_nodes.add(f.sender)
            all_nodes.add(f.receiver)

        detected_reports: List[WashCycleReport] = []
        seen_cycles: Set[Tuple[str, ...]] = set()

        for node in sorted(all_nodes):
            raw_cycles = self.find_simple_cycles(adj, node)
            for cycle in raw_cycles:
                nodes = [node] + [step[0] for step in cycle[:-1]]
                canonical = tuple(sorted(nodes))
                if canonical in seen_cycles:
                    continue
                seen_cycles.add(canonical)

                cycle_flows = [step[1] for step in cycle]
                timestamps = [f.timestamp for f in cycle_flows]
                duration = max(timestamps) - min(timestamps)

                if duration > self.time_window_seconds:
                    continue

                amounts = [f.amount for f in cycle_flows]
                min_amount = min(amounts)
                max_amount = max(amounts)

                # Conservation ratio: how closely preserved the funds are along the loop
                conservation = min_amount / max_amount if max_amount > 0 else 0.0

                is_wash = conservation >= self.min_conservation_ratio

                detected_reports.append(
                    WashCycleReport(
                        cycle_nodes=nodes,
                        flow_ids=[f.flow_id for f in cycle_flows],
                        total_volume=sum(amounts),
                        volume_conservation_ratio=conservation,
                        duration_seconds=duration,
                        is_wash_trade=is_wash,
                    )
                )

        return detected_reports
