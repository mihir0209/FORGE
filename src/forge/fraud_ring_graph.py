"""Graph-Based Fraud Ring & Entity Resolution Engine for FORGE.

Resolves heterogeneous accounts into consolidated synthetic fraud clusters
based on multi-attribute linkages (shared IP subnets, device hashes, phone clusters,
synthetic identity roots), and detects cyclic transaction flows (smurfing/layering).
"""

from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class AccountNode:
    account_id: str
    phone: Optional[str] = None
    ip_address: Optional[str] = None
    device_hash: Optional[str] = None
    postal_code: Optional[str] = None
    ssn_hash: Optional[str] = None
    email: Optional[str] = None
    created_timestamp: float = 0.0


@dataclass
class TransactionFlow:
    source_id: str
    target_id: str
    amount: float
    timestamp: float
    channel: str = "wire"


@dataclass
class FraudRingCluster:
    cluster_id: str
    member_account_ids: List[str]
    shared_attributes: Dict[str, List[str]]
    risk_score: float
    detected_cycles: List[List[str]]
    total_flow_amount: float
    density: float
    hub_accounts: List[str]


@dataclass
class EntityResolutionReport:
    total_accounts: int
    resolved_clusters_count: int
    high_risk_clusters: List[FraudRingCluster]
    global_cycle_count: int
    overall_syndicate_risk: float


class FraudRingGraphEngine:
    """Multi-attribute entity resolution and transaction graph analyzer."""

    def __init__(self, cycle_max_hops: int = 6, risk_threshold: float = 0.65) -> None:
        self.cycle_max_hops = cycle_max_hops
        self.risk_threshold = risk_threshold
        self.nodes: Dict[str, AccountNode] = {}
        self.attribute_index: Dict[str, Dict[str, Set[str]]] = {
            "phone": defaultdict(set),
            "ip_address": defaultdict(set),
            "device_hash": defaultdict(set),
            "postal_code": defaultdict(set),
            "ssn_hash": defaultdict(set),
            "email_domain": defaultdict(set),
        }
        self.adjacency_list: Dict[str, Dict[str, List[TransactionFlow]]] = defaultdict(lambda: defaultdict(list))

    def register_account(self, node: AccountNode) -> None:
        """Register an account and index its attributes for entity resolution."""
        self.nodes[node.account_id] = node

        if node.phone:
            clean_phone = "".join(ch for ch in node.phone if ch.isdigit())
            if len(clean_phone) >= 7:
                self.attribute_index["phone"][clean_phone].add(node.account_id)

        if node.ip_address:
            parts = node.ip_address.split(".")
            if len(parts) == 4:
                subnet = ".".join(parts[:3])
                self.attribute_index["ip_address"][subnet].add(node.account_id)
            else:
                self.attribute_index["ip_address"][node.ip_address].add(node.account_id)

        if node.device_hash:
            self.attribute_index["device_hash"][node.device_hash].add(node.account_id)

        if node.postal_code:
            self.attribute_index["postal_code"][node.postal_code].add(node.account_id)

        if node.ssn_hash:
            self.attribute_index["ssn_hash"][node.ssn_hash].add(node.account_id)

        if node.email and "@" in node.email:
            domain = node.email.split("@")[-1].lower()
            if domain not in {"gmail.com", "yahoo.com", "outlook.com", "icloud.com"}:
                self.attribute_index["email_domain"][domain].add(node.account_id)

    def add_transaction(self, tx: TransactionFlow) -> None:
        """Add a directed transaction flow between accounts."""
        self.adjacency_list[tx.source_id][tx.target_id].append(tx)

    def find_connected_clusters(self) -> List[Set[str]]:
        """Identify connected components using shared attribute linkages."""
        adj: Dict[str, Set[str]] = defaultdict(set)

        for attr_type, values_map in self.attribute_index.items():
            weight_threshold = 2
            for attr_val, accounts in values_map.items():
                if len(accounts) >= weight_threshold:
                    acc_list = list(accounts)
                    for i in range(len(acc_list)):
                        for j in range(i + 1, len(acc_list)):
                            adj[acc_list[i]].add(acc_list[j])
                            adj[acc_list[j]].add(acc_list[i])

        for src, targets in self.adjacency_list.items():
            for tgt in targets.keys():
                adj[src].add(tgt)
                adj[tgt].add(src)

        visited: Set[str] = set()
        clusters: List[Set[str]] = []

        for acc_id in self.nodes.keys():
            if acc_id not in visited:
                cluster: Set[str] = set()
                queue: deque[str] = deque([acc_id])
                visited.add(acc_id)

                while queue:
                    curr = queue.popleft()
                    cluster.add(curr)
                    for neighbor in adj[curr]:
                        if neighbor not in visited and neighbor in self.nodes:
                            visited.add(neighbor)
                            queue.append(neighbor)

                if len(cluster) > 1:
                    clusters.append(cluster)

        return clusters

    def detect_cycles_in_cluster(self, members: Set[str]) -> List[List[str]]:
        """Detect circular layering transaction flows within a cluster up to cycle_max_hops."""
        cycles: List[List[str]] = []
        visited_cycles: Set[Tuple[str, ...]] = set()

        def dfs(start: str, current: str, path: List[str], depth: int) -> None:
            if depth > self.cycle_max_hops:
                return

            for neighbor in self.adjacency_list.get(current, {}).keys():
                if neighbor not in members:
                    continue
                if neighbor == start and len(path) >= 3:
                    min_idx = path.index(min(path))
                    canon = tuple(path[min_idx:] + path[:min_idx])
                    if canon not in visited_cycles:
                        visited_cycles.add(canon)
                        cycles.append(list(canon))
                elif neighbor not in path:
                    dfs(start, neighbor, path + [neighbor], depth + 1)

        for member in members:
            dfs(member, member, [member], 1)

        return cycles

    def compute_cluster_metrics(self, members: Set[str], cluster_idx: int) -> FraudRingCluster:
        """Compute structural risk, flow volume, density, and hub centrality for a cluster."""
        member_list = sorted(members)
        n = len(member_list)

        internal_edges = 0
        total_flow = 0.0
        degree: Dict[str, int] = defaultdict(int)

        for src in members:
            for tgt, flows in self.adjacency_list.get(src, {}).items():
                if tgt in members:
                    internal_edges += 1
                    degree[src] += 1
                    degree[tgt] += 1
                    total_flow += sum(f.amount for f in flows)

        possible_edges = n * (n - 1) if n > 1 else 1
        density = internal_edges / possible_edges if possible_edges > 0 else 0.0

        hub_accounts = sorted(member_list, key=lambda a: degree[a], reverse=True)[:3]

        shared_attrs: Dict[str, List[str]] = defaultdict(list)
        for attr, val_map in self.attribute_index.items():
            for val, accs in val_map.items():
                overlap = accs.intersection(members)
                if len(overlap) >= 2:
                    shared_attrs[attr].append(f"{val} ({len(overlap)} accounts)")

        cycles = self.detect_cycles_in_cluster(members)

        size_factor = min(1.0, math.log2(max(2, n)) / 4.0)
        cycle_factor = min(1.0, len(cycles) * 0.5) if cycles else 0.0
        density_factor = min(1.0, density * 1.5)
        shared_factor = min(1.0, len(shared_attrs) * 0.3)

        base_risk = (
            0.40 * cycle_factor
            + 0.25 * shared_factor
            + 0.20 * size_factor
            + 0.15 * density_factor
        )
        if cycles:
            base_risk += 0.25  # Laundering cycles provide immediate severe risk bonus

        risk_score = round(min(1.0, max(0.0, base_risk)), 4)

        return FraudRingCluster(
            cluster_id=f"RING-{cluster_idx:04d}",
            member_account_ids=member_list,
            shared_attributes=dict(shared_attrs),
            risk_score=risk_score,
            detected_cycles=cycles,
            total_flow_amount=round(total_flow, 2),
            density=round(density, 4),
            hub_accounts=hub_accounts,
        )

    def analyze(self) -> EntityResolutionReport:
        """Execute complete entity resolution and fraud ring detection."""
        clusters_raw = self.find_connected_clusters()
        clusters: List[FraudRingCluster] = []
        total_cycles = 0

        for idx, member_set in enumerate(clusters_raw, 1):
            cl = self.compute_cluster_metrics(member_set, idx)
            clusters.append(cl)
            total_cycles += len(cl.detected_cycles)

        high_risk = [c for c in clusters if c.risk_score >= self.risk_threshold]
        avg_risk = sum(c.risk_score for c in clusters) / len(clusters) if clusters else 0.0

        return EntityResolutionReport(
            total_accounts=len(self.nodes),
            resolved_clusters_count=len(clusters),
            high_risk_clusters=high_risk,
            global_cycle_count=total_cycles,
            overall_syndicate_risk=round(avg_risk, 4),
        )
