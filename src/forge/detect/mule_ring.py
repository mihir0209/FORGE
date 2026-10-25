# pyright: reportMissingTypeStubs=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportMissingTypeArgument=false
"""Money Mule Graph Ring Detector: identifies circular wash trading and fan-out/fan-in funds pooling.

Models transaction flows as a directed graph using networkx, detects cycles and flow
pooling patterns, and scores candidate mule rings with confidence metrics.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import networkx as nx
from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from collections.abc import Iterable

    from forge.contracts.contracts import ObservedTraceView, SyntheticTrace, TraceEvent


class MuleTransaction(BaseModel):
    """Normalized transaction edge in the money flow graph."""

    tx_id: str
    source: str
    destination: str
    amount: float
    timestamp: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


class MuleRing(BaseModel):
    """Identified money mule ring or flow aggregation structure."""

    ring_id: str
    pattern_type: str  # "circular_wash" | "fan_out_fan_in"
    cycle_path: list[str]  # e.g. ["A", "B", "C", "A"] or ["S", "M1", "M2", "C"]
    nodes: list[str]
    transaction_ids: list[str]
    total_volume: float
    confidence_score: float  # [0.0, 1.0]
    time_window_seconds: float
    hop_count: int
    details: dict[str, Any] = Field(default_factory=dict)


class MuleRingDetectionResult(BaseModel):
    """Aggregate result from graph analysis."""

    total_nodes: int
    total_edges: int
    total_transactions: int
    rings_detected: int
    rings: list[MuleRing]


@dataclass
class EdgeData:
    transactions: list[MuleTransaction] = field(default_factory=list)

    @property
    def total_amount(self) -> float:
        return sum(tx.amount for tx in self.transactions)

    @property
    def count(self) -> int:
        return len(self.transactions)

    @property
    def first_timestamp(self) -> datetime | None:
        if not self.transactions:
            return None
        return min(tx.timestamp for tx in self.transactions)

    @property
    def last_timestamp(self) -> datetime | None:
        if not self.transactions:
            return None
        return max(tx.timestamp for tx in self.transactions)


class MuleRingDetector:
    """Detects money mule rings, circular wash trading, and smurfing/pooling structures."""

    def __init__(self) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()
        self._tx_registry: dict[str, MuleTransaction] = {}

    def add_transaction(
        self,
        source: str,
        destination: str,
        amount: float,
        timestamp: datetime | None = None,
        tx_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> MuleTransaction:
        """Add a transaction edge to the graph."""
        if not source or not destination or source == destination:
            # Self-loops are ignored for mule rings
            raise ValueError("source and destination must be non-empty and distinct")

        ts = timestamp or datetime.now(UTC)
        tid = tx_id or f"tx_{uuid.uuid4().hex[:12]}"
        tx = MuleTransaction(
            tx_id=tid,
            source=source,
            destination=destination,
            amount=round(float(amount), 2),
            timestamp=ts,
            metadata=metadata or {},
        )
        self._tx_registry[tid] = tx

        if not self.graph.has_node(source):
            self.graph.add_node(source)
        if not self.graph.has_node(destination):
            self.graph.add_node(destination)

        if self.graph.has_edge(source, destination):
            data: EdgeData = self.graph[source][destination]["data"]
            data.transactions.append(tx)
        else:
            edge_data = EdgeData(transactions=[tx])
            self.graph.add_edge(source, destination, data=edge_data)

        return tx

    def ingest_events(
        self,
        events: Iterable[TraceEvent],
    ) -> int:
        """Ingest transactions from trace events."""
        ingested = 0
        for event in events:
            if event.kind != "payment":
                continue
            p = event.payload
            src = str(p.get("customer") or p.get("source_account") or event.actor_id)
            dst = str(p.get("destination_account") or p.get("merchant") or "")
            amt = float(p.get("amount", 0.0))
            if src and dst and src != dst and amt > 0:
                self.add_transaction(
                    source=src,
                    destination=dst,
                    amount=amt,
                    timestamp=event.ts,
                    tx_id=event.event_id,
                    metadata=p,
                )
                ingested += 1
        return ingested

    def ingest_trace(self, trace: SyntheticTrace | ObservedTraceView) -> int:
        """Ingest all events from a SyntheticTrace or ObservedTraceView."""
        return self.ingest_events(trace.events)

    # ------------------------------------------------------------------ circular wash trading

    def detect_circular_wash(
        self,
        *,
        min_cycle_length: int = 2,
        max_cycle_length: int = 6,
        time_window_hours: float = 72.0,
        min_flow_preservation: float = 0.50,
    ) -> list[MuleRing]:
        """Detect circular transaction paths (e.g. A -> B -> C -> A)."""
        rings: list[MuleRing] = []
        if self.graph.number_of_nodes() < min_cycle_length:
            return rings

        # Find simple cycles
        try:
            raw_cycles = list(nx.simple_cycles(self.graph))
        except Exception:
            raw_cycles = []

        seen_rings: set[frozenset[str]] = set()

        for cycle in raw_cycles:
            cycle_len = len(cycle)
            if cycle_len < min_cycle_length or cycle_len > max_cycle_length:
                continue

            cycle_nodes_set = frozenset(cycle)
            if cycle_nodes_set in seen_rings:
                continue
            seen_rings.add(cycle_nodes_set)

            # Reconstruct cycle edges: (u, v) pairs
            cycle_edges: list[tuple[str, str]] = []
            for i in range(cycle_len):
                u = cycle[i]
                v = cycle[(i + 1) % cycle_len]
                cycle_edges.append((u, v))

            # Inspect transactions along edges
            hop_amounts: list[float] = []
            all_tx_ids: list[str] = []
            hop_times: list[datetime] = []

            valid_cycle = True
            for u, v in cycle_edges:
                if not self.graph.has_edge(u, v):
                    valid_cycle = False
                    break
                edge_data: EdgeData = self.graph[u][v]["data"]
                hop_amounts.append(edge_data.total_amount)
                for tx in edge_data.transactions:
                    all_tx_ids.append(tx.tx_id)
                    hop_times.append(tx.timestamp)

            if not valid_cycle or not hop_amounts or not hop_times:
                continue

            min_amt = min(hop_amounts)
            max_amt = max(hop_amounts)
            if max_amt <= 0:
                continue

            # Amount conservation / preservation ratio across the ring
            flow_preservation = min_amt / max_amt
            if flow_preservation < min_flow_preservation:
                continue

            t_min = min(hop_times)
            t_max = max(hop_times)
            duration_sec = (t_max - t_min).total_seconds()
            duration_hours = duration_sec / 3600.0

            if duration_hours > time_window_hours:
                continue

            # Compute confidence score
            # 1. Flow preservation weight: 0.45
            score_flow = flow_preservation
            # 2. Velocity/temporal compactness weight: 0.35 (faster = higher score)
            score_time = max(0.0, 1.0 - (duration_hours / time_window_hours))
            # 3. Compact cycle factor: 0.20 (shorter cycles are harder to form accidentally)
            score_length = max(0.0, 1.0 - ((cycle_len - 2) / float(max_cycle_length)))

            confidence = round(0.45 * score_flow + 0.35 * score_time + 0.20 * score_length, 3)
            confidence = min(max(confidence, 0.1), 0.99)

            cycle_path = [*cycle, cycle[0]]
            ring_id = f"ring_wash_{uuid.uuid4().hex[:8]}"

            rings.append(
                MuleRing(
                    ring_id=ring_id,
                    pattern_type="circular_wash",
                    cycle_path=cycle_path,
                    nodes=cycle,
                    transaction_ids=all_tx_ids,
                    total_volume=round(sum(hop_amounts), 2),
                    confidence_score=confidence,
                    time_window_seconds=round(duration_sec, 2),
                    hop_count=cycle_len,
                    details={
                        "hop_amounts": [round(a, 2) for a in hop_amounts],
                        "flow_preservation_ratio": round(flow_preservation, 4),
                        "duration_hours": round(duration_hours, 2),
                    },
                )
            )

        return sorted(rings, key=lambda r: -r.confidence_score)

    # ------------------------------------------------------------------ fan-out / fan-in pooling

    def detect_fan_out_fan_in(
        self,
        *,
        min_mules: int = 2,
        max_mules: int = 20,
        time_window_hours: float = 72.0,
    ) -> list[MuleRing]:
        """Detect smurfing / pooling: Source -> {Mule_1, Mule_2, ...} -> Collector."""
        rings: list[MuleRing] = []

        # Find candidate sources with out_degree >= min_mules
        for source in list(self.graph.nodes()):
            out_neighbors = list(self.graph.successors(source))
            if len(out_neighbors) < min_mules:
                continue

            # For each potential collector C, group mules that send to C
            collector_mules: dict[str, list[str]] = {}
            for mule in out_neighbors:
                for collector in self.graph.successors(mule):
                    if collector in (source, mule):
                        continue
                    collector_mules.setdefault(collector, []).append(mule)

            for collector, mules in collector_mules.items():
                if len(mules) < min_mules:
                    continue

                selected_mules = mules[:max_mules]
                mule_count = len(selected_mules)

                # Gather transaction details
                inflow_amounts: list[float] = []
                outflow_amounts: list[float] = []
                all_tx_ids: list[str] = []
                timestamps: list[datetime] = []

                temporal_valid = True
                for m in selected_mules:
                    e_in: EdgeData = self.graph[source][m]["data"]
                    e_out: EdgeData = self.graph[m][collector]["data"]

                    inflow_amounts.append(e_in.total_amount)
                    outflow_amounts.append(e_out.total_amount)

                    for tx in e_in.transactions:
                        all_tx_ids.append(tx.tx_id)
                        timestamps.append(tx.timestamp)
                    for tx in e_out.transactions:
                        all_tx_ids.append(tx.tx_id)
                        timestamps.append(tx.timestamp)

                    # Temporal causality check: inflow before outflow
                    if (
                        e_in.first_timestamp
                        and e_out.last_timestamp
                        and e_out.last_timestamp < e_in.first_timestamp
                    ):
                        temporal_valid = False

                if not temporal_valid or not timestamps:
                    continue

                t_min = min(timestamps)
                t_max = max(timestamps)
                duration_sec = (t_max - t_min).total_seconds()
                duration_hours = duration_sec / 3600.0

                if duration_hours > time_window_hours:
                    continue

                total_in = sum(inflow_amounts)
                total_out = sum(outflow_amounts)
                if total_in <= 0 or total_out <= 0:
                    continue

                # Preservation of funds from source through mules to collector
                retention_ratio = min(total_out, total_in) / max(total_out, total_in)

                # Confidence calculation:
                # 1. Number of mules: 0.35 (e.g. 2 mules = 0.5, 4+ mules = 1.0)
                score_mules = min(1.0, mule_count / 4.0)
                # 2. Retention ratio: 0.40
                score_retention = retention_ratio
                # 3. Temporal velocity: 0.25
                score_time = max(0.0, 1.0 - (duration_hours / time_window_hours))

                confidence = round(
                    0.35 * score_mules + 0.40 * score_retention + 0.25 * score_time, 3
                )
                confidence = min(max(confidence, 0.15), 0.99)

                ring_id = f"ring_pool_{uuid.uuid4().hex[:8]}"
                cycle_path = [source, *selected_mules, collector]
                all_nodes = [source, *selected_mules, collector]

                rings.append(
                    MuleRing(
                        ring_id=ring_id,
                        pattern_type="fan_out_fan_in",
                        cycle_path=cycle_path,
                        nodes=all_nodes,
                        transaction_ids=all_tx_ids,
                        total_volume=round(total_in + total_out, 2),
                        confidence_score=confidence,
                        time_window_seconds=round(duration_sec, 2),
                        hop_count=len(selected_mules) * 2,
                        details={
                            "source": source,
                            "collector": collector,
                            "mule_count": mule_count,
                            "mules": selected_mules,
                            "total_inflow": round(total_in, 2),
                            "total_outflow": round(total_out, 2),
                            "retention_ratio": round(retention_ratio, 4),
                            "duration_hours": round(duration_hours, 2),
                        },
                    )
                )

        return sorted(rings, key=lambda r: -r.confidence_score)

    # ------------------------------------------------------------------ comprehensive detection

    def detect_rings(
        self,
        *,
        max_cycle_length: int = 6,
        time_window_hours: float = 72.0,
    ) -> list[MuleRing]:
        """Detect both circular wash rings and fan-out/fan-in funds pooling structures."""
        circular = self.detect_circular_wash(
            max_cycle_length=max_cycle_length,
            time_window_hours=time_window_hours,
        )
        pooling = self.detect_fan_out_fan_in(
            time_window_hours=time_window_hours,
        )
        merged = [*circular, *pooling]
        return sorted(merged, key=lambda r: -r.confidence_score)

    def analyze(self) -> MuleRingDetectionResult:
        """Run full detection and return a structured analysis report."""
        rings = self.detect_rings()
        return MuleRingDetectionResult(
            total_nodes=self.graph.number_of_nodes(),
            total_edges=self.graph.number_of_edges(),
            total_transactions=len(self._tx_registry),
            rings_detected=len(rings),
            rings=rings,
        )


__all__ = [
    "EdgeData",
    "MuleRing",
    "MuleRingDetectionResult",
    "MuleRingDetector",
    "MuleTransaction",
]
