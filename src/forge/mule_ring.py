# pyright: reportMissingTypeStubs=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownParameterType=false, reportMissingTypeArgument=false, reportArgumentType=false
"""Mule ring graph analytics and circular flow detection for AML and fraud intelligence."""

from __future__ import annotations

import hashlib
import math
import time
from datetime import datetime
from typing import TYPE_CHECKING, Any

import networkx as nx
from pydantic import Field

from forge.contracts.contracts import GraphEvent, Strict, TraceEvent

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence


def canonicalize_cycle(nodes: Sequence[str]) -> tuple[str, ...]:
    """Rotate a directed cycle so that the lexicographical minimum node is at index 0."""
    if not nodes:
        return ()
    node_list = list(nodes)
    min_idx = node_list.index(min(node_list))
    return tuple(node_list[min_idx:] + node_list[:min_idx])


class TransactionEdge(Strict):
    """Immutable directed transaction edge in a financial graph."""

    edge_id: str
    source: str
    destination: str
    amount: float = Field(ge=0.0)
    amount_minor: int = Field(ge=0)
    timestamp: datetime | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class MuleRing(Strict):
    """Detected circular mule ring in the transaction graph."""

    cycle_id: str
    nodes: tuple[str, ...]
    length: int = Field(ge=2)
    confidence_score: float = Field(ge=0.0, le=1.0)
    total_volume: float = Field(ge=0.0)
    mean_amount: float = Field(ge=0.0)
    amount_variance: float = Field(ge=0.0)
    flow_completion_ratio: float = Field(ge=0.0, le=1.0)
    duration_seconds: float | None = None
    edges: list[str] = Field(default_factory=list)
    motif: str = "circular_mule_ring"


class MuleRingDetectionResult(Strict):
    """Aggregate result from mule ring analysis across a transaction graph."""

    rings: list[MuleRing] = Field(default_factory=list)
    cycle_count: int = Field(ge=0)
    nodes_involved: list[str] = Field(default_factory=list)
    max_confidence: float = Field(ge=0.0, le=1.0)
    execution_time_ms: float = Field(ge=0.0)
    total_flow_volume: float = Field(ge=0.0)


class MuleRingGraph:
    """Graph representation of directed financial flows optimized for cycle discovery."""

    def __init__(self, edges: Iterable[TransactionEdge] | None = None) -> None:
        self._graph = nx.DiGraph()
        self._edges: list[TransactionEdge] = []
        self._seq: int = 0
        if edges:
            for edge in edges:
                self.add_edge(edge)

    @property
    def nx_graph(self) -> nx.DiGraph:
        return self._graph

    @property
    def node_count(self) -> int:
        return int(self._graph.number_of_nodes())

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    @property
    def nodes(self) -> list[str]:
        return [str(n) for n in self._graph.nodes()]

    @property
    def edges(self) -> list[TransactionEdge]:
        return list(self._edges)

    def add_edge(self, edge: TransactionEdge) -> None:
        self._edges.append(edge)
        src = edge.source
        dst = edge.destination
        if self._graph.has_edge(src, dst):
            data = self._graph[src][dst]
            amounts = data.setdefault("amounts", [])
            amounts.append(edge.amount)
            data["total_amount"] = data.get("total_amount", 0.0) + edge.amount
            edge_ids = data.setdefault("edge_ids", [])
            edge_ids.append(edge.edge_id)
            if edge.timestamp is not None:
                timestamps = data.setdefault("timestamps", [])
                timestamps.append(edge.timestamp)
        else:
            self._graph.add_edge(
                src,
                dst,
                amounts=[edge.amount],
                total_amount=edge.amount,
                edge_ids=[edge.edge_id],
                timestamps=[edge.timestamp] if edge.timestamp is not None else [],
            )

    def add_transaction(
        self,
        source: str,
        destination: str,
        amount: float,
        *,
        timestamp: datetime | None = None,
        edge_id: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> TransactionEdge:
        self._seq += 1
        eid = edge_id or f"tx_edge_{self._seq:07d}"
        edge = TransactionEdge(
            edge_id=eid,
            source=source,
            destination=destination,
            amount=amount,
            amount_minor=round(amount * 100),
            timestamp=timestamp,
            attributes=attributes or {},
        )
        self.add_edge(edge)
        return edge

    @classmethod
    def from_events(cls, events: Sequence[GraphEvent]) -> MuleRingGraph:
        """Construct graph from FORGE contracts GraphEvent records."""
        graph = cls()
        for event in events:
            if event.source_account_ref and event.destination_account_ref:
                graph.add_transaction(
                    source=event.source_account_ref,
                    destination=event.destination_account_ref,
                    amount=event.amount_minor / 100.0,
                    timestamp=event.event_time,
                    edge_id=event.event_id,
                    attributes=event.attributes,
                )
        return graph

    @classmethod
    def from_trace_events(cls, events: Sequence[TraceEvent]) -> MuleRingGraph:
        """Construct graph from FORGE SyntheticTrace TraceEvent records."""
        graph = cls()
        for event in events:
            if event.kind in {"payment", "transfer", "cash_out"}:
                src = str(event.payload.get("customer", event.actor_id))
                dst = str(event.payload.get("merchant", event.payload.get("destination", "unknown")))
                amt = float(event.payload.get("amount", 0.0))
                if src and dst and dst != "unknown":
                    graph.add_transaction(
                        source=src,
                        destination=dst,
                        amount=amt,
                        timestamp=event.ts,
                        edge_id=event.event_id,
                    )
        return graph


class MuleRingDetector:
    """Discovers closed directed circular rings in financial graphs and computes risk scores."""

    def __init__(
        self,
        *,
        min_ring_size: int = 3,
        max_ring_size: int = 12,
        min_confidence: float = 0.0,
    ) -> None:
        if min_ring_size < 2:
            raise ValueError("min_ring_size must be >= 2")
        if max_ring_size < min_ring_size:
            raise ValueError("max_ring_size must be >= min_ring_size")
        self.min_ring_size = min_ring_size
        self.max_ring_size = max_ring_size
        self.min_confidence = min_confidence

    def detect_rings(
        self, graph: MuleRingGraph | nx.DiGraph | Sequence[TransactionEdge]
    ) -> MuleRingDetectionResult:
        start_t = time.perf_counter()
        if isinstance(graph, MuleRingGraph):
            g = graph.nx_graph
        elif isinstance(graph, nx.DiGraph):
            g = graph
        else:
            g = MuleRingGraph(graph).nx_graph

        raw_cycles = nx.simple_cycles(g)
        detected_rings: list[MuleRing] = []
        seen_canonical: set[tuple[str, ...]] = set()

        for cycle_nodes in raw_cycles:
            cycle_len = len(cycle_nodes)
            if cycle_len < self.min_ring_size or cycle_len > self.max_ring_size:
                continue

            canonical = canonicalize_cycle([str(n) for n in cycle_nodes])
            if canonical in seen_canonical:
                continue
            seen_canonical.add(canonical)

            ring = self._evaluate_cycle(g, canonical)
            if ring.confidence_score >= self.min_confidence:
                detected_rings.append(ring)

        detected_rings.sort(key=lambda r: (-r.confidence_score, r.length, r.nodes))
        nodes_involved = sorted({node for ring in detected_rings for node in ring.nodes})
        max_conf = max((ring.confidence_score for ring in detected_rings), default=0.0)
        total_vol = sum(ring.total_volume for ring in detected_rings)
        elapsed_ms = (time.perf_counter() - start_t) * 1000.0

        return MuleRingDetectionResult(
            rings=detected_rings,
            cycle_count=len(detected_rings),
            nodes_involved=nodes_involved,
            max_confidence=max_conf,
            execution_time_ms=elapsed_ms,
            total_flow_volume=total_vol,
        )

    def _evaluate_cycle(self, g: nx.DiGraph, cycle_nodes: tuple[str, ...]) -> MuleRing:
        k = len(cycle_nodes)
        edge_ids: list[str] = []
        hop_amounts: list[float] = []
        all_timestamps: list[datetime] = []

        for i in range(k):
            u = cycle_nodes[i]
            v = cycle_nodes[(i + 1) % k]
            edge_data = g.get_edge_data(u, v) or {}
            amounts = edge_data.get("amounts", [edge_data.get("total_amount", 0.0)])
            hop_vol = sum(amounts) if amounts else float(edge_data.get("total_amount", 0.0))
            hop_amounts.append(hop_vol)
            edge_ids.extend(edge_data.get("edge_ids", []))
            for ts in edge_data.get("timestamps", []):
                if isinstance(ts, datetime):
                    all_timestamps.append(ts)

        total_volume = sum(hop_amounts)
        mean_amount = total_volume / k if k > 0 else 0.0
        variance = sum((a - mean_amount) ** 2 for a in hop_amounts) / k if k > 0 else 0.0
        std_dev = math.sqrt(variance)
        cv = std_dev / mean_amount if mean_amount > 0.0 else 0.0
        amount_consistency = max(0.0, 1.0 - min(cv, 1.0))

        min_hop = min(hop_amounts) if hop_amounts else 0.0
        max_hop = max(hop_amounts) if hop_amounts else 0.0
        flow_completion = min_hop / max_hop if max_hop > 0.0 else 1.0

        duration_seconds: float | None = None
        temporal_factor = 0.85
        if all_timestamps:
            min_ts = min(all_timestamps)
            max_ts = max(all_timestamps)
            duration_seconds = max(0.0, (max_ts - min_ts).total_seconds())
            if duration_seconds <= 3600.0:  # <= 1 hour
                temporal_factor = 1.0
            elif duration_seconds <= 86400.0:  # <= 24 hours
                temporal_factor = 0.90
            else:
                temporal_factor = max(0.50, 1.0 - math.log10(max(1.0, duration_seconds / 3600.0)) * 0.15)

        length_factor = max(0.50, 1.0 - 0.025 * (k - 3))

        # Base confidence for confirmed circular topologies: 0.65
        confidence = (
            0.35
            + 0.30 * amount_consistency
            + 0.20 * length_factor
            + 0.15 * temporal_factor
        )
        confidence = float(min(0.99, max(0.50, confidence)))

        cycle_hash = hashlib.sha256(":".join(cycle_nodes).encode()).hexdigest()[:16]
        return MuleRing(
            cycle_id=f"ring_{cycle_hash}",
            nodes=cycle_nodes,
            length=k,
            confidence_score=confidence,
            total_volume=total_volume,
            mean_amount=mean_amount,
            amount_variance=variance,
            flow_completion_ratio=flow_completion,
            duration_seconds=duration_seconds,
            edges=edge_ids,
            motif=f"circular_mule_ring_{k}",
        )
