# pyright: reportMissingTypeStubs=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownParameterType=false, reportMissingTypeArgument=false, reportArgumentType=false
"""Real-time streaming transaction risk scoring engine with dynamic velocity windows and mule-ring graph intelligence."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import Field

from forge.contracts.contracts import Strict
from forge.mule_ring import MuleRingDetector, MuleRingGraph


class RiskDecision(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class StreamingTransaction(Strict):
    """Inbound streaming transaction event."""

    tx_id: str
    source_account: str
    destination_account: str
    amount: float = Field(ge=0.0)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    device_id: str | None = None
    ip_address: str | None = None
    channel: str = "WIRE"
    metadata: dict[str, Any] = Field(default_factory=dict)


class RiskAssessment(Strict):
    """Real-time risk scoring decision and explainable risk breakdown."""

    tx_id: str
    risk_score: float = Field(ge=0.0, le=1.0)
    decision: RiskDecision
    reasons: list[str] = Field(default_factory=list)
    velocity_count_5m: int = 0
    velocity_amount_5m: float = 0.0
    fan_out_degree: int = 0
    in_mule_ring: bool = False
    ring_cycle_length: int | None = None
    scoring_latency_ms: float = 0.0
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SlidingVelocityTracker:
    """Sliding time-window tracker for real-time velocity and volume anomalies."""

    def __init__(self, window_seconds: float = 300.0) -> None:
        self.window_seconds = window_seconds
        # Maps account_id -> deque of (epoch_timestamp, amount, destination)
        self.history: dict[str, deque[tuple[float, float, str]]] = defaultdict(deque)

    def record(self, source_account: str, amount: float, destination: str, timestamp: float) -> None:
        self._prune(source_account, timestamp)
        self.history[source_account].append((timestamp, amount, destination))

    def _prune(self, account: str, current_timestamp: float) -> None:
        cutoff = current_timestamp - self.window_seconds
        q = self.history[account]
        while q and q[0][0] < cutoff:
            q.popleft()

    def get_window_stats(self, account: str, current_timestamp: float) -> tuple[int, float, int]:
        """Returns (tx_count, total_amount, distinct_counterparties) within the sliding window."""
        self._prune(account, current_timestamp)
        q = self.history[account]
        count = len(q)
        total_amount = sum(item[1] for item in q)
        counterparties = len({item[2] for item in q})
        return count, total_amount, counterparties


class StreamingRiskEngine:
    """High-throughput real-time streaming transaction risk scorer.
    
    Combines sliding velocity window analytics, out-degree dispersal detection,
    and topological cycle analysis from MuleRingGraph.
    """

    def __init__(
        self,
        velocity_window_seconds: float = 300.0,
        burst_count_threshold: int = 4,
        burst_volume_threshold: float = 50000.0,
        high_risk_amount_threshold: float = 100000.0,
        review_score_threshold: float = 0.45,
        block_score_threshold: float = 0.75,
    ) -> None:
        self.graph = MuleRingGraph()
        self.detector = MuleRingDetector(min_ring_size=2, max_ring_size=5, min_confidence=0.3)
        self.velocity = SlidingVelocityTracker(window_seconds=velocity_window_seconds)
        self.burst_count_threshold = burst_count_threshold
        self.burst_volume_threshold = burst_volume_threshold
        self.high_risk_amount_threshold = high_risk_amount_threshold
        self.review_score_threshold = review_score_threshold
        self.block_score_threshold = block_score_threshold

    def ingest_and_score(self, tx: StreamingTransaction) -> RiskAssessment:
        t0 = time.perf_counter()

        ts_epoch = tx.timestamp.timestamp()
        source = tx.source_account
        dest = tx.destination_account
        amount = tx.amount

        # 1. Update velocity window
        self.velocity.record(source, amount, dest, ts_epoch)
        v_count, v_volume, v_distinct_dest = self.velocity.get_window_stats(source, ts_epoch)

        # 2. Add transaction to graph
        self.graph.add_transaction(source, dest, amount, timestamp=tx.timestamp)

        # 3. Graph degree metrics
        fan_out = self.graph.nx_graph.out_degree(source) if source in self.graph.nx_graph else 1

        # 4. Check for participation in circular mule rings
        detection = self.detector.detect_rings(self.graph)
        involved_ring = next((r for r in detection.rings if source in r.nodes or dest in r.nodes), None)

        reasons: list[str] = []
        score_components: list[float] = []

        # Feature A: Velocity Burst Check
        if v_count >= self.burst_count_threshold:
            reasons.append(f"VELOCITY_BURST: {v_count} txs in 5m window")
            score_components.append(0.45 + min(0.3, (v_count - self.burst_count_threshold) * 0.10))

        # Feature B: High Burst Volume
        if v_volume >= self.burst_volume_threshold:
            reasons.append(f"HIGH_BURST_VOLUME: ${v_volume:,.2f} in window")
            score_components.append(0.30)

        # Feature C: Rapid Counterparty Dispersal (Fan-Out)
        if v_distinct_dest >= 3:
            reasons.append(f"RAPID_DISPERSAL: {v_distinct_dest} distinct counterparties in window")
            score_components.append(0.25)

        # Feature D: Mule Ring Cycle Participation
        in_mule_ring = involved_ring is not None
        cycle_len = involved_ring.length if involved_ring else None
        if in_mule_ring and involved_ring is not None:
            reasons.append(f"MULE_RING_CYCLE_DETECTED: {cycle_len}-hop loop confidence={involved_ring.confidence_score:.2f}")
            score_components.append(0.50 * involved_ring.confidence_score + 0.35)

        # Feature E: Single Large Transaction Anomaly
        if amount >= self.high_risk_amount_threshold:
            reasons.append(f"HIGH_VALUE_ANOMALY: ${amount:,.2f} single transaction")
            score_components.append(0.25)

        # Combine scores using probabilistic union: 1 - prod(1 - s_i)
        if not score_components:
            final_score = 0.05
        else:
            unioned = 1.0
            for sc in score_components:
                unioned *= (1.0 - min(sc, 0.95))
            final_score = round(min(1.0, max(0.0, 1.0 - unioned)), 4)

        if final_score >= self.block_score_threshold:
            decision = RiskDecision.BLOCK
        elif final_score >= self.review_score_threshold:
            decision = RiskDecision.REVIEW
        else:
            decision = RiskDecision.ALLOW

        latency_ms = (time.perf_counter() - t0) * 1000.0

        return RiskAssessment(
            tx_id=tx.tx_id,
            risk_score=final_score,
            decision=decision,
            reasons=reasons,
            velocity_count_5m=v_count,
            velocity_amount_5m=v_volume,
            fan_out_degree=fan_out,
            in_mule_ring=in_mule_ring,
            ring_cycle_length=cycle_len,
            scoring_latency_ms=round(latency_ms, 3),
        )
