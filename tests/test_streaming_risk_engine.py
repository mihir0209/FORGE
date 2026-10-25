"""Unit and adversarial tests for the real-time StreamingRiskEngine."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from forge import (
    RiskAssessment,
    RiskDecision,
    StreamingRiskEngine,
    StreamingTransaction,
)


def test_benign_single_transaction_allowed():
    engine = StreamingRiskEngine()
    tx = StreamingTransaction(
        tx_id="tx_norm_01",
        source_account="acc_alice",
        destination_account="acc_groceries",
        amount=45.50,
    )
    result = engine.ingest_and_score(tx)

    assert result.tx_id == "tx_norm_01"
    assert result.decision == RiskDecision.ALLOW
    assert result.risk_score < 0.30
    assert not result.in_mule_ring
    assert result.reasons == []
    assert result.scoring_latency_ms < 10.0


def test_velocity_burst_triggers_risk_escalation():
    engine = StreamingRiskEngine(burst_count_threshold=4)
    now = datetime.now(timezone.utc)

    # Send 5 transactions in rapid succession (< 30 seconds)
    assessments: list[RiskAssessment] = []
    for i in range(5):
        tx = StreamingTransaction(
            tx_id=f"tx_burst_{i}",
            source_account="acc_spammer",
            destination_account="acc_target",
            amount=500.0,
            timestamp=now + timedelta(seconds=i * 5),
        )
        assessments.append(engine.ingest_and_score(tx))

    # First few are allowed
    assert assessments[0].decision == RiskDecision.ALLOW

    # 4th and 5th should trigger VELOCITY_BURST
    final_tx = assessments[-1]
    assert final_tx.decision in (RiskDecision.REVIEW, RiskDecision.BLOCK)
    assert any("VELOCITY_BURST" in r for r in final_tx.reasons)
    assert final_tx.velocity_count_5m == 5


def test_sliding_window_pruning():
    engine = StreamingRiskEngine(velocity_window_seconds=300.0)
    t0 = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    # 3 transactions at 12:00
    for i in range(3):
        tx = StreamingTransaction(
            tx_id=f"tx_old_{i}",
            source_account="acc_bob",
            destination_account="acc_charlie",
            amount=100.0,
            timestamp=t0 + timedelta(seconds=i),
        )
        engine.ingest_and_score(tx)

    # 4th transaction arrives 10 minutes later (12:10)
    t_later = t0 + timedelta(minutes=10)
    tx_later = StreamingTransaction(
        tx_id="tx_later",
        source_account="acc_bob",
        destination_account="acc_charlie",
        amount=100.0,
        timestamp=t_later,
    )
    result = engine.ingest_and_score(tx_later)

    # Prior transactions outside the 300s window should be pruned
    assert result.velocity_count_5m == 1
    assert result.velocity_amount_5m == 100.0
    assert result.decision == RiskDecision.ALLOW


def test_mule_ring_cycle_closure_triggers_block():
    engine = StreamingRiskEngine()
    now = datetime.now(timezone.utc)

    # Build 3-hop mule ring: ACC_1 -> ACC_2 -> ACC_3 -> ACC_1
    tx1 = StreamingTransaction(
        tx_id="tx_ring_1",
        source_account="ACC_1",
        destination_account="ACC_2",
        amount=15000.0,
        timestamp=now,
    )
    tx2 = StreamingTransaction(
        tx_id="tx_ring_2",
        source_account="ACC_2",
        destination_account="ACC_3",
        amount=14800.0,
        timestamp=now + timedelta(seconds=10),
    )
    tx3 = StreamingTransaction(
        tx_id="tx_ring_3",
        source_account="ACC_3",
        destination_account="ACC_1",
        amount=14500.0,
        timestamp=now + timedelta(seconds=20),
    )

    r1 = engine.ingest_and_score(tx1)
    assert not r1.in_mule_ring

    r2 = engine.ingest_and_score(tx2)
    assert not r2.in_mule_ring

    # Closing the cycle triggers ring detection
    r3 = engine.ingest_and_score(tx3)
    assert r3.in_mule_ring
    assert r3.ring_cycle_length == 3
    assert r3.decision == RiskDecision.BLOCK
    assert r3.risk_score >= 0.75
    assert any("MULE_RING_CYCLE_DETECTED" in r for r in r3.reasons)


def test_rapid_counterparty_dispersal_fan_out():
    engine = StreamingRiskEngine()
    now = datetime.now(timezone.utc)

    # Account sends to 4 distinct counterparties in 1 minute
    for i in range(4):
        tx = StreamingTransaction(
            tx_id=f"tx_fan_{i}",
            source_account="acc_dispatcher",
            destination_account=f"acc_recv_{i}",
            amount=5000.0,
            timestamp=now + timedelta(seconds=i * 10),
        )
        res = engine.ingest_and_score(tx)

    # Final transaction should identify counterparty dispersal
    assert any("RAPID_DISPERSAL" in r for r in res.reasons)
    assert res.decision in (RiskDecision.REVIEW, RiskDecision.BLOCK)


def test_real_time_scoring_latency_and_throughput():
    engine = StreamingRiskEngine()
    now = datetime.now(timezone.utc)

    latencies: list[float] = []
    # Benchmark 100 sequential transactions
    for i in range(100):
        tx = StreamingTransaction(
            tx_id=f"bench_tx_{i}",
            source_account=f"acc_src_{i % 10}",
            destination_account=f"acc_dst_{i % 15}",
            amount=100.0 * (i + 1),
            timestamp=now + timedelta(seconds=i),
        )
        res = engine.ingest_and_score(tx)
        latencies.append(res.scoring_latency_ms)

    avg_latency = sum(latencies) / len(latencies)
    assert avg_latency < 5.0, f"Average latency too high: {avg_latency:.3f} ms"
    assert len(latencies) == 100
