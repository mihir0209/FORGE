# pyright: reportMissingTypeStubs=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownParameterType=false, reportMissingTypeArgument=false, reportArgumentType=false
"""Adversarial QA test suite: Mule ring graph topology validation, latency benchmarks, and false-positive immunity."""

import time
from datetime import UTC, datetime, timedelta

import pytest

from forge.contracts.contracts import GraphEvent
from forge.mule_ring import (
    MuleRingDetector,
    MuleRingGraph,
    canonicalize_cycle,
)

NOW = datetime(2026, 8, 25, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# 1. Graph Topology Validation: Known Circular Rings
# ---------------------------------------------------------------------------


def test_3_node_circular_ring_discovered_with_exact_cycle() -> None:
    """Topology: A -> B -> C -> A. Mule detector must find the exact 3-node cycle."""
    graph = MuleRingGraph()
    # Construct exact 3-node circular ring
    graph.add_transaction("mule_3a", "mule_3b", 5000.0, timestamp=NOW - timedelta(minutes=45))
    graph.add_transaction("mule_3b", "mule_3c", 4950.0, timestamp=NOW - timedelta(minutes=30))
    graph.add_transaction("mule_3c", "mule_3a", 4900.0, timestamp=NOW - timedelta(minutes=15))

    detector = MuleRingDetector(min_ring_size=3, max_ring_size=10)
    result = detector.detect_rings(graph)

    assert result.cycle_count == 1
    assert len(result.rings) == 1

    ring = result.rings[0]
    assert ring.length == 3
    # Check exact cycle topology: nodes in circular order
    assert set(ring.nodes) == {"mule_3a", "mule_3b", "mule_3c"}
    assert ring.nodes == canonicalize_cycle(["mule_3a", "mule_3b", "mule_3c"])

    # Assert valid confidence score
    assert 0.0 <= ring.confidence_score <= 1.0
    assert ring.confidence_score >= 0.70  # Coordinated tight flow
    assert ring.total_volume == pytest.approx(14850.0)
    assert ring.flow_completion_ratio > 0.95
    assert ring.duration_seconds == pytest.approx(1800.0)
    assert result.nodes_involved == sorted(["mule_3a", "mule_3b", "mule_3c"])


def test_4_node_circular_ring_discovered_with_exact_cycle() -> None:
    """Topology: A -> B -> C -> D -> A. Mule detector must find the exact 4-node cycle."""
    graph = MuleRingGraph()
    ring_nodes = ["ring4_node1", "ring4_node2", "ring4_node3", "ring4_node4"]
    for i in range(len(ring_nodes)):
        src = ring_nodes[i]
        dst = ring_nodes[(i + 1) % len(ring_nodes)]
        graph.add_transaction(src, dst, 8500.0, timestamp=NOW - timedelta(minutes=60 - i * 15))

    detector = MuleRingDetector(min_ring_size=3, max_ring_size=10)
    result = detector.detect_rings(graph)

    assert result.cycle_count == 1
    ring = result.rings[0]
    assert ring.length == 4
    assert set(ring.nodes) == set(ring_nodes)
    assert ring.nodes == canonicalize_cycle(ring_nodes)
    assert 0.0 <= ring.confidence_score <= 1.0
    assert ring.confidence_score >= 0.75
    assert ring.total_volume == pytest.approx(34000.0)
    assert ring.mean_amount == pytest.approx(8500.0)
    assert ring.amount_variance == pytest.approx(0.0)  # Identical hop amounts


def test_6_node_circular_ring_discovered_with_exact_cycle() -> None:
    """Topology: A -> B -> C -> D -> E -> F -> A. Mule detector must find the exact 6-node cycle."""
    graph = MuleRingGraph()
    ring_nodes = [f"mule6_acc_{k}" for k in range(6)]
    for i in range(6):
        src = ring_nodes[i]
        dst = ring_nodes[(i + 1) % 6]
        # Layering with slight laundering fee cut at each hop
        amount = 12000.0 - i * 150.0
        graph.add_transaction(src, dst, amount, timestamp=NOW - timedelta(minutes=120 - i * 18))

    detector = MuleRingDetector(min_ring_size=3, max_ring_size=10)
    result = detector.detect_rings(graph)

    assert result.cycle_count == 1
    ring = result.rings[0]
    assert ring.length == 6
    assert set(ring.nodes) == set(ring_nodes)
    assert ring.nodes == canonicalize_cycle(ring_nodes)
    assert 0.0 <= ring.confidence_score <= 1.0
    assert ring.confidence_score >= 0.70
    assert ring.flow_completion_ratio > 0.90
    assert result.max_confidence == ring.confidence_score


def test_multiple_disjoint_rings_simultaneously_discovered() -> None:
    """Embed 3-node, 4-node, and 6-node rings into a single graph with background traffic."""
    graph = MuleRingGraph()

    # Ring 1: 3-node ring
    r3 = ["r3_a", "r3_b", "r3_c"]
    for i in range(3):
        graph.add_transaction(r3[i], r3[(i + 1) % 3], 3000.0)

    # Ring 2: 4-node ring
    r4 = ["r4_a", "r4_b", "r4_c", "r4_d"]
    for i in range(4):
        graph.add_transaction(r4[i], r4[(i + 1) % 4], 4000.0)

    # Ring 3: 6-node ring
    r6 = [f"r6_{k}" for k in range(6)]
    for i in range(6):
        graph.add_transaction(r6[i], r6[(i + 1) % 6], 6000.0)

    # Add 150 background acyclic transactions
    for k in range(150):
        graph.add_transaction(f"legit_buyer_{k}", f"legit_merchant_{k % 10}", 50.0 + k)

    detector = MuleRingDetector(min_ring_size=3, max_ring_size=10)
    result = detector.detect_rings(graph)

    assert result.cycle_count == 3
    discovered_node_sets = [set(ring.nodes) for ring in result.rings]
    assert set(r3) in discovered_node_sets
    assert set(r4) in discovered_node_sets
    assert set(r6) in discovered_node_sets

    lengths = sorted(ring.length for ring in result.rings)
    assert lengths == [3, 4, 6]
    for ring in result.rings:
        assert 0.0 <= ring.confidence_score <= 1.0
        assert ring.confidence_score >= 0.70


# ---------------------------------------------------------------------------
# 2. False-Positive Immunity: Acyclic High-Velocity Merchant Graphs
# ---------------------------------------------------------------------------


def test_acyclic_high_velocity_merchant_graph_produces_zero_false_positives() -> None:
    """Legitimate high-velocity e-commerce and retail traffic forms a directed acyclic graph (DAG).

    Assert 0 cycle flags and 0 false positives despite thousands of transactions.
    """
    graph = MuleRingGraph()
    # 500 customers making high-velocity purchases across 30 merchants
    # Merchants sweep funds to 3 settlement accounts / bank master accounts.
    # Strictly acyclic: Consumer -> Merchant -> Settlement / Supplier
    for c in range(500):
        cust = f"consumer_{c:04d}"
        for tx in range(3):
            merchant = f"merchant_{(c * 3 + tx) % 30:02d}"
            amount = round(15.0 + ((c * 17 + tx * 31) % 450), 2)
            graph.add_transaction(
                source=cust,
                destination=merchant,
                amount=amount,
                timestamp=NOW - timedelta(seconds=c * 10 + tx),
            )

    # 30 merchants pay out to 3 processors/settlement banks
    for m in range(30):
        merchant = f"merchant_{m:02d}"
        processor = f"processor_{m % 3}"
        graph.add_transaction(source=merchant, destination=processor, amount=125000.0)

    assert graph.edge_count == 1500 + 30
    assert graph.node_count == 500 + 30 + 3

    detector = MuleRingDetector(min_ring_size=3, max_ring_size=12)
    result = detector.detect_rings(graph)

    # Strict assertion: Zero false positives
    assert result.cycle_count == 0
    assert len(result.rings) == 0
    assert result.nodes_involved == []
    assert result.max_confidence == 0.0
    assert result.total_flow_volume == 0.0


def test_acyclic_payroll_and_supplier_fanout_graph_has_zero_false_positives() -> None:
    """Complex enterprise graph: Parent corporate -> 10 subsidiaries -> 400 employees -> 50 billers."""
    graph = MuleRingGraph()
    parent = "corp_hq"
    for sub_idx in range(10):
        sub = f"subsidiary_{sub_idx}"
        graph.add_transaction(parent, sub, 500_000.0)
        # Each subsidiary pays 40 employees
        for emp_idx in range(40):
            emp = f"emp_{sub_idx}_{emp_idx}"
            graph.add_transaction(sub, emp, 4_500.0)
            # Each employee pays utility/mortgage billers
            biller = f"biller_{(emp_idx * 7) % 50}"
            graph.add_transaction(emp, biller, 350.0)

    detector = MuleRingDetector(min_ring_size=3, max_ring_size=8)
    result = detector.detect_rings(graph)

    assert result.cycle_count == 0
    assert result.rings == []
    assert result.max_confidence == 0.0


# ---------------------------------------------------------------------------
# 3. Latency & Throughput Benchmark
# ---------------------------------------------------------------------------


def test_latency_benchmark_1000_edges_under_50ms() -> None:
    """Verify graph construction and cycle detection complete within latency threshold (< 50ms for 1,000 edges)."""
    import gc

    # Prepare 1,000 edges: 994 legitimate DAG transactions + one embedded 6-node mule ring
    edges_data: list[tuple[str, str, float]] = []

    # 994 DAG edges (consumers to merchants and distributors)
    for i in range(994):
        src = f"acct_bench_src_{i}"
        dst = f"acct_bench_dst_{i % 50}"
        edges_data.append((src, dst, 100.0 + (i % 200)))

    # 6 edges forming an embedded circular mule ring
    ring_nodes = [f"bench_mule_{k}" for k in range(6)]
    for k in range(6):
        edges_data.append((ring_nodes[k], ring_nodes[(k + 1) % 6], 10000.0))

    assert len(edges_data) == 1000

    detector = MuleRingDetector(min_ring_size=3, max_ring_size=10)

    # Warmup pass
    w_graph = MuleRingGraph()
    for src, dst, amt in edges_data[:100]:
        w_graph.add_transaction(src, dst, amt)
    _ = detector.detect_rings(w_graph)

    # Benchmark: Full graph construction + full cycle detection
    gc.collect()
    start_time = time.perf_counter()

    graph = MuleRingGraph()
    for src, dst, amt in edges_data:
        graph.add_transaction(src, dst, amt)

    result = detector.detect_rings(graph)

    total_latency_ms = (time.perf_counter() - start_time) * 1000.0

    # Strict SLA Assertion: < 50ms for 1,000 edges
    assert total_latency_ms < 50.0, f"Latency breached: {total_latency_ms:.2f}ms >= 50.0ms"

    # Correctness verification
    assert graph.edge_count == 1000
    assert result.cycle_count == 1
    assert result.rings[0].length == 6
    assert set(result.rings[0].nodes) == set(ring_nodes)
    assert result.rings[0].confidence_score >= 0.70


def test_throughput_stability_across_multiple_iterations() -> None:
    """Stress test: 10 repeated executions of 1,000-edge graphs to verify p50 and p95 latency remain < 50ms."""
    import gc

    detector = MuleRingDetector(min_ring_size=3, max_ring_size=10)
    durations: list[float] = []

    for trial in range(10):
        gc.collect()
        t0 = time.perf_counter()
        graph = MuleRingGraph()
        for i in range(996):
            graph.add_transaction(f"t{trial}_u_{i}", f"t{trial}_m_{i % 30}", 25.0)
        # 4-node ring
        r = [f"t{trial}_r_{k}" for k in range(4)]
        for k in range(4):
            graph.add_transaction(r[k], r[(k + 1) % 4], 7500.0)

        res = detector.detect_rings(graph)
        elapsed = (time.perf_counter() - t0) * 1000.0
        durations.append(elapsed)

        assert res.cycle_count == 1
        assert res.rings[0].length == 4

    p50 = sorted(durations)[len(durations) // 2]
    p95 = sorted(durations)[int(len(durations) * 0.95)]

    assert p50 < 50.0, f"p50 latency {p50:.2f}ms >= 50ms"
    assert p95 < 50.0, f"p95 latency {p95:.2f}ms >= 50ms"


# ---------------------------------------------------------------------------
# 4. Integration with FORGE GraphEvent Contracts
# ---------------------------------------------------------------------------


def test_from_events_detects_mule_ring_from_forge_contracts() -> None:
    """Verify interoperability with forge.contracts.contracts.GraphEvent."""
    nodes = ["event_mule_1", "event_mule_2", "event_mule_3"]
    events = [
        GraphEvent(
            event_id=f"ge_mule_{i}",
            event_time=NOW - timedelta(minutes=30 - i * 10),
            available_at=NOW - timedelta(minutes=30 - i * 10),
            kind="payment.settled",
            institution_id="bank-forge",
            source_account_ref=nodes[i],
            destination_account_ref=nodes[(i + 1) % 3],
            amount_minor=500000,
        )
        for i in range(3)
    ]

    graph = MuleRingGraph.from_events(events)
    assert graph.edge_count == 3
    assert graph.node_count == 3

    detector = MuleRingDetector()
    result = detector.detect_rings(graph)
    assert result.cycle_count == 1
    assert result.rings[0].length == 3
    assert result.rings[0].total_volume == pytest.approx(15000.0)
