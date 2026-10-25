# pyright: reportMissingTypeStubs=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false
"""Tests for SyntheticFraudAttackGenerator, MuleRingDetector, and StreamingBenchmark."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from forge.benchmark.streaming import (
    StreamingBenchmark,
    StreamingBenchmarkConfig,
    run_streaming_benchmark,
)
from forge.detect.mule_ring import (
    MuleRingDetector,
)
from forge.simulate.generator import (
    AttackVectorType,
    SyntheticFraudAttackGenerator,
    haversine_distance_km,
)


def test_haversine_distance() -> None:
    # NY (40.7128, -74.0060) to London (51.5074, -0.1278) is approx 5570 km
    dist = haversine_distance_km(40.7128, -74.0060, 51.5074, -0.1278)
    assert 5500 < dist < 5650


def test_generator_micro_burst() -> None:
    gen = SyntheticFraudAttackGenerator(seed=42)
    start = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
    burst = gen.generate_micro_burst(
        customer_id="cust_alice",
        merchant_id="merch_steam",
        start_time=start,
        count=10,
        interval_seconds=0.5,
        min_amount=0.50,
        max_amount=3.00,
    )

    assert len(burst) == 10
    for idx, e in enumerate(burst):
        assert e.is_attack_step is True
        assert e.payload["burst"] is True
        assert e.payload["customer"] == "cust_alice"
        assert 0.50 <= e.payload["amount"] <= 3.00
        if idx > 0:
            assert burst[idx].ts > burst[idx - 1].ts

    # Verify observed_view strips private/ground truth
    trace = gen.generate_adversarial_trace(pattern=AttackVectorType.MICRO_BURST)
    obs = trace.observed_view()
    for e in obs.events:
        assert e.is_attack_step is False


def test_generator_impossible_geo_velocity() -> None:
    gen = SyntheticFraudAttackGenerator(seed=101)
    start = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
    hops = gen.generate_geo_velocity_hops(
        customer_id="cust_bob",
        start_time=start,
        hop_cities=["New York", "London", "Tokyo"],
        hop_minutes=10.0,
    )

    assert len(hops) == 3
    # First hop is origin
    assert hops[0].payload["distance_from_prev_km"] == 0.0
    # Second hop: NY -> London in 10 minutes is ~33,000 km/h -> impossible!
    assert hops[1].payload["distance_from_prev_km"] > 5000
    assert hops[1].payload["impossible_velocity"] is True
    assert hops[1].payload["speed_kmh"] > 1000.0
    assert hops[1].payload["spoofed_fingerprint"] is True


def test_generator_smurfing_structuring() -> None:
    gen = SyntheticFraudAttackGenerator(seed=202)
    threshold = 10000.0
    smurfs = gen.generate_smurfing_pattern(
        threshold=threshold,
        num_transactions=6,
        target_account="acc_mule_king",
    )

    assert len(smurfs) == 6
    for e in smurfs:
        amt = e.payload["amount"]
        assert 9000.0 <= amt < threshold
        assert e.payload["is_structured"] is True
        assert e.payload["destination_account"] == "acc_mule_king"


def test_generator_streaming() -> None:
    gen = SyntheticFraudAttackGenerator(seed=777)
    stream = list(gen.stream_attacks(count=25))
    assert len(stream) == 25
    assert all(e.is_attack_step for e in stream)


def test_mule_ring_circular_wash_detection() -> None:
    detector = MuleRingDetector()
    base_time = datetime(2026, 8, 25, 10, 0, tzinfo=UTC)

    # Circular wash trading: A -> B -> C -> A
    # Flow: $5,000 -> $4,950 -> $4,900 -> $4,850 within 4 hours
    detector.add_transaction("acc_A", "acc_B", 5000.0, base_time + timedelta(hours=1))
    detector.add_transaction("acc_B", "acc_C", 4950.0, base_time + timedelta(hours=2))
    detector.add_transaction("acc_C", "acc_A", 4900.0, base_time + timedelta(hours=3))

    # Also add unrelated normal noise
    detector.add_transaction("acc_X", "acc_Y", 100.0, base_time)
    detector.add_transaction("acc_Y", "acc_Z", 50.0, base_time + timedelta(hours=1))

    rings = detector.detect_circular_wash(time_window_hours=24.0)
    assert len(rings) >= 1

    wash_ring = next((r for r in rings if set(r.nodes) == {"acc_A", "acc_B", "acc_C"}), None)
    assert wash_ring is not None
    assert wash_ring.pattern_type == "circular_wash"
    assert wash_ring.hop_count == 3
    assert wash_ring.cycle_path[0] == wash_ring.cycle_path[-1]  # Closed cycle
    assert wash_ring.confidence_score >= 0.70
    assert wash_ring.total_volume >= 14000.0


def test_mule_ring_fan_out_fan_in_detection() -> None:
    detector = MuleRingDetector()
    base_time = datetime(2026, 8, 25, 8, 0, tzinfo=UTC)

    # Fan-out / Fan-in: Source -> {M1, M2, M3} -> Collector
    source = "acc_boss_source"
    collector = "acc_boss_collector"
    mules = ["mule_01", "mule_02", "mule_03"]

    # Source fans out $3,000 each
    for idx, m in enumerate(mules):
        detector.add_transaction(source, m, 3000.0, base_time + timedelta(hours=idx))

    # Mules fan in $2,850 each (minus fee)
    for idx, m in enumerate(mules):
        detector.add_transaction(m, collector, 2850.0, base_time + timedelta(hours=4 + idx))

    pooling_rings = detector.detect_fan_out_fan_in(min_mules=2)
    assert len(pooling_rings) >= 1

    ring = pooling_rings[0]
    assert ring.pattern_type == "fan_out_fan_in"
    assert ring.details["source"] == source
    assert ring.details["collector"] == collector
    assert ring.details["mule_count"] == 3
    assert ring.confidence_score >= 0.70
    assert ring.total_volume > 15000.0


def test_mule_ring_full_analysis_and_ingest_trace() -> None:
    detector = MuleRingDetector()
    gen = SyntheticFraudAttackGenerator(seed=55)

    # Ingest a smurfing pattern trace
    trace = gen.generate_adversarial_trace(pattern=AttackVectorType.SMURFING)
    ingested = detector.ingest_trace(trace)
    assert ingested > 0

    analysis = detector.analyze()
    assert analysis.total_transactions == ingested
    assert analysis.total_nodes > 0


def test_streaming_benchmark_execution() -> None:
    # Run a quick 500-transaction streaming benchmark
    cfg = StreamingBenchmarkConfig(transaction_count=500, seed=42)
    detector = MuleRingDetector()
    bench = StreamingBenchmark(detector=detector, config=cfg)
    result = bench.run()

    assert result.total_transactions == 500
    assert result.total_duration_seconds > 0.0
    assert result.throughput_tx_per_sec > 100.0  # Should be thousands of tx/sec
    assert result.latency_mean_ms >= 0.0
    assert result.latency_p50_ms <= result.latency_p95_ms <= result.latency_p99_ms
    assert result.latency_min_ms <= result.latency_max_ms

    summary = result.summary()
    assert "Streaming Benchmark Results" in summary
    assert "Throughput" in summary

    d = result.to_dict()
    assert d["total_transactions"] == 500


def test_streaming_benchmark_helper() -> None:
    res = run_streaming_benchmark(volume=300, seed=99)
    assert res.total_transactions == 300
    assert res.throughput_tx_per_sec > 0
