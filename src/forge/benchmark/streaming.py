# pyright: reportMissingTypeStubs=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false
"""Streaming benchmark: measures detection latency and throughput under high streaming transaction volume."""

from __future__ import annotations

import os
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import numpy as np

from forge.contracts.contracts import ActorKind, TraceEvent
from forge.detect.mule_ring import MuleRingDetector
from forge.simulate.generator import (
    SyntheticFraudAttackGenerator,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


@dataclass
class StreamingBenchmarkConfig:
    """Configuration for streaming detection benchmark."""

    transaction_count: int = 5000
    batch_size: int = 1  # 1 for pure event-by-event streaming, >1 for micro-batches
    burst_ratio: float = 0.04
    geo_hop_ratio: float = 0.02
    smurf_ratio: float = 0.04
    seed: int = 42


@dataclass
class StreamingBenchmarkResult:
    """Metrics captured during streaming throughput and latency benchmarking."""

    total_transactions: int
    total_duration_seconds: float
    throughput_tx_per_sec: float
    latency_mean_ms: float
    latency_p50_ms: float
    latency_p90_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    latency_min_ms: float
    latency_max_ms: float
    detections_count: int
    memory_rss_delta_mb: float
    benchmark_timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def summary(self) -> str:
        return (
            f"=== Streaming Benchmark Results ===\n"
            f"Transactions Processed : {self.total_transactions:,}\n"
            f"Total Duration         : {self.total_duration_seconds:.4f} s\n"
            f"Throughput             : {self.throughput_tx_per_sec:,.1f} tx/sec\n"
            f"Latency (mean)         : {self.latency_mean_ms:.4f} ms\n"
            f"Latency (p50 / median) : {self.latency_p50_ms:.4f} ms\n"
            f"Latency (p95)          : {self.latency_p95_ms:.4f} ms\n"
            f"Latency (p99)          : {self.latency_p99_ms:.4f} ms\n"
            f"Latency (min / max)    : {self.latency_min_ms:.4f} ms / {self.latency_max_ms:.4f} ms\n"
            f"Detections Triggered   : {self.detections_count}\n"
            f"Memory RSS Delta       : {self.memory_rss_delta_mb:.2f} MB\n"
            f"==================================="
        )


def _get_process_rss_mb() -> float:
    """Get current process RSS memory in megabytes."""
    try:
        import psutil

        proc = psutil.Process(os.getpid())
        return proc.memory_info().rss / (1024.0 * 1024.0)
    except Exception:
        return 0.0


def generate_benchmark_transaction_stream(
    count: int = 5000,
    *,
    seed: int = 42,
    burst_ratio: float = 0.04,
    geo_hop_ratio: float = 0.02,
    smurf_ratio: float = 0.04,
) -> Iterator[TraceEvent]:
    """Generate a high-volume interleaved stream of baseline and adversarial transactions."""
    rng = np.random.default_rng(seed)
    attack_gen = SyntheticFraudAttackGenerator(seed=seed)

    base_time = datetime(2026, 8, 25, 6, 0, tzinfo=UTC)
    produced = 0

    customers = [f"cust_{i:04d}" for i in range(200)]
    merchants = [f"merch_{i:03d}" for i in range(50)]

    while produced < count:
        dice = float(rng.uniform(0.0, 1.0))

        if dice < burst_ratio and produced + 10 <= count:
            c = customers[int(rng.integers(0, len(customers)))]
            burst = attack_gen.generate_micro_burst(
                customer_id=c,
                count=int(rng.integers(6, 12)),
                start_time=base_time,
            )
            for event in burst:
                yield event
                produced += 1
                if produced >= count:
                    return
            base_time = burst[-1].ts + timedelta(seconds=5)

        elif dice < (burst_ratio + geo_hop_ratio) and produced + 3 <= count:
            c = customers[int(rng.integers(0, len(customers)))]
            hops = attack_gen.generate_geo_velocity_hops(
                customer_id=c,
                start_time=base_time,
                hop_minutes=float(rng.uniform(5.0, 15.0)),
            )
            for event in hops:
                yield event
                produced += 1
                if produced >= count:
                    return
            base_time = hops[-1].ts + timedelta(seconds=10)

        elif dice < (burst_ratio + geo_hop_ratio + smurf_ratio) and produced + 5 <= count:
            collector = f"acc_collector_{int(rng.integers(1, 10)):02d}"
            smurfs = attack_gen.generate_smurfing_pattern(
                target_account=collector,
                num_transactions=int(rng.integers(3, 6)),
                start_time=base_time,
                spread_hours=float(rng.uniform(1.0, 6.0)),
            )
            for event in smurfs:
                yield event
                produced += 1
                if produced >= count:
                    return
            base_time = smurfs[-1].ts + timedelta(seconds=15)

        else:
            # Baseline normal payment
            c = customers[int(rng.integers(0, len(customers)))]
            m = merchants[int(rng.integers(0, len(merchants)))]
            amount = round(float(rng.lognormal(mean=3.5, sigma=0.8)), 2)
            base_time += timedelta(milliseconds=float(rng.uniform(20.0, 500.0)))

            event = TraceEvent(
                event_id=f"base_tx_{seed}_{produced:07d}",
                ts=base_time,
                actor_kind=ActorKind.CUSTOMER,
                actor_id=c,
                kind="payment",
                payload={
                    "customer": c,
                    "merchant": m,
                    "amount": amount,
                    "currency": "USD",
                },
                is_attack_step=False,
            )
            yield event
            produced += 1


class StreamingBenchmark:
    """Benchmark harness measuring latency percentiles and throughput for detectors under stream load."""

    def __init__(
        self,
        detector: Any | None = None,
        config: StreamingBenchmarkConfig | None = None,
        processor_fn: Callable[[TraceEvent], Any] | None = None,
    ) -> None:
        self.config = config or StreamingBenchmarkConfig()
        self.detector = detector if detector is not None else MuleRingDetector()
        self.processor_fn = processor_fn

    def _default_process(self, event: TraceEvent) -> Any:
        """Default event processing step for MuleRingDetector."""
        if isinstance(self.detector, MuleRingDetector):
            p = event.payload
            src = str(p.get("customer") or p.get("source_account") or event.actor_id)
            dst = str(p.get("destination_account") or p.get("merchant") or "")
            amt = float(p.get("amount", 0.0))
            if src and dst and src != dst and amt > 0:
                return self.detector.add_transaction(
                    source=src,
                    destination=dst,
                    amount=amt,
                    timestamp=event.ts,
                    tx_id=event.event_id,
                    metadata=p,
                )
            return None
        elif hasattr(self.detector, "score_features"):
            return self.detector.score_features({"volume": 1.0})
        return None

    def run(self) -> StreamingBenchmarkResult:
        """Execute the streaming volume benchmark and record latency percentiles."""
        stream = generate_benchmark_transaction_stream(
            count=self.config.transaction_count,
            seed=self.config.seed,
            burst_ratio=self.config.burst_ratio,
            geo_hop_ratio=self.config.geo_hop_ratio,
            smurf_ratio=self.config.smurf_ratio,
        )

        process_fn = self.processor_fn or self._default_process

        initial_rss = _get_process_rss_mb()
        latencies_ms: list[float] = []
        detections = 0

        t_start = time.perf_counter()

        for event in stream:
            # Measure individual transaction processing latency
            t0 = time.perf_counter_ns()
            out = process_fn(event)
            t1 = time.perf_counter_ns()

            lat_ms = (t1 - t0) / 1_000_000.0
            latencies_ms.append(lat_ms)

            if out is not None:
                detections += 1

        t_end = time.perf_counter()
        final_rss = _get_process_rss_mb()

        total_duration = max(t_end - t_start, 1e-6)
        total_count = len(latencies_ms)
        throughput = total_count / total_duration

        lat_arr = np.array(latencies_ms) if latencies_ms else np.zeros(1)

        # Detect rings if the detector is a MuleRingDetector
        if isinstance(self.detector, MuleRingDetector):
            rings = self.detector.detect_rings()
            detections = len(rings)

        return StreamingBenchmarkResult(
            total_transactions=total_count,
            total_duration_seconds=round(total_duration, 4),
            throughput_tx_per_sec=round(throughput, 2),
            latency_mean_ms=round(float(np.mean(lat_arr)), 4),
            latency_p50_ms=round(float(np.percentile(lat_arr, 50)), 4),
            latency_p90_ms=round(float(np.percentile(lat_arr, 90)), 4),
            latency_p95_ms=round(float(np.percentile(lat_arr, 95)), 4),
            latency_p99_ms=round(float(np.percentile(lat_arr, 99)), 4),
            latency_min_ms=round(float(np.min(lat_arr)), 4),
            latency_max_ms=round(float(np.max(lat_arr)), 4),
            detections_count=detections,
            memory_rss_delta_mb=round(max(0.0, final_rss - initial_rss), 2),
            metadata={
                "seed": self.config.seed,
                "batch_size": self.config.batch_size,
                "detector_class": self.detector.__class__.__name__,
            },
        )


def run_streaming_benchmark(
    volume: int = 5000,
    seed: int = 42,
    detector: Any | None = None,
) -> StreamingBenchmarkResult:
    """Convenience helper to run a streaming benchmark with a given volume and seed."""
    cfg = StreamingBenchmarkConfig(transaction_count=volume, seed=seed)
    benchmark = StreamingBenchmark(detector=detector, config=cfg)
    return benchmark.run()


__all__ = [
    "StreamingBenchmark",
    "StreamingBenchmarkConfig",
    "StreamingBenchmarkResult",
    "generate_benchmark_transaction_stream",
    "run_streaming_benchmark",
]
