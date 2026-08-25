"""Benchmark V1 paired dataset and evaluation protocol."""

from forge.benchmark.generate import generate_pair
from forge.benchmark.protocol import (
    BENCHMARK_PROTOCOL_VERSION,
    BenchmarkSource,
    ProtocolConfig,
    build_benchmark,
    verify_benchmark,
)

__all__ = [
    "BENCHMARK_PROTOCOL_VERSION",
    "BenchmarkSource",
    "ProtocolConfig",
    "build_benchmark",
    "generate_pair",
    "verify_benchmark",
]
