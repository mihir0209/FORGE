# pyright: reportMissingTypeStubs=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false
"""Streaming benchmark entrypoint (src/forge/benchmark.py): measures detection latency and throughput."""

from __future__ import annotations

import argparse
import sys

from forge.benchmark.streaming import (
    StreamingBenchmark,
    StreamingBenchmarkConfig,
    StreamingBenchmarkResult,
    generate_benchmark_transaction_stream,
    run_streaming_benchmark,
)

__all__ = [
    "StreamingBenchmark",
    "StreamingBenchmarkConfig",
    "StreamingBenchmarkResult",
    "generate_benchmark_transaction_stream",
    "main",
    "run_streaming_benchmark",
]


def main() -> int:
    parser = argparse.ArgumentParser(description="FORGE Streaming Detection Benchmark")
    parser.add_argument(
        "--volume",
        type=int,
        default=5000,
        help="Number of transactions to stream (default: 5000)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Master seed for reproducible streaming generation (default: 42)",
    )
    args = parser.parse_args()

    print(f"Running streaming benchmark with {args.volume:,} transactions (seed={args.seed})...")
    result = run_streaming_benchmark(volume=args.volume, seed=args.seed)
    print(result.summary())
    return 0


if __name__ == "__main__":
    sys.exit(main())
