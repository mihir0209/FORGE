"""forge CLI — offline cycle runner (G1) and future pipeline helpers."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from forge.cycle_runner import run_offline_cycle
from forge.kb import SQLiteRegistry
from forge.redteam.fixtures import default_draft


def _cmd_cycle(args: argparse.Namespace) -> int:
    registry = SQLiteRegistry(Path(args.db))
    record = run_offline_cycle(
        args.seed,
        registry,
        draft=None if args.live else default_draft(),
    )
    summary = {
        "cycle_id": record.cycle_id,
        "strategy": {
            "id": record.strategy.strategy_id,
            "family": record.strategy.attack_family,
            "f3_tactic": record.strategy.f3.tactic,
            "fingerprint": record.strategy.fingerprint(),
            "novel_accepted": record.accepted,
        },
        "trace_ref": record.trace_ref,
        "blue": {
            "verdict": record.blue_report.verdict.value,
            "confidence": round(record.blue_report.confidence, 3),
            "signals": [s.name for s in record.blue_report.signals],
        },
        "gate": {
            "detector": record.gate_result.detector_id,
            "score": record.gate_result.score,
            "action": record.gate_result.action.value,
            "coverage": record.gate_result.coverage.value,
            "reason_codes": record.gate_result.reason_codes,
        },
    }
    print(json.dumps(summary, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="forge", description="FORGE lab CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    cyc = sub.add_parser("cycle", help="run one offline adversarial cycle")
    cyc.add_argument("--seed", type=int, required=True)
    cyc.add_argument("--db", default="data/registry.sqlite")
    cyc.add_argument(
        "--live",
        action="store_true",
        help="use live LLM reasoning instead of the scripted offline fixture",
    )
    cyc.set_defaults(func=_cmd_cycle)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:  # pragma: no cover - CLI boundary
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
