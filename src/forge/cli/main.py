"""forge CLI — offline cycle runner (G1) and future pipeline helpers."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from forge.app_scam_runner import run_app_scam_cycle
from forge.artifacts import artifact_store_from_env
from forge.cycle_runner import run_offline_cycle
from forge.kb import SQLiteRegistry
from forge.redteam.fixtures import default_draft


def _cmd_train(args: argparse.Namespace) -> int:
    from pathlib import Path as _Path

    from forge.detect.dataset import build_dataset
    from forge.detect.promotion import evaluate, install_if_passed
    from forge.detect.train import train_detector
    from forge.kb import SQLiteRegistry

    reg = SQLiteRegistry(_Path(args.db))
    ref = build_dataset(reg, n_negatives=args.n_negatives)
    report = train_detector(ref)
    verdict = evaluate(report, reg)
    ok = install_if_passed(report, verdict)
    print(
        json.dumps(
            {
                "candidate_id": report.candidate_id,
                "roc_auc": round(report.roc_auc, 3),
                "passed": verdict.passed,
                "installed": ok,
                "checks": verdict.checks,
            },
            indent=2,
        )
    )
    return 0 if verdict.passed else 1


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


def _cmd_app_scam(args: argparse.Namespace) -> int:
    registry = SQLiteRegistry(Path(args.db))
    store = artifact_store_from_env()
    record = run_app_scam_cycle(
        seed=args.seed,
        cycle_id=args.cycle_id or f"cycle-app-{args.seed}",
        registry=registry,
        store=store,
    )
    print(
        json.dumps(
            {
                "cycle_id": record.cycle_id,
                "family": record.strategy.attack_family,
                "verdict": record.blue_report.verdict.value,
                "signals": [s.name for s in record.blue_report.signals],
                "gate_score": record.gate_result.score,
                "trace_ref": record.trace_ref,
            },
            indent=2,
        )
    )
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

    app_scam = sub.add_parser(
        "app-scam-cycle",
        help="execute an AI-assisted authorized-push-payment scam cycle",
    )
    app_scam.add_argument("--seed", type=int, required=True)
    app_scam.add_argument("--cycle-id")
    app_scam.add_argument("--db", default="data/registry.sqlite")
    app_scam.set_defaults(func=_cmd_app_scam)

    trn = sub.add_parser("train", help="run one training round from the current registry")
    trn.add_argument("--db", default="data/registry.sqlite")
    trn.add_argument("--n-negatives", type=int, default=80)
    trn.set_defaults(func=_cmd_train)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:  # pragma: no cover - CLI boundary
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
