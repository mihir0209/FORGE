# pyright: reportMissingTypeStubs=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportArgumentType=false
"""forge CLI — offline cycle runner (G1) and future pipeline helpers."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from forge.app_scam_runner import run_app_scam_cycle
from forge.artifacts import artifact_store_from_env
from forge.cycle_runner import run_offline_cycle
from forge.kb import SQLiteRegistry
from forge.redteam.fixtures import default_draft

if TYPE_CHECKING:
    from forge.contracts.contracts import EvidenceCapability


def _cmd_train(args: argparse.Namespace) -> int:
    from pathlib import Path as _Path

    from forge.detect.dataset import build_dataset, build_family_holdout_dataset
    from forge.detect.promotion import evaluate, install_if_passed
    from forge.detect.train import train_detector
    from forge.kb import SQLiteRegistry

    reg = SQLiteRegistry(_Path(args.db))
    ref = (
        build_family_holdout_dataset(
            reg,
            n_negatives_per_split=args.n_negatives_per_split,
            dataset_seed=args.seed,
            calibration_family=args.calibration_family,
            test_family=args.test_family,
        )
        if args.protocol == "attack-family-disjoint-holdout"
        else build_dataset(reg, n_negatives=args.n_negatives, dataset_seed=args.seed)
    )
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
                "evaluation_protocol": report.evaluation_protocol,
                "feature_schema_version": report.feature_schema_version,
                "held_out_families": report.held_out_families,
                "dataset_manifest_path": report.dataset_manifest_path,
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
        variant=args.variant,
        family_version=args.family_version,
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


def _cmd_family_register(args: argparse.Namespace) -> int:
    from forge.contracts.contracts import FraudFamilyDefinition
    from forge.families import FamilyRegistry

    definition = Path(args.definition)
    family = FraudFamilyDefinition.model_validate_json(definition.read_text())
    registry = FamilyRegistry(
        definition.parent,
        require_approval=True,
        registry=SQLiteRegistry(Path(args.db)),
    )
    registry.register(family)
    print(
        json.dumps(
            {
                "family": family.slug,
                "version": family.version,
                "definition_sha256": family.definition_sha256,
                "database": str(args.db),
            },
            indent=2,
        )
    )
    return 0


def _cmd_variant_list(args: argparse.Namespace) -> int:
    from forge.families import FamilyRegistry
    from forge.kb import registry_from_env

    registry = SQLiteRegistry(Path(args.db)) if args.db else registry_from_env()
    active = {
        (family.slug, family.version, family.definition_sha256)
        for family in FamilyRegistry(registry=registry).list()
    }
    print(
        json.dumps(
            [
                {
                    "proposal_id": proposal.proposal_id,
                    "source_cycle_id": proposal.source_cycle_id,
                    "parent_family": proposal.parent_family_slug,
                    "candidate_family": proposal.candidate_family.slug,
                    "status": "approved"
                    if (
                        proposal.candidate_family.slug,
                        proposal.candidate_family.version,
                        proposal.candidate_family.definition_sha256,
                    )
                    in active
                    else "pending",
                    "residual_kinds": [kind.value for kind in proposal.residual_kinds],
                    "changes": [change.model_dump(mode="json") for change in proposal.changes],
                }
                for proposal in registry.variant_proposals()
            ],
            indent=2,
        )
    )
    return 0


def _cmd_variant_approve(args: argparse.Namespace) -> int:
    from forge.families import FamilyRegistry
    from forge.kb import registry_from_env
    from forge.research_snapshots import ResearchSnapshotStore

    registry = SQLiteRegistry(Path(args.db)) if args.db else registry_from_env()
    proposal = registry.variant_proposal(args.proposal_id)
    if proposal is None:
        raise ValueError(f"unknown variant proposal {args.proposal_id}")
    source = registry.cycle(proposal.source_cycle_id)
    if source is None or source.strategy.family_definition_sha256 != proposal.parent_definition_sha256:
        raise ValueError("variant proposal source cycle or parent checksum is unavailable")

    data_root = Path(args.data_dir)
    family_registry = FamilyRegistry(
        data_root / "families",
        require_approval=True,
        registry=registry,
    )
    parent = family_registry.get(proposal.parent_family_slug, proposal.parent_family_version)
    if parent.definition_sha256 != proposal.parent_definition_sha256:
        raise ValueError("variant proposal parent definition has changed")
    from forge.gapmine import propose_variant

    expected = propose_variant(source, parent)
    if expected != proposal:
        raise ValueError("variant proposal checksum or derivation is invalid")
    ResearchSnapshotStore(data_root / "research").approve_family(
        proposal.candidate_family,
        args.snapshot_id,
        reviewer=args.reviewer,
        approved=True,
    )
    family_registry.register(proposal.candidate_family)
    print(
        json.dumps(
            {
                "proposal_id": proposal.proposal_id,
                "registered_family": proposal.candidate_family.slug,
                "definition_sha256": proposal.candidate_family.definition_sha256,
            },
            indent=2,
        )
    )
    return 0


def _cmd_data_audit(args: argparse.Namespace) -> int:
    from forge.data_quality import audit_registry
    from forge.kb import registry_from_env

    registry = SQLiteRegistry(Path(args.db)) if args.db else registry_from_env()
    result = audit_registry(registry, run_id=args.run_id)
    print(json.dumps(result, indent=2))
    return 0 if result[args.require] else 1


def _cmd_benchmark_v1(args: argparse.Namespace) -> int:
    import pandas as pd

    from forge.benchmark import ProtocolConfig, build_benchmark, generate_pair
    from forge.benchmark.external import external_component_evaluated
    from forge.detect.benchmark import run_benchmark
    from forge.families import family_registry_from_env
    from forge.feature_schema import FEATURE_NAMES

    root = Path(args.output)
    families = family_registry_from_env().list()
    sources = [
        source
        for index, family in enumerate(families)
        for repeat in range(args.worlds_per_family)
        for source in generate_pair(
            family,
            seed=args.seed + index * 100 + repeat,
            output_root=root / "generation",
        )
    ]
    feature_capabilities = {
        name: _feature_capability(name) for name in FEATURE_NAMES
    }
    sealed_templates = frozenset[str](
        value for value in str(args.sealed_templates).split(",") if value
    )
    sealed_families = frozenset[str](
        value for value in str(args.sealed_families).split(",") if value
    )
    manifest = build_benchmark(
        sources,
        feature_capabilities=feature_capabilities,
        config=ProtocolConfig(
            sealed_families=sealed_families,
            sealed_templates=sealed_templates,
            development_folds=args.development_folds,
        ),
        output_root=root / "datasets",
    )
    dataset_root = root / "datasets" / manifest.dataset_id
    dataset = pd.concat(
        [pd.read_parquet(dataset_root / artifact.path) for artifact in manifest.artifacts],
        ignore_index=True,
    )
    result = run_benchmark(
        dataset,
        FEATURE_NAMES,
        root / "runs",
        dataset_id=manifest.dataset_id,
        bootstrap_samples=args.bootstrap_samples,
        capability_features={
            capability.value: tuple(
                name for name, owner in feature_capabilities.items() if owner == capability
            )
            for capability in set(feature_capabilities.values())
        },
    )
    unique = int(dataset["feature_sha256"].nunique())
    external_ready = bool(
        args.external_manifest and external_component_evaluated(Path(args.external_manifest))
    )
    publishable = unique >= args.min_unique_vectors and external_ready
    print(
        json.dumps(
            {
                "dataset_id": manifest.dataset_id,
                "rows": len(dataset),
                "unique_feature_vectors": unique,
                "families": len(families),
                "templates": len({family.scenario_template for family in families}),
                "report_paths": result.report_paths,
                "run_manifest": result.manifest_path,
                "publishable": publishable,
                "publication_blockers": [
                    reason
                    for condition, reason in (
                        (unique < args.min_unique_vectors, "insufficient unique feature vectors"),
                        (
                            not external_ready,
                            "external component has no validated media inference metrics",
                        ),
                    )
                    if condition
                ],
            },
            indent=2,
        )
    )
    return 0


def _feature_capability(name: str) -> EvidenceCapability:
    from forge.contracts.contracts import EvidenceCapability

    if name in {"burst", "new_device", "refund_pressure", "off_hours_focus", "cashout_pressure", "volume"}:
        return EvidenceCapability.PAYMENT_HISTORY
    if name in {"behavioral_coaching_risk", "warning_override", "balance_depletion"}:
        return EvidenceCapability.APP_BEHAVIOR
    if name == "beneficiary_network_risk":
        return EvidenceCapability.BENEFICIARY_NETWORK
    if name == "first_time_payee":
        return EvidenceCapability.PAYEE_VERIFICATION
    if name in {"active_external_call", "transaction_during_call"}:
        return EvidenceCapability.SYSTEM_CALL_STATE
    return EvidenceCapability.BANK_CONTROLLED_MEDIA


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
    app_scam.add_argument(
        "--family-slug",
        "--variant",
        dest="variant",
        default="safe_account",
        help="family slug (legacy aliases safe_account, family_emergency, investment_coaching work)",
    )
    app_scam.add_argument("--family-version", default="1.0.0")
    app_scam.set_defaults(func=_cmd_app_scam)

    family_register = sub.add_parser(
        "family-register",
        help="activate an approved family definition in the runtime registry",
    )
    family_register.add_argument("--definition", required=True)
    family_register.add_argument("--db", default="data/registry.sqlite")
    family_register.set_defaults(func=_cmd_family_register)

    data_audit = sub.add_parser(
        "data-audit",
        help="verify trace persistence, defender blindness, evidence links, and LLM readiness",
    )
    data_audit.add_argument("--db", help="SQLite registry; omit to use configured runtime registry")
    data_audit.add_argument("--run-id", help="audit only one supervised run")
    data_audit.add_argument(
        "--require", choices=("integrity_ready", "llm_ready"), default="integrity_ready"
    )
    data_audit.set_defaults(func=_cmd_data_audit)

    variant_list = sub.add_parser("variant-list", help="list pending residual family variants")
    variant_list.add_argument("--db")
    variant_list.set_defaults(func=_cmd_variant_list)

    variant_approve = sub.add_parser(
        "variant-approve",
        help="approve and register a pending residual family variant",
    )
    variant_approve.add_argument("--proposal-id", required=True)
    variant_approve.add_argument("--reviewer", required=True)
    variant_approve.add_argument("--snapshot-id", action="append", required=True)
    variant_approve.add_argument("--data-dir", default="data")
    variant_approve.add_argument("--db")
    variant_approve.set_defaults(func=_cmd_variant_approve)

    trn = sub.add_parser("train", help="run one training round from the current registry")
    trn.add_argument("--db", default="data/registry.sqlite")
    trn.add_argument("--n-negatives", type=int, default=80)
    trn.add_argument("--n-negatives-per-split", type=int, default=20)
    trn.add_argument("--seed", type=int, default=0)
    trn.add_argument("--calibration-family")
    trn.add_argument("--test-family")
    trn.add_argument(
        "--protocol",
        choices=["legacy-stratified", "attack-family-disjoint-holdout"],
        default="attack-family-disjoint-holdout",
    )
    trn.set_defaults(func=_cmd_train)

    bench = sub.add_parser("benchmark-v1", help="build the paired development benchmark")
    bench.add_argument("--output", default="data/benchmarks/forge-v1")
    bench.add_argument("--seed", type=int, default=30_000)
    bench.add_argument("--worlds-per-family", type=int, default=3)
    bench.add_argument("--development-folds", type=int, default=5)
    bench.add_argument("--sealed-families", default="ai_romance_remittance,genai_otp_auth_bypass")
    bench.add_argument("--sealed-templates", default="synthetic_kyc,agent_hijack")
    bench.add_argument("--bootstrap-samples", type=int, default=500)
    bench.add_argument("--min-unique-vectors", type=int, default=500)
    bench.add_argument("--external-manifest")
    bench.set_defaults(func=_cmd_benchmark_v1)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:  # pragma: no cover - CLI boundary
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
