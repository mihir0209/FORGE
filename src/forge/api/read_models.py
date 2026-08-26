# pyright: reportMissingTypeStubs=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false
"""Judge-facing read models over the registry and model artifacts."""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.request import urlopen

from forge.config import settings
from forge.families import family_registry_from_env
from forge.gapmine import rank
from forge.kb import Registry, f3_matrix, registry_from_env


def registry() -> Registry:
    return registry_from_env()


def cycles() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for cycle in reversed(registry().cycles()):
        out.append(
            {
                "cycle_id": cycle.cycle_id,
                "run_id": cycle.run_id,
                "recorded_at": cycle.recorded_at.isoformat(),
                "accepted": cycle.accepted,
                "strategy_id": cycle.strategy.strategy_id,
                "family": cycle.strategy.attack_family,
                "tactic": cycle.strategy.f3.tactic,
                "techniques": cycle.strategy.f3.techniques,
                "rail": cycle.strategy.rail,
                "channel": cycle.strategy.channel,
                "blue_verdict": cycle.blue_report.verdict.value,
                "blue_confidence": cycle.blue_report.confidence,
                "signals": [s.model_dump(mode="json") for s in cycle.blue_report.signals],
                "gate_score": cycle.gate_result.score,
                "gate_action": cycle.gate_result.action.value,
                "coverage": cycle.gate_result.coverage.value,
                "detector_id": cycle.gate_result.detector_id,
                "detection_track": cycle.detection_track.value,
                "evidence_capabilities": [c.value for c in cycle.evidence_capabilities],
                "feature_schema_version": cycle.feature_schema_version,
            }
        )
    return out


def cycle_detail(cycle_id: str) -> dict[str, Any] | None:
    for cycle in registry().cycles():
        if cycle.cycle_id == cycle_id:
            return cycle.model_dump(mode="json")
    return None


def strategy_repository(
    *, limit: int = 25, offset: int = 0, query: str | None = None
) -> dict[str, Any]:
    """Pair persisted red-team strategies with their latest blue-team handling."""
    reg = registry()
    cycles_by_strategy: dict[str, list[Any]] = {}
    for cycle in reg.cycles():
        cycles_by_strategy.setdefault(cycle.strategy.strategy_id, []).append(cycle)

    entries: list[dict[str, Any]] = []
    needle = query.casefold().strip() if query else ""
    for strategy in reg.strategies():
        if needle and needle not in " ".join(
            (
                strategy.strategy_id,
                strategy.attack_family,
                strategy.fraud_objective,
                strategy.f3.tactic,
                *strategy.f3.techniques,
            )
        ).casefold():
            continue
        runs = sorted(
            cycles_by_strategy.get(strategy.strategy_id, []),
            key=lambda cycle: cycle.recorded_at,
            reverse=True,
        )
        latest = runs[0] if runs else None
        entries.append(
            {
                "strategy_id": strategy.strategy_id,
                "attack_family": strategy.attack_family,
                "fingerprint": strategy.fingerprint(),
                "family_version": strategy.family_version,
                "family_definition_sha256": strategy.family_definition_sha256,
                "scenario_template": strategy.scenario_template,
                "run_count": len(runs),
                "latest_cycle_id": latest.cycle_id if latest else None,
                "recorded_at": latest.recorded_at.isoformat() if latest else None,
                "strategy": strategy.model_dump(mode="json"),
                "blue_report": latest.blue_report.model_dump(mode="json") if latest else None,
                "gate_result": latest.gate_result.model_dump(mode="json") if latest else None,
                "detection_track": latest.detection_track.value if latest else None,
                "evidence_capabilities": (
                    [capability.value for capability in latest.evidence_capabilities]
                    if latest
                    else []
                ),
                "markdown": _strategy_markdown(strategy, latest),
            }
        )

    entries.sort(key=lambda item: (item["recorded_at"] or "", item["strategy_id"]), reverse=True)
    return {
        "total": len(entries),
        "summary": {
            "investigated": sum(item["blue_report"] is not None for item in entries),
            "unhandled": sum(item["blue_report"] is None for item in entries),
            "families": len({item["attack_family"] for item in entries}),
        },
        "limit": limit,
        "offset": offset,
        "items": entries[offset : offset + limit],
    }


def _strategy_markdown(strategy: Any, cycle: Any | None) -> str:
    lines = [
        f"# {strategy.attack_family.replace('_', ' ').title()}",
        "",
        "## Red Team Strategy",
        "",
        f"- Strategy ID: `{strategy.strategy_id}`",
        f"- Fingerprint: `{strategy.fingerprint()}`",
        f"- F3 tactic: `{strategy.f3.tactic}`",
        f"- F3 techniques: {', '.join(f'`{item}`' for item in strategy.f3.techniques) or 'None'}",
        f"- Rail / channel: `{strategy.rail}` / `{strategy.channel}`",
        f"- Family version: `{strategy.family_version}`",
        f"- Scenario template: `{strategy.scenario_template}`",
        "",
        "### Fraud Objective",
        "",
        strategy.fraud_objective,
        "",
        "### Behavioral Sequence",
        "",
        *[f"{index}. {step}" for index, step in enumerate(strategy.behavioral_sequence, 1)],
        "",
        "### GenAI Leverage",
        "",
        strategy.genai_leverage,
        "",
        "### Evasion Hypothesis",
        "",
        strategy.evasion_hypothesis,
        "",
        "### Expected Signals",
        "",
        *([f"- {signal}" for signal in strategy.expected_signals] or ["- None declared"]),
    ]
    if cycle is None:
        lines.extend(["", "## Blue Team Handling", "", "Not yet investigated."])
        return "\n".join(lines)

    report = cycle.blue_report
    lines.extend(
        [
            "",
            "## Blue Team Handling",
            "",
            f"- Cycle ID: `{cycle.cycle_id}`",
            f"- Verdict: **{report.verdict.value}**",
            f"- Confidence: `{report.confidence:.3f}`",
            f"- Investigator: `{report.investigator_id}`",
            f"- Detector action: **{cycle.gate_result.action.value}**",
            f"- Coverage: **{cycle.gate_result.coverage.value}**",
            f"- Gate score: `{cycle.gate_result.score:.3f}`",
            "",
            "### Signals and Evidence",
            "",
        ]
    )
    for signal in report.signals:
        refs = ", ".join(f"`{ref}`" for ref in signal.evidence_refs) or "none"
        lines.append(f"- **{signal.name}** ({signal.strength:.3f}): {signal.description} Evidence: {refs}.")
    if not report.signals:
        lines.append("- No observable signals.")
    lines.extend(["", "### Recommended Mitigations", ""])
    lines.extend([f"- {item}" for item in report.mitigations] or ["- None proposed."])
    lines.extend(["", "### Uncovered Gaps", ""])
    lines.extend([f"- {item}" for item in report.uncovered_gaps] or ["- None reported."])
    return "\n".join(lines)


def coverage() -> dict[str, Any]:
    matrix = f3_matrix()
    records = registry().cycles()
    cells: list[dict[str, Any]] = []
    for tactic in matrix.tactics:
        tactic_cycles = [c for c in records if c.strategy.f3.tactic == tactic.slug]
        counts = Counter(c.gate_result.coverage.value for c in tactic_cycles)
        tested = {t for c in tactic_cycles for t in c.strategy.f3.techniques}
        total = len(matrix.techniques_of(tactic.slug))
        cells.append(
            {
                "id": tactic.tactic_id,
                "name": tactic.name,
                "slug": tactic.slug,
                "techniques_total": total,
                "techniques_tested": len(tested),
                "cycles": len(tactic_cycles),
                "coverage": dict(counts),
                "status": "uncovered"
                if not tactic_cycles
                else "blind_spot"
                if counts.get("blind_spot")
                else "partial"
                if counts.get("partial")
                else "covered",
            }
        )
    return {
        "summary": {
            "tactics_tested": sum(1 for c in cells if c["cycles"]),
            "tactics_total": len(cells),
            "techniques_tested": sum(c["techniques_tested"] for c in cells),
            "techniques_total": len(matrix.techniques),
        },
        "cells": cells,
    }


def gaps() -> list[dict[str, Any]]:
    return [b.model_dump(mode="json") for b in rank(registry(), limit=8)]


def families() -> list[dict[str, object]]:
    return [
        {
            "slug": family.slug,
            "version": family.version,
            "title": family.title,
            "track": family.detection_track.value,
            "rail": family.rail,
            "channel": family.channel,
            "definition_sha256": family.definition_sha256,
            "research_refs": family.research_refs,
        }
        for family in family_registry_from_env().list()
    ]


def model_card() -> dict[str, Any]:
    data_dir = Path(os.environ.get("FORGE_DATA_DIR", "data"))
    latest_path = data_dir / "models" / "latest-evaluation.json"
    latest_evaluation = (
        cast("dict[str, Any]", json.loads(latest_path.read_text()))
        if latest_path.exists()
        else None
    )
    pointer = data_dir / "models" / "incumbent.json"
    if not pointer.exists():
        return {
            "detector_id": "rule-baseline-v1",
            "kind": "rules",
            "promoted": False,
            "latest_evaluation": latest_evaluation,
        }
    meta: dict[str, Any] = json.loads(pointer.read_text())
    report_path = data_dir / "models" / "candidates" / f"{meta['candidate_id']}.json"
    report = (
        cast("dict[str, Any]", json.loads(report_path.read_text())) if report_path.exists() else {}
    )
    from forge.feature_schema import FEATURE_NAMES

    feature_names = list(meta.get("feature_names", []))
    compatible = feature_names == list(FEATURE_NAMES)
    if not compatible:
        from forge.feature_schema import KNOWN_SCHEMAS

        known_legacy = tuple(feature_names) in KNOWN_SCHEMAS.values()
        return {
            "detector_id": (
                f"compatible:{meta['candidate_id']}+rule-baseline-v1"
                if known_legacy
                else "rule-baseline-v1"
            ),
            "kind": "legacy-compatible-ensemble" if known_legacy else "rules",
            "promoted": False,
            "schema_compatible": False,
            "legacy_compatible": known_legacy,
            "compatibility_policy": "max_score" if known_legacy else None,
            "incompatible_candidate_id": meta["candidate_id"],
            "feature_names": feature_names,
            "metrics": {},
            "incompatible_candidate_metrics": report,
            "latest_evaluation": latest_evaluation,
        }
    receipt_path = data_dir / "models" / "promotion-verdict.json"
    receipt = (
        cast("dict[str, Any]", json.loads(receipt_path.read_text()))
        if receipt_path.exists()
        else {}
    )
    promoted = bool(receipt.get("passed") and receipt.get("candidate_id") == meta["candidate_id"])
    return {
        "detector_id": meta["candidate_id"],
        "kind": "lightgbm-calibrated",
        "promoted": promoted,
        "schema_compatible": compatible,
        "feature_names": feature_names,
        "artifact_path": meta["artifact_path"],
        "metrics": report,
        "promotion_checks": receipt.get("checks", {}),
        "promotion_notes": receipt.get("notes", []),
        "installed": receipt.get("installed", False),
        "evaluation_protocol": report.get("evaluation_protocol"),
        "dataset": report.get("dataset"),
        "artifact_sha256": report.get("artifact_sha256"),
        "latest_evaluation": latest_evaluation,
    }


def variants() -> list[dict[str, Any]]:
    reg = registry()
    active = {
        (family.slug, family.version, family.definition_sha256)
        for family in family_registry_from_env().list()
    }
    return [
        {
            "proposal_id": proposal.proposal_id,
            "proposal_sha256": proposal.proposal_sha256,
            "source_cycle_id": proposal.source_cycle_id,
            "parent_family_slug": proposal.parent_family_slug,
            "parent_family_version": proposal.parent_family_version,
            "candidate_family_slug": proposal.candidate_family.slug,
            "residual_kinds": [kind.value for kind in proposal.residual_kinds],
            "gate_coverage": proposal.gate_coverage.value,
            "blue_verdict": proposal.blue_verdict.value,
            "changes": [change.model_dump(mode="json") for change in proposal.changes],
            "created_at": proposal.created_at.isoformat(),
            "status": "approved"
            if (
                proposal.candidate_family.slug,
                proposal.candidate_family.version,
                proposal.candidate_family.definition_sha256,
            )
            in active
            else "pending",
        }
        for proposal in reg.variant_proposals()
    ]


def operations() -> dict[str, Any]:
    observed_at = datetime.now(UTC)
    reg = registry()
    records = reg.cycles()
    proposals = variants()
    data_root = Path(os.environ.get("FORGE_DATA_DIR", "data"))
    orchestrator = _inngest_status()
    workers = _worker_status(observed_at)
    supervisor = _supervisor_status()
    storage = _storage_inventory(data_root)
    components = [orchestrator["status"], workers["status"], supervisor["status"]]
    overall = (
        "unavailable"
        if "unavailable" in components
        else "degraded"
        if any(status in {"degraded", "unknown", "not_configured"} for status in components)
        else "healthy"
    )
    model = model_card()
    from forge.detect.incumbent import load_incumbent

    serving = load_incumbent()
    model["runtime_detector_id"] = serving.detector_id
    model["runtime_verified"] = model.get("detector_id") == serving.detector_id
    backup_receipt_path = data_root / "backup-verification.json"
    backup_receipt = (
        cast("dict[str, Any]", json.loads(backup_receipt_path.read_text()))
        if backup_receipt_path.exists()
        else None
    )
    return {
        "observed_at": observed_at.isoformat(),
        "overall_status": overall,
        "control_plane": {
            "api": {"status": "healthy", "detail": "FastAPI read model responded"},
            "orchestrator": orchestrator,
            "registry": {
                "status": "healthy",
                "detail": "Registry query completed",
                "backend": "postgresql" if os.environ.get("FORGE_DATABASE_URL") else "sqlite",
            },
        },
        "worker_plane": workers,
        "run": supervisor,
        "counts": {
            "families": len(family_registry_from_env().list()),
            "strategies": reg.strategy_count(),
            "cycles": len(records),
            "accepted_cycles": sum(cycle.accepted for cycle in records),
            "pending_variants": sum(item["status"] == "pending" for item in proposals),
            "training_corpora": len(reg.training_corpora()),
        },
        "storage": storage,
        "model": model,
        "backups": {
            "status": "degraded" if backup_receipt else "not_configured",
            "detail": (
                "Local backup restore verified; off-host backup is not configured"
                if backup_receipt
                else "Host persistence and MinIO versioning are enabled; no off-host backup "
                "or restore verification receipt exists"
            ),
            "sqlite_bootstrap_present": (data_root / "registry.sqlite").exists(),
            "last_successful_at": backup_receipt.get("verified_at") if backup_receipt else None,
            "restore_verified_at": backup_receipt.get("verified_at") if backup_receipt else None,
        },
        "pending_variants": proposals,
        "training": {
            "threshold": settings().pipeline.training_threshold_min,
            "accepted_cycles": sum(cycle.accepted for cycle in records),
            "corpora": [
                {"claim_id": claim_id, "cycle_count": count}
                for claim_id, count in reg.training_corpora()
            ],
        },
    }


def _inngest_status() -> dict[str, Any]:
    base = os.environ.get("INNGEST_BASE_URL")
    if not base:
        return {"status": "not_configured", "detail": "No Inngest base URL configured"}
    try:
        with urlopen(f"{base.rstrip('/')}/health", timeout=1.5) as response:
            healthy = response.status == 200
        queue_depth: float | None = None
        with urlopen(f"{base.rstrip('/')}/metrics", timeout=1.5) as response:
            metrics = response.read().decode()
        match = re.search(r"^inngest_queue_depth(?:\{[^}]*\})?\s+([\d.]+)$", metrics, re.MULTILINE)
        if match:
            queue_depth = float(match.group(1))
        return {
            "status": "healthy" if healthy else "degraded",
            "detail": "Inngest health endpoint responded",
            "queue_depth": queue_depth,
        }
    except Exception as exc:
        return {"status": "unavailable", "detail": str(exc), "queue_depth": None}


def _worker_status(observed_at: datetime) -> dict[str, Any]:
    configured = int(os.environ.get("FORGE_WORKER_REPLICAS", settings().run.workers))
    dsn = os.environ.get("FORGE_DATABASE_URL")
    if not dsn:
        return {
            "status": "unknown",
            "configured": configured,
            "observed": None,
            "detail": "Worker probes require PostgreSQL",
            "workers": [],
        }
    try:
        import psycopg

        with psycopg.connect(dsn) as connection, connection.cursor() as cursor:
            cursor.execute("SELECT to_regclass('public.forge_worker_probe')")
            table_row = cursor.fetchone()
            if table_row is None or table_row[0] is None:
                rows: list[tuple[str, datetime]] = []
            else:
                cursor.execute(
                    """
                    SELECT worker_id, max(completed_at)
                    FROM forge_worker_probe GROUP BY worker_id ORDER BY worker_id
                    """
                )
                rows = [(str(worker), completed) for worker, completed in cursor.fetchall()]
        worker_rows = [
            {
                "worker_id": worker,
                "last_seen_at": completed.isoformat(),
                "age_seconds": max(0, int((observed_at - completed).total_seconds())),
                "status": "responsive"
                if (observed_at - completed).total_seconds() <= 300
                else "stale",
            }
            for worker, completed in rows
        ]
        responsive = sum(row["status"] == "responsive" for row in worker_rows)
        return {
            "status": "healthy" if responsive >= configured else "degraded",
            "configured": configured,
            "observed": responsive,
            "detail": "Recent completed worker probes",
            "workers": worker_rows,
        }
    except Exception as exc:
        return {
            "status": "unavailable",
            "configured": configured,
            "observed": None,
            "detail": str(exc),
            "workers": [],
        }


def _supervisor_status() -> dict[str, Any]:
    from forge.operations.runtime import supervisor_from_env

    try:
        supervisor = supervisor_from_env()
        if supervisor is None:
            return {"status": "not_configured", "detail": "No bounded run configured"}
        state = supervisor.load()
        if state is None:
            return {"status": "unknown", "detail": "Run configured but not initialized"}
        return {
            "status": "healthy" if state.state.value in {"running", "scheduled"} else "degraded",
            "detail": state.state.value,
            "state": state.model_dump(mode="json"),
        }
    except Exception as exc:
        return {"status": "unavailable", "detail": str(exc)}


def _storage_inventory(root: Path) -> dict[str, Any]:
    inventories: dict[str, dict[str, Any]] = {}
    for name in (
        "artifacts",
        "objects",
        "datasets",
        "models",
        "families",
        "research",
        "runs",
        "benchmarks",
    ):
        path = root / name
        files = list(path.rglob("*")) if path.exists() else []
        regular = [item for item in files if item.is_file()]
        inventories[name] = {
            "files": len(regular),
            "bytes": sum(item.stat().st_size for item in regular),
        }
    object_backend = "filesystem"
    object_versioning = False
    object_status = "healthy" if root.exists() else "unavailable"
    object_detail = "Local object directory"
    if os.environ.get("S3_BUCKET"):
        object_backend = "minio"
        try:
            import boto3
            from botocore.config import Config

            client = boto3.client(
                "s3",
                endpoint_url=os.environ.get("S3_ENDPOINT_URL"),
                region_name=os.environ.get("S3_REGION", "us-east-1"),
                aws_access_key_id=os.environ.get("S3_ACCESS_KEY_ID"),
                aws_secret_access_key=os.environ.get("S3_SECRET_ACCESS_KEY"),
                config=Config(connect_timeout=1.5, read_timeout=1.5, retries={"max_attempts": 1}),
            )
            bucket = os.environ["S3_BUCKET"]
            client.head_bucket(Bucket=bucket)
            versioning = client.get_bucket_versioning(Bucket=bucket).get("Status")
            paginator = client.get_paginator("list_objects_v2")
            object_count = 0
            object_bytes = 0
            for page in paginator.paginate(Bucket=bucket):
                object_count += int(page.get("KeyCount", 0))
                object_bytes += sum(
                    int(item.get("Size", 0)) for item in page.get("Contents", [])
                )
            inventories["objects"] = {
                "files": object_count,
                "bytes": object_bytes,
            }
            object_versioning = versioning == "Enabled"
            object_detail = "Bucket probe succeeded"
        except Exception as exc:
            object_status = "unavailable"
            object_detail = str(exc)
    return {
        "status": object_status,
        "data_root": str(root),
        "stores": inventories,
        "object_backend": object_backend,
        "object_versioning": object_versioning,
        "object_detail": object_detail,
    }


def f3_view() -> dict[str, Any]:
    matrix = f3_matrix()
    return {
        "version": "1.1",
        "tactics": [
            {
                **tactic.model_dump(mode="json"),
                "techniques": [
                    t.model_dump(mode="json") for t in matrix.techniques_of(tactic.slug)
                ],
            }
            for tactic in matrix.tactics
        ],
    }
