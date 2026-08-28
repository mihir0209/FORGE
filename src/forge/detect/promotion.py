# pyright: reportMissingTypeStubs=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportArgumentType=false, reportCallIssue=false
"""Promotion suite — candidate vs controls and incumbent (conservative policy)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import numpy as np
import pandas as pd

from forge.config import settings
from forge.contracts.contracts import CandidateReport, PromotionVerdict, WorldSeed
from forge.detect.incumbent import load_incumbent
from forge.feature_schema import FEATURE_NAMES
from forge.simulate import build_legit_trace

if TYPE_CHECKING:
    from forge.kb import Registry


def _control_fp_rate(candidate: CandidateReport, n_controls: int = 20) -> float:
    import joblib

    artifact = Path(candidate.artifact_path)
    # only allow artifacts under data/models
    try:
        artifact.resolve().relative_to(Path("data/models").resolve())
    except ValueError:
        return 1.0
    if not artifact.exists():
        return 1.0
    # verify hash before deserializing to prevent RCE via crafted joblib pickle
    if candidate.artifact_sha256:
        try:
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        except Exception:
            return 1.0
        if digest != candidate.artifact_sha256:
            return 1.0
    model: Any = joblib.load(artifact)
    from forge.detect import trace_features

    flagged = 0
    from forge.actor_sandbox import ActorSandbox, legitimate_app_payment_plan
    from forge.artifacts import LocalArtifactStore

    for i in range(n_controls):
        views = [build_legit_trace(WorldSeed(master_seed=20_000 + i)).observed_view()]
        app_trace = (
            ActorSandbox(LocalArtifactStore(Path("data/control-artifacts")))
            .execute(
                legitimate_app_payment_plan(
                    "promotion-control",
                    f"promotion-control-{i}",
                    active_call=i % 2 == 0,
                    first_time_payee=i % 3 == 0,
                ),
                WorldSeed(master_seed=40_000 + i),
                cycle_id=f"promotion-control-{i}",
            )
            .trace
        )
        views.append(app_trace.observed_view())
        for view in views:
            vec = [[float(trace_features(view).get(k, 0.0)) for k in FEATURE_NAMES]]
            proba = float(model.predict_proba(vec)[0, 1])  # type: ignore[operator]
            if proba >= 0.5:
                flagged += 1
    return flagged / max(n_controls * 2, 1)


def _incumbent_auc_on_dataset(dataset: Any, incumbent: Any) -> float:
    try:
        from sklearn.metrics import roc_auc_score

        X_test = pd.read_parquet(str(dataset.test_path))[list(FEATURE_NAMES)].to_numpy()
        y_test = pd.read_parquet(str(dataset.test_path))["label"].to_numpy()
        proba = np.array(
            [
                float(incumbent.score_features(dict(zip(FEATURE_NAMES, row, strict=False))))
                for row in X_test
            ]
        )
        return float(roc_auc_score(y_test, proba))
    except Exception:
        return float("nan")


def _validate_manifest(report: CandidateReport) -> bool:
    try:
        raw_path = report.dataset_manifest_path or ""
        path = Path(raw_path)
        # prevent path traversal: manifest must live under data/datasets
        try:
            path.resolve().relative_to(Path("data/datasets").resolve())
        except ValueError:
            return False
        manifest: dict[str, Any] = json.loads(path.read_text())
        payload = {key: value for key, value in manifest.items() if key != "sha256"}
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if digest != manifest.get("sha256"):
            return False
        if manifest.get("protocol") != report.evaluation_protocol:
            return False
        if manifest.get("feature_schema_version") != report.feature_schema_version:
            return False
        if {manifest.get("calibration_family"), manifest.get("test_family")} != set(
            report.held_out_families
        ):
            return False
        manifest_hashes = manifest.get("parquet_sha256", {})
        if manifest_hashes != report.dataset.parquet_sha256:
            return False
        for split, expected in manifest_hashes.items():
            parquet_path = Path(str(getattr(report.dataset, f"{split}_path")))
            if hashlib.sha256(parquet_path.read_bytes()).hexdigest() != expected:
                return False
        rows = manifest.get("rows", [])
        for split, count in report.dataset.split_positive_counts.items():
            actual = sum(1 for row in rows if row["split"] == split and row["label"] == 1)
            if actual != count:
                return False
        train_families = {row["family"] for row in rows if row["split"] == "train"}
        if train_families.intersection(report.held_out_families):
            return False
        positive_rows = [row for row in rows if row["label"] == 1]
        included_tracks = {row["track"] for row in positive_rows}
        train_tracks = {row["track"] for row in positive_rows if row["split"] == "train"}
        if included_tracks != {track.value for track in report.dataset.included_tracks}:
            return False
        if train_tracks != {track.value for track in report.dataset.train_tracks}:
            return False
        return len(rows) == report.dataset.rows
    except Exception:
        return False


def evaluate(report: CandidateReport, registry: Registry) -> PromotionVerdict:
    settings()
    checks: dict[str, bool] = {}

    # hard gates (settings-tunable via detect section; keep concrete values in code's default so code-review can see them)
    checks["roc_auc_ge_0.85"] = report.roc_auc >= 0.85
    checks["recall_at_fpr_1e2_ge_0.5"] = report.recall_at_fpr_1e2 >= 0.50
    checks["brier_le_0.25"] = report.brier <= 0.25
    checks["latency_p95_le_100ms"] = report.p95_latency_ms <= 100.0
    checks["control_fp_rate_le_0.15"] = _control_fp_rate(report) <= 0.15
    checks["approved_evaluation_protocol"] = report.evaluation_protocol in {
        "attack-family-disjoint-holdout",
        "temporal-holdout",
        "external-sealed-holdout",
    }
    checks["current_feature_schema"] = report.feature_schema_version == "forge-feature-v2"
    checks["manifest_verified"] = _validate_manifest(report)
    checks["prediction_ledger_present"] = bool(
        report.prediction_ledger_path
        and report.prediction_ledger_sha256
        and Path(report.prediction_ledger_path).exists()
        and hashlib.sha256(Path(report.prediction_ledger_path).read_bytes()).hexdigest()
        == report.prediction_ledger_sha256
    )
    checks["evaluation_summary_present"] = bool(
        report.evaluation_summary_path
        and report.evaluation_summary_sha256
        and Path(report.evaluation_summary_path).exists()
        and hashlib.sha256(Path(report.evaluation_summary_path).read_bytes()).hexdigest()
        == report.evaluation_summary_sha256
    )
    checks["model_artifact_verified"] = bool(
        report.artifact_sha256
        and Path(report.artifact_path).exists()
        and hashlib.sha256(Path(report.artifact_path).read_bytes()).hexdigest()
        == report.artifact_sha256
    )
    checks["held_out_family_count_ge_2"] = len(report.held_out_families) >= 2
    checks["dataset_rows_ge_60"] = report.dataset.rows >= 60
    checks["calibration_positives_ge_20"] = (
        report.dataset.split_positive_counts.get("calib", 0) >= 20
    )
    checks["test_positives_ge_20"] = report.dataset.split_positive_counts.get("test", 0) >= 20
    included_tracks = {track.value for track in report.dataset.included_tracks}
    checks["behavioral_track_present"] = "behavioral_payment" in included_tracks
    checks["ai_assisted_app_track_present"] = "ai_assisted_app" in included_tracks
    train_tracks = {track.value for track in report.dataset.train_tracks}
    checks["behavioral_track_in_train"] = "behavioral_payment" in train_tracks
    checks["ai_assisted_app_track_in_train"] = "ai_assisted_app" in train_tracks

    incumbent = load_incumbent()
    inc_auc = _incumbent_auc_on_dataset(report.dataset, incumbent)
    checks["incumbent_evaluation_succeeded"] = not np.isnan(inc_auc)
    checks["beats_incumbent"] = not np.isnan(inc_auc) and report.roc_auc >= inc_auc

    passed = all(checks.values())
    notes: list[str] = []
    if not passed:
        notes.append("; ".join(k for k, v in checks.items() if not v) + " failed")
    if passed and registry.strategy_count() < 3:
        notes.append(f"small registry ({registry.strategy_count()} strategies)")

    return PromotionVerdict(
        candidate_id=report.candidate_id,
        passed=passed,
        checks=checks,
        notes=notes,
    )


def install_if_passed(report: CandidateReport, verdict: PromotionVerdict) -> bool:
    if not verdict.passed or verdict.candidate_id != report.candidate_id:
        return False
    from forge.detect.incumbent import install_candidate

    install_candidate(
        report.artifact_path,
        report.candidate_id,
        promotion_receipt={
            "candidate_id": verdict.candidate_id,
            "passed": verdict.passed,
            "checks": verdict.checks,
            "evaluation_protocol": report.evaluation_protocol,
            "feature_schema_version": report.feature_schema_version,
            "dataset_manifest_path": report.dataset_manifest_path,
            "artifact_sha256": report.artifact_sha256,
            "prediction_ledger_sha256": report.prediction_ledger_sha256,
            "evaluation_summary_sha256": report.evaluation_summary_sha256,
        },
    )
    return True
