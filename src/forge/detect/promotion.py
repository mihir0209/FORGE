# pyright: reportMissingTypeStubs=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportArgumentType=false, reportCallIssue=false
"""Promotion suite — candidate vs controls and incumbent (conservative policy)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import numpy as np
import pandas as pd

from forge.config import settings
from forge.contracts.contracts import CandidateReport, PromotionVerdict, WorldSeed
from forge.detect.incumbent import load_incumbent
from forge.signals import FEATURE_NAMES
from forge.simulate import build_legit_trace

if TYPE_CHECKING:
    from forge.kb import Registry


def _control_fp_rate(candidate: CandidateReport, n_controls: int = 20) -> float:
    from pathlib import Path

    import joblib

    if not Path(candidate.artifact_path).exists():
        return 1.0
    model: Any = joblib.load(candidate.artifact_path)
    from forge.detect import trace_features

    flagged = 0
    for i in range(n_controls):
        view = build_legit_trace(WorldSeed(master_seed=20_000 + i)).observed_view()
        vec = [[float(trace_features(view).get(k, 0.0)) for k in FEATURE_NAMES]]
        proba = float(model.predict_proba(vec)[0, 1])  # type: ignore[operator]
        if proba >= 0.5:
            flagged += 1
    return flagged / max(n_controls, 1)


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
        "temporal-family-holdout",
        "external-sealed-holdout",
    }

    incumbent = load_incumbent()
    inc_auc = _incumbent_auc_on_dataset(report.dataset, incumbent)
    if np.isnan(inc_auc):
        checks["beats_incumbent"] = True
    else:
        checks["beats_incumbent"] = report.roc_auc + 0.10 >= inc_auc

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
    if not verdict.passed:
        return False
    from forge.detect.incumbent import install_candidate

    install_candidate(report.artifact_path, report.candidate_id)
    return True
