# pyright: reportMissingTypeStubs=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportArgumentType=false, reportCallIssue=false
"""Promoted detector training (see research/ml-detection-stack-*)."""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import joblib  # type: ignore[import-untyped]
import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

from forge.config import settings
from forge.contracts.contracts import CandidateReport
from forge.signals import FEATURE_NAMES

if TYPE_CHECKING:
    from sklearn.base import BaseEstimator

CANDIDATES_ROOT = Path("data/models/candidates")


def _load(ref: Any) -> tuple[Any, Any]:
    df = pd.read_parquet(str(ref))
    return df[list(FEATURE_NAMES)].to_numpy(), df["label"].to_numpy()


def _recall_at_fpr(y_true: Any, proba: Any, fpr_target: float) -> float:
    fpr, tpr, _ = roc_curve(y_true, proba)
    # best tpr among thresholds where fpr <= target
    eligible = tpr[fpr <= fpr_target]
    return float(eligible.max()) if len(eligible) else 0.0


def train_detector(
    dataset: Any,
    *,
    candidate_id: str | None = None,
    n_estimators: int = 200,
) -> CandidateReport:
    import hashlib

    X_train, y_train = _load(dataset.train_path)
    X_calib, y_calib = _load(dataset.calib_path)
    X_test, y_test = _load(dataset.test_path)

    base = lgb.LGBMClassifier(
        n_estimators=n_estimators,
        learning_rate=0.08,
        num_leaves=15,
        min_child_samples=2,
        subsample=0.9,
        colsample_bytree=0.9,
        random_state=0,
        verbose=-1,
    )
    base.fit(
        X_train,
        y_train,
        eval_X=X_test,
        eval_y=y_test,
        callbacks=[lgb.early_stopping(20, verbose=False)],
    )

    from sklearn.frozen import FrozenEstimator  # type: ignore[attr-defined]

    calib_method = "isotonic" if len(X_calib) >= settings().detect.min_calib_rows else "sigmoid"
    calibrated: BaseEstimator = CalibratedClassifierCV(
        FrozenEstimator(base),
        method=calib_method,
    )
    calibrated.fit(X_calib, y_calib)

    proba: Any = calibrated.predict_proba(X_test)[:, 1]
    y_pred: Any = calibrated.predict(X_test)

    # latency
    single = X_test[0:1]
    timings: list[float] = []
    for _ in range(200):
        t0 = time.perf_counter()
        calibrated.predict_proba(single)  # type: ignore[operator]
        timings.append((time.perf_counter() - t0) * 1000)
    p50 = float(np.median(timings))
    p95 = float(np.percentile(timings, 95))

    cid = candidate_id or f"cand_{hashlib.sha256(dataset.dataset_id.encode()).hexdigest()[:8]}"
    artifact = CANDIDATES_ROOT / f"{cid}.joblib"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(calibrated, artifact)

    report = CandidateReport(
        candidate_id=cid,
        dataset=dataset,
        precision=float(precision_score(y_test, y_pred, zero_division=0)),
        recall=float(recall_score(y_test, y_pred, zero_division=0)),
        f1=float(
            2
            * precision_score(y_test, y_pred, zero_division=0)
            * recall_score(y_test, y_pred, zero_division=0)
            / max(
                precision_score(y_test, y_pred, zero_division=0)
                + recall_score(y_test, y_pred, zero_division=0),
                1e-9,
            )
        ),
        roc_auc=float(roc_auc_score(y_test, proba)),
        pr_auc=float(average_precision_score(y_test, proba)),
        recall_at_fpr_1e3=float(_recall_at_fpr(y_test, proba, 0.001)),
        recall_at_fpr_1e2=float(_recall_at_fpr(y_test, proba, 0.01)),
        brier=float(brier_score_loss(y_test, proba)),
        p50_latency_ms=p50,
        p95_latency_ms=p95,
        artifact_path=str(artifact),
    )
    artifact.with_suffix(".json").write_text(report.model_dump_json(indent=2))
    return report
