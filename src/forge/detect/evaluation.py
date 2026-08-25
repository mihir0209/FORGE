# pyright: reportMissingTypeStubs=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportArgumentType=false
"""Paper-ready metrics recomputed exclusively from prediction ledgers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    precision_recall_fscore_support,
    roc_auc_score,
    roc_curve,
)

if TYPE_CHECKING:
    import pandas as pd


def summarize_predictions(
    ledger: pd.DataFrame,
    *,
    bootstrap_samples: int = 500,
    seed: int = 0,
) -> dict[str, Any]:
    """Report aggregate slices and a deterministic family/scenario bootstrap."""
    required = {"label", "score", "track", "family"}
    if not required <= set(ledger.columns):
        raise ValueError(f"prediction ledger missing columns: {sorted(required - set(ledger.columns))}")
    if not 0 <= ledger["score"].min() <= ledger["score"].max() <= 1:
        raise ValueError("scores must be probabilities in [0,1]")

    summary: dict[str, Any] = {
        "overall": _metrics(ledger),
        "by_track": {
            str(track): _metrics(frame)
            for track, frame in ledger.groupby("track", sort=True)
        },
        "by_family": {
            str(family): _metrics(frame)
            for family, frame in ledger.groupby("family", sort=True)
        },
        "bootstrap_95": _bootstrap_interval(ledger, bootstrap_samples, seed),
        "families": sorted(str(value) for value in ledger["family"].unique()),
        "observability": _observability_ceiling(ledger),
    }
    family_metrics = [{"family": family, **value} for family, value in summary["by_family"].items()]
    metric = "recall" if "threshold" in ledger.columns else "roc_auc"
    eligible_families = [value for value in family_metrics if value.get(metric) is not None]
    summary["worst_family"] = (
        min(eligible_families, key=lambda value: float(value[metric]))
        if eligible_families
        else None
    )
    summary["worst_family_metric"] = metric
    if "purpose" in ledger.columns:
        controls = ledger[ledger["purpose"] == "matched_control"]
        summary["matched_control_fpr"] = (
            float((controls["score"] >= controls["threshold"]).mean())
            if len(controls) and "threshold" in controls.columns
            else None
        )
    return summary


def _observability_ceiling(ledger: pd.DataFrame) -> dict[str, float | int]:
    if "feature_sha256" not in ledger.columns:
        return {"equivalence_classes": len(ledger), "ambiguous_rows": 0, "bayes_accuracy_ceiling": 1.0}
    groups = ledger.groupby("feature_sha256", sort=True)
    ambiguous_rows = 0
    correctly_classifiable = 0
    for _, frame in groups:
        counts = frame["label"].value_counts()
        correctly_classifiable += int(counts.max())
        if len(counts) > 1:
            ambiguous_rows += len(frame)
    return {
        "equivalence_classes": int(ledger["feature_sha256"].nunique()),
        "ambiguous_rows": int(ambiguous_rows),
        "bayes_accuracy_ceiling": float(correctly_classifiable / max(len(ledger), 1)),
    }


def _metrics(frame: pd.DataFrame) -> dict[str, float | int | None]:
    labels = frame["label"].to_numpy()
    scores = frame["score"].to_numpy()
    has_both = len(np.unique(labels)) == 2
    result: dict[str, Any] = {
        "rows": len(frame),
        "positives": int(labels.sum()),
        "negatives": int((labels == 0).sum()),
        "prevalence": float(labels.mean()),
        "roc_auc": float(roc_auc_score(labels, scores)) if has_both else None,
        "pr_auc": float(average_precision_score(labels, scores)) if labels.sum() else None,
        "brier": float(brier_score_loss(labels, scores)),
    }
    if "threshold" in frame.columns:
        predicted = scores >= frame["threshold"].to_numpy()
        precision, recall, f1, _ = precision_recall_fscore_support(
            labels, predicted, average="binary", zero_division=0
        )
        result.update(precision=float(precision), recall=float(recall), f1=float(f1))
    for target in (0.001, 0.01):
        key = f"recall_at_fpr_{target:g}"
        negatives = int((labels == 0).sum())
        required = int(np.ceil(1 / target))
        if negatives < required or not has_both:
            result[key] = None
            result[f"{key}_status"] = "insufficient_negatives"
        else:
            fpr, tpr, _ = roc_curve(labels, scores)
            eligible = tpr[fpr <= target]
            result[key] = float(eligible.max()) if len(eligible) else 0.0
            result[f"{key}_status"] = "ok"
    return result


def _bootstrap_interval(ledger: pd.DataFrame, samples: int, seed: int) -> dict[str, list[float]]:
    if samples <= 0:
        raise ValueError("bootstrap_samples must be positive")
    rng = np.random.default_rng(seed)
    aucs: list[float] = []
    aps: list[float] = []
    work = ledger.reset_index(drop=True).copy()
    cluster_column = "pair_id" if "pair_id" in work.columns else "scenario_id"
    if cluster_column not in work.columns:
        cluster_column = "scenario_id"
        work[cluster_column] = [f"row-{index}" for index in range(len(work))]
    families = {
        str(family): {
            str(scenario): frame.index.to_numpy()
            for scenario, frame in family_frame.groupby(cluster_column, sort=True)
        }
        for family, family_frame in work.groupby("family", sort=True)
    }
    family_names = sorted(families)
    for _ in range(samples):
        sampled_indices: list[int] = []
        for family in rng.choice(family_names, size=len(family_names), replace=True):
            scenarios = families[str(family)]
            scenario_names = sorted(scenarios)
            for scenario in rng.choice(scenario_names, size=len(scenario_names), replace=True):
                rows = scenarios[str(scenario)]
                sampled_indices.extend(int(value) for value in rng.choice(rows, len(rows), replace=True))
        sampled = work.iloc[sampled_indices]
        labels = sampled["label"].to_numpy()
        if len(np.unique(labels)) < 2:
            continue
        scores = sampled["score"].to_numpy()
        aucs.append(float(roc_auc_score(labels, scores)))
        aps.append(float(average_precision_score(labels, scores)))
    if not aucs:
        raise ValueError("bootstrap requires both classes")
    return {
        "roc_auc": [float(v) for v in np.percentile(aucs, [2.5, 97.5])],
        "pr_auc": [float(v) for v in np.percentile(aps, [2.5, 97.5])],
    }
