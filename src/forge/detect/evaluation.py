# pyright: reportMissingTypeStubs=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportArgumentType=false
"""Paper-ready evaluation summaries over a model prediction ledger."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import numpy as np
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score

if TYPE_CHECKING:
    import pandas as pd


def summarize_predictions(
    ledger: pd.DataFrame,
    *,
    bootstrap_samples: int = 500,
    seed: int = 0,
) -> dict[str, Any]:
    """Report overall/per-track metrics and stratified bootstrap intervals."""
    required = {"label", "score", "track", "family"}
    if not required <= set(ledger.columns):
        raise ValueError(f"prediction ledger missing columns: {sorted(required - set(ledger.columns))}")
    if not 0 <= ledger["score"].min() <= ledger["score"].max() <= 1:
        raise ValueError("scores must be probabilities in [0,1]")

    return {
        "overall": _metrics(ledger),
        "by_track": {
            str(track): _metrics(frame)
            for track, frame in ledger.groupby("track", sort=True)
        },
        "bootstrap_95": _bootstrap_interval(ledger, bootstrap_samples, seed),
        "families": sorted(str(value) for value in ledger["family"].unique()),
    }


def _metrics(frame: pd.DataFrame) -> dict[str, float | int | None]:
    labels = frame["label"].to_numpy()
    scores = frame["score"].to_numpy()
    has_both = len(np.unique(labels)) == 2
    return {
        "rows": len(frame),
        "positives": int(labels.sum()),
        "prevalence": float(labels.mean()),
        "roc_auc": float(roc_auc_score(labels, scores)) if has_both else None,
        "pr_auc": float(average_precision_score(labels, scores)) if labels.sum() else None,
        "brier": float(brier_score_loss(labels, scores)),
    }


def _bootstrap_interval(ledger: pd.DataFrame, samples: int, seed: int) -> dict[str, list[float]]:
    if samples <= 0:
        raise ValueError("bootstrap_samples must be positive")
    rng = np.random.default_rng(seed)
    aucs: list[float] = []
    aps: list[float] = []
    grouped = [frame.index.to_numpy() for _, frame in ledger.groupby("family", sort=True)]
    for _ in range(samples):
        indices = np.concatenate(
            [rng.choice(group, size=len(group), replace=True) for group in grouped]
        )
        sampled = ledger.loc[indices]
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
