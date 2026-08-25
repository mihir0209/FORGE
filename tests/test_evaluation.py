# pyright: reportMissingTypeStubs=false
"""Research reporting remains deterministic and track-aware."""

import pandas as pd

from forge.detect.evaluation import summarize_predictions


def test_prediction_summary_reports_tracks_and_confidence_intervals() -> None:
    ledger = pd.DataFrame(
        [
            {"label": 1, "score": 0.9, "track": "ai_assisted_app", "family": "app-a"},
            {"label": 1, "score": 0.8, "track": "behavioral_payment", "family": "legacy-a"},
            {"label": 0, "score": 0.2, "track": "ai_assisted_app", "family": "app-control"},
            {"label": 0, "score": 0.1, "track": "behavioral_payment", "family": "legacy-control"},
        ]
    )
    first = summarize_predictions(ledger, bootstrap_samples=25, seed=7)
    second = summarize_predictions(ledger, bootstrap_samples=25, seed=7)
    assert first == second
    assert first["overall"]["roc_auc"] == 1.0
    assert set(first["by_track"]) == {"ai_assisted_app", "behavioral_payment"}


def test_observability_ceiling_reports_conflicting_identical_features() -> None:
    ledger = pd.DataFrame(
        [
            {"label": 1, "score": 0.5, "track": "app", "family": "a", "feature_sha256": "same"},
            {"label": 0, "score": 0.5, "track": "app", "family": "a", "feature_sha256": "same"},
            {"label": 1, "score": 0.9, "track": "app", "family": "b", "feature_sha256": "other"},
        ]
    )
    summary = summarize_predictions(ledger, bootstrap_samples=10)
    assert summary["observability"]["ambiguous_rows"] == 2
    assert summary["observability"]["bayes_accuracy_ceiling"] == 2 / 3
