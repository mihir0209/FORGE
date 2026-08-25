# pyright: reportMissingTypeStubs=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false
"""Common benchmark protocol, provenance, and report regression tests."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from forge.detect.benchmark import run_benchmark
from forge.detect.evaluation import summarize_predictions
from forge.detect.models import ModelSpec


def _dataset(rows_per_class: int = 5) -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    for split_index, split in enumerate(("train", "calibration", "development", "sealed_test")):
        for label in (0, 1):
            for index in range(rows_per_class):
                rows.append(
                    {
                        "row_id": f"{split}-{label}-{index}",
                        "split": split,
                        "label": label,
                        "track": "track-a" if index % 2 else "track-b",
                        "family": f"family-{split}-{index % 2}",
                        "scenario_id": f"scenario-{index % 3}",
                        "pair_id": f"{split}-{index}",
                        "purpose": "attack" if label else "matched_control",
                        "capabilities": ["device"] if index % 2 else ["payment"],
                        "signal": float(label) * 0.7 + index * 0.02 + split_index * 0.001,
                        "context": float(index % 2),
                    }
                )
    return pd.DataFrame(rows)


def test_benchmark_runs_all_baselines_with_one_sealed_row_ledger(tmp_path: Path) -> None:
    result = run_benchmark(
        _dataset(),
        ("signal", "context"),
        tmp_path,
        dataset_id="synthetic-v1",
        bootstrap_samples=20,
        capability_features={"device": ("context",)},
    )

    assert set(result.ledger_paths) == {
        "rules",
        "logistic_regression",
        "hist_gradient_boosting",
        "lightgbm",
    }
    row_sets = {
        tuple(sorted(pd.read_parquet(path)["row_id"].astype(str).tolist()))
        for path in result.ledger_paths.values()
    }
    assert len(row_sets) == 1
    report = json.loads(Path(result.report_paths["json"]).read_text())
    assert report["auto_promoted"] is False
    perturbation = report["models"]["logistic_regression"][
        "capability_inference_perturbations"
    ]["device"]
    assert perturbation["method"] == "post_training_inference_perturbation"
    assert Path(result.report_paths["csv"]).exists()
    assert "No candidate was promoted" in Path(result.report_paths["markdown"]).read_text()

    manifest = json.loads(Path(result.manifest_path).read_text())
    assert manifest["dataset_sha256"]
    assert manifest["code_sha256"]
    assert manifest["auto_promoted"] is False
    assert len(set(manifest["candidate_ids"].values())) == 4


def test_sealed_test_never_changes_calibration_or_threshold(tmp_path: Path) -> None:
    spec = (ModelSpec("logistic_regression", {"C": 1.0, "standardized": True}),)
    original = _dataset()
    changed = original.copy(deep=True)
    sealed = changed["split"] == "sealed_test"
    changed.loc[sealed, "signal"] = 1.0 - changed.loc[sealed, "signal"]
    changed.loc[sealed, "label"] = 1 - changed.loc[sealed, "label"]

    first = run_benchmark(
        original, ("signal", "context"), tmp_path / "first", dataset_id="one", model_specs=spec,
        bootstrap_samples=10,
    )
    second = run_benchmark(
        changed, ("signal", "context"), tmp_path / "second", dataset_id="two", model_specs=spec,
        bootstrap_samples=10,
    )
    first_report = json.loads(Path(first.report_paths["json"]).read_text())
    second_report = json.loads(Path(second.report_paths["json"]).read_text())
    assert first_report["models"]["logistic_regression"]["threshold"] == second_report["models"][
        "logistic_regression"
    ]["threshold"]


def test_metrics_are_recomputed_and_low_fpr_claims_are_rejected() -> None:
    ledger = _dataset(rows_per_class=3).query("split == 'sealed_test'").copy()
    ledger["score"] = ledger["signal"]
    ledger["threshold"] = 0.5

    first = summarize_predictions(ledger, bootstrap_samples=30, seed=11)
    second = summarize_predictions(ledger, bootstrap_samples=30, seed=11)
    assert first == second
    assert first["overall"]["recall_at_fpr_0.01"] is None
    assert first["overall"]["recall_at_fpr_0.01_status"] == "insufficient_negatives"
    assert first["matched_control_fpr"] == 0.0
    assert set(first["by_family"]) == {"family-sealed_test-0", "family-sealed_test-1"}
    assert first["worst_family"] is not None


def test_benchmark_rejects_duplicate_rows_and_incomplete_splits(tmp_path: Path) -> None:
    duplicate = _dataset()
    duplicate.loc[1, "row_id"] = duplicate.loc[0, "row_id"]
    with pytest.raises(ValueError, match="row_id"):
        run_benchmark(duplicate, ("signal", "context"), tmp_path, dataset_id="bad")

    incomplete = _dataset().query("split != 'development'")
    with pytest.raises(ValueError, match="exactly these splits"):
        run_benchmark(incomplete, ("signal", "context"), tmp_path, dataset_id="bad")
