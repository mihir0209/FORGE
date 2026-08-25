# pyright: reportMissingTypeStubs=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportArgumentType=false
"""Leakage-safe common benchmark harness for detector model families."""

from __future__ import annotations

import hashlib
import json
import platform
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import numpy as np
import pandas as pd
from sklearn.isotonic import IsotonicRegression

from forge.detect.evaluation import summarize_predictions
from forge.detect.models import ModelSpec, ScoreModel, baseline_model_specs
from forge.detect.report import write_report

if TYPE_CHECKING:
    from collections.abc import Callable

REQUIRED_METADATA = {
    "row_id",
    "split",
    "label",
    "track",
    "family",
    "scenario_id",
    "pair_id",
    "purpose",
    "capabilities",
}
ALLOWED_SPLITS = {"train", "calibration", "development", "sealed_test"}


@dataclass(frozen=True)
class BenchmarkResult:
    run_id: str
    output_dir: str
    manifest_path: str
    report_paths: dict[str, str]
    ledger_paths: dict[str, str]


def run_benchmark(
    dataset: pd.DataFrame,
    feature_names: tuple[str, ...],
    output_root: str | Path,
    *,
    dataset_id: str,
    model_specs: tuple[ModelSpec, ...] | None = None,
    seed: int = 0,
    bootstrap_samples: int = 500,
    threshold_target_fpr: float = 0.01,
    capability_features: dict[str, tuple[str, ...]] | None = None,
) -> BenchmarkResult:
    """Fit all baselines on identical rows and emit immutable score ledgers/reports."""
    availability_names = tuple(
        f"{name}__available" for name in feature_names if f"{name}__available" in dataset.columns
    )
    model_feature_names = (*feature_names, *availability_names)
    _validate_dataset(dataset, model_feature_names)
    specs = model_specs or baseline_model_specs()
    dataset_hash = _frame_hash(dataset, model_feature_names)
    code_hash = _code_hash()
    run_inputs = {
        "dataset_id": dataset_id,
        "dataset_sha256": dataset_hash,
        "code_sha256": code_hash,
        "feature_names": list(model_feature_names),
        "seed": seed,
        "threshold_target_fpr": threshold_target_fpr,
        "models": [{"name": spec.name, "config": dict(spec.config)} for spec in specs],
    }
    run_id = f"bench_{_digest(run_inputs)[:12]}"
    output_dir = Path(output_root) / run_id
    output_dir.mkdir(parents=True, exist_ok=True)

    frames = {split: dataset[dataset["split"] == split].copy() for split in sorted(ALLOWED_SPLITS)}
    ledgers: dict[str, str] = {}
    reports: dict[str, Any] = {}
    candidate_ids: dict[str, str] = {}
    for spec in specs:
        candidate_inputs = {
            "model": spec.name,
            "config": dict(spec.config),
            "dataset_id": dataset_id,
            "dataset_sha256": dataset_hash,
            "code_sha256": code_hash,
            "feature_names": list(feature_names),
            "seed": seed,
            "threshold_target_fpr": threshold_target_fpr,
        }
        candidate_id = f"cand_{spec.name}_{_digest(candidate_inputs)[:12]}"
        candidate_ids[spec.name] = candidate_id
        model = spec.build(model_feature_names)
        model.fit(
            _features(frames["train"], model_feature_names),
            np.asarray(frames["train"]["label"], dtype=int),
        )
        calibrator = _fit_calibrator(model, frames["calibration"], model_feature_names)
        development_scores = calibrator(_features(frames["development"], model_feature_names))
        threshold = _select_threshold(
            np.asarray(frames["development"]["label"], dtype=int),
            development_scores,
            threshold_target_fpr,
        )
        test = frames["sealed_test"].copy()
        test["score"] = calibrator(_features(test, model_feature_names))
        test["threshold"] = threshold
        test["model"] = spec.name
        test["candidate_id"] = candidate_id
        ledger_path = output_dir / f"{spec.name}.ledger.parquet"
        test.to_parquet(ledger_path, index=False)
        ledgers[spec.name] = str(ledger_path)

        # Re-read the persisted ledger so reports cannot silently use a separate score path.
        persisted = pd.read_parquet(ledger_path)
        summary = summarize_predictions(persisted, bootstrap_samples=bootstrap_samples, seed=seed)
        summary["candidate_id"] = candidate_id
        summary["threshold"] = threshold
        summary["ledger_sha256"] = hashlib.sha256(ledger_path.read_bytes()).hexdigest()
        summary["capability_inference_perturbations"] = _capability_perturbations(
            calibrator,
            test,
            model_feature_names,
            threshold,
            capability_features or {},
            bootstrap_samples,
            seed,
        )
        reports[spec.name] = summary

    report = {"run_id": run_id, "dataset_id": dataset_id, "models": reports, "auto_promoted": False}
    report_paths = write_report(output_dir, report)
    manifest = {
        **run_inputs,
        "run_id": run_id,
        "created_at": datetime.now(UTC).isoformat(),
        "python": platform.python_version(),
        "candidate_ids": candidate_ids,
        "row_ids_by_split": {
            split: sorted(frame["row_id"].astype(str).tolist()) for split, frame in frames.items()
        },
        "ledgers": {
            name: {"path": path, "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest()}
            for name, path in ledgers.items()
        },
        "reports": report_paths,
        "auto_promoted": False,
    }
    manifest_path = output_dir / "run_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return BenchmarkResult(run_id, str(output_dir), str(manifest_path), report_paths, ledgers)


def _fit_calibrator(
    model: ScoreModel, calibration: pd.DataFrame, feature_names: tuple[str, ...]
) -> Callable[[np.ndarray], np.ndarray]:
    labels = np.asarray(calibration["label"], dtype=int)
    if len(np.unique(labels)) < 2:
        raise ValueError("calibration split requires both classes")
    scores = model.predict_scores(_features(calibration, feature_names))
    isotonic = IsotonicRegression(out_of_bounds="clip")
    isotonic.fit(scores, labels)
    def calibrated_scores(features: np.ndarray) -> np.ndarray:
        return np.asarray(isotonic.predict(model.predict_scores(features)), dtype=float)

    return calibrated_scores


def _select_threshold(labels: np.ndarray, scores: np.ndarray, target_fpr: float) -> float:
    negatives = np.sort(scores[labels == 0])
    if not len(negatives):
        raise ValueError("development split requires negatives for threshold selection")
    allowed_false_positives = int(np.floor(target_fpr * len(negatives)))
    index = max(0, len(negatives) - allowed_false_positives - 1)
    return float(np.nextafter(negatives[index], np.inf))


def _capability_perturbations(
    calibrator: Callable[[np.ndarray], np.ndarray],
    test: pd.DataFrame,
    feature_names: tuple[str, ...],
    threshold: float,
    capability_features: dict[str, tuple[str, ...]],
    samples: int,
    seed: int,
) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for capability, names in sorted(capability_features.items()):
        unknown = set(names) - set(feature_names)
        if unknown:
            raise ValueError(f"unknown ablation features for {capability}: {sorted(unknown)}")
        ablated = test.copy()
        ablated[list(names)] = 0.0
        for name in names:
            available = f"{name}__available"
            if available in ablated.columns:
                ablated[available] = 0.0
        ablated["score"] = calibrator(_features(ablated, feature_names))
        ablated["threshold"] = threshold
        output[capability] = {
            "method": "post_training_inference_perturbation",
            "metrics": summarize_predictions(
            ablated, bootstrap_samples=samples, seed=seed
            )["overall"],
        }
    return output


def _validate_dataset(dataset: pd.DataFrame, feature_names: tuple[str, ...]) -> None:
    missing = (REQUIRED_METADATA | set(feature_names)) - set(dataset.columns)
    if missing:
        raise ValueError(f"benchmark dataset missing columns: {sorted(missing)}")
    if bool(dataset["row_id"].duplicated().any()):
        raise ValueError("benchmark row_id values must be unique")
    splits = set(dataset["split"].astype(str))
    if splits != ALLOWED_SPLITS:
        raise ValueError(f"benchmark requires exactly these splits: {sorted(ALLOWED_SPLITS)}")
    if not bool(np.asarray(dataset["label"].isin([0, 1])).all()):
        raise ValueError("labels must be binary")
    for split in ALLOWED_SPLITS:
        if dataset.loc[dataset["split"] == split, "label"].nunique() < 2:
            raise ValueError(f"{split} split requires both classes")
    for column in ("pair_id", "family"):
        if any(group["split"].nunique() != 1 for _, group in dataset.groupby(column)):
            raise ValueError(f"{column} cannot cross benchmark splits")
    if "world_id" in dataset.columns and any(
        group["split"].nunique() != 1 for _, group in dataset.groupby("world_id")
    ):
        raise ValueError("world_id cannot cross benchmark splits")


def _features(frame: pd.DataFrame, feature_names: tuple[str, ...]) -> np.ndarray:
    return frame[list(feature_names)].fillna(0.0).to_numpy(dtype=float)


def _frame_hash(frame: pd.DataFrame, feature_names: tuple[str, ...]) -> str:
    columns = sorted(REQUIRED_METADATA) + list(feature_names)
    ordered = frame[columns].copy().set_index("row_id", drop=False).sort_index()
    canonical = ordered.to_json(orient="records", double_precision=15)
    canonical = cast("str", canonical)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _code_hash() -> str:
    from forge.detect import evaluation, models, report

    sources = [Path(__file__), Path(evaluation.__file__), Path(models.__file__), Path(report.__file__)]
    digest = hashlib.sha256()
    for path in sorted(sources):
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()
