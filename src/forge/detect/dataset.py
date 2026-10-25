# pyright: reportMissingTypeStubs=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportArgumentType=false, reportCallIssue=false
"""Dataset builder: registry cycles + legit worlds -> versioned train/calib/test."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING

import numpy as np
import pandas as pd
from pandas.util import hash_pandas_object

from forge.actor_sandbox import ActorSandbox, legitimate_app_payment_plan
from forge.artifacts import LocalArtifactStore
from forge.contracts.contracts import DatasetRef, WorldSeed
from forge.detect import trace_features
from forge.feature_schema import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    adapt_features,
    infer_schema,
)
from forge.simulate import build_legit_trace

if TYPE_CHECKING:
    from forge.contracts.contracts import CycleRecord
    from forge.kb import Registry

DATASETS_ROOT = Path("data/datasets")
MIN_HOLDOUT_POSITIVES = 20


def _cycle_features(cycle: CycleRecord) -> dict[str, float] | None:
    features = cycle.detector_features
    if not features:
        return None
    declared = cycle.feature_schema_version
    if declared == "legacy-unversioned":
        declared = infer_schema(features)
    return adapt_features(features, declared)


def build_dataset(
    registry: Registry,
    *,
    n_negatives: int = 40,
    dataset_seed: int = 0,
    test_size: float = 0.2,
    calib_size: float = 0.2,
) -> DatasetRef:
    """Positives: one row per DISTINCT attack strategy in registry.
    Negatives: fresh legit worlds. Stratified split -> train/calib/test parquet.
    """
    from sklearn.model_selection import StratifiedShuffleSplit

    rows: list[dict[str, float | int]] = []

    # Only exact feature vectors scored during accepted cycles belong in the
    # current schema. Legacy cycles must be replayed and migrated explicitly.
    for cycle in registry.cycles():
        feats = _cycle_features(cycle)
        if feats is not None:
            rows.append({**{k: float(v) for k, v in feats.items()}, "label": 1})

    if not rows:
        raise ValueError(
            "no current-schema attack cycles in registry — run forge app-scam-cycle first"
        )

    # negatives — balanced-ish
    base = 10_000 + dataset_seed * 1_000
    for i in range(n_negatives):
        trace = build_legit_trace(WorldSeed(master_seed=base + i))
        feats = trace_features(trace.observed_view())
        rows.append({**{k: float(v) for k, v in feats.items()}, "label": 0})

    df = pd.DataFrame(rows)
    # ensure column order: features then label
    df = df[[*FEATURE_NAMES, "label"]]

    # stratified split: first hold out test, then calib from remaining train
    sss_test = StratifiedShuffleSplit(n_splits=1, test_size=test_size, random_state=dataset_seed)
    train_idx, test_idx = next(sss_test.split(df[list(FEATURE_NAMES)], df["label"]))
    df_train_all = df.iloc[train_idx].reset_index(drop=True)
    df_test = df.iloc[test_idx].reset_index(drop=True)

    calib_fraction = calib_size / (1.0 - test_size)
    sss_calib = StratifiedShuffleSplit(
        n_splits=1, test_size=calib_fraction, random_state=dataset_seed + 1
    )
    train_idx2, calib_idx = next(
        sss_calib.split(df_train_all[list(FEATURE_NAMES)], df_train_all["label"])
    )
    df_train = df_train_all.iloc[train_idx2].reset_index(drop=True)
    df_calib = df_train_all.iloc[calib_idx].reset_index(drop=True)

    # include feature distribution in id to avoid label-only collisions
    dataset_id = hashlib.sha256(
        json.dumps(
            {
                "labels": [int(r["label"]) for _, r in df.iterrows()],
                "feature_hash": hashlib.sha256(
                    np.asarray(hash_pandas_object(df[list(FEATURE_NAMES)], index=False)).tobytes()
                ).hexdigest()[:16],
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()[:10]
    dataset_id = f"ds_{dataset_id}"

    root = DATASETS_ROOT / dataset_id
    root.mkdir(parents=True, exist_ok=True)
    df_train.to_parquet(root / "train.parquet")
    df_calib.to_parquet(root / "calib.parquet")
    df_test.to_parquet(root / "test.parquet")

    return DatasetRef(
        dataset_id=dataset_id,
        train_path=str(root / "train.parquet"),
        calib_path=str(root / "calib.parquet"),
        test_path=str(root / "test.parquet"),
        rows=len(df),
        feature_schema_version=FEATURE_SCHEMA_VERSION,
    )


def build_family_holdout_dataset(
    registry: Registry,
    *,
    n_negatives_per_split: int = 20,
    dataset_seed: int = 0,
    calibration_family: str | None = None,
    test_family: str | None = None,
) -> DatasetRef:
    """Family-disjoint train/calibration/test split with a checksum manifest."""
    cycles = [cycle for cycle in registry.cycles() if _cycle_features(cycle) is not None]
    families = sorted({cycle.strategy.attack_family for cycle in cycles})
    if len(families) < 3:
        raise ValueError("family holdout requires at least three distinct attack families")

    family_counts = Counter(cycle.strategy.attack_family for cycle in cycles)
    holdout_eligible = sorted(family for family, count in family_counts.items() if count >= 2)
    if calibration_family is None or test_family is None:
        if len(holdout_eligible) < 2:
            raise ValueError(
                "family holdout requires two families with at least two positive cycles"
            )
        sufficiently_sampled = sorted(
            (
                family
                for family in holdout_eligible
                if family_counts[family] >= MIN_HOLDOUT_POSITIVES
            ),
            key=lambda family: (-family_counts[family], family),
        )
        candidates = sufficiently_sampled if len(sufficiently_sampled) >= 2 else holdout_eligible
        calibration_family = calibration_family or candidates[0]
        test_family = test_family or candidates[1]
    if calibration_family == test_family:
        raise ValueError("calibration and test families must differ")
    if calibration_family not in families or test_family not in families:
        raise ValueError("held-out families must exist in the registry")
    held_out = [calibration_family, test_family]
    partitions: dict[str, list[dict[str, object]]] = {"train": [], "calib": [], "test": []}
    manifest_rows: list[dict[str, object]] = []

    for cycle in cycles:
        family = cycle.strategy.attack_family
        split = (
            "test"
            if family == test_family
            else "calib"
            if family == calibration_family
            else "train"
        )
        features = _cycle_features(cycle)
        assert features is not None
        row: dict[str, object] = {**features, "label": 1}
        partitions[split].append(row)
        manifest_rows.append(
            {
                "row_id": cycle.cycle_id,
                "split": split,
                "label": 1,
                "family": family,
                "track": cycle.detection_track.value,
                "capabilities": sorted(cap.value for cap in cycle.evidence_capabilities),
            }
        )

    for split in ("train", "calib", "test"):
        positives = sum(int(row["label"]) for row in partitions[split])
        if positives < 2:
            raise ValueError(f"{split} split requires at least two positive cycles")

    for split_index, split in enumerate(("train", "calib", "test")):
        for i in range(n_negatives_per_split):
            seed = 30_000 + dataset_seed * 1_000 + split_index * 100 + i
            if i % 2:
                sandbox = ActorSandbox(LocalArtifactStore(DATASETS_ROOT / "control-artifacts"))
                control = sandbox.execute(
                    legitimate_app_payment_plan(
                        "legitimate-app-control",
                        f"legit-app-{seed}",
                        active_call=i % 4 == 1,
                        first_time_payee=i % 3 == 1,
                    ),
                    WorldSeed(master_seed=seed),
                    cycle_id=f"legit-app-{seed}",
                ).trace
                features = trace_features(control.observed_view())
                control_family = "legitimate_app_control"
                control_track = "ai_assisted_app"
                capabilities = [
                    "device_integrity",
                    "app_behavior",
                    "payee_verification",
                    "beneficiary_network",
                    "system_call_state",
                ]
            else:
                features = trace_features(
                    build_legit_trace(WorldSeed(master_seed=seed)).observed_view()
                )
                control_family = "legitimate_behavioral_control"
                control_track = "behavioral_payment"
                capabilities = ["payment_history"]
            partitions[split].append({**features, "label": 0})
            manifest_rows.append(
                {
                    "row_id": f"legit-{seed}",
                    "split": split,
                    "label": 0,
                    "family": control_family,
                    "track": control_track,
                    "capabilities": capabilities,
                }
            )

    root_seed = {
        "protocol": "attack-family-disjoint-holdout",
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "calibration_family": calibration_family,
        "test_family": test_family,
        "rows": manifest_rows,
    }
    seed_digest = hashlib.sha256(json.dumps(root_seed, sort_keys=True).encode()).hexdigest()
    temp_root = DATASETS_ROOT / f".building-{seed_digest[:10]}"
    temp_root.mkdir(parents=True, exist_ok=True)
    parquet_sha256: dict[str, str] = {}
    for split, rows in partitions.items():
        path = temp_root / f"{split}.parquet"
        pd.DataFrame(rows)[[*FEATURE_NAMES, "label"]].to_parquet(path)
        parquet_sha256[split] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_body = {**root_seed, "parquet_sha256": parquet_sha256}
    digest = hashlib.sha256(
        json.dumps(manifest_body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    dataset_id = f"ds_family_{digest[:10]}"
    root = DATASETS_ROOT / dataset_id
    if root.exists():
        import shutil

        shutil.rmtree(temp_root)
    else:
        temp_root.replace(root)
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps({**manifest_body, "sha256": digest}, indent=2))

    return DatasetRef(
        dataset_id=dataset_id,
        train_path=str(root / "train.parquet"),
        calib_path=str(root / "calib.parquet"),
        test_path=str(root / "test.parquet"),
        rows=sum(len(rows) for rows in partitions.values()),
        split_protocol="attack-family-disjoint-holdout",
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        manifest_path=str(manifest_path),
        held_out_families=held_out,
        split_positive_counts={
            split: sum(int(row["label"]) for row in rows) for split, rows in partitions.items()
        },
        included_tracks=sorted(
            {cycle.detection_track for cycle in cycles}, key=lambda track: track.value
        ),
        train_tracks=sorted(
            {
                cycle.detection_track
                for cycle in cycles
                if cycle.strategy.attack_family not in held_out
            },
            key=lambda track: track.value,
        ),
        parquet_sha256=parquet_sha256,
    )
