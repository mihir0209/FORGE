# pyright: reportMissingTypeStubs=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportArgumentType=false, reportCallIssue=false
"""Dataset builder: registry cycles + legit worlds -> versioned train/calib/test."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING

import pandas as pd

from forge.contracts.contracts import DatasetRef, WorldSeed
from forge.detect import trace_features
from forge.detect.base import FEATURE_NAMES  # tight coupling, deliberate
from forge.simulate import build_legit_trace, simulate

if TYPE_CHECKING:
    from forge.kb import Registry

DATASETS_ROOT = Path("data/datasets")


def _parse_seed(run_id: str | None) -> int:
    if run_id and "-" in run_id:
        try:
            return int(run_id.split("-")[-1])
        except ValueError:
            pass
    return abs(hash(run_id or "")) % 10_000


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

    # positives — every cycle's trace (per-seed RNG gives trace-level diversity)
    for cycle in registry.cycles():
        seed = _parse_seed(cycle.run_id)
        trace = simulate(cycle.strategy, WorldSeed(master_seed=seed)).trace
        feats = trace_features(trace.observed_view())
        rows.append({**{k: float(v) for k, v in feats.items()}, "label": 1})

    if not rows:
        raise ValueError("no attack cycles in registry — run forge cycle first")

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

    dataset_id = hashlib.sha256(
        json.dumps([r["label"] for _, r in df.iterrows()], sort_keys=True).encode()
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
    )
