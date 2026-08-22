"""Incumbent pointer + LightGBM detector adapter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import joblib  # type: ignore[import-untyped]

from forge.detect import RuleBaselineDetector
from forge.detect.base import Detector
from forge.signals import FEATURE_NAMES

if TYPE_CHECKING:
    from collections.abc import Mapping


def _models_root() -> Path:
    import os

    base = Path(os.environ.get("FORGE_DATA_DIR", "data"))
    return base / "models"


def _pointer() -> Path:
    return _models_root() / "incumbent.json"


class LightGBMDetector(Detector):
    def __init__(self, model: Any, detector_id: str) -> None:
        self._model = model
        self.detector_id = detector_id

    def score_features(self, features: Mapping[str, float]) -> float:
        vec = [[float(features.get(k, 0.0)) for k in FEATURE_NAMES]]
        proba: Any = self._model.predict_proba(vec)
        return float(proba[0, 1])


def load_incumbent() -> Detector:
    """Rule baseline until a candidate clears promotion."""
    if not _pointer().exists():
        return RuleBaselineDetector()
    try:
        meta: dict[str, Any] = json.loads(_pointer().read_text())
        if tuple(meta.get("feature_names", ())) != FEATURE_NAMES:
            return RuleBaselineDetector()
        artifact = Path(str(meta["artifact_path"]))
        if not artifact.exists():
            return RuleBaselineDetector()
        model: Any = joblib.load(artifact)  # type: ignore[reportUnknownMemberType]
        return LightGBMDetector(model, detector_id=str(meta.get("candidate_id", "lgbm")))
    except Exception:
        return RuleBaselineDetector()


def install_candidate(artifact_path: str, candidate_id: str) -> None:
    _models_root().mkdir(parents=True, exist_ok=True)
    tmp = _pointer().with_suffix(".tmp")
    tmp.write_text(
        json.dumps(
            {
                "candidate_id": candidate_id,
                "artifact_path": artifact_path,
                "feature_names": list(FEATURE_NAMES),
            },
            sort_keys=True,
        )
    )
    tmp.replace(_pointer())
