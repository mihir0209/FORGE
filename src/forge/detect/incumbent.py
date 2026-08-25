"""Incumbent pointer + LightGBM detector adapter."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import joblib  # type: ignore[import-untyped]

from forge.detect import RuleBaselineDetector
from forge.detect.base import Detector
from forge.feature_schema import FEATURE_NAMES, KNOWN_SCHEMAS

if TYPE_CHECKING:
    from collections.abc import Mapping


def _models_root() -> Path:
    import os

    base = Path(os.environ.get("FORGE_DATA_DIR", "data"))
    return base / "models"


def _pointer() -> Path:
    return _models_root() / "incumbent.json"


def _promotion_receipt() -> Path:
    return _models_root() / "promotion-verdict.json"


class LightGBMDetector(Detector):
    def __init__(self, model: Any, detector_id: str, feature_names: tuple[str, ...]) -> None:
        self._model = model
        self.detector_id = detector_id
        self.feature_names = feature_names

    def score_features(self, features: Mapping[str, float]) -> float:
        vec = [[float(features.get(k, 0.0)) for k in self.feature_names]]
        proba: Any = self._model.predict_proba(vec)
        return float(proba[0, 1])


class CompatibleEnsembleDetector(Detector):
    """Preserve a known historical model while the union-schema challenger matures."""

    def __init__(self, legacy: LightGBMDetector) -> None:
        self.legacy = legacy
        self.current = RuleBaselineDetector()
        self.detector_id = f"compatible:{legacy.detector_id}+{self.current.detector_id}"

    def score_features(self, features: Mapping[str, float]) -> float:
        return max(self.legacy.score_features(features), self.current.score_features(features))


def load_incumbent() -> Detector:
    """Rule baseline until a candidate clears promotion."""
    if not _pointer().exists():
        return RuleBaselineDetector()
    try:
        meta: dict[str, Any] = json.loads(_pointer().read_text())
        feature_names = tuple(str(name) for name in meta.get("feature_names", ()))
        if feature_names not in KNOWN_SCHEMAS.values():
            return RuleBaselineDetector()
        artifact = Path(str(meta["artifact_path"]))
        if not artifact.exists():
            return RuleBaselineDetector()
        model: Any = joblib.load(artifact)  # type: ignore[reportUnknownMemberType]
        detector = LightGBMDetector(
            model,
            detector_id=str(meta.get("candidate_id", "lgbm")),
            feature_names=feature_names,
        )
        if feature_names == FEATURE_NAMES:
            receipt = json.loads(_promotion_receipt().read_text())
            if (
                not receipt.get("passed")
                or receipt.get("candidate_id") != detector.detector_id
                or receipt.get("artifact_sha256")
                != hashlib.sha256(artifact.read_bytes()).hexdigest()
            ):
                return RuleBaselineDetector()
            return detector
        return CompatibleEnsembleDetector(detector)
    except Exception:
        return RuleBaselineDetector()


def install_candidate(
    artifact_path: str,
    candidate_id: str,
    *,
    promotion_receipt: dict[str, Any] | None = None,
) -> None:
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
    if promotion_receipt is not None:
        receipt_tmp = _promotion_receipt().with_suffix(".tmp")
        receipt_tmp.write_text(json.dumps(promotion_receipt, sort_keys=True))
        receipt_tmp.replace(_promotion_receipt())
