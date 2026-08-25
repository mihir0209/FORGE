# pyright: reportMissingTypeStubs=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportArgumentType=false
"""Common deterministic model adapters used by detector benchmarks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

import lightgbm as lgb
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from forge.detect import RuleBaselineDetector

if TYPE_CHECKING:
    from collections.abc import Mapping


class ScoreModel(Protocol):
    def fit(self, features: np.ndarray, labels: np.ndarray) -> None: ...

    def predict_scores(self, features: np.ndarray) -> np.ndarray: ...


class RuleModel:
    def __init__(self, feature_names: tuple[str, ...]) -> None:
        self._feature_names = feature_names
        self._detector = RuleBaselineDetector()

    def fit(self, features: np.ndarray, labels: np.ndarray) -> None:
        del features, labels

    def predict_scores(self, features: np.ndarray) -> np.ndarray:
        return np.asarray(
            [
                self._detector.score_features(dict(zip(self._feature_names, row, strict=True)))
                for row in features
            ],
            dtype=float,
        )


class SklearnModel:
    def __init__(self, estimator: Any) -> None:
        self._estimator = estimator

    def fit(self, features: np.ndarray, labels: np.ndarray) -> None:
        self._estimator.fit(features, labels)

    def predict_scores(self, features: np.ndarray) -> np.ndarray:
        return np.asarray(self._estimator.predict_proba(features)[:, 1], dtype=float)


@dataclass(frozen=True)
class ModelSpec:
    name: str
    config: Mapping[str, object]

    def build(self, feature_names: tuple[str, ...]) -> ScoreModel:
        if self.name == "rules":
            return RuleModel(feature_names)
        if self.name == "logistic_regression":
            return SklearnModel(
                make_pipeline(
                    StandardScaler(),
                    LogisticRegression(C=float(self.config["C"]), random_state=0, max_iter=1000),
                )
            )
        if self.name == "hist_gradient_boosting":
            return SklearnModel(
                HistGradientBoostingClassifier(
                    max_iter=int(self.config["max_iter"]),
                    learning_rate=float(self.config["learning_rate"]),
                    random_state=0,
                )
            )
        if self.name == "lightgbm":
            return SklearnModel(
                lgb.LGBMClassifier(
                    n_estimators=int(self.config["n_estimators"]),
                    learning_rate=float(self.config["learning_rate"]),
                    num_leaves=int(self.config["num_leaves"]),
                    random_state=0,
                    deterministic=True,
                    force_col_wise=True,
                    n_jobs=1,
                    verbose=-1,
                )
            )
        raise ValueError(f"unknown benchmark model: {self.name}")


def baseline_model_specs() -> tuple[ModelSpec, ...]:
    """Minimum required baselines with explicit, hashable configuration."""
    return (
        ModelSpec("rules", {"version": "rule-baseline-v1"}),
        ModelSpec("logistic_regression", {"C": 1.0, "standardized": True}),
        ModelSpec("hist_gradient_boosting", {"max_iter": 100, "learning_rate": 0.1}),
        ModelSpec("lightgbm", {"n_estimators": 100, "learning_rate": 0.08, "num_leaves": 15}),
    )
