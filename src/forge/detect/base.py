"""Shared detector vocabulary — no deps on dataset or incumbent."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Mapping


class Detector(Protocol):
    detector_id: str

    def score_features(self, features: Mapping[str, float]) -> float: ...
