"""Shared detector vocabulary — no deps on dataset or incumbent."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Mapping

FEATURE_NAMES: tuple[str, ...] = (
    "burst",
    "new_device",
    "refund_pressure",
    "off_hours_focus",
    "cashout_pressure",
    "volume",
)


class Detector(Protocol):
    detector_id: str

    def score_features(self, features: Mapping[str, float]) -> float: ...
