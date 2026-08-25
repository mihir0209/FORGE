"""Versioned detector feature schema and explicit historical adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

FEATURE_SCHEMA_VERSION = "forge-feature-v2"

BEHAVIORAL_FEATURES: tuple[str, ...] = (
    "burst",
    "new_device",
    "refund_pressure",
    "off_hours_focus",
    "cashout_pressure",
    "volume",
)

MEDIA_FEATURES: tuple[str, ...] = (
    "unknown_peer_network",
    "media_liveness_anomaly",
    "transaction_during_call",
)

APP_FEATURES: tuple[str, ...] = (
    "first_time_payee",
    "behavioral_coaching_risk",
    "beneficiary_network_risk",
    "warning_override",
    "balance_depletion",
    "active_external_call",
)

FEATURE_NAMES = (*BEHAVIORAL_FEATURES, *MEDIA_FEATURES, *APP_FEATURES)

KNOWN_SCHEMAS: dict[str, tuple[str, ...]] = {
    "legacy-behavioral-v1": BEHAVIORAL_FEATURES,
    "legacy-multimodal-v1": (*BEHAVIORAL_FEATURES, *MEDIA_FEATURES),
    "app-scam-v1": (*BEHAVIORAL_FEATURES, *APP_FEATURES),
    FEATURE_SCHEMA_VERSION: FEATURE_NAMES,
}


def infer_schema(features: Mapping[str, float]) -> str:
    names = set(features)
    for version, schema_names in KNOWN_SCHEMAS.items():
        if names == set(schema_names):
            return version
    raise ValueError(f"unknown feature schema: {sorted(names)}")


def adapt_features(features: Mapping[str, float], source_version: str) -> dict[str, float]:
    """Adapt a known historical vector by feature name; reject unknown schemas."""
    source_names = KNOWN_SCHEMAS.get(source_version)
    if source_names is None:
        raise ValueError(f"unknown feature schema version: {source_version}")
    if set(features) != set(source_names):
        raise ValueError(f"feature vector does not match declared schema {source_version}")
    return {name: float(features.get(name, 0.0)) for name in FEATURE_NAMES}
