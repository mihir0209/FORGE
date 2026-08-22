"""forge.signals — deep signal primitives; one definition of every heuristic.

Both `blueteam` (human-readable verdict) and `detect` (tabular features)
depend on this module. Change a threshold here once, both stay in sync.
"""

from __future__ import annotations

from forge.signals._primitives import (
    FEATURE_NAMES,
    all_signals,
    media_liveness_anomaly,
    new_device_then_payment,
    off_hours_activity,
    refund_chains,
    transaction_during_call,
    unknown_peer_network,
    velocity_bursts,
)

__all__ = [
    "FEATURE_NAMES",
    "all_signals",
    "media_liveness_anomaly",
    "new_device_then_payment",
    "off_hours_activity",
    "refund_chains",
    "transaction_during_call",
    "unknown_peer_network",
    "velocity_bursts",
]
