"""forge.signals — deep signal primitives; one definition of every heuristic.

Both `blueteam` (human-readable verdict) and `detect` (tabular features)
depend on this module. Change a threshold here once, both stay in sync.
"""

from __future__ import annotations

from forge.signals._primitives import (
    FEATURE_NAMES,
    all_signals,
    app_scam_signals,
    new_device_then_payment,
    off_hours_activity,
    refund_chains,
    velocity_bursts,
)

__all__ = [
    "FEATURE_NAMES",
    "all_signals",
    "app_scam_signals",
    "new_device_then_payment",
    "off_hours_activity",
    "refund_chains",
    "velocity_bursts",
]
