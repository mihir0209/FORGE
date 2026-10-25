"""FORGE — Fraud Offense-defense Research and Generation Engine."""

from forge.adversarial_simulator import (
    AdversarialAttackGenerator,
    AdversarialTransaction,
    AttackMode,
)
from forge.mule_ring import (
    MuleRing,
    MuleRingDetectionResult,
    MuleRingDetector,
    MuleRingGraph,
    TransactionEdge,
    canonicalize_cycle,
)

__version__ = "0.1.0"

__all__ = [
    "AdversarialAttackGenerator",
    "AdversarialTransaction",
    "AttackMode",
    "MuleRing",
    "MuleRingDetectionResult",
    "MuleRingDetector",
    "MuleRingGraph",
    "TransactionEdge",
    "canonicalize_cycle",
]

