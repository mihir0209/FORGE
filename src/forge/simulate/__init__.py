"""forge.simulate — sandboxed synthetic payment world (see plans/ architecture §2.5)."""

from forge.simulate.generator import (
    AttackVectorType,
    SyntheticFraudAttackGenerator,
    haversine_distance_km,
)
from forge.simulate.simulate import SimulationResult, build_legit_trace, simulate

__all__ = [
    "AttackVectorType",
    "SimulationResult",
    "SyntheticFraudAttackGenerator",
    "build_legit_trace",
    "haversine_distance_km",
    "simulate",
]
