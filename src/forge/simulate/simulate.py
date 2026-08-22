"""Public interface of forge.simulate.

simulate(spec, seed)     -> SimulationResult(trace)   # attack cycle
build_legit_trace(seed)  -> SyntheticTrace            # baseline-only world
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import numpy as np

from forge.contracts.contracts import (
    GroundTruth,
    StrategySpec,
    SyntheticTrace,
    WorldSeed,
)
from forge.simulate._baseline import BaselineEngine
from forge.simulate._fidelity import compute_fidelity, payment_graph_density
from forge.simulate._injector import AttackInjector
from forge.simulate._rng import derive_rng
from forge.simulate._world import World, WorldBuilder, draw_amount

BASE_DATE = datetime(2026, 6, 1, tzinfo=UTC)


@dataclass(frozen=True)
class SimulationResult:
    trace: SyntheticTrace


def simulate(
    spec: StrategySpec,
    seed: WorldSeed,
    *,
    n_days: int = 14,
    n_customers: int = 400,
    n_merchants: int = 60,
) -> SimulationResult:
    world = WorldBuilder(seed, n_customers, n_merchants).build()
    start = _calendar_start(seed)

    baseline_events = BaselineEngine(world, seed, start, n_days).run()
    pre_attack_density = payment_graph_density(baseline_events)

    injection = AttackInjector(world, seed).inject(spec, start, n_days)

    events = sorted([*baseline_events, *injection.events], key=lambda e: e.ts)

    fidelity = compute_fidelity(
        events,
        reference_amounts=_reference_amounts(seed, world),
        gap_reference_rng=derive_rng(seed, "gapref"),
        pre_attack_density=pre_attack_density,
        reachability_ok=injection.reachability_ok,
    )

    ground_truth = GroundTruth(
        strategy_id=spec.strategy_id,
        fingerprint=spec.fingerprint(),
        attack_event_ids=injection.attack_event_ids,
    )
    return SimulationResult(
        trace=SyntheticTrace(
            trace_id=_trace_id(seed, spec.strategy_id),
            seed=seed,
            events=events,
            ground_truth=ground_truth,
            fidelity=fidelity,
        )
    )


def build_legit_trace(
    seed: WorldSeed,
    *,
    n_days: int = 14,
    n_customers: int = 400,
    n_merchants: int = 60,
) -> SyntheticTrace:
    """Baseline-only world — zero labeled events; the detector's negative universe."""
    world = WorldBuilder(seed, n_customers, n_merchants).build()
    start = _calendar_start(seed)
    events = BaselineEngine(world, seed, start, n_days).run()
    fidelity = compute_fidelity(
        events,
        reference_amounts=_reference_amounts(seed, world),
        gap_reference_rng=derive_rng(seed, "gapref"),
        pre_attack_density=None,
        reachability_ok=True,
    )
    return SyntheticTrace(
        trace_id=_trace_id(seed, "__baseline__"),
        seed=seed,
        events=events,
        ground_truth=GroundTruth(strategy_id="__baseline__", fingerprint="-"),
        fidelity=fidelity,
    )


# ------------------------------------------------------------------ internals


def _calendar_start(seed: WorldSeed) -> datetime:
    rng = derive_rng(seed, "calendar")
    return BASE_DATE + timedelta(days=int(rng.integers(0, 28)))


def _reference_amounts(seed: WorldSeed, world: World) -> np.ndarray:
    """Draws from declared category profiles — implementation-honesty reference."""
    rng = derive_rng(seed, "amountref")
    draws: list[float] = []
    for _ in range(4000):
        m = world.merchants[int(rng.integers(0, len(world.merchants)))]
        draws.append(draw_amount(rng, m.category))
    return np.array(draws)


def _trace_id(seed: WorldSeed, strategy_id: str) -> str:
    h = sha256(f"{seed.master_seed}:{strategy_id}".encode()).hexdigest()[:12]
    return f"tr_{h}"
