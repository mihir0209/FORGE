"""P1 simulator core: determinism, label channel, lifecycle coverage, plausibility."""

import itertools
import json
import os
import subprocess
import sys
from hashlib import sha256

from forge.contracts.contracts import StrategySpec, TraceEvent, WorldSeed
from forge.simulate import build_legit_trace, simulate
from tests.fixtures_spec import make_spec

SEED = WorldSeed(master_seed=42)


def _spec(**over: object) -> StrategySpec:
    return make_spec(**over)


def _digest(events: list[TraceEvent]) -> str:
    payload = json.dumps([e.model_dump(mode="json") for e in events], sort_keys=True)
    return sha256(payload.encode()).hexdigest()


# ---------------------------------------------------------------- determinism


def test_same_seed_same_trace() -> None:
    a = simulate(_spec(), SEED).trace
    b = simulate(_spec(), SEED).trace
    assert _digest(a.events) == _digest(b.events)
    assert a.trace_id == b.trace_id


def test_different_seed_different_world() -> None:
    a = simulate(_spec(), SEED).trace
    b = simulate(_spec(), WorldSeed(master_seed=43)).trace
    assert a.trace_id != b.trace_id
    assert _digest(a.events) != _digest(b.events)


def test_determinism_survives_hash_randomization() -> None:
    """PYTHONHASHSEED must not influence generation (crc32-tagged RNG streams)."""
    code = (
        "import hashlib, json;"
        "from forge.contracts.contracts import WorldSeed;"
        "from forge.simulate import simulate;"
        "from tests.fixtures_spec import make_spec;"
        "t = simulate(make_spec(), WorldSeed(master_seed=7), n_customers=80).trace;"
        "print(hashlib.sha256(json.dumps("
        "[e.model_dump(mode='json') for e in t.events], sort_keys=True"
        ").encode()).hexdigest())"
    )

    def run(hseed: str) -> str:
        env = {**os.environ, "PYTHONHASHSEED": hseed}
        out = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            env=env,
            cwd=".",
            check=True,
        )
        return out.stdout.strip()

    assert run("0") == run("12345")


# ------------------------------------------------------------------- labels


def test_attack_events_are_labeled_and_listed() -> None:
    result = simulate(_spec(), SEED)
    labeled = [e for e in result.trace.events if e.is_attack_step]
    assert labeled, "expected injected attack events"
    listed = set(result.trace.ground_truth.attack_event_ids)
    assert listed == {e.event_id for e in labeled}


def test_every_lifecycle_stage_is_covered() -> None:
    spec = _spec()
    trace = simulate(spec, SEED).trace
    stages_seen = {e.attack_stage for e in trace.events if e.is_attack_step and e.attack_stage}
    assert set(spec.lifecycle_stages) <= stages_seen
    assert trace.fidelity.reachability_ok


def test_legit_only_trace_has_no_labels() -> None:
    trace = build_legit_trace(SEED)
    assert not any(e.is_attack_step for e in trace.events)
    assert not any(e.attack_stage is not None for e in trace.events)


# -------------------------------------------------------------- plausibility


def test_events_sorted_by_time() -> None:
    events = simulate(_spec(), SEED).trace.events
    assert all(a.ts <= b.ts for a, b in itertools.pairwise(events))


def test_fidelity_within_v1_bounds() -> None:
    f = simulate(_spec(), SEED).trace.fidelity
    assert f.psi_amount < 0.25
    assert abs(f.temporal_autocorr) < 0.5
    assert abs(f.graph_density_delta) < 0.05
