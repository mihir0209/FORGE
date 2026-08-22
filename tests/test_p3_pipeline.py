"""P3: pipeline stage chain vs offline runner — semantic parity + durability bits."""

import hashlib
from pathlib import Path

import pytest

from forge.contracts.contracts import (
    EvCycleRequested,
    EvGateScored,
    EvInvestigationCompleted,
    EvStrategyProposed,
    EvTraceCompleted,
    StrategySpec,
    SyntheticTrace,
    WorldSeed,
)
from forge.cycle_runner import run_offline_cycle
from forge.pipeline import stages
from forge.simulate import simulate
from forge.storage import ensure_dirs, load_artifact


@pytest.fixture()
def isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reg = tmp_path / "reg.sqlite"
    monkeypatch.setenv("FORGE_REGISTRY_PATH", str(reg))
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path))
    ensure_dirs.cache_clear()
    return reg


def _drive_chain(seed: int) -> dict[str, object]:
    """Manually walk the event chain the inngest functions would drive."""
    composed = stages.stage_compose(EvCycleRequested(seed=seed, brief_id=None).model_dump())
    assert composed is not None, "compose dropped a novel strategy"
    proposed = EvStrategyProposed.model_validate(composed)

    traced = EvTraceCompleted.model_validate(stages.stage_simulate(proposed.model_dump()))
    investigated = EvInvestigationCompleted.model_validate(
        stages.stage_investigate(traced.model_dump())
    )
    scored = EvGateScored.model_validate(stages.stage_gate(investigated.model_dump()))
    out = stages.stage_finalize(scored.model_dump())
    return {"proposed": proposed, "traced": traced, "scored": scored, "out": out}


def test_stage_chain_matches_offline_cycle(isolated_env: Path) -> None:
    from forge.kb import InMemoryRegistry

    # Isolate: pipeline chain mutates isolated_env, offline gets a fresh copy
    pipe = _drive_chain(42)
    offline = run_offline_cycle(42, InMemoryRegistry())

    p_proposed: EvStrategyProposed = pipe["proposed"]  # type: ignore[assignment]
    assert p_proposed.attack_family == offline.strategy.attack_family

    p_scored: EvGateScored = pipe["scored"]  # type: ignore[assignment]
    assert p_scored.gate.score == offline.gate_result.score
    assert p_scored.gate.action == offline.gate_result.action
    assert p_scored.gate.coverage == offline.gate_result.coverage
    assert p_scored.gate.reason_codes == offline.gate_result.reason_codes
    assert p_scored.trace_ref == f"traces/{offline.trace_ref}.json"

    report = load_artifact(p_scored.report_ref)
    assert report["verdict"] == offline.blue_report.verdict.value
    names = {s["name"] for s in report["signals"]}
    offline_names = {s.name for s in offline.blue_report.signals}
    assert names == offline_names


def test_duplicate_seed_is_dropped_at_compose(isolated_env: Path) -> None:
    first = stages.stage_compose(EvCycleRequested(seed=42, brief_id=None).model_dump())
    second = stages.stage_compose(EvCycleRequested(seed=42, brief_id=None).model_dump())
    assert first is not None
    assert second is None, "duplicate fingerprint must not re-enter the pipeline"


def test_finalize_records_cycle(isolated_env: Path) -> None:
    out = _drive_chain(7)["out"]
    accepted_payload: dict[str, object] = out["accepted"]  # type: ignore[assignment]
    expected_id = "s_off_" + hashlib.sha256(b"7").hexdigest()[:10]
    assert accepted_payload["strategy_id"] == expected_id


def test_trace_artifact_roundtrips_to_equal_model(isolated_env: Path) -> None:
    traced: EvTraceCompleted = _drive_chain(42)["traced"]  # type: ignore[assignment]

    spec = StrategySpec.model_validate(load_artifact(traced.spec_ref))
    original = simulate(spec, WorldSeed(master_seed=traced.seed)).trace
    rebuilt = SyntheticTrace.model_validate(load_artifact(traced.trace_ref))

    assert rebuilt.trace_id == original.trace_id == traced.trace_id
    assert len(rebuilt.events) == len(original.events)
    assert rebuilt.fidelity.reachability_ok == original.fidelity.reachability_ok


def test_compose_uses_shared_strategy_ids(isolated_env: Path) -> None:
    composed = stages.stage_compose(EvCycleRequested(seed=1, brief_id=None).model_dump())
    assert composed is not None
    proposed = EvStrategyProposed.model_validate(composed)
    assert proposed.strategy_id.startswith("s_off_")
