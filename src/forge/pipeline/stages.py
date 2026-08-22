"""Pipeline stage runners — pure seam composition.

Only functions.py imports inngest (architecture invariant #1). Each stage takes
the previous event's JSON payload and returns the next event payload(s), or None
when the chain terminates for that run.
"""

from __future__ import annotations

import json
import os
import zlib
from datetime import date
from pathlib import Path
from typing import Any

from forge.blueteam import investigate
from forge.config import settings
from forge.contracts.contracts import (
    BlueReport,
    Coverage,
    CycleRecord,
    EvCorpusThresholdReached,
    EvCycleAccepted,
    EvCycleRequested,
    EvGateScored,
    EvInvestigationCompleted,
    EvStrategyProposed,
    EvTraceCompleted,
    GapBrief,
    GateResult,
    KBQuery,
    StrategySpec,
    SyntheticTrace,
    WorldSeed,
    ev_dict,
)
from forge.detect import RuleBaselineDetector, gate_score
from forge.gapmine import fallback_brief, rank
from forge.ids import cycle_id_base, strategy_id_for
from forge.kb import Registry, SQLiteRegistry, search
from forge.redteam import compose_draft, novelty
from forge.redteam.fixtures import default_draft
from forge.simulate import simulate


def _registry() -> Registry:
    path = os.environ.get(
        "FORGE_REGISTRY_PATH",
        str(Path(__file__).resolve().parents[2] / "data" / "registry.sqlite"),
    )
    return SQLiteRegistry(Path(path))


def _pick_brief(reg: Registry, brief_id: str | None) -> GapBrief:
    briefs = rank(reg)
    if brief_id:
        for b in briefs:
            if b.brief_id == brief_id:
                return b
    return briefs[0] if briefs else fallback_brief()


# ------------------------------------------------------------------- stages


def stage_gap_mine(_: dict[str, Any] | None = None) -> list[dict[str, object]]:
    """Nightly/demand: rank deficits, request one cycle per brief."""
    reg = _registry()
    day = date.today().isoformat()
    outs: list[dict[str, object]] = []
    for b in rank(reg):
        seed = zlib.crc32(f"{b.brief_id}:{day}".encode()) & 0x7FFFFFFF
        outs.append(ev_dict(EvCycleRequested(seed=int(seed), brief_id=b.brief_id)))
    return outs


def stage_compose(data: dict[str, Any]) -> dict[str, object] | None:
    """cycle.requested -> strategy.proposed. None terminates duplicate runs."""
    ev = EvCycleRequested.model_validate(data)
    reg = _registry()

    brief = _pick_brief(reg, ev.brief_id)
    slug = brief.suggested_family.removesuffix("_family")
    search(KBQuery(tactic=slug, technique_ids=brief.target_f3_cells, limit=8))

    spec = compose_draft(default_draft(), strategy_id=strategy_id_for(ev.seed))
    verdict = novelty(spec, reg)

    if not verdict.novel:
        # Offline runner records duplicates as rejected cycles; here compose is
        # the sole upstream filter — documented divergence (pipeline drops them).
        return None

    # Register immediately: concurrent composes must see each other even if
    # their finalize steps have not landed yet.
    reg.record_strategy(spec)
    ref = save_spec(spec)
    return ev_dict(
        EvStrategyProposed(
            strategy_id=spec.strategy_id,
            attack_family=spec.attack_family,
            spec_ref=ref,
            seed=ev.seed,
        )
    )


def stage_simulate(data: dict[str, Any]) -> dict[str, object]:
    ev = EvStrategyProposed.model_validate(data)
    spec = StrategySpec.model_validate(load_artifact(ev.spec_ref))
    result = simulate(spec, WorldSeed(master_seed=ev.seed))
    t = result.trace
    trace_ref = save_trace(t.trace_id, json.loads(t.model_dump_json()))
    return ev_dict(
        EvTraceCompleted(
            trace_id=t.trace_id,
            strategy_id=ev.strategy_id,
            attack_family=ev.attack_family,
            trace_ref=trace_ref,
            spec_ref=ev.spec_ref,
            seed=ev.seed,
        )
    )


def stage_investigate(data: dict[str, Any]) -> dict[str, object]:
    ev = EvTraceCompleted.model_validate(data)
    trace = SyntheticTrace.model_validate(load_artifact(ev.trace_ref))
    report = investigate(trace.observed_view(), reasoning=None)
    ref = save_report(ev.strategy_id, json.loads(report.model_dump_json()))
    return ev_dict(
        EvInvestigationCompleted(
            trace_id=ev.trace_id,
            strategy_id=ev.strategy_id,
            attack_family=ev.attack_family,
            trace_ref=ev.trace_ref,
            spec_ref=ev.spec_ref,
            report_ref=ref,
            seed=ev.seed,
        )
    )


def stage_gate(data: dict[str, Any]) -> dict[str, object]:
    ev = EvInvestigationCompleted.model_validate(data)
    trace = SyntheticTrace.model_validate(load_artifact(ev.trace_ref))
    gate = gate_score(trace.observed_view(), RuleBaselineDetector())
    return ev_dict(
        EvGateScored(
            strategy_id=ev.strategy_id,
            attack_family=ev.attack_family,
            trace_ref=ev.trace_ref,
            report_ref=ev.report_ref,
            spec_ref=ev.spec_ref,
            gate=gate,
            seed=ev.seed,
        )
    )


def stage_finalize(data: dict[str, Any]) -> dict[str, object]:
    """gate.scored -> record cycle (+ corpus threshold event when reached)."""
    ev = EvGateScored.model_validate(data)
    reg = _registry()
    spec = StrategySpec.model_validate(load_artifact(ev.spec_ref))
    report = BlueReport.model_validate(load_artifact(ev.report_ref))

    accepted = ev.gate.coverage != Coverage.COVERED
    ordinal = len(reg.cycles()) + 1
    record = CycleRecord(
        cycle_id=f"{cycle_id_base(ev.strategy_id, ev.seed)}{ordinal:04d}",
        run_id=f"pipe-{ev.seed}",
        strategy=spec,
        trace_ref=ev.trace_ref.split("/")[-1].removesuffix(".json"),
        blue_report=report,
        gate_result=ev.gate,
        accepted=accepted,
    )
    reg.record_cycle(record)

    out: dict[str, object] = {
        "accepted": ev_dict(
            EvCycleAccepted(
                cycle_id=record.cycle_id,
                strategy_id=spec.strategy_id,
                attack_family=spec.attack_family,
            )
        )
    }
    verified = sum(1 for c in reg.cycles() if c.accepted)
    minimum = settings().pipeline.training_threshold_min
    if verified >= minimum:
        out["threshold"] = ev_dict(
            EvCorpusThresholdReached(verified_count=verified, min_required=minimum)
        )
    return out


# ----------------------------------------------------------------- helpers


def save_spec(spec: StrategySpec) -> str:
    from forge.storage import save_artifact

    return save_artifact("specs", spec.strategy_id, json.loads(spec.model_dump_json()))


def save_trace(trace_id: str, payload: dict[str, Any]) -> str:
    from forge.storage import save_artifact

    return save_artifact("traces", trace_id, payload)


def save_report(strategy_id: str, payload: dict[str, Any]) -> str:
    from forge.storage import save_artifact

    return save_artifact("reports", strategy_id, payload)


def load_artifact(ref: str) -> dict[str, Any]:
    from forge.storage import load_artifact as _load

    return _load(ref)


def load_gate(payload: dict[str, Any]) -> GateResult:
    return GateResult.model_validate(payload)
