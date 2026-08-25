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
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from forge.reasoning import ReasoningClient

from forge.blueteam import investigate
from forge.config import settings
from forge.contracts.contracts import (
    BlueReport,
    Coverage,
    CycleRecord,
    DetectionTrack,
    EvCorpusThresholdReached,
    EvCycleAccepted,
    EvCycleRequested,
    EvGateScored,
    EvidenceCapability,
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
from forge.detect import gate_score, trace_features
from forge.detect.incumbent import load_incumbent
from forge.feature_schema import FEATURE_SCHEMA_VERSION
from forge.gapmine import fallback_brief, rank
from forge.ids import cycle_id_base, strategy_id_for
from forge.kb import Registry, registry_from_env, search
from forge.redteam import compose_draft, novelty
from forge.redteam.fixtures import draft_for_tactic
from forge.simulate import simulate


def _live_reasoning() -> ReasoningClient | None:
    from forge.reasoning.live import default_client

    return default_client()


def _registry() -> Registry:
    return registry_from_env()


def _pick_brief(reg: Registry, brief_id: str | None) -> GapBrief:
    briefs = rank(reg)
    if brief_id:
        for b in briefs:
            if b.brief_id == brief_id:
                return b
    return briefs[0] if briefs else fallback_brief()


def _cycle_key(data: dict[str, Any]) -> str:
    return f"{data.get('scenario') or data.get('brief_id') or 'auto'}:{data.get('seed')}"


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


def stage_admit_cycle(data: dict[str, Any]) -> bool:
    """Atomic multi-day admission; a no-op outside supervised runs."""
    from forge.operations.runtime import notifier_from_env, supervisor_from_env

    supervisor = supervisor_from_env()
    if supervisor is None:
        return True
    state = supervisor.start()
    before_alert = state.queue_alert_open
    allowed = supervisor.admit(
        cycle_key=_cycle_key(data),
        queue_depth=int(data.get("queue_depth", state.queued_cycles)),
        storage_reservation=int(data.get("storage_reservation", 25 * 1024**2)),
    )
    after = supervisor.load_required()
    if after.queue_alert_open and not before_alert:
        notifier_from_env().send(
            notification_type="queue.full",
            run_id=after.run_id,
            subject=f"FORGE queue high-water: {after.run_id}",
            body=f"Queued={after.queued_cycles}; capacity={supervisor.config.queue_capacity}.",
            dedup_scope=f"queue-episode-{after.version}",
            dry_run=os.environ.get("SMTP_DRY_RUN", "0") == "1",
        )
    return allowed


def stage_cycle_started(_: dict[str, Any]) -> dict[str, object]:
    from forge.operations.runtime import supervisor_from_env

    supervisor = supervisor_from_env()
    return (
        supervisor.cycle_started(_cycle_key(_)).model_dump(mode="json")
        if supervisor is not None
        else {}
    )


def stage_release_admission(_: dict[str, Any]) -> dict[str, object]:
    from forge.operations.runtime import supervisor_from_env

    supervisor = supervisor_from_env()
    return (
        supervisor.release_admission(_cycle_key(_)).model_dump(mode="json")
        if supervisor is not None
        else {}
    )


def stage_compose(data: dict[str, Any]) -> dict[str, object] | None:
    """cycle.requested -> strategy.proposed. None terminates duplicate runs."""
    ev = EvCycleRequested.model_validate(data)
    reg = _registry()

    brief = _pick_brief(reg, ev.brief_id)
    slug = brief.suggested_family.removesuffix("_family")
    search(KBQuery(tactic=slug, technique_ids=brief.target_f3_cells, limit=8))

    spec = compose_draft(draft_for_tactic(slug), strategy_id=strategy_id_for(ev.seed))
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


def stage_app_scam_cycle(data: dict[str, Any]) -> dict[str, object]:
    """Execute the AI-assisted APP scenario with realistic evidence scopes."""
    from forge.app_scam_runner import run_app_scam_cycle
    from forge.artifacts import artifact_store_from_env
    from forge.operations.runtime import supervisor_from_env

    ev = EvCycleRequested.model_validate(data)
    cycle_id = f"cycle-app-{ev.seed}"
    record = run_app_scam_cycle(
        seed=ev.seed,
        cycle_id=cycle_id,
        registry=_registry(),
        store=artifact_store_from_env(),
        variant=str(data.get("family_slug") or data.get("variant", "safe_account")),
    )
    supervisor = supervisor_from_env()
    if supervisor is not None:
        supervisor.cycle_completed(cycle_key=_cycle_key(data))
    return ev_dict(
        EvCycleAccepted(
            cycle_id=record.cycle_id,
            strategy_id=record.strategy.strategy_id,
            attack_family=record.strategy.attack_family,
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
    report = investigate(
        trace.observed_view(),
        reasoning=_live_reasoning(),  # None offline -> deterministic heuristics
    )
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
    gate = gate_score(trace.observed_view(), load_incumbent())
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
    trace = SyntheticTrace.model_validate(load_artifact(ev.trace_ref))

    accepted = ev.gate.coverage != Coverage.COVERED
    ordinal = len(reg.cycles()) + 1
    record = CycleRecord(
        cycle_id=f"{cycle_id_base(ev.strategy_id, ev.seed)}{ordinal:04d}",
        run_id=f"pipe-{ev.seed}",
        strategy=spec,
        trace_ref=ev.trace_ref.split("/")[-1].removesuffix(".json"),
        blue_report=report,
        gate_result=ev.gate,
        detector_features=trace_features(trace.observed_view()),
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        detection_track=DetectionTrack.BEHAVIORAL_PAYMENT,
        evidence_capabilities=[EvidenceCapability.PAYMENT_HISTORY],
        accepted=accepted,
    )
    reg.record_cycle(record)

    from forge.operations.runtime import supervisor_from_env

    supervisor = supervisor_from_env()
    if supervisor is not None:
        supervisor.cycle_completed(cycle_key=_cycle_key(data))

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


def stage_build_dataset(data: dict[str, Any]) -> dict[str, object]:
    """corpus.threshold_reached -> dataset built."""
    from forge.detect.dataset import build_family_holdout_dataset as _build

    # registry is the source of truth; seeds for negatives come from event or defaults
    reg = _registry()
    seed = int(data.get("seed", 0))
    ref = _build(reg, n_negatives_per_split=40, dataset_seed=seed)
    return ref.model_dump(mode="json")


def stage_train(data: dict[str, Any]) -> dict[str, object]:
    """DatasetRef -> CandidateReport."""
    from forge.contracts.contracts import DatasetRef
    from forge.detect.train import train_detector

    ref = DatasetRef.model_validate(data)
    report = train_detector(ref)
    from forge.operations.runtime import notifier_from_env, supervisor_from_env

    supervisor = supervisor_from_env()
    run_id = supervisor.config.run_id if supervisor else "unsupervised"
    notifier_from_env().send(
        notification_type="model.trained",
        run_id=run_id,
        subject=f"FORGE model trained: {report.candidate_id}",
        body=report.model_dump_json(indent=2),
        dedup_scope=report.candidate_id,
        dry_run=os.environ.get("SMTP_DRY_RUN", "0") == "1",
    )
    return report.model_dump(mode="json")


def stage_evaluate(data: dict[str, Any]) -> dict[str, object]:
    """CandidateReport -> PromotionVerdict."""
    from forge.contracts.contracts import CandidateReport
    from forge.detect.promotion import evaluate

    report = CandidateReport.model_validate(data)
    reg = _registry()
    verdict = evaluate(report, reg)
    return verdict.model_dump(mode="json")


def stage_install(data: dict[str, Any]) -> dict[str, object]:
    """PromotionVerdict (+ stashed report) -> install + promote/retain event."""
    # data carries {verdict, report} from the finalize step's merged payload
    from forge.contracts.contracts import CandidateReport, PromotionVerdict
    from forge.detect.promotion import install_if_passed

    verdict = PromotionVerdict.model_validate(data["verdict"])
    report = CandidateReport.model_validate(data["report"])
    installed = install_if_passed(report, verdict)
    from forge.operations.runtime import notifier_from_env, supervisor_from_env

    supervisor = supervisor_from_env()
    run_id = supervisor.config.run_id if supervisor else "unsupervised"
    if installed:
        from forge.contracts.contracts import EvModelPromoted

        out: dict[str, object] = EvModelPromoted(
            candidate_id=verdict.candidate_id, roc_auc=report.roc_auc
        ).model_dump(mode="json")
        out["promoted"] = True
        notifier_from_env().send(
            notification_type="model.promoted",
            run_id=run_id,
            subject=f"FORGE incumbent promoted: {verdict.candidate_id}",
            body=verdict.model_dump_json(indent=2),
            dedup_scope=verdict.candidate_id,
            dry_run=os.environ.get("SMTP_DRY_RUN", "0") == "1",
        )
        return out
    from forge.contracts.contracts import EvModelRetained

    reason = "; ".join(verdict.notes) or "gates not all passed"
    out = EvModelRetained(candidate_id=verdict.candidate_id, reason=reason).model_dump(mode="json")
    out["promoted"] = False
    notifier_from_env().send(
        notification_type="model.retained",
        run_id=run_id,
        subject=f"FORGE incumbent retained: {verdict.candidate_id}",
        body=verdict.model_dump_json(indent=2),
        dedup_scope=verdict.candidate_id,
        dry_run=os.environ.get("SMTP_DRY_RUN", "0") == "1",
    )
    return out


def stage_supervisor_tick(_: dict[str, Any] | None = None) -> dict[str, object]:
    """Deadline/drain reconciliation; terminal state freezes manifest and emails."""
    from forge.operations.runtime import notifier_from_env, supervisor_from_env

    supervisor = supervisor_from_env()
    if supervisor is None:
        return {}
    state = supervisor.start()
    state = supervisor.tick()
    if state.state.value != "finalizing":
        return state.model_dump(mode="json")

    data_root = Path(os.environ.get("FORGE_DATA_DIR", "data"))
    manifest = supervisor.finalize(
        {
            "traces": data_root / "artifacts" / "traces",
            "media": data_root / "objects",
            "datasets": data_root / "datasets",
            "models": data_root / "models",
            "notifications": data_root / "notifications",
        }
    )
    notifier_from_env().send(
        notification_type="run.terminal",
        run_id=state.run_id,
        subject=f"FORGE run ended: {state.run_id}",
        body=manifest.model_dump_json(indent=2),
        dedup_scope="terminal",
        dry_run=os.environ.get("SMTP_DRY_RUN", "0") == "1",
    )
    return manifest.model_dump(mode="json")


def stage_worker_probe(data: dict[str, Any]) -> dict[str, object]:
    """Five-worker acceptance barrier: persist the worker instance per probe."""
    import socket
    import time

    probe_id = str(data["probe_id"])
    worker_id = os.environ.get("HOSTNAME", socket.gethostname())
    time.sleep(float(data.get("hold_seconds", 3)))
    dsn = os.environ.get("FORGE_DATABASE_URL")
    if dsn:
        import psycopg

        with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS forge_worker_probe (
                  probe_id TEXT PRIMARY KEY,
                  worker_id TEXT NOT NULL,
                  completed_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            cur.execute(
                """
                INSERT INTO forge_worker_probe(probe_id,worker_id)
                VALUES (%s,%s) ON CONFLICT (probe_id) DO NOTHING
                """,
                (probe_id, worker_id),
            )
    return {"probe_id": probe_id, "worker_id": worker_id}


def save_report(strategy_id: str, payload: dict[str, Any]) -> str:
    from forge.storage import save_artifact

    return save_artifact("reports", strategy_id, payload)


def load_artifact(ref: str) -> dict[str, Any]:
    from forge.storage import load_artifact as _load

    return _load(ref)


def load_gate(payload: dict[str, Any]) -> GateResult:
    return GateResult.model_validate(payload)
