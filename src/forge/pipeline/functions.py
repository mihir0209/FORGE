# pyright: reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownParameterType=false, reportMissingTypeArgument=false, reportArgumentType=false, reportUntypedFunctionDecorator=false, reportPrivateUsage=false
"""Inngest functions — thin durable adapters over forge.pipeline.stages.

The inngest SDK ships loose types; this adapter file relaxes the Unknown-family
pyright rules rather than sprinkling ignores. Business logic stays strict in stages.py.


Flow: gap.mine → cycle.requested → compose → strategy.proposed → simulate →
trace.completed → investigate → investigation.completed → gate.scored →
finalize → cycle.accepted (+ corpus.threshold_reached).

Concurrency keys per attack_family keep workers diversified (architecture §2.9).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import inngest

from forge.pipeline import stages
from forge.pipeline.client import client

if TYPE_CHECKING:
    from collections.abc import Callable

_FN_CONCURRENCY = 2  # configs.settings.pipeline.concurrency_per_family
_logger = logging.getLogger("forge.pipeline")


async def _run_step(step: inngest.Step, name: str, fn: Callable[..., Any], *args: Any) -> Any:
    """Step execution with traceback capture — SDK turns errors into bare 500s."""
    try:
        return await step.run(name, fn, *args)
    except Exception:
        _logger.exception("pipeline step '%s' failed", name)
        raise


@client.create_function(
    fn_id="gap_mine",
    trigger=inngest.TriggerCron(cron="TZ=UTC 0 3 * * *"),
)
async def gap_mine(ctx: inngest.Context) -> None:
    payloads = await _run_step(ctx.step, "rank_gaps", stages.stage_gap_mine)
    if payloads:
        await ctx.step.send_event(
            "request_cycles",
            [inngest.Event(name="cycle.requested", data=p) for p in payloads],
        )


@client.create_function(
    fn_id="cycle_compose",
    trigger=inngest.TriggerEvent(event="cycle.requested"),
)
async def cycle_compose(ctx: inngest.Context) -> None:
    data = dict(ctx.event.data)
    admitted = await _run_step(ctx.step, "admit", stages.stage_admit_cycle, data)
    if not admitted:
        return
    if data.get("scenario") == "ai_assisted_app_scam":
        await _run_step(ctx.step, "cycle_started", stages.stage_cycle_started, data)
        result = await _run_step(ctx.step, "app_scam_cycle", stages.stage_app_scam_cycle, data)
        await ctx.step.send_event(
            "emit_app_scam_complete",
            inngest.Event(name="cycle.accepted", data=result),
        )
        return
    proposed = await _run_step(ctx.step, "compose", stages.stage_compose, data)
    if proposed is None:
        await _run_step(ctx.step, "release_admission", stages.stage_release_admission, data)
        return
    await _run_step(ctx.step, "cycle_started", stages.stage_cycle_started, data)
    await ctx.step.send_event(
        "emit_proposed",
        inngest.Event(name="strategy.proposed", data=proposed),
    )


@client.create_function(
    fn_id="cycle_simulate",
    trigger=inngest.TriggerEvent(event="strategy.proposed"),
    concurrency=[
        inngest.Concurrency(
            scope="fn",
            key="event.data.attack_family",
            limit=_FN_CONCURRENCY,
        )
    ],
)
async def cycle_simulate(ctx: inngest.Context) -> None:
    data = dict(ctx.event.data)
    completed = await _run_step(ctx.step, "simulate", stages.stage_simulate, data)
    await ctx.step.send_event("emit_trace", inngest.Event(name="trace.completed", data=completed))


@client.create_function(
    fn_id="cycle_investigate",
    trigger=inngest.TriggerEvent(event="trace.completed"),
    concurrency=[
        inngest.Concurrency(
            scope="fn",
            key="event.data.attack_family",
            limit=_FN_CONCURRENCY,
        )
    ],
)
async def cycle_investigate(ctx: inngest.Context) -> None:
    data = dict(ctx.event.data)
    investigated = await _run_step(ctx.step, "investigate", stages.stage_investigate, data)
    await ctx.step.send_event(
        "emit_report",
        inngest.Event(name="investigation.completed", data=investigated),
    )


@client.create_function(
    fn_id="gate_score",
    trigger=inngest.TriggerEvent(event="investigation.completed"),
    concurrency=[
        inngest.Concurrency(
            scope="fn",
            key="event.data.attack_family",
            limit=_FN_CONCURRENCY,
        )
    ],
)
async def gate_score_fn(ctx: inngest.Context) -> None:
    data = dict(ctx.event.data)
    scored = await _run_step(ctx.step, "gate", stages.stage_gate, data)
    await ctx.step.send_event("emit_scored", inngest.Event(name="gate.scored", data=scored))


@client.create_function(
    fn_id="cycle_finalize",
    trigger=inngest.TriggerEvent(event="gate.scored"),
)
async def cycle_finalize(ctx: inngest.Context) -> None:
    data = dict(ctx.event.data)
    out = await _run_step(ctx.step, "finalize", stages.stage_finalize, data)

    events: list[inngest.Event] = [inngest.Event(name="cycle.accepted", data=out["accepted"])]
    if "threshold" in out:
        events.append(inngest.Event(name="corpus.threshold_reached", data=out["threshold"]))
    await ctx.step.send_event("emit_final", events)


@client.create_function(
    fn_id="run_supervisor_tick",
    trigger=inngest.TriggerCron(cron="TZ=UTC */1 * * * *"),
)
async def run_supervisor_tick(ctx: inngest.Context) -> None:
    await _run_step(ctx.step, "tick", stages.stage_supervisor_tick)


@client.create_function(
    fn_id="train_round",
    trigger=inngest.TriggerEvent(event="corpus.threshold_reached"),
)
async def train_round(ctx: inngest.Context) -> None:
    ref = await _run_step(
        ctx.step, "build_dataset", stages.stage_build_dataset, dict(ctx.event.data)
    )
    report = await _run_step(ctx.step, "train", stages.stage_train, ref)
    verdict = await _run_step(ctx.step, "evaluate", stages.stage_evaluate, report)
    result = await _run_step(
        ctx.step,
        "install",
        stages.stage_install,
        {"verdict": verdict, "report": report},
    )
    event_name = "model.promoted" if result.get("promoted") else "model.retained"
    await ctx.step.send_event("emit_model_result", inngest.Event(name=event_name, data=result))


@client.create_function(
    fn_id="worker_probe",
    trigger=inngest.TriggerEvent(event="worker.probe"),
)
async def worker_probe(ctx: inngest.Context) -> None:
    result = await _run_step(
        ctx.step, "worker_probe", stages.stage_worker_probe, dict(ctx.event.data)
    )
    await ctx.step.send_event(
        "emit_worker_probe",
        inngest.Event(name="worker.probe.completed", data=result),
    )


functions: list[object] = [
    gap_mine,
    cycle_compose,
    cycle_simulate,
    cycle_investigate,
    gate_score_fn,
    cycle_finalize,
    run_supervisor_tick,
    train_round,
    worker_probe,
]
