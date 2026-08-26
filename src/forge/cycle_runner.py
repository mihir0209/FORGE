"""One synchronous adversarial cycle — the seam composition the pipeline adapts.

Business logic only: no inngest import (architecture invariant #1). The Inngest
functions call these same stage seams; this runner exists for offline/G1 mode,
the CLI, and judge-facing replay.
"""

from __future__ import annotations

import json
import os
from hashlib import sha256
from typing import TYPE_CHECKING

from forge.blueteam import investigate
from forge.contracts.contracts import (
    CycleRecord,
    DetectionTrack,
    DraftStrategy,
    EvidenceCapability,
    GapBrief,
    KBQuery,
    NoveltyVerdict,
    WorldSeed,
)
from forge.detect import RuleBaselineDetector, gate_score, trace_features
from forge.feature_schema import FEATURE_SCHEMA_VERSION
from forge.gapmine import fallback_brief, rank
from forge.ids import cycle_id_base, strategy_id_for
from forge.kb import Registry, search
from forge.redteam import compose, compose_draft, novelty
from forge.redteam.fixtures import draft_for_tactic
from forge.simulate import simulate
from forge.storage import artifact_sha256, save_artifact

if TYPE_CHECKING:
    from forge.reasoning import ReasoningClient


def run_offline_cycle(
    seed: int,
    registry: Registry,
    *,
    draft: DraftStrategy | None = None,
    reasoning: ReasoningClient | None = None,
    n_days: int = 14,
    n_customers: int = 400,
    n_merchants: int = 60,
) -> CycleRecord:
    """Gap brief → strategy → simulate → blind investigate → gate → record."""
    if reasoning is not None and draft is not None:
        raise ValueError("pass either a live reasoning client or a scripted draft")

    world_seed = WorldSeed(master_seed=seed)

    briefs = rank(registry)
    brief = briefs[0] if briefs else _fallback_brief()
    slug = _slug_of(brief)

    hits = search(KBQuery(tactic=slug, technique_ids=brief.target_f3_cells, limit=8))

    provider, model = "scripted", "fixture"
    # Offline mode picks fixture by gap brief's target tactic
    if draft is None and reasoning is None:
        tactic_hint = brief.suggested_family.removesuffix("_family")
        draft = draft_for_tactic(tactic_hint)
    if draft is not None:
        spec = compose_draft(
            draft, strategy_id=strategy_id_for(seed), provider=provider, model=model
        )
    else:
        assert reasoning is not None
        provider = reasoning.name.split("+")[0].split(":")[0] or reasoning.name
        model = reasoning.name
        spec = compose(
            brief,
            hits,
            reasoning,
            strategy_id=strategy_id_for(seed),
            provider=provider,
            model=model,
        )

    verdict: NoveltyVerdict = novelty(spec, registry)

    result = simulate(
        spec,
        world_seed,
        n_days=n_days,
        n_customers=n_customers,
        n_merchants=n_merchants,
    )
    view = result.trace.observed_view()

    report = investigate(view, reasoning=None if reasoning is None else reasoning)
    gate = gate_score(view, RuleBaselineDetector())

    accepted = verdict.novel and gate.coverage.value != "covered"
    trace_ref = save_artifact(
        "traces", result.trace.trace_id, json.loads(result.trace.model_dump_json())
    )
    ordinal = len(registry.cycles()) + 1  # deterministic, unique per run order
    record = CycleRecord(
        cycle_id=f"{cycle_id_base(spec.strategy_id, seed)}{ordinal:04d}",
        run_id=os.environ.get("FORGE_RUN_ID", f"offline-{seed}"),
        strategy=spec,
        trace_ref=trace_ref,
        trace_sha256=artifact_sha256(trace_ref),
        blue_report=report,
        gate_result=gate,
        detector_features=trace_features(view),
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        detection_track=DetectionTrack.BEHAVIORAL_PAYMENT,
        evidence_capabilities=[EvidenceCapability.PAYMENT_HISTORY],
        accepted=accepted,
    )
    registry.record_cycle(record)
    return record


del sha256  # ids moved to forge.ids


def _slug_of(brief: GapBrief) -> str:
    family = brief.suggested_family
    return family.removesuffix("_family")


_fallback_brief = fallback_brief
