"""FORGE contracts — the only shared dependency between modules.

Everything here is pydantic models and pure helpers. No behavior, no I/O.
Blindness is enforced at the type level: `blueteam.investigate` accepts
ObservedTraceView, which can only be constructed from SyntheticTrace.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


def _now() -> datetime:
    return datetime.now(UTC)


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Verdict(StrEnum):
    DEFEATED = "defeated"
    PARTIAL = "partial"
    MISSED = "missed"


class Coverage(StrEnum):
    COVERED = "covered"
    PARTIAL = "partial"
    BLIND_SPOT = "blind_spot"


class Action(StrEnum):
    APPROVE = "approve"
    STEP_UP = "step_up"
    REVIEW = "review"
    DECLINE = "decline"


class SafetyClass(StrEnum):
    SYNTHETIC_RESEARCH = "synthetic_research"
    RESTRICTED = "restricted"


# ---------------------------------------------------------------------------
# Red team
# ---------------------------------------------------------------------------


class F3Mapping(Strict):
    tactic: str
    techniques: list[str] = Field(default_factory=list)


class LifecycleStage(StrEnum):
    ONBOARDING = "onboarding"
    AUTHENTICATION = "authentication"
    PAYMENT = "payment"
    REFUND = "refund"
    SETTLEMENT = "settlement"
    CASH_OUT = "cash_out"


class Provenance(Strict):
    brief_id: str | None = None
    provider: str
    model: str
    created_at: datetime = Field(default_factory=_now)
    run_id: str | None = None
    worker_id: str | None = None


class StrategySpec(Strict):
    """Red team's validated attack hypothesis."""

    strategy_id: str
    fraud_objective: str
    attack_family: str
    f3: F3Mapping
    rail: str
    channel: str
    prerequisites: list[str] = Field(default_factory=list)
    lifecycle_stages: list[LifecycleStage]
    entities: dict[str, int] = Field(default_factory=dict)
    behavioral_sequence: list[str] = Field(min_length=1)
    genai_leverage: str
    evasion_hypothesis: str
    expected_signals: list[str] = Field(default_factory=list)
    safety_class: SafetyClass = SafetyClass.SYNTHETIC_RESEARCH
    novelty_rationale: str
    provenance: Provenance

    def fingerprint(self) -> str:
        payload = json.dumps(
            {
                "family": self.attack_family,
                "f3": self.f3.model_dump(),
                "rail": self.rail,
                "channel": self.channel,
                "stages": sorted(s.value for s in self.lifecycle_stages),
                "sequence": self.behavioral_sequence,
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Simulation
# ---------------------------------------------------------------------------


class WorldSeed(Strict):
    master_seed: int
    world_params_version: str = "1"


class ActorKind(StrEnum):
    CUSTOMER = "customer"
    MERCHANT = "merchant"
    DEVICE = "device"
    SYSTEM = "system"


class TraceEvent(Strict):
    event_id: str
    ts: datetime
    actor_kind: ActorKind
    actor_id: str
    kind: str
    payload: dict[str, Any] = Field(default_factory=dict)
    # ground truth channel — stripped by ObservedTraceView
    is_attack_step: bool = False
    attack_stage: LifecycleStage | None = None


class FidelityReport(Strict):
    psi_amount: float
    ks_timestamp_gap: float
    graph_density_delta: float
    temporal_autocorr: float
    reachability_ok: bool
    notes: list[str] = Field(default_factory=list)


class GroundTruth(Strict):
    strategy_id: str
    fingerprint: str
    attack_event_ids: list[str] = Field(default_factory=list)


class SyntheticTrace(Strict):
    trace_id: str
    seed: WorldSeed
    events: list[TraceEvent] = Field(min_length=1)
    ground_truth: GroundTruth
    fidelity: FidelityReport

    def observed_view(self) -> ObservedTraceView:
        """The ONLY way to build an ObservedTraceView."""
        return ObservedTraceView(
            trace_id=self.trace_id,
            events=[
                e.model_copy(
                    update={"is_attack_step": False, "attack_stage": None},
                    deep=True,
                )
                for e in self.events
            ],
        )


class ObservedTraceView(Strict):
    """What defenders may see. Ground-truth fields are nulled by construction."""

    trace_id: str
    events: list[TraceEvent]

    @model_validator(mode="after")
    def _no_ground_truth(self) -> ObservedTraceView:
        if any(e.is_attack_step or e.attack_stage is not None for e in self.events):
            raise ValueError("ObservedTraceView must not contain ground-truth labels")
        return self

    @property
    def event_ids(self) -> list[str]:
        return [e.event_id for e in self.events]


# ---------------------------------------------------------------------------
# Blue team / gate
# ---------------------------------------------------------------------------


class Signal(Strict):
    name: str
    description: str
    evidence_refs: list[str] = Field(default_factory=list)
    strength: float = Field(ge=0.0, le=1.0)


class Motif(Strict):
    kind: str  # e.g. "velocity_burst", "graph_fanout", "timing_anomaly"
    detail: str
    evidence_refs: list[str] = Field(default_factory=list)


class BlueReport(Strict):
    investigator_id: str
    signals: list[Signal] = Field(default_factory=list[Signal])
    motifs: list[Motif] = Field(default_factory=list[Motif])
    mitigations: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    verdict: Verdict
    uncovered_gaps: list[str] = Field(default_factory=list)
    provenance: Provenance


class GateResult(Strict):
    detector_id: str
    score: float = Field(ge=0.0, le=1.0)
    action: Action
    reason_codes: list[str] = Field(default_factory=list)
    coverage: Coverage
    latency_ms: float
    similarity_to_known: float = Field(ge=0.0, le=1.0)


# ---------------------------------------------------------------------------
# Gap miner
# ---------------------------------------------------------------------------


class GapBrief(Strict):
    brief_id: str
    objective: str
    target_f3_cells: list[str] = Field(default_factory=list)
    suggested_family: str
    priority: float = Field(ge=0.0, le=1.0)
    rationale: str


# ---------------------------------------------------------------------------
# Detection lifecycle
# ---------------------------------------------------------------------------


class DatasetRef(Strict):
    dataset_id: str
    train_path: str
    calib_path: str
    test_path: str
    rows: int


class CandidateReport(Strict):
    candidate_id: str
    dataset: DatasetRef
    precision: float
    recall: float
    f1: float
    roc_auc: float
    pr_auc: float
    recall_at_fpr_1e3: float
    recall_at_fpr_1e2: float
    brier: float
    p50_latency_ms: float
    p95_latency_ms: float
    artifact_path: str


class PromotionVerdict(Strict):
    candidate_id: str
    passed: bool
    checks: dict[str, bool] = Field(default_factory=dict)
    installed: bool = False
    notes: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Cycle aggregate + events
# ---------------------------------------------------------------------------


class CycleRecord(Strict):
    cycle_id: str
    run_id: str | None
    strategy: StrategySpec
    trace_ref: str
    blue_report: BlueReport
    gate_result: GateResult
    accepted: bool
    recorded_at: datetime = Field(default_factory=_now)


class EvGapBriefCreated(Strict):
    brief_id: str
    suggested_family: str


class EvStrategyProposed(Strict):
    strategy_id: str
    attack_family: str
    spec_ref: str  # artifact ref; events stay small (<64 KiB)
    seed: int


class EvTraceCompleted(Strict):
    trace_id: str
    strategy_id: str
    attack_family: str
    trace_ref: str  # artifact ref
    spec_ref: str  # artifact ref
    seed: int


class EvInvestigationCompleted(Strict):
    trace_id: str
    strategy_id: str
    attack_family: str
    trace_ref: str
    spec_ref: str
    report_ref: str
    seed: int


class EvGateScored(Strict):
    strategy_id: str
    attack_family: str
    trace_ref: str
    report_ref: str
    spec_ref: str
    gate: GateResult
    seed: int


# ---------------------------------------------------------------------------
# Knowledge base (P2)
# ---------------------------------------------------------------------------


class F3Tactic(Strict):
    tactic_id: str  # TA0043 / FA0001 …
    name: str
    slug: str  # x_mitre_shortname, e.g. "reconnaissance"


class F3Technique(Strict):
    technique_id: str  # F1005 / T1566 …
    name: str
    tactic: str  # slug join via kill_chain_phases
    fraud_native: bool  # True for F1XXX-series


class KBQuery(Strict):
    tactic: str | None = None
    technique_ids: list[str] = Field(default_factory=list)
    family: str | None = None
    limit: int = 8


class KBHit(Strict):
    source: str  # "f3" | "skill" | "registry"
    ref: str  # technique id / skill name / strategy id
    title: str
    detail: str = ""
    score: float = 0.0


class SkillRef(Strict):
    name: str
    domain: str
    techniques: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)


class StrategyRef(Strict):
    strategy_id: str
    fingerprint: str
    attack_family: str


class NoveltyVerdict(Strict):
    novel: bool
    reason: str
    exact_duplicate: bool = False
    same_family_count: int = 0


# ---------------------------------------------------------------------------
# LLM-facing drafts (P2) — what the models emit before server-side enrichment
# ---------------------------------------------------------------------------


class DraftStrategy(Strict):
    """Red team LLM output; compose() turns this into a full StrategySpec."""

    fraud_objective: str
    attack_family: str
    f3_tactic: str  # slug
    f3_techniques: list[str] = Field(default_factory=list)
    rail: str
    channel: str
    lifecycle_stages: list[LifecycleStage] = Field(min_length=1)
    behavioral_sequence: list[str] = Field(min_length=1)
    entities: dict[str, int] = Field(default_factory=dict)
    genai_leverage: str
    evasion_hypothesis: str = ""
    expected_signals: list[str] = Field(default_factory=list)
    novelty_rationale: str


class SignalDraft(Strict):
    name: str
    description: str
    strength: float = Field(ge=0.0, le=1.0)


class BlueAssessment(Strict):
    """Blue team LLM output layered on deterministic heuristic signals."""

    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    mitigations: list[str] = Field(default_factory=list)
    uncovered_gaps: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Pipeline events (P3) — small payloads; heavy artifacts live behind refs
# ---------------------------------------------------------------------------


class EvCycleRequested(Strict):
    seed: int
    brief_id: str | None = None


class EvCycleAccepted(Strict):
    cycle_id: str
    strategy_id: str
    attack_family: str


class EvCorpusThresholdReached(Strict):
    verified_count: int
    min_required: int


def ev_dict(e: Strict) -> dict[str, object]:
    """Event data must be JSON-safe and small."""
    dump = e.model_dump(mode="json")
    assert len(json.dumps(dump)) < 64 * 1024, "event payload exceeds 64 KiB"
    return dump
