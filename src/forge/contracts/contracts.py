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

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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
    ATTACKER = "attacker"
    VICTIM = "victim"
    CUSTOMER = "customer"
    MERCHANT = "merchant"
    DEVICE = "device"
    SYSTEM = "system"


class EvidenceScope(StrEnum):
    INTERNAL = "internal"
    DEFENDER = "defender"


class TraceEvent(Strict):
    event_id: str
    ts: datetime
    actor_kind: ActorKind
    actor_id: str
    kind: str
    payload: dict[str, Any] = Field(default_factory=dict)
    evidence_scope: EvidenceScope = EvidenceScope.DEFENDER
    # Internal generation truth must live here, never in payload. It is stripped
    # by observed_view() before anything reaches blue-team code.
    private_payload: dict[str, Any] = Field(default_factory=dict)
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
                    update={
                        "private_payload": {},
                        "is_attack_step": False,
                        "attack_stage": None,
                    },
                    deep=True,
                )
                for e in self.events
                if e.evidence_scope == EvidenceScope.DEFENDER
            ],
        )


class ObservedTraceView(Strict):
    """What defenders may see. Ground-truth fields are nulled by construction."""

    trace_id: str
    events: list[TraceEvent]

    @model_validator(mode="after")
    def _no_ground_truth(self) -> ObservedTraceView:
        if any(
            e.private_payload
            or e.is_attack_step
            or e.attack_stage is not None
            or e.evidence_scope != EvidenceScope.DEFENDER
            for e in self.events
        ):
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
    split_protocol: str = "legacy-stratified"


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
    evaluation_protocol: str = "legacy-stratified"


class PromotionVerdict(Strict):
    candidate_id: str
    passed: bool
    checks: dict[str, bool] = Field(default_factory=dict)
    installed: bool = False
    notes: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Multimodal actor sandbox (P6)
# ---------------------------------------------------------------------------


class ToolKind(StrEnum):
    IMAGE_GENERATE = "image.generate"
    AUDIO_GENERATE = "audio.generate"
    VIDEO_GENERATE = "video.generate"
    MEDIA_INSPECT = "media.inspect"
    APP_SESSION_START = "app.session.start"
    DEVICE_ATTEST = "device.attest"
    CALL_STATE_OBSERVE = "call_state.observe"
    PAYEE_ADD = "payee.add"
    PAYEE_VERIFY = "payee.verify"
    BEHAVIOR_SAMPLE = "behavior.sample"
    BENEFICIARY_RISK_QUERY = "beneficiary.risk.query"
    SCAM_INTERVENE = "scam.intervene"
    PAYMENT_INITIATE = "payment.initiate"


class ToolAction(Strict):
    action_id: str
    tool: ToolKind
    parameters: dict[str, Any] = Field(default_factory=dict)
    depends_on: list[str] = Field(default_factory=list)


class ActionPlan(Strict):
    plan_id: str
    strategy_id: str
    actor_id: str
    actions: list[ToolAction] = Field(min_length=1)


class ArtifactRef(Strict):
    artifact_id: str
    uri: str
    sha256: str
    media_type: str
    byte_size: int


class ArtifactProvenance(Strict):
    artifact: ArtifactRef
    cycle_id: str
    operation_id: str
    adapter_name: str
    adapter_version: str
    seed: int
    input_artifact_ids: list[str] = Field(default_factory=list)
    tool_versions: dict[str, str] = Field(default_factory=dict)
    # Red-only generation truth; never serialized into MediaObservation.
    generation_parameters: dict[str, Any] = Field(default_factory=dict)


class MediaObservation(Strict):
    artifact: ArtifactRef
    role: str
    observed_at: datetime
    container: str | None = None
    codecs: list[str] = Field(default_factory=list)
    duration_seconds: float | None = None
    width: int | None = None
    height: int | None = None
    frame_rate: float | None = None
    audio_sample_rate: int | None = None
    encoder_tags: dict[str, str] = Field(default_factory=dict)
    decode_warnings: list[str] = Field(default_factory=list)
    perceptual_hash: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)


class MediaJobRequest(Strict):
    job_id: str
    cycle_id: str
    operation: ToolKind
    input_artifact_ids: list[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)
    seed: int
    profile: str = "fixture-v1"
    deadline_ms: int = 300_000


class MediaJobResult(Strict):
    job_id: str
    status: str
    output_artifacts: list[ArtifactRef] = Field(default_factory=list[ArtifactRef])
    observations: list[MediaObservation] = Field(default_factory=list[MediaObservation])
    error_code: str | None = None


# ---------------------------------------------------------------------------
# Context budget and durable compaction (P6)
# ---------------------------------------------------------------------------


class EvidenceRef(Strict):
    ref: str
    sha256: str
    media_type: str
    byte_size: int


class ContextBudgetPolicy(Strict):
    context_window_tokens: int = Field(gt=0)
    max_fraction: float = Field(default=0.25, gt=0, le=0.25)
    max_output_tokens: int = Field(gt=0)
    fixed_safety_tokens: int = 512
    target_fraction_after_compaction: float = Field(default=0.18, gt=0, lt=0.25)
    min_recent_turns: int = 2
    max_compaction_passes: int = 2


class CompactionRecord(Strict):
    compaction_id: str
    run_id: str
    conversation_id: str
    agent_role: str
    sequence: int
    created_at: datetime = Field(default_factory=_now)
    source_history_ref: str
    source_history_sha256: str
    previous_compaction_ref: str | None = None
    previous_digest_sha256: str | None = None
    objective: str
    constraints: list[str] = Field(default_factory=list)
    decisions: list[str] = Field(default_factory=list)
    completed: list[str] = Field(default_factory=list)
    open_work: list[str] = Field(default_factory=list)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list[EvidenceRef])
    recent_message_ids: list[str] = Field(default_factory=list)
    input_tokens_estimated: int
    record_sha256: str


# ---------------------------------------------------------------------------
# Multi-day run supervision and export (P6)
# ---------------------------------------------------------------------------


class RunState(StrEnum):
    SCHEDULED = "scheduled"
    RUNNING = "running"
    DRAINING = "draining"
    FINALIZING = "finalizing"
    COMPLETED = "completed"
    STOPPED = "stopped"
    EXPIRED = "expired"
    FAILED = "failed"


class RunSupervisorConfig(Strict):
    run_id: str
    starts_at: datetime
    ends_at: datetime
    max_cycles: int = Field(gt=0)
    max_storage_bytes: int = Field(gt=0)
    queue_capacity: int = Field(gt=0)
    queue_full_threshold: float = Field(default=0.90, gt=0, le=1)
    queue_resume_threshold: float = Field(default=0.70, gt=0, le=1)
    deadline_grace_seconds: int = 1800
    terminal_manifest_prefix: str = "exports"


class RunSupervisorState(Strict):
    run_id: str
    state: RunState
    version: int = 0
    started_at: datetime | None = None
    stop_requested_at: datetime | None = None
    stop_reason: str | None = None
    deadline_at: datetime
    admitted_cycles: int = 0
    completed_cycles: int = 0
    active_cycles: int = 0
    queued_cycles: int = 0
    storage_bytes: int = 0
    queue_alert_open: bool = False
    admitted_cycle_ids: list[str] = Field(default_factory=list)
    active_cycle_ids: list[str] = Field(default_factory=list)
    completed_cycle_ids: list[str] = Field(default_factory=list)
    terminal_manifest_ref: str | None = None
    terminal_manifest_sha256: str | None = None


class ManifestEntry(Strict):
    ref: str
    sha256: str
    byte_size: int
    kind: str


class ArtifactManifest(Strict):
    run_id: str
    created_at: datetime = Field(default_factory=_now)
    state: RunState
    entries: list[ManifestEntry] = Field(default_factory=list[ManifestEntry])
    manifest_sha256: str


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
    detector_features: dict[str, float] = Field(default_factory=dict)
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
    f3_tactic: str  # slug, e.g. "monetization" / "initial-access"
    f3_techniques: list[str] = Field(default_factory=list)  # IDs like F1010, T1566

    @field_validator("f3_tactic", mode="after")
    @classmethod
    def _tactic_exists(cls, v: str) -> str:
        from forge.kb._f3 import f3_matrix

        if f3_matrix().tactic_by_slug(v) is None:
            raise ValueError(f"unknown F3 tactic slug '{v}'")
        return v

    @field_validator("f3_techniques", mode="after")
    @classmethod
    def _techniques_exist(cls, vs: list[str]) -> list[str]:
        from forge.kb._f3 import f3_matrix

        m = f3_matrix()
        for tid in vs:
            if m.technique(tid) is None:
                raise ValueError(f"unknown F3 technique '{tid}'")
        return vs

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
    scenario: str | None = None


class EvCycleAccepted(Strict):
    cycle_id: str
    strategy_id: str
    attack_family: str


class EvCorpusThresholdReached(Strict):
    verified_count: int
    min_required: int


class EvModelPromoted(Strict):
    candidate_id: str
    roc_auc: float


class EvModelRetained(Strict):
    candidate_id: str
    reason: str


def ev_dict(e: Strict) -> dict[str, object]:
    """Event data must be JSON-safe and small."""
    dump = e.model_dump(mode="json")
    assert len(json.dumps(dump)) < 64 * 1024, "event payload exceeds 64 KiB"
    return dump
