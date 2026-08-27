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
from typing import Any, cast

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


class DetectionTrack(StrEnum):
    BEHAVIORAL_PAYMENT = "behavioral_payment"
    AI_ASSISTED_APP = "ai_assisted_app"
    BANK_CONTROLLED_MEDIA = "bank_controlled_media"


class EvidenceCapability(StrEnum):
    PAYMENT_HISTORY = "payment_history"
    DEVICE_INTEGRITY = "device_integrity"
    APP_BEHAVIOR = "app_behavior"
    PAYEE_VERIFICATION = "payee_verification"
    BENEFICIARY_NETWORK = "beneficiary_network"
    SYSTEM_CALL_STATE = "system_call_state"
    BANK_CONTROLLED_MEDIA = "bank_controlled_media"


class BenchmarkSplit(StrEnum):
    TRAIN = "train"
    CALIBRATION = "calibration"
    DEVELOPMENT = "development"
    SEALED_TEST = "sealed_test"
    OOD = "ood"


class ScenarioPurpose(StrEnum):
    ATTACK = "attack"
    MATCHED_CONTROL = "matched_control"
    HARD_NEGATIVE = "hard_negative"
    LOW_SIGNAL_ATTACK = "low_signal_attack"


class BenchmarkSlice(StrEnum):
    TEMPORAL_OOD = "temporal_ood"
    RAIL_OOD = "rail_ood"
    CHANNEL_OOD = "channel_ood"


class FeatureValue(Strict):
    value: float | None
    available: bool
    capability: EvidenceCapability | None = None
    evidence_refs: list[str] = Field(default_factory=list)


class BenchmarkRowMetadata(Strict):
    row_id: str
    scenario_id: str
    world_id: str
    pair_id: str
    family_slug: str
    family_version: str
    family_definition_sha256: str
    scenario_template: str
    purpose: ScenarioPurpose
    split: BenchmarkSplit
    fold: int | None = None
    detection_track: DetectionTrack
    payment_rail: str
    channel: str
    capability_mask: dict[EvidenceCapability, bool]
    graph_snapshot_sha256: str | None = None
    source_refs: list[str] = Field(default_factory=list)
    feature_sha256: str
    feature_equivalence_size: int = 1


class BenchmarkArtifact(Strict):
    split: BenchmarkSplit
    path: str
    sha256: str
    byte_size: int
    rows: int


class BenchmarkManifest(Strict):
    protocol_version: str = "forge-benchmark-v1"
    dataset_id: str
    feature_schema_version: str
    feature_names: list[str]
    feature_capabilities: dict[str, EvidenceCapability]
    ablated_capabilities: list[EvidenceCapability] = Field(
        default_factory=list[EvidenceCapability]
    )
    development_folds: int
    sealed_families: list[str]
    sealed_templates: list[str] = Field(default_factory=list)
    rows: list[BenchmarkRowMetadata]
    slices: dict[BenchmarkSlice, list[str]]
    artifacts: list[BenchmarkArtifact]
    metadata_sha256: str


class GraphScope(StrEnum):
    LOCAL_BANK = "local_bank"
    CONSORTIUM = "consortium"


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


class LLMCall(Strict):
    """Content-free operational receipt for one provider attempt."""

    call_id: str
    started_at: datetime = Field(default_factory=_now)
    duration_ms: float = Field(ge=0.0)
    team: str
    stage: str
    provider: str
    model: str
    schema_name: str
    status: str
    requests: int | None = Field(default=None, ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    cache_read_tokens: int | None = Field(default=None, ge=0)
    cache_write_tokens: int | None = Field(default=None, ge=0)
    tool_calls: int | None = Field(default=None, ge=0)
    run_id: str | None = None
    cycle_id: str | None = None
    error_type: str | None = None


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
    family_version: str = "1.0.0"
    family_definition_sha256: str | None = None
    scenario_template: str = "legacy_behavioral"

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
    feature_schema_version: str = "forge-feature-v2"
    manifest_path: str | None = None
    held_out_families: list[str] = Field(default_factory=list)
    split_positive_counts: dict[str, int] = Field(default_factory=dict)
    included_tracks: list[DetectionTrack] = Field(default_factory=list[DetectionTrack])
    train_tracks: list[DetectionTrack] = Field(default_factory=list[DetectionTrack])
    parquet_sha256: dict[str, str] = Field(default_factory=dict)


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
    feature_schema_version: str = "forge-feature-v2"
    dataset_manifest_path: str | None = None
    held_out_families: list[str] = Field(default_factory=list)
    prediction_ledger_path: str | None = None
    evaluation_summary_path: str | None = None
    artifact_sha256: str | None = None
    prediction_ledger_sha256: str | None = None
    evaluation_summary_sha256: str | None = None


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
    KYC_SUBMIT = "kyc.submit"
    VENDOR_DETAILS_CHANGE = "vendor.details.change"
    AGENT_CONTENT_INGEST = "agent.content.ingest"
    AUTH_CHALLENGE = "auth.challenge"
    WALLET_TOKEN_PROVISION = "wallet.token.provision"
    SUBSCRIPTION_ENROLL = "subscription.enroll"
    DELEGATION_CREATE = "delegation.create"
    PAYMENT_REQUEST_CREATE = "payment_request.create"
    CONSENT_CREATE = "consent.create"
    CRYPTO_TRANSFER = "crypto.transfer"
    CLAIM_SUBMIT = "claim.submit"
    PAYROLL_DESTINATION_CHANGE = "payroll.destination.change"


class FamilyEvidenceStatus(StrEnum):
    DEMONSTRATED = "demonstrated"
    EXPERIMENTAL = "experimental"


class ResidualKind(StrEnum):
    GATE_PARTIAL = "gate_partial"
    GATE_BLIND_SPOT = "gate_blind_spot"
    BLUE_PARTIAL = "blue_partial"
    BLUE_MISSED = "blue_missed"
    BLUE_UNCOVERED_GAP = "blue_uncovered_gap"


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


class FraudFamilyDefinition(Strict):
    """Immutable declarative family; selects reviewed tools but defines no code."""

    slug: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    title: str
    description: str
    detection_track: DetectionTrack
    f3: F3Mapping
    rail: str
    channel: str
    genai_leverage: str
    evasion_hypothesis: str
    evidence_status: FamilyEvidenceStatus = FamilyEvidenceStatus.DEMONSTRATED
    scenario_template: str = Field(
        default="async_coaching", pattern=r"^[a-z][a-z0-9_]{2,63}$"
    )
    allowed_tools: list[ToolKind]
    required_capabilities: list[EvidenceCapability] = Field(
        default_factory=list[EvidenceCapability]
    )
    scenario_defaults: dict[str, bool | int | float | str] = Field(default_factory=dict)
    research_refs: list[str] = Field(default_factory=list)
    definition_sha256: str


class VariantChange(Strict):
    field: str
    previous_value: bool | int | float | str
    proposed_value: bool | int | float | str
    rule_id: str


class FamilyVariantProposal(Strict):
    """Immutable, non-executable candidate derived from one residual cycle."""

    schema_version: str = "forge-family-variant-proposal-v1"
    proposal_id: str
    proposal_sha256: str
    source_cycle_id: str
    source_strategy_id: str
    parent_family_slug: str
    parent_family_version: str
    parent_definition_sha256: str
    residual_kinds: list[ResidualKind]
    gate_coverage: Coverage
    blue_verdict: Verdict
    uncovered_gaps: list[str] = Field(default_factory=list)
    gate_reason_codes: list[str] = Field(default_factory=list)
    derivation_rule_version: str = "bounded-low-signal-v1"
    changes: list[VariantChange]
    candidate_family: FraudFamilyDefinition
    created_at: datetime


class ResearchSnapshot(Strict):
    snapshot_id: str
    source_url: str
    retrieved_at: datetime
    title: str
    content_sha256: str
    artifact_ref: str
    provider: str
    parser_version: str
    trust: str = "untrusted-public-web"


class FamilyApprovalReceipt(Strict):
    family_slug: str
    family_version: str
    definition_sha256: str
    research_snapshot_ids: list[str]
    approved: bool
    reviewer: str
    approved_at: datetime


class GraphEvent(Strict):
    event_id: str
    event_time: datetime
    available_at: datetime
    kind: str
    institution_id: str
    source_account_ref: str | None = None
    destination_account_ref: str | None = None
    device_ref: str | None = None
    identity_ref: str | None = None
    amount_minor: int = 0
    attributes: dict[str, Any] = Field(default_factory=dict)


class GraphQuery(Strict):
    beneficiary_ref: str
    decision_at: datetime
    scopes: list[GraphScope]
    local_institution_id: str | None = None
    feature_version: str = "beneficiary-risk-v1"

    @model_validator(mode="after")
    def local_scope_requires_institution(self) -> GraphQuery:
        if (
            GraphScope.LOCAL_BANK in self.scopes
            and GraphScope.CONSORTIUM not in self.scopes
            and not self.local_institution_id
        ):
            raise ValueError("local_bank scope requires local_institution_id")
        if not self.scopes:
            raise ValueError("at least one graph scope is required")
        if len(set(self.scopes)) != len(self.scopes):
            raise ValueError("graph scopes must be unique")
        return self


class GraphSnapshot(Strict):
    snapshot_id: str
    snapshot_sha256: str
    query: GraphQuery
    event_ids: list[str]
    canonical_json: str


class BeneficiaryGraphAssessment(Strict):
    assessment_id: str
    beneficiary_ref: str
    decision_at: datetime
    scopes: list[GraphScope]
    snapshot_id: str
    snapshot_sha256: str
    features: dict[str, float]
    evidence_event_ids: list[str]


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
    trace_sha256: str | None = None
    blue_report: BlueReport
    gate_result: GateResult
    detector_features: dict[str, float] = Field(default_factory=dict)
    feature_schema_version: str = "legacy-unversioned"
    detection_track: DetectionTrack = DetectionTrack.BEHAVIORAL_PAYMENT
    evidence_capabilities: list[EvidenceCapability] = Field(
        default_factory=list[EvidenceCapability]
    )
    graph_assessment: BeneficiaryGraphAssessment | None = None
    accepted: bool
    recorded_at: datetime = Field(default_factory=_now)

    @model_validator(mode="before")
    @classmethod
    def _infer_historical_track(cls, data: Any) -> Any:
        if not isinstance(data, dict) or "detection_track" in data:
            return cast("Any", data)
        raw = cast("dict[str, Any]", data)
        strategy: Any = raw.get("strategy")
        strategy_data = cast("dict[str, Any]", strategy) if isinstance(strategy, dict) else {}
        family = str(strategy_data.get("attack_family", ""))
        migrated: dict[str, Any] = dict(raw)
        if family == "deepfake_video_call_payment":
            migrated["detection_track"] = DetectionTrack.BANK_CONTROLLED_MEDIA
            migrated["evidence_capabilities"] = []
        elif family == "ai_assisted_app_scam" or family.startswith("ai_"):
            migrated["detection_track"] = DetectionTrack.AI_ASSISTED_APP
            migrated["evidence_capabilities"] = []
        else:
            migrated["detection_track"] = DetectionTrack.BEHAVIORAL_PAYMENT
            migrated["evidence_capabilities"] = []
        return migrated


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
    variant: str | None = None
    family_slug: str | None = None
    family_version: str = "1.0.0"


class EvCycleAccepted(Strict):
    cycle_id: str
    strategy_id: str
    attack_family: str


class EvFamilyVariantProposed(Strict):
    proposal_id: str
    source_cycle_id: str
    parent_family_slug: str
    candidate_family_slug: str
    proposal_sha256: str


class EvCorpusThresholdReached(Strict):
    verified_count: int
    min_required: int
    corpus_sha256: str = "legacy-unversioned"
    cycle_ids: list[str] = Field(default_factory=list)


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
