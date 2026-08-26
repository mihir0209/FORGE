export type View = "overview" | "loop" | "repository" | "operations" | "attack" | "defense" | "model" | "gaps" | "chat";

export interface Signal {
  name: string;
  description: string;
  evidence_refs: string[];
  strength: number;
}

export interface CycleSummary {
  cycle_id: string;
  run_id: string | null;
  recorded_at: string;
  accepted: boolean;
  strategy_id: string;
  family: string;
  tactic: string;
  techniques: string[];
  rail: string;
  channel: string;
  blue_verdict: "defeated" | "partial" | "missed";
  blue_confidence: number;
  signals: Signal[];
  gate_score: number;
  gate_action: string;
  coverage: "covered" | "partial" | "blind_spot";
  detector_id: string;
  detection_track: "behavioral_payment" | "ai_assisted_app" | "bank_controlled_media";
  evidence_capabilities: string[];
  feature_schema_version: string;
}

export interface CycleDetail {
  cycle_id: string;
  run_id: string | null;
  trace_ref: string;
  accepted: boolean;
  recorded_at: string;
  strategy: {
    fraud_objective: string;
    attack_family: string;
    f3: { tactic: string; techniques: string[] };
    behavioral_sequence: string[];
    genai_leverage: string;
    evasion_hypothesis: string;
  };
  blue_report: {
    verdict: string;
    confidence: number;
    signals: Signal[];
    mitigations: string[];
    uncovered_gaps: string[];
  };
  gate_result: {
    detector_id: string;
    score: number;
    action: string;
    coverage: string;
    reason_codes: string[];
    latency_ms: number;
    similarity_to_known: number;
  };
  detection_track: "behavioral_payment" | "ai_assisted_app" | "bank_controlled_media";
  evidence_capabilities: string[];
  feature_schema_version: string;
  graph_assessment?: {
    assessment_id: string;
    beneficiary_ref: string;
    decision_at: string;
    scopes: string[];
    snapshot_id: string;
    snapshot_sha256: string;
    features: Record<string, number>;
    evidence_event_ids: string[];
  } | null;
}

export interface CoverageCell {
  id: string;
  name: string;
  slug: string;
  techniques_total: number;
  techniques_tested: number;
  cycles: number;
  coverage: Record<string, number>;
  status: "covered" | "partial" | "blind_spot" | "uncovered";
}

export interface Coverage {
  summary: {
    tactics_tested: number;
    tactics_total: number;
    techniques_tested: number;
    techniques_total: number;
  };
  cells: CoverageCell[];
}

export interface Gap {
  brief_id: string;
  objective: string;
  target_f3_cells: string[];
  suggested_family: string;
  priority: number;
  rationale: string;
}

export interface ModelCard {
  detector_id: string;
  kind: string;
  promoted: boolean;
  schema_compatible?: boolean;
  legacy_compatible?: boolean;
  compatibility_policy?: string;
  incompatible_candidate_id?: string;
  incompatible_candidate_metrics?: ModelCard["metrics"];
  feature_names?: string[];
  artifact_path?: string;
  artifact_sha256?: string;
  runtime_detector_id?: string;
  runtime_verified?: boolean;
  latest_evaluation?: {
    candidate_id: string;
    dataset_id: string;
    evaluation_protocol: string;
    passed: boolean;
    installed: boolean;
    checks: Record<string, boolean>;
    notes: string[];
    metrics: Partial<Record<"recall" | "roc_auc" | "pr_auc" | "brier" | "p95_latency_ms", number>>;
  } | null;
  installed?: boolean;
  promotion_checks?: Record<string, boolean>;
  promotion_notes?: string[];
  evaluation_protocol?: string;
  dataset?: {
    dataset_id: string;
    rows: number;
    split_protocol: string;
    held_out_families: string[];
    included_tracks: string[];
  };
  metrics?: Partial<Record<"precision" | "recall" | "f1" | "roc_auc" | "pr_auc" | "brier" | "p50_latency_ms" | "p95_latency_ms", number>>;
}

export type OperationalStatus = "healthy" | "degraded" | "unavailable" | "unknown" | "not_configured";

export interface PendingVariant {
  proposal_id: string;
  proposal_sha256: string;
  source_cycle_id: string;
  parent_family_slug: string;
  parent_family_version: string;
  candidate_family_slug: string;
  residual_kinds: string[];
  gate_coverage: string;
  blue_verdict: string;
  changes: Array<{ field: string; previous_value: string | number | boolean; proposed_value: string | number | boolean; rule_id: string }>;
  created_at: string;
  status: "pending" | "approved";
}

export interface Operations {
  observed_at: string;
  overall_status: OperationalStatus;
  control_plane: {
    api: { status: OperationalStatus; detail: string };
    orchestrator: { status: OperationalStatus; detail: string; queue_depth?: number | null };
    registry: { status: OperationalStatus; detail: string; backend: string };
  };
  worker_plane: {
    status: OperationalStatus;
    configured: number;
    observed: number | null;
    detail: string;
    workers: Array<{ worker_id: string; last_seen_at: string; age_seconds: number; status: string }>;
  };
  run: { status: OperationalStatus; detail: string; state?: Record<string, unknown> };
  counts: {
    families: number;
    strategies: number;
    cycles: number;
    accepted_cycles: number;
    pending_variants: number;
    training_corpora: number;
  };
  storage: {
    status: OperationalStatus;
    data_root: string;
    stores: Record<string, { files: number; bytes: number }>;
    object_backend: string;
    object_versioning: boolean;
    object_detail: string;
  };
  model: ModelCard;
  backups: {
    status: OperationalStatus;
    detail: string;
    sqlite_bootstrap_present: boolean;
    last_successful_at: string | null;
    restore_verified_at: string | null;
  };
  pending_variants: PendingVariant[];
  training: {
    threshold: number;
    accepted_cycles: number;
    corpora: Array<{ claim_id: string; cycle_count: number }>;
  };
}

export interface FraudFamily {
  slug: string;
  version: string;
  title: string;
  track: string;
  rail: string;
  channel: string;
  definition_sha256: string;
  research_refs: string[];
}

export interface StrategyRepositoryEntry {
  strategy_id: string;
  attack_family: string;
  fingerprint: string;
  family_version: string;
  family_definition_sha256: string | null;
  scenario_template: string;
  run_count: number;
  latest_cycle_id: string | null;
  recorded_at: string | null;
  strategy: CycleDetail["strategy"] & {
    strategy_id: string;
    rail: string;
    channel: string;
    prerequisites: string[];
    expected_signals: string[];
    novelty_rationale: string;
    provenance: { provider: string; model: string; created_at: string };
  };
  blue_report: CycleDetail["blue_report"] | null;
  gate_result: CycleDetail["gate_result"] | null;
  detection_track: CycleDetail["detection_track"] | null;
  evidence_capabilities: string[];
  markdown: string;
}

export interface StrategyRepository {
  total: number;
  summary: { investigated: number; unhandled: number; families: number };
  limit: number;
  offset: number;
  items: StrategyRepositoryEntry[];
}
