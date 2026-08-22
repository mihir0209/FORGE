export type View = "overview" | "attack" | "defense" | "model" | "gaps" | "chat";

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
}

export interface CycleDetail {
  cycle_id: string;
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
  };
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
  artifact_path?: string;
  metrics?: Partial<Record<"precision" | "recall" | "f1" | "roc_auc" | "pr_auc" | "brier" | "p50_latency_ms" | "p95_latency_ms", number>>;
}
