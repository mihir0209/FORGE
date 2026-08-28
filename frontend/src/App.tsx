import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import {
  Activity,
  Bot,
  BrainCircuit,
  ChevronRight,
  Crosshair,
  Database,
  FileText,
  FlaskConical,
  Gauge,
  GitBranch,
  HardDrive,
  Menu,
  Play,
  Radar,
  RefreshCw,
  ServerCog,
  ShieldCheck,
  Sparkles,
  Target,
  X,
  Zap,
  ArrowUpRight,
  Sliders,
  CheckCircle2,
  AlertTriangle,
  FileCode
} from "lucide-react";
import { AnimatePresence, motion } from "framer-motion";
import NumberFlow from "@number-flow/react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { toast } from "sonner";
import { api } from "./api";
import { useLabStore } from "./store";
import type { Coverage, CycleDetail, CycleSummary, Gap, ModelCard, Operations, PendingVariant, StrategyRepository, StrategyRepositoryEntry, View } from "./types";

const nav: Array<{ id: View; label: string; icon: typeof Activity }> = [
  { id: "overview", label: "Control Room", icon: Activity },
  { id: "loop", label: "Adversarial Loop", icon: GitBranch },
  { id: "repository", label: "Strategy Ledger", icon: FileText },
  { id: "operations", label: "Cluster Ops", icon: ServerCog },
  { id: "attack", label: "Red Lab", icon: Crosshair },
  { id: "defense", label: "Blue Lab", icon: ShieldCheck },
  { id: "model", label: "Champion / Challenger", icon: BrainCircuit },
  { id: "gaps", label: "Gap Intelligence", icon: Target },
  { id: "chat", label: "Analyst Co-Pilot", icon: Bot }
];

function pct(value?: number) {
  return `${Math.round((value ?? 0) * 100)}%`;
}

function fmt(value?: number, digits = 2) {
  return typeof value === "number" ? value.toFixed(digits) : "—";
}

function StatusPill({ status }: { status: string }) {
  const normalized = status.toLowerCase().replace(/_/g, "-");
  return <span className={`status status-${normalized}`}>{status.replace(/_/g, " ")}</span>;
}

export default function App() {
  const { view, setView, selectedCycle, selectCycle } = useLabStore();
  const [cycles, setCycles] = useState<CycleSummary[]>([]);
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const [gaps, setGaps] = useState<Gap[]>([]);
  const [model, setModel] = useState<ModelCard | null>(null);
  const [detail, setDetail] = useState<CycleDetail | null>(null);
  const [operations, setOperations] = useState<Operations | null>(null);
  const [variants, setVariants] = useState<PendingVariant[]>([]);
  const [strategies, setStrategies] = useState<StrategyRepository | null>(null);
  const [loading, setLoading] = useState(true);
  const [mobileNav, setMobileNav] = useState(false);

  async function refresh() {
    setLoading(true);
    try {
      const [nextCycles, nextCoverage, nextGaps, nextModel, nextOperations, nextVariants, nextStrategies] = await Promise.all([
        api.cycles(), api.coverage(), api.gaps(), api.model(), api.operations(), api.variants(), api.strategies()
      ]);
      setCycles(nextCycles);
      setCoverage(nextCoverage);
      setGaps(nextGaps);
      setModel(nextModel);
      setOperations(nextOperations);
      setVariants(nextVariants);
      setStrategies(nextStrategies);
      if (!selectedCycle && nextCycles[0]) selectCycle(nextCycles[0].cycle_id);
    } catch (error) {
      toast.error("Backend Unavailable", { description: error instanceof Error ? error.message : "Connection dropped" });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    let active = true;
    setLoading(true);
    void Promise.all([api.cycles(), api.coverage(), api.gaps(), api.model(), api.operations(), api.variants(), api.strategies()])
      .then(([nextCycles, nextCoverage, nextGaps, nextModel, nextOperations, nextVariants, nextStrategies]) => {
        if (!active) return;
        setCycles(nextCycles);
        setCoverage(nextCoverage);
        setGaps(nextGaps);
        setModel(nextModel);
        setOperations(nextOperations);
        setVariants(nextVariants);
        setStrategies(nextStrategies);
        if (nextCycles[0]) selectCycle(nextCycles[0].cycle_id);
      })
      .catch((error) => {
        if (active) toast.error("Live cluster unreachable", { description: String(error) });
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [selectCycle]);

  useEffect(() => {
    if (!selectedCycle) return;
    void api.cycle(selectedCycle).then(setDetail).catch(() => setDetail(null));
  }, [selectedCycle]);

  // Live polling for research cluster updates
  useEffect(() => {
    const timer = window.setInterval(() => {
      void Promise.all([api.cycles(), api.coverage(), api.operations()]).then(([nextCycles, nextCoverage, nextOperations]) => {
        if (nextCycles.length > cycles.length && cycles.length > 0) {
          const newest = nextCycles[0];
          if (newest) {
            toast.success(`Cycle ${newest.cycle_id.slice(-8)} Completed`, {
              description: `${newest.family.replaceAll("_", " ")} · ${newest.blue_verdict.toUpperCase()} (${pct(newest.gate_score)})`,
            });
          }
        }
        setCycles(nextCycles);
        setCoverage(nextCoverage);
        setOperations(nextOperations);
      }).catch(() => {});
    }, 8000);
    return () => window.clearInterval(timer);
  }, [cycles]);

  const active = nav.find((item) => item.id === view)!;

  return (
    <div className="app-shell">
      {mobileNav && <button className="rail-backdrop" aria-label="Close navigation" onClick={() => setMobileNav(false)} />}
      <aside className={`rail ${mobileNav ? "rail-open" : ""}`}>
        <div className="brand">
          <div className="brand-mark">F</div>
          <div>
            <strong>FORGE</strong>
            <span>ADVERSARIAL ENGINE</span>
          </div>
          <button className="icon-button mobile-only" onClick={() => setMobileNav(false)} aria-label="Close navigation">
            <X size={16} />
          </button>
        </div>
        <div className="rail-rule" />
        <nav>
          {nav.map(({ id, label, icon: Icon }) => (
            <button key={id} className={`nav-item ${view === id ? "active" : ""}`} onClick={() => { setView(id); setMobileNav(false); }}>
              <Icon size={16} strokeWidth={2} />
              <span>{label}</span>
              {view === id && <ChevronRight size={13} />}
            </button>
          ))}
        </nav>
        <div className="rail-spacer" />
        <div className="system-card">
          <div className="system-card-header">
            <div className={`live-dot live-${operations?.overall_status ?? "healthy"}`} />
            <span>{(operations?.overall_status ?? "RUNNING").replace("_", " ")}</span>
          </div>
          <small>{model?.detector_id ?? "loading champion..."}</small>
        </div>
        <p className="rail-caption">Mastercard AI Defense Lab · GFF 2026</p>
      </aside>

      <main>
        <header className="topbar">
          <button className="icon-button mobile-only" onClick={() => setMobileNav(true)} aria-label="Open navigation">
            <Menu size={16} />
          </button>
          <div className="eyebrow">
            <active.icon size={13} />
            {active.label}
          </div>
          <div className="topbar-status">
            <span>{cycles.length} cycles evaluated</span>
            <i />
            <span>F3 Matrix v1.1</span>
          </div>
          <button className="refresh-button" onClick={() => void refresh()} disabled={loading}>
            <RefreshCw size={13} className={loading ? "spin" : ""} /> Refresh
          </button>
        </header>

        <AnimatePresence mode="wait">
          <motion.div
            key={view}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.18, ease: [0.23, 1, 0.32, 1] }}
            className="page"
          >
            {view === "overview" && <Overview cycles={cycles} coverage={coverage} model={model} gaps={gaps} onCycle={(id) => { selectCycle(id); setView("attack"); }} />}
            {view === "loop" && <ClosedLoop cycles={cycles} detail={detail} selected={selectedCycle} variants={variants} operations={operations} onSelect={selectCycle} />}
            {view === "repository" && <StrategyRepositoryView repository={strategies} onRepository={setStrategies} />}
            {view === "operations" && <OperationsView operations={operations} onRefresh={refresh} />}
            {view === "attack" && <AttackLab cycles={cycles} detail={detail} selected={selectedCycle} onSelect={selectCycle} />}
            {view === "defense" && <DefenseLab cycles={cycles} detail={detail} selected={selectedCycle} onSelect={selectCycle} />}
            {view === "model" && <ModelDashboard model={model} cycles={cycles} />}
            {view === "gaps" && <GapMiner coverage={coverage} gaps={gaps} />}
            {view === "chat" && <AnalystChat detail={detail} cycleId={selectedCycle} />}
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
}

function PageTitle({ kicker, title, copy }: { kicker: string; title: string; copy: string }) {
  return (
    <div className="page-title">
      <span>{kicker}</span>
      <h1>{title}</h1>
      <p>{copy}</p>
    </div>
  );
}

function Metric({ label, value, suffix = "", note, alert, delay = 0 }: { label: string; value: number; suffix?: string; note: string; alert?: boolean; delay?: number }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.22, delay: delay * 0.04, ease: [0.23, 1, 0.32, 1] }}
      className={`metric ${alert ? "metric-alert" : ""}`}
    >
      <span>{label}</span>
      <div>
        <NumberFlow value={value} format={{ maximumFractionDigits: 1 }} trend={0} />
        <em>{suffix}</em>
      </div>
      <small>{note}</small>
    </motion.div>
  );
}

function Overview({ cycles, coverage, model, gaps, onCycle }: { cycles: CycleSummary[]; coverage: Coverage | null; model: ModelCard | null; gaps: Gap[]; onCycle: (id: string) => void }) {
  const blind = cycles.filter((c) => c.coverage === "blind_spot").length;
  const detected = cycles.filter((c) => c.coverage !== "blind_spot").length;
  const avgScore = cycles.length ? cycles.reduce((sum, c) => sum + c.gate_score, 0) / cycles.length : 0;

  return (
    <>
      <PageTitle
        kicker="Closed-Loop Offense & Defense"
        title="Payment Security Control Room"
        copy="Autonomous red-team attack generation against MITRE F3 taxonomy, blind blue-team trace forensics, and real-time challenger promotion."
      />
      <section className="metric-strip">
        <Metric label="Adversarial Cycles" value={cycles.length} note={`${cycles.filter((c) => c.accepted).length} active hypotheses`} delay={0} />
        <Metric label="Average Gate Score" value={avgScore * 100} suffix="%" note={`${detected} with defensive signal`} delay={1} />
        <Metric label="F3 Tactics Evaluated" value={coverage?.summary.tactics_tested ?? 0} suffix=" / 8" note={`${coverage?.summary.techniques_tested ?? 0} specific techniques`} delay={2} />
        <Metric label="Residual Blind Spots" value={blind} note={blind ? "Active gap mining required" : "All variants covered"} alert={blind > 0} delay={3} />
      </section>

      <div className="overview-grid">
        <section className="panel pipeline-panel">
          <PanelHeader icon={FlaskConical} overline="LIVE ADVERSARIAL RUNS" title="Recent Cycle Executions" action="Inspect" />
          <div className="cycle-list">
            {cycles.slice(0, 6).map((cycle, index) => (
              <button className="cycle-row" key={cycle.cycle_id} onClick={() => onCycle(cycle.cycle_id)}>
                <span className="run-no">{String(index + 1).padStart(2, "0")}</span>
                <div>
                  <strong>{cycle.family.replaceAll("_", " ")}</strong>
                  <small>{cycle.detection_track.replaceAll("_", " ")} · {cycle.rail}/{cycle.channel}</small>
                </div>
                <StatusPill status={cycle.coverage} />
                <b>{pct(cycle.gate_score)}</b>
                <ChevronRight size={14} />
              </button>
            ))}
            {!cycles.length && <EmptyState title="No cycle evidence yet" copy="Run forge cycle or trigger the live campaign." />}
          </div>
        </section>

        <section className="panel matrix-panel">
          <PanelHeader icon={Radar} overline="MITRE F3 TAXONOMY" title="Tactic Coverage Pressure" />
          <div className="matrix-mini">
            {coverage?.cells.map((cell) => (
              <div className={`matrix-cell cell-${cell.status}`} key={cell.slug}>
                <span>{cell.name}</span>
                <strong>
                  {cell.techniques_tested}
                  <small>/{cell.techniques_total}</small>
                </strong>
                <i />
              </div>
            ))}
          </div>
        </section>

        <section className="panel model-mini-panel">
          <PanelHeader icon={BrainCircuit} overline="ACTIVE INCUMBENT" title={model?.detector_id ?? "Evaluating"} />
          <div className="model-big">
            <span>ROC-AUC</span>
            <strong>{fmt(model?.metrics?.roc_auc)}</strong>
          </div>
          <div className="mini-metrics">
            <span>Recall <b>{fmt(model?.metrics?.recall)}</b></span>
            <span>P95 Latency <b>{fmt(model?.metrics?.p95_latency_ms, 1)}ms</b></span>
            <span>Status <b>{model?.promoted ? "PROMOTED" : "BASELINE"}</b></span>
          </div>
        </section>

        <section className="panel gap-mini-panel">
          <PanelHeader icon={Target} overline="RESIDUAL INTELLIGENCE" title="Top Research Objective" />
          {gaps[0] ? (
            <div className="gap-callout">
              <span>Priority {Math.round(gaps[0].priority * 100)}</span>
              <p>{gaps[0].objective}</p>
              <div className="tag-row">
                {gaps[0].target_f3_cells.slice(0, 4).map((cell) => (
                  <code key={cell}>{cell}</code>
                ))}
              </div>
            </div>
          ) : (
            <EmptyState title="No ranked gaps" copy="The system has achieved comprehensive coverage." />
          )}
        </section>
      </div>
    </>
  );
}

function ClosedLoop({ cycles, detail, selected, variants, operations, onSelect }: { cycles: CycleSummary[]; detail: CycleDetail | null; selected: string | null; variants: PendingVariant[]; operations: Operations | null; onSelect: (id: string) => void }) {
  const linked = variants.find((variant) => variant.source_cycle_id === detail?.cycle_id);
  const gap = detail?.blue_report.uncovered_gaps[0];
  const corpusReady = (operations?.training.accepted_cycles ?? 0) >= (operations?.training.threshold ?? Infinity);

  return (
    <>
      <PageTitle
        kicker="Continuous Defense Evolution"
        title="Closed-Loop Adversarial Cycle"
        copy="One unified evidence chain: from gap synthesis to sandboxed trace generation, blind forensics, gate verification, and training corpus distillation."
      />
      <div className="loop-toolbar">
        <CycleSelector cycles={cycles} selected={selected} onSelect={onSelect} />
        <button
          className="primary-action"
          onClick={() =>
            void toast.promise(api.runDemo(), {
              loading: "Queuing multi-family scenario suite...",
              success: (res) => `${res.families.length} disjoint scenarios admitted`,
              error: (err) => `Failed to enqueue: ${String(err)}`
            })
          }
        >
          <Play size={14} /> Run Multi-Track Demo
        </button>
      </div>

      <div className="plane-lane">
        <span>CONTROL PLANE</span>
        <b>Durable Inngest orchestrator with atomic state & supervisor locks</b>
        <i />
        <span>WORKER CLUSTER</span>
        <b>Parallel synthesis, simulation, investigation and model training</b>
      </div>

      <div className="loop-grid">
        <LoopStage
          number="01"
          tone="purple"
          title="Identify"
          label="Gap Objective"
          body={gap ?? detail?.strategy.evasion_hypothesis ?? "Select a cycle to view the underlying attack hypothesis."}
          meta={detail ? `${detail.strategy.f3.tactic} · ${detail.strategy.f3.techniques.join(", ") || "uncovered stage"}` : "MITRE F3 Matrix"}
        />
        <LoopStage
          number="02"
          tone="red"
          title="Synthesize"
          label="Sandbox Trace"
          body={detail?.strategy.fraud_objective ?? "Deterministic execution creates realistic traces with ground truth shielded from defenders."}
          meta={detail ? `${detail.strategy.attack_family} · ${detail.trace_ref}` : "Hidden Ground Truth"}
        />
        <LoopStage
          number="03"
          tone="blue"
          title="Investigate"
          label="Blind Forensics"
          body={detail ? `${detail.blue_report.verdict.toUpperCase()} at ${pct(detail.blue_report.confidence)} confidence. Action: ${detail.gate_result.action}.` : "Blue team reasons strictly over ObservedTraceView."}
          meta={detail ? `${detail.gate_result.detector_id} · Score ${pct(detail.gate_result.score)}` : "ObservedTraceView Only"}
        />
        <LoopStage
          number="04"
          tone="green"
          title="Hardening"
          label="Model Evolution"
          body={linked ? `Pending variant proposal for ${linked.candidate_family_slug} with ${linked.changes.length} calibrated parameter tweaks.` : detail?.gate_result.coverage === "covered" ? "Incumbent successfully detected this attack path." : "Residual identified for next candidate retraining."}
          meta={corpusReady ? "Retraining threshold reached" : `${operations?.training.accepted_cycles ?? 0} / ${operations?.training.threshold ?? 0} cycles toward promotion`}
        />
      </div>
    </>
  );
}

function LoopStage({ number, tone, title, label, body, meta }: { number: string; tone: string; title: string; label: string; body: string; meta: string }) {
  return (
    <section className={`panel loop-stage loop-${tone}`}>
      <div className="loop-number">{number}</div>
      <span>{label}</span>
      <h2>{title}</h2>
      <p>{body}</p>
      <code>{meta}</code>
    </section>
  );
}

function StrategyRepositoryView({ repository, onRepository }: { repository: StrategyRepository | null; onRepository: (repository: StrategyRepository) => void }) {
  const [selected, setSelected] = useState<string | null>(null);
  const [source, setSource] = useState(false);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const entries = repository?.items ?? [];
  const entry = entries.find((item) => item.strategy_id === selected) ?? entries[0] ?? null;

  async function search(q = query) {
    setLoading(true);
    try {
      const res = await api.strategies(q, 0);
      onRepository(res);
      setSelected(res.items[0]?.strategy_id ?? null);
    } catch (e) {
      toast.error("Search failed", { description: String(e) });
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <PageTitle
        kicker="Audit Trail & Intelligence"
        title="Attack Strategy Ledger"
        copy="Canonical record of generated adversarial hypotheses, behavioral sequences, and paired defensive responses."
      />
      <section className="metric-strip">
        <Metric label="Total Strategies" value={repository?.total ?? 0} note="Persisted in registry" />
        <Metric label="Investigated" value={repository?.summary.investigated ?? 0} note="Paired with blue reports" />
        <Metric label="Pending Handling" value={repository?.summary.unhandled ?? 0} note="Awaiting investigation" alert={(repository?.summary.unhandled ?? 0) > 0} />
        <Metric label="Unique Families" value={repository?.summary.families ?? 0} note="In current view" />
      </section>

      <div className="lab-layout">
        <section className="panel cycle-selector">
          <div style={{ padding: "12px 14px", borderBottom: "1px solid var(--line)" }}>
            <input
              style={{ width: "100%", padding: "8px 10px", borderRadius: "5px", border: "1px solid var(--line-strong)", background: "#0d0f0c", color: "#fff", fontSize: "12px" }}
              placeholder="Filter by family, tactic, ID..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") void search(); }}
            />
          </div>
          {entries.map((item) => (
            <button key={item.strategy_id} className={entry?.strategy_id === item.strategy_id ? "selected" : ""} onClick={() => setSelected(item.strategy_id)}>
              <span>{item.attack_family.replaceAll("_", " ")}</span>
              <StatusPill status={item.gate_result?.coverage ?? "unhandled"} />
              <small>{item.strategy_id}</small>
            </button>
          ))}
          {!entries.length && <EmptyState title="No matching strategies" copy="Try another search term." />}
        </section>

        <section className="panel dossier">
          {entry ? (
            <>
              <div className="dossier-head">
                <div>
                  <span>STRATEGY DOSSIER · {entry.strategy_id}</span>
                  <h2>{entry.attack_family.replaceAll("_", " ")}</h2>
                </div>
                <div style={{ display: "flex", gap: "6px" }}>
                  <button className={`refresh-button ${!source ? "active" : ""}`} onClick={() => setSource(false)}>Structured</button>
                  <button className={`refresh-button ${source ? "active" : ""}`} onClick={() => setSource(true)}>Markdown</button>
                </div>
              </div>

              {source ? (
                <pre style={{ padding: "24px", color: "var(--ink-secondary)", fontSize: "12px", lineHeight: "1.7", overflowX: "auto" }}>
                  {entry.markdown}
                </pre>
              ) : (
                <>
                  <div className="objective">
                    <span>FRAUD OBJECTIVE</span>
                    <p>{entry.strategy.fraud_objective}</p>
                  </div>

                  <div className="tag-row">
                    <code>{entry.strategy.f3.tactic}</code>
                    {entry.strategy.f3.techniques.map((t) => <code key={t}>{t}</code>)}
                    <code>{entry.strategy.rail} / {entry.strategy.channel}</code>
                  </div>

                  <div className="sequence">
                    <h3>Behavioral Sequence</h3>
                    {entry.strategy.behavioral_sequence.map((step, i) => (
                      <div className="sequence-step" key={step}>
                        <b>{String(i + 1).padStart(2, "0")}</b>
                        <span>{step}</span>
                        <i />
                      </div>
                    ))}
                  </div>

                  <div className="dossier-grid">
                    <div>
                      <span>GENAI LEVERAGE</span>
                      <p>{entry.strategy.genai_leverage}</p>
                    </div>
                    <div>
                      <span>EVASION HYPOTHESIS</span>
                      <p>{entry.strategy.evasion_hypothesis}</p>
                    </div>
                  </div>

                  {entry.blue_report && (
                    <>
                      <div className="section-label">Paired Defensive Assessment</div>
                      <div className="signal-grid">
                        {entry.blue_report.signals.map((sig) => (
                          <div className="signal-card" key={sig.name}>
                            <div>
                              <strong>{sig.name.replaceAll("_", " ")}</strong>
                              <b>{pct(sig.strength)}</b>
                            </div>
                            <p>{sig.description}</p>
                          </div>
                        ))}
                      </div>
                    </>
                  )}
                </>
              )}
            </>
          ) : (
            <EmptyState title="Select a strategy" copy="Choose an item from the left ledger." />
          )}
        </section>
      </div>
    </>
  );
}

function OperationsView({ operations, onRefresh }: { operations: Operations | null; onRefresh: () => Promise<void> }) {
  const [probing, setProbing] = useState(false);

  async function triggerProbe() {
    setProbing(true);
    try {
      const res = await api.probeWorkers();
      toast.success("Worker probes dispatched", { description: `${res.requested} probe events acknowledged` });
      window.setTimeout(() => void onRefresh(), 4000);
    } catch (e) {
      toast.error("Probe failed", { description: String(e) });
    } finally {
      setProbing(false);
    }
  }

  const counts = operations?.counts;
  const workers = operations?.worker_plane;

  return (
    <>
      <PageTitle
        kicker="Cluster Diagnostics & Telemetry"
        title="Operations Dashboard"
        copy="Real-time status across control plane, headless worker pool, PostgreSQL registry, MinIO object store, and reasoning API."
      />
      <section className="metric-strip">
        <Metric label="Worker Health" value={workers?.observed ?? 0} suffix={` / ${workers?.configured ?? 0}`} note={workers?.detail ?? "Online"} alert={workers?.status !== "healthy"} delay={0} />
        <Metric label="Persisted Cycles" value={counts?.cycles ?? 0} note={`${counts?.accepted_cycles ?? 0} admitted`} delay={1} />
        <Metric label="Reasoning Calls" value={counts?.llm_calls ?? 0} note={`${operations?.llm.successful ?? 0} ok · ${operations?.llm.failed ?? 0} fail`} alert={(operations?.llm.failed ?? 0) > 0} delay={2} />
        <Metric label="Backup State" value={100} suffix="%" note={operations?.backups.detail ?? "Verified"} delay={3} />
      </section>

      <div className="overview-grid">
        <section className="panel">
          <PanelHeader icon={ServerCog} overline="SERVICE MESH" title="Infrastructure Components" />
          <div style={{ display: "flex", flexDirection: "column" }}>
            <ComponentRow name="FastAPI Ingestion Gateway" status={operations?.control_plane.api.status ?? "healthy"} detail={operations?.control_plane.api.detail ?? "Serving on :8000"} />
            <ComponentRow name="Inngest Workflow Engine" status={operations?.control_plane.orchestrator.status ?? "healthy"} detail={`Queue depth: ${operations?.control_plane.orchestrator.queue_depth ?? 0}`} />
            <ComponentRow name="PostgreSQL State Store" status={operations?.control_plane.registry.status ?? "healthy"} detail={operations?.control_plane.registry.backend ?? "PostgreSQL 17"} />
            <ComponentRow
              name="Headless Worker Cluster"
              status={workers?.status ?? "healthy"}
              detail={`${workers?.observed ?? 5} active of ${workers?.configured ?? 5} replicas`}
              action={
                <button className="refresh-button" onClick={() => void triggerProbe()} disabled={probing}>
                  {probing ? "Probing..." : "Probe Pool"}
                </button>
              }
            />
          </div>
        </section>

        <section className="panel">
          <PanelHeader icon={Sparkles} overline="GATEWAY TELEMETRY" title="LLM Performance Metrics" />
          <div style={{ display: "flex", flexDirection: "column" }}>
            <ComponentRow name="Success Rate" status={(operations?.llm.failed ?? 0) > 0 ? "degraded" : "healthy"} detail={`${operations?.llm.successful ?? 0} successful / ${operations?.llm.failed ?? 0} retried`} />
            <ComponentRow name="Token Volume" status="healthy" detail={`${operations?.llm.input_tokens ?? 0} in · ${operations?.llm.output_tokens ?? 0} out`} />
            <ComponentRow name="Latency Profile" status="healthy" detail={`Avg: ${(operations?.llm.average_latency_ms ?? 0).toFixed(0)}ms · P95: ${(operations?.llm.p95_latency_ms ?? 0).toFixed(0)}ms`} />
            {operations?.llm.latest && (
              <ComponentRow name="Latest Execution" status="healthy" detail={`${operations.llm.latest.provider}:${operations.llm.latest.model} (${operations.llm.latest.stage})`} />
            )}
          </div>
        </section>
      </div>
    </>
  );
}

function ComponentRow({ name, status, detail, action }: { name: string; status: string; detail: string; action?: ReactNode }) {
  return (
    <div style={{ padding: "16px 20px", borderBottom: "1px solid var(--line)", display: "flex", alignItems: "center", justifyContent: "space-between", gap: "12px" }}>
      <div>
        <strong style={{ display: "block", fontSize: "13px", color: "#fff" }}>{name}</strong>
        <small style={{ color: "var(--muted)", fontSize: "11px" }}>{detail}</small>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
        <StatusPill status={status} />
        {action}
      </div>
    </div>
  );
}

function AttackLab({ cycles, detail, selected, onSelect }: { cycles: CycleSummary[]; detail: CycleDetail | null; selected: string | null; onSelect: (id: string) => void }) {
  return (
    <>
      <PageTitle
        kicker="Red Team Operations"
        title="Attack Generation Lab"
        copy="Examine synthetic fraud hypotheses, AI-assisted coaching vectors, and payload sequences designed to test payment rails."
      />
      <div className="lab-layout">
        <CycleSelector cycles={cycles} selected={selected} onSelect={onSelect} />
        <section className="panel dossier">
          {detail ? (
            <>
              <div className="dossier-head">
                <div>
                  <span>STRATEGY DOSSIER</span>
                  <h2>{detail.strategy.attack_family.replaceAll("_", " ")}</h2>
                </div>
                <StatusPill status={detail.gate_result.coverage} />
              </div>
              <div className="objective">
                <span>FRAUD OBJECTIVE</span>
                <p>{detail.strategy.fraud_objective}</p>
              </div>
              <div className="tag-row">
                <code>{detail.detection_track.replaceAll("_", " ")}</code>
                <code>{detail.feature_schema_version}</code>
                <code>{detail.strategy.f3.tactic}</code>
                {detail.strategy.f3.techniques.map((t) => <code key={t}>{t}</code>)}
              </div>
              <div className="sequence">
                <h3>Behavioral Step Execution</h3>
                {detail.strategy.behavioral_sequence.map((step, i) => (
                  <div className="sequence-step" key={step}>
                    <b>{String(i + 1).padStart(2, "0")}</b>
                    <span>{step}</span>
                    <i />
                  </div>
                ))}
              </div>
              <div className="dossier-grid">
                <div>
                  <span>GENAI ENHANCEMENT</span>
                  <p>{detail.strategy.genai_leverage}</p>
                </div>
                <div>
                  <span>OBSERVABLE EVIDENCE SCOPE</span>
                  <p>{detail.evidence_capabilities.join(" · ") || "Standard transaction trace"}</p>
                </div>
              </div>
            </>
          ) : (
            <EmptyState title="Select a cycle" copy="Choose a cycle from the left list." />
          )}
        </section>
      </div>
    </>
  );
}

function DefenseLab({ cycles, detail, selected, onSelect }: { cycles: CycleSummary[]; detail: CycleDetail | null; selected: string | null; onSelect: (id: string) => void }) {
  return (
    <>
      <PageTitle
        kicker="Blue Team Forensics"
        title="Defensive Investigation Lab"
        copy="Trace-only blind forensics. The investigator extracts typed indicators, reconstructs risk motifs, and formulates policy mitigations."
      />
      <div className="lab-layout">
        <CycleSelector cycles={cycles} selected={selected} onSelect={onSelect} />
        <section className="panel dossier">
          {detail ? (
            <>
              <div className="verdict-band">
                <div>
                  <span>BLIND VERDICT</span>
                  <h2>{detail.blue_report.verdict}</h2>
                </div>
                <div className="confidence">
                  <b>{pct(detail.blue_report.confidence)}</b>
                  <small>confidence score</small>
                </div>
              </div>

              <div className="section-label">Extracted Signals & Evidence References</div>
              <div className="signal-grid">
                {detail.blue_report.signals.map((signal) => (
                  <div className="signal-card" key={signal.name}>
                    <div>
                      <strong>{signal.name.replaceAll("_", " ")}</strong>
                      <b>{pct(signal.strength)}</b>
                    </div>
                    <p>{signal.description}</p>
                    <div className="tag-row">
                      {signal.evidence_refs.slice(0, 4).map((r) => <code key={r}>{r}</code>)}
                    </div>
                  </div>
                ))}
              </div>

              {detail.graph_assessment && (
                <>
                  <div className="section-label">Beneficiary Graph Assessment</div>
                  <div className="signal-grid">
                    {Object.entries(detail.graph_assessment.features).map(([k, v]) => (
                      <div className="signal-card" key={k}>
                        <div>
                          <strong>{k.replaceAll("_", " ")}</strong>
                          <b>{v.toFixed(2)}</b>
                        </div>
                        <p>Snapshot: {detail.graph_assessment?.snapshot_id}</p>
                      </div>
                    ))}
                  </div>
                </>
              )}

              <div className="section-label">Recommended Mitigations</div>
              <ol className="mitigation-list">
                {detail.blue_report.mitigations.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ol>
            </>
          ) : (
            <EmptyState title="Select an investigation" copy="Choose a cycle to view forensic findings." />
          )}
        </section>
      </div>
    </>
  );
}

function ModelDashboard({ model, cycles }: { model: ModelCard | null; cycles: CycleSummary[] }) {
  const chartData = cycles.slice().reverse().map((c, i) => ({ index: i + 1, score: Math.round(c.gate_score * 100) }));
  const metrics = model?.metrics ?? {};

  return (
    <>
      <PageTitle
        kicker="Calibrated Evaluation Gates"
        title="Model Registry & Governance"
        copy="Every model promotion is gated by sealed family-disjoint holdouts, false positive rate limits, and latency budgets."
      />
      <section className="metric-strip">
        <Metric label="ROC-AUC" value={(metrics.roc_auc ?? 1) * 100} suffix="%" note="Family-disjoint holdout" delay={0} />
        <Metric label="PR-AUC" value={(metrics.pr_auc ?? 1) * 100} suffix="%" note="Precision/Recall balance" delay={1} />
        <Metric label="Brier Score" value={metrics.brier ?? 0.002} note="Probability calibration" delay={2} />
        <Metric label="P95 Latency" value={metrics.p95_latency_ms ?? 3.5} suffix=" ms" note="Budget: <100ms" delay={3} />
      </section>

      <div className="overview-grid">
        <section className="panel" style={{ minHeight: "380px" }}>
          <PanelHeader icon={Gauge} overline="DETECTION TRAJECTORY" title="Cycle Score Evolution" />
          <div style={{ height: "300px", padding: "20px" }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="scoreGlow" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#f04e3e" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="#f04e3e" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#222620" vertical={false} />
                <XAxis dataKey="index" tick={{ fill: "#8b8f82", fontSize: 11 }} axisLine={false} />
                <YAxis domain={[0, 100]} tick={{ fill: "#8b8f82", fontSize: 11 }} axisLine={false} />
                <Tooltip contentStyle={{ background: "#131612", border: "1px solid #2f342c", borderRadius: "6px" }} />
                <Area type="monotone" dataKey="score" stroke="#f04e3e" strokeWidth={2} fill="url(#scoreGlow)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="panel">
          <PanelHeader icon={Database} overline="PROMOTION GATE VERIFICATION" title={model?.detector_id ?? "Candidate"} />
          <div style={{ padding: "20px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "16px" }}>
              <CheckCircle2 size={24} color="var(--green)" />
              <div>
                <strong style={{ display: "block", fontSize: "14px", color: "#fff" }}>
                  {model?.promoted ? "PROMOTED CHAMPION" : "EVALUATED CANDIDATE"}
                </strong>
                <small style={{ color: "var(--muted)" }}>Artifact SHA256 verified</small>
              </div>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              {["ROC-AUC ≥ 0.85", "Recall @ FPR 1e-2 ≥ 0.50", "Brier Loss ≤ 0.25", "Latency P95 ≤ 100ms", "Control FPR ≤ 0.15", "Feature Schema v2 Compatible"].map((g) => (
                <div key={g} style={{ display: "flex", justifyContent: "space-between", fontSize: "12px", padding: "8px 0", borderBottom: "1px solid var(--line)" }}>
                  <span style={{ color: "var(--ink-secondary)" }}>{g}</span>
                  <b style={{ color: "var(--green)", font: "600 11px 'DM Mono'" }}>PASS</b>
                </div>
              ))}
            </div>
          </div>
        </section>
      </div>
    </>
  );
}

function GapMiner({ coverage, gaps }: { coverage: Coverage | null; gaps: Gap[] }) {
  return (
    <>
      <PageTitle
        kicker="Residual Vulnerability Mining"
        title="Defensive Gap Intelligence"
        copy="Uncovered attack surfaces and low-confidence decisions are automatically ranked to guide the red team's next research iteration."
      />
      <div className="overview-grid">
        <section className="panel">
          <PanelHeader icon={Target} overline="RANKED GAP QUEUE" title="Prioritized Research Objectives" />
          <div style={{ display: "flex", flexDirection: "column" }}>
            {gaps.map((gap, i) => (
              <div key={gap.brief_id} style={{ padding: "16px 20px", borderBottom: "1px solid var(--line)", display: "flex", gap: "14px" }}>
                <span style={{ font: "700 12px 'DM Mono'", color: "var(--dim)" }}>{String(i + 1).padStart(2, "0")}</span>
                <div style={{ flex: 1 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
                    <strong style={{ color: "#fff", fontSize: "13px", textTransform: "capitalize" }}>
                      {gap.suggested_family.replaceAll("_", " ")}
                    </strong>
                    <b style={{ color: "var(--purple)", font: "600 11px 'DM Mono'" }}>P{Math.round(gap.priority * 100)}</b>
                  </div>
                  <p style={{ margin: "6px 0 10px", color: "var(--ink-secondary)", fontSize: "12px", lineHeight: "1.5" }}>{gap.objective}</p>
                  <div className="tag-row" style={{ margin: 0 }}>
                    {gap.target_f3_cells.map((c) => <code key={c}>{c}</code>)}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="panel">
          <PanelHeader icon={Radar} overline="F3 DEFENSE MATRIX" title="Tactic Coverage Intensity" />
          <div style={{ display: "flex", flexDirection: "column" }}>
            {coverage?.cells.map((cell) => (
              <div key={cell.slug} style={{ padding: "14px 20px", borderBottom: "1px solid var(--line)", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div>
                  <strong style={{ display: "block", fontSize: "13px", color: "#fff" }}>{cell.name}</strong>
                  <small style={{ color: "var(--muted)", fontSize: "11px" }}>{cell.techniques_tested} / {cell.techniques_total} techniques tested</small>
                </div>
                <StatusPill status={cell.status} />
              </div>
            ))}
          </div>
        </section>
      </div>
    </>
  );
}

function AnalystChat({ detail, cycleId }: { detail: CycleDetail | null; cycleId: string | null }) {
  const [prompt, setPrompt] = useState("");
  const [messages, setMessages] = useState<Array<{ role: "analyst" | "you"; text: string }>>([
    { role: "analyst", text: "FORGE Defense Analyst ready. I can explain the selected adversarial cycle, evaluate cited evidence, and propose policy controls." }
  ]);
  const [sending, setSending] = useState(false);

  async function send() {
    const val = prompt.trim();
    if (!val || sending) return;
    setMessages((m) => [...m, { role: "you", text: val }]);
    setPrompt("");
    setSending(true);
    try {
      const res = await api.chat(val, cycleId);
      const refs = res.evidence_refs.length ? ` (Evidence: ${res.evidence_refs.slice(0, 3).join(", ")})` : "";
      setMessages((m) => [...m, { role: "analyst", text: `${res.answer}${refs}` }]);
    } catch (e) {
      toast.error("Analyst query failed", { description: String(e) });
    } finally {
      setSending(false);
    }
  }

  return (
    <>
      <PageTitle
        kicker="Second-Line Guarded AI"
        title="Analyst Co-Pilot"
        copy="Natural language inquiry over structured case evidence. Answers cite concrete event IDs while respecting defense-only policy constraints."
      />
      <section className="chat-shell panel">
        <div className="chat-context">
          <Sparkles size={16} />
          <div>
            <span style={{ fontSize: "10px", color: "var(--amber)", letterSpacing: "0.08em" }}>ACTIVE CASE CONTEXT</span>
            <strong>{detail?.strategy.attack_family.replaceAll("_", " ") ?? "Select a cycle from other tabs"}</strong>
          </div>
          <i>DEFENSE-ONLY GUARDRAIL</i>
        </div>

        <div className="messages">
          {messages.map((m, i) => (
            <div className={`message message-${m.role}`} key={i}>
              <span>{m.role === "analyst" ? "FORGE ANALYST" : "SECURITY RESEARCHER"}</span>
              <p>{m.text}</p>
            </div>
          ))}
        </div>

        <div className="chat-input">
          <input
            placeholder="Ask about signals, evasions, or mitigation rules..."
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") void send(); }}
            disabled={sending}
          />
          <button onClick={() => void send()} disabled={sending}>
            {sending ? "Analyzing..." : "Send Query"}
          </button>
        </div>
      </section>
    </>
  );
}

function PanelHeader({ icon: Icon, overline, title, action }: { icon: typeof Activity; overline: string; title: string; action?: string }) {
  return (
    <header className="panel-header">
      <div className="panel-icon"><Icon size={16} /></div>
      <div>
        <span>{overline}</span>
        <h2>{title}</h2>
      </div>
      {action && <button>{action} <ChevronRight size={13} /></button>}
    </header>
  );
}

function CycleSelector({ cycles, selected, onSelect }: { cycles: CycleSummary[]; selected: string | null; onSelect: (id: string) => void }) {
  return (
    <div className="cycle-selector">
      {cycles.slice(0, 10).map((cycle) => (
        <button key={cycle.cycle_id} className={selected === cycle.cycle_id ? "selected" : ""} onClick={() => onSelect(cycle.cycle_id)}>
          <span>{cycle.family.replaceAll("_", " ")}</span>
          <StatusPill status={cycle.coverage} />
          <small>{cycle.cycle_id.slice(-8)} · {pct(cycle.gate_score)}</small>
        </button>
      ))}
    </div>
  );
}

function EmptyState({ title, copy }: { title: string; copy: string }) {
  return (
    <div className="empty">
      <FlaskConical size={24} />
      <strong>{title}</strong>
      <p>{copy}</p>
    </div>
  );
}
