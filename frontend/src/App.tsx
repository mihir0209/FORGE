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
  X
} from "lucide-react";
import NumberFlow from "@number-flow/react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { toast } from "sonner";
import { api } from "./api";
import { useLabStore } from "./store";
import type { Coverage, CycleDetail, CycleSummary, Gap, ModelCard, Operations, PendingVariant, StrategyRepository, StrategyRepositoryEntry, View } from "./types";

const nav: Array<{ id: View; label: string; icon: typeof Activity }> = [
  { id: "overview", label: "Control room", icon: Activity },
  { id: "loop", label: "Closed loop", icon: GitBranch },
  { id: "repository", label: "Strategy repository", icon: FileText },
  { id: "operations", label: "Operations", icon: ServerCog },
  { id: "attack", label: "Attack lab", icon: Crosshair },
  { id: "defense", label: "Defense lab", icon: ShieldCheck },
  { id: "model", label: "Model registry", icon: BrainCircuit },
  { id: "gaps", label: "Gap miner", icon: Target },
  { id: "chat", label: "Analyst chat", icon: Bot }
];

function pct(value?: number) {
  return `${Math.round((value ?? 0) * 100)}%`;
}

function fmt(value?: number, digits = 2) {
  return typeof value === "number" ? value.toFixed(digits) : "—";
}

function StatusPill({ status }: { status: string }) {
  return <span className={`status status-${status.replace("_", "-")}`}>{status.replace("_", " ")}</span>;
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
      toast.error("Backend unavailable", { description: error instanceof Error ? error.message : "Unknown error" });
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
        if (active) toast.error("Backend unavailable", { description: error instanceof Error ? error.message : "Unknown error" });
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [selectCycle]);

  useEffect(() => {
    if (!selectedCycle) return;
    void api.cycle(selectedCycle).then(setDetail).catch(() => setDetail(null));
  }, [selectedCycle]);

  const active = nav.find((item) => item.id === view)!;

  return (
    <div className="app-shell">
      <aside className={`rail ${mobileNav ? "rail-open" : ""}`}>
        <div className="brand">
          <div className="brand-mark">F</div>
          <div><strong>FORGE</strong><span>ADVERSARIAL LAB</span></div>
          <button className="icon-button mobile-only" onClick={() => setMobileNav(false)} aria-label="Close navigation"><X size={18} /></button>
        </div>
        <div className="rail-rule" />
        <nav>
          {nav.map(({ id, label, icon: Icon }) => (
            <button key={id} className={`nav-item ${view === id ? "active" : ""}`} onClick={() => { setView(id); setMobileNav(false); }}>
              <Icon size={17} strokeWidth={1.8} /><span>{label}</span>
              {view === id && <ChevronRight size={14} />}
            </button>
          ))}
        </nav>
        <div className="rail-spacer" />
        <div className="system-card">
          <div className={`live-dot live-${operations?.overall_status ?? "unknown"}`} /><span>{(operations?.overall_status ?? "unknown").replace("_", " ")}</span>
          <small>{model?.detector_id ?? "rule-baseline-v1"}</small>
        </div>
        <p className="rail-caption">Fraud Offense-defense<br />Research & Generation Engine</p>
      </aside>

      <main>
        <header className="topbar">
          <button className="icon-button mobile-only" onClick={() => setMobileNav(true)} aria-label="Open navigation"><Menu size={18} /></button>
          <div className="eyebrow"><active.icon size={13} /> {active.label}</div>
          <div className="topbar-status"><span>{cycles.length} cycles archived</span><i /> <span>F3 v1.1</span></div>
          <button className="refresh-button" onClick={() => void refresh()} disabled={loading}><RefreshCw size={14} className={loading ? "spin" : ""} /> Refresh</button>
        </header>

        <div className="page">
          {view === "overview" && <Overview cycles={cycles} coverage={coverage} model={model} gaps={gaps} onCycle={(id) => { selectCycle(id); setView("attack"); }} />}
          {view === "loop" && <ClosedLoop cycles={cycles} detail={detail} selected={selectedCycle} variants={variants} operations={operations} onSelect={selectCycle} />}
          {view === "repository" && <StrategyRepositoryView repository={strategies} onRepository={setStrategies} />}
          {view === "operations" && <OperationsView operations={operations} onRefresh={refresh} />}
          {view === "attack" && <AttackLab cycles={cycles} detail={detail} selected={selectedCycle} onSelect={selectCycle} />}
          {view === "defense" && <DefenseLab cycles={cycles} detail={detail} selected={selectedCycle} onSelect={selectCycle} />}
          {view === "model" && <ModelDashboard model={model} cycles={cycles} />}
          {view === "gaps" && <GapMiner coverage={coverage} gaps={gaps} />}
          {view === "chat" && <AnalystChat detail={detail} cycleId={selectedCycle} />}
        </div>
      </main>
    </div>
  );
}

function PageTitle({ kicker, title, copy }: { kicker: string; title: string; copy: string }) {
  return <div className="page-title"><span>{kicker}</span><h1>{title}</h1><p>{copy}</p></div>;
}

function Overview({ cycles, coverage, model, gaps, onCycle }: { cycles: CycleSummary[]; coverage: Coverage | null; model: ModelCard | null; gaps: Gap[]; onCycle: (id: string) => void }) {
  const blind = cycles.filter((c) => c.coverage === "blind_spot").length;
  const detected = cycles.filter((c) => c.coverage !== "blind_spot").length;
  const avgScore = cycles.length ? cycles.reduce((sum, c) => sum + c.gate_score, 0) / cycles.length : 0;
  return <>
    <PageTitle kicker="Featured AI-assisted scam defense" title="Detect the campaign, not just the fake." copy="The latest APP scenario models off-channel impersonation driving a genuine customer session. Historical research cycles remain visible below." />
    <section className="metric-strip">
      <Metric label="Adversarial cycles" value={cycles.length} note={`${cycles.filter((c) => c.accepted).length} admitted`} />
      <Metric label="Mean gate score" value={avgScore * 100} suffix="%" note={`${detected} with signal`} />
      <Metric label="F3 tactics tested" value={coverage?.summary.tactics_tested ?? 0} suffix=" / 8" note={`${coverage?.summary.techniques_tested ?? 0} techniques`} />
      <Metric label="Residual blind spots" value={blind} note={blind ? "requires action" : "no unresolved misses"} alert={blind > 0} />
    </section>
    <div className="overview-grid">
      <section className="panel pipeline-panel">
        <PanelHeader icon={FlaskConical} overline="ACTIVE LOOP" title="Latest adversarial runs" action="Inspect" />
        <div className="cycle-list">
          {cycles.slice(0, 6).map((cycle, index) => <button className="cycle-row" key={cycle.cycle_id} onClick={() => onCycle(cycle.cycle_id)}>
            <span className="run-no">{String(index + 1).padStart(2, "0")}</span>
            <div><strong>{cycle.family.replaceAll("_", " ")}</strong><small>{cycle.detection_track.replaceAll("_", " ")} · {cycle.rail}/{cycle.channel}</small></div>
            <StatusPill status={cycle.coverage} />
            <b>{pct(cycle.gate_score)}</b>
            <ChevronRight size={14} />
          </button>)}
          {!cycles.length && <EmptyState title="No cycle evidence yet" copy="Run forge cycle --seed 42, then refresh." />}
        </div>
      </section>
      <section className="panel matrix-panel">
        <PanelHeader icon={Radar} overline="COVERAGE BACKBONE" title="F3 tactic matrix" />
        <div className="matrix-mini">
          {coverage?.cells.map((cell) => <div className={`matrix-cell cell-${cell.status}`} key={cell.slug}><span>{cell.name}</span><strong>{cell.techniques_tested}<small>/{cell.techniques_total}</small></strong><i /></div>)}
        </div>
      </section>
      <section className="panel model-mini-panel">
        <PanelHeader icon={BrainCircuit} overline="INCUMBENT" title={model?.detector_id ?? "Loading"} />
        <div className="model-big"><span>ROC-AUC</span><strong>{fmt(model?.metrics?.roc_auc)}</strong></div>
        <div className="mini-metrics"><span>Recall <b>{fmt(model?.metrics?.recall)}</b></span><span>P95 <b>{fmt(model?.metrics?.p95_latency_ms, 1)}ms</b></span><span>State <b>{model?.promoted ? "PROMOTED" : model?.legacy_compatible ? "COMPATIBILITY" : "BASELINE"}</b></span></div>
      </section>
      <section className="panel gap-mini-panel">
        <PanelHeader icon={Target} overline="NEXT OBJECTIVE" title="Gap miner" />
        {gaps[0] ? <div className="gap-callout"><span>Priority {Math.round(gaps[0].priority * 100)}</span><p>{gaps[0].objective}</p><div>{gaps[0].target_f3_cells.slice(0, 4).map((cell) => <code key={cell}>{cell}</code>)}</div></div> : <EmptyState title="No ranked gaps" copy="Run a cycle to seed the research queue." />}
      </section>
    </div>
  </>;
}

function ClosedLoop({ cycles, detail, selected, variants, operations, onSelect }: { cycles: CycleSummary[]; detail: CycleDetail | null; selected: string | null; variants: PendingVariant[]; operations: Operations | null; onSelect: (id: string) => void }) {
  const linked = variants.find((variant) => variant.source_cycle_id === detail?.cycle_id);
  const gap = detail?.blue_report.uncovered_gaps[0];
  const corpusReady = (operations?.training.accepted_cycles ?? 0) >= (operations?.training.threshold ?? Infinity);
  return <>
    <PageTitle kicker="Competition proof · identify → generate → defend → learn" title="Closed Loop" copy="One evidence chain from a ranked fraud hypothesis to a blind decision, residual variant and content-addressed hardening corpus." />
    <div className="loop-toolbar">
      <CycleSelector cycles={cycles} selected={selected} onSelect={onSelect} />
      <button className="primary-action" onClick={() => void api.runDemo().then((result) => toast.success("Demo suite queued", { description: `${result.families.length} family-disjoint scenarios` })).catch((error) => toast.error("Demo queue failed", { description: String(error) }))}><Play size={15} /> Run demo suite</button>
    </div>
    <div className="plane-lane"><span>CONTROL PLANE</span><b>Inngest schedules, retries and persists state</b><i /><span>WORKER PLANE</span><b>Compose · simulate · investigate · score · learn</b></div>
    <div className="loop-grid">
      <LoopStage number="01" tone="purple" title="Identify" label="Threat gap" body={gap ?? detail?.strategy.evasion_hypothesis ?? "Select a cycle to inspect its research objective."} meta={detail ? `${detail.strategy.f3.tactic} · ${detail.strategy.f3.techniques.join(", ") || "family evidence"}` : "F3-ranked research"} />
      <LoopStage number="02" tone="red" title="Generate" label="Sandbox trace" body={detail?.strategy.fraud_objective ?? "A reviewed family definition becomes a deterministic, labeled synthetic journey."} meta={detail ? `${detail.strategy.attack_family} · ${detail.trace_ref}` : "Typed tools · hidden truth"} />
      <LoopStage number="03" tone="blue" title="Defend" label="Blind evidence" body={detail ? `${detail.blue_report.verdict} at ${pct(detail.blue_report.confidence)} confidence; detector action ${detail.gate_result.action}.` : "Blue team receives only the observed trace and evidence-linked signals."} meta={detail ? `${detail.gate_result.detector_id} · score ${pct(detail.gate_result.score)}` : "ObservedTraceView only"} />
      <LoopStage number="04" tone="green" title="Learn" label="Residual hardening" body={linked ? `${linked.status} bounded variant ${linked.candidate_family_slug} changes ${linked.changes.length} reviewed parameters.` : detail?.gate_result.coverage === "covered" ? "Defense covered this mechanism; the gap miner advances to weaker families." : "Residual awaits an automatically persisted bounded proposal."} meta={linked ? `${linked.residual_kinds.join(" · ")} · non-executable until approval` : corpusReady ? "Training corpus threshold reached" : `${operations?.training.accepted_cycles ?? 0}/${operations?.training.threshold ?? 0} accepted cycles`} />
    </div>
  </>;
}

function StrategyRepositoryView({ repository, onRepository }: { repository: StrategyRepository | null; onRepository: (repository: StrategyRepository) => void }) {
  const [selected, setSelected] = useState<string | null>(null);
  const [source, setSource] = useState(false);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const entries = repository?.items ?? [];
  const entry = entries.find((item) => item.strategy_id === selected) ?? entries[0] ?? null;
  async function load(nextOffset: number, nextQuery = query) {
    setLoading(true);
    try {
      const next = await api.strategies(nextQuery, nextOffset);
      onRepository(next);
      setSelected(next.items[0]?.strategy_id ?? null);
    } catch (error) {
      toast.error("Strategy repository unavailable", { description: String(error) });
    } finally {
      setLoading(false);
    }
  }
  return <>
    <PageTitle kicker="Red hypotheses · blue handling · immutable evidence" title="Strategy Repository" copy="The current strategy ledger in readable form. Each red-team hypothesis is paired with its latest blind blue-team response and can be inspected as canonical Markdown." />
    <section className="metric-strip repository-metrics">
      <Metric label="Persisted strategies" value={repository?.total ?? 0} note="canonical registry records" />
      <Metric label="Investigated" value={repository?.summary.investigated ?? 0} note="latest blue handling linked" />
      <Metric label="Awaiting handling" value={repository?.summary.unhandled ?? 0} note="red strategy only" alert={(repository?.summary.unhandled ?? 0) > 0} />
      <Metric label="Families represented" value={repository?.summary.families ?? 0} note="within the filtered ledger" />
    </section>
    <div className="repository-layout">
      <section className="panel repository-index">
        <PanelHeader icon={FileText} overline="CURRENT LEDGER" title={`${repository?.total ?? 0} strategy dossiers`} />
        <form className="repository-search" onSubmit={(event) => { event.preventDefault(); void load(0); }}><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search family, tactic, ID..." aria-label="Search strategies" /><button disabled={loading}>Search</button></form>
        {entries.map((item) => <button key={item.strategy_id} className={entry?.strategy_id === item.strategy_id ? "selected" : ""} onClick={() => setSelected(item.strategy_id)}>
          <div><strong>{item.attack_family.replaceAll("_", " ")}</strong><small>{item.strategy_id}</small></div>
          <StatusPill status={item.gate_result?.coverage ?? "unhandled"} />
          <code>{item.fingerprint}</code>
        </button>)}
        {!entries.length && <EmptyState title="No strategies persisted" copy="Run a reviewed red-team cycle to populate this repository." />}
        {(repository?.total ?? 0) > (repository?.limit ?? 25) && <div className="repository-pager"><button disabled={loading || (repository?.offset ?? 0) === 0} onClick={() => void load(Math.max(0, (repository?.offset ?? 0) - (repository?.limit ?? 25)))}>Previous</button><span>{(repository?.offset ?? 0) + 1}-{Math.min((repository?.offset ?? 0) + entries.length, repository?.total ?? 0)} / {repository?.total ?? 0}</span><button disabled={loading || (repository?.offset ?? 0) + (repository?.limit ?? 25) >= (repository?.total ?? 0)} onClick={() => void load((repository?.offset ?? 0) + (repository?.limit ?? 25))}>Next</button></div>}
      </section>
      <section className="panel repository-document">
        {entry ? <>
          <header className="document-toolbar"><div><span>STRATEGY / BLUE RESPONSE</span><strong>{entry.strategy_id}</strong></div><div><button className={!source ? "active" : ""} onClick={() => setSource(false)}>Readable</button><button className={source ? "active" : ""} onClick={() => setSource(true)}>Markdown</button></div></header>
          {source ? <pre className="markdown-source">{entry.markdown}</pre> : <StrategyDocument entry={entry} />}
        </> : <EmptyState title="Select a strategy" copy="The paired red and blue dossier will appear here." />}
      </section>
    </div>
  </>;
}

function StrategyDocument({ entry }: { entry: StrategyRepositoryEntry }) {
  const strategy = entry.strategy;
  const report = entry.blue_report;
  return <article className="strategy-document">
    <div className="document-title"><span>RED TEAM STRATEGY</span><h2>{entry.attack_family.replaceAll("_", " ")}</h2><p>{strategy.fraud_objective}</p></div>
    <div className="document-meta"><code>{strategy.f3.tactic}</code>{strategy.f3.techniques.map((item) => <code key={item}>{item}</code>)}<code>{strategy.rail} / {strategy.channel}</code><code>v{entry.family_version}</code></div>
    <DocumentSection title="Behavioral sequence"><ol>{strategy.behavioral_sequence.map((step) => <li key={step}>{step}</li>)}</ol></DocumentSection>
    <div className="document-columns"><DocumentSection title="GenAI leverage"><p>{strategy.genai_leverage}</p></DocumentSection><DocumentSection title="Evasion hypothesis"><p>{strategy.evasion_hypothesis}</p></DocumentSection></div>
    <div className="blue-divider"><span>BLUE TEAM HANDLING</span><i /></div>
    {report && entry.gate_result ? <>
      <div className="handling-summary"><div><span>Verdict</span><strong>{report.verdict}</strong></div><div><span>Confidence</span><strong>{pct(report.confidence)}</strong></div><div><span>Gate action</span><strong>{entry.gate_result.action}</strong></div><div><span>Coverage</span><StatusPill status={entry.gate_result.coverage} /></div></div>
      <DocumentSection title="Signals and cited evidence"><div className="repository-signals">{report.signals.map((signal) => <div key={signal.name}><strong>{signal.name.replaceAll("_", " ")} <b>{pct(signal.strength)}</b></strong><p>{signal.description}</p><small>{signal.evidence_refs.join(" · ") || "No cited event"}</small></div>)}</div></DocumentSection>
      <div className="document-columns"><DocumentSection title="Recommended mitigations"><ul>{report.mitigations.map((item) => <li key={item}>{item}</li>)}</ul></DocumentSection><DocumentSection title="Uncovered gaps"><ul>{report.uncovered_gaps.length ? report.uncovered_gaps.map((item) => <li key={item}>{item}</li>) : <li>None reported.</li>}</ul></DocumentSection></div>
    </> : <div className="unhandled-note">No blue-team investigation has been persisted for this strategy.</div>}
  </article>;
}

function DocumentSection({ title, children }: { title: string; children: ReactNode }) {
  return <section className="document-section"><h3>{title}</h3>{children}</section>;
}

function LoopStage({ number, tone, title, label, body, meta }: { number: string; tone: string; title: string; label: string; body: string; meta: string }) {
  return <section className={`panel loop-stage loop-${tone}`}><div className="loop-number">{number}</div><span>{label}</span><h2>{title}</h2><p>{body}</p><code>{meta}</code></section>;
}

function OperationsView({ operations, onRefresh }: { operations: Operations | null; onRefresh: () => Promise<void> }) {
  const [acting, setActing] = useState(false);
  async function probe() {
    setActing(true);
    try {
      const result = await api.probeWorkers();
      toast.success("Worker probes queued", { description: `${result.requested} independent probe jobs` });
      window.setTimeout(() => void onRefresh(), 5000);
    } catch (error) {
      toast.error("Worker probe failed", { description: String(error) });
    } finally {
      setActing(false);
    }
  }
  const counts = operations?.counts;
  const workers = operations?.worker_plane;
  return <>
    <PageTitle kicker="Runtime truth · control plane / worker plane" title="Operations" copy="Live evidence for orchestration, worker responsiveness, structured records, artifact stores, model governance and recovery posture." />
    <section className="metric-strip">
      <Metric label="Observed workers" value={workers?.observed ?? 0} suffix={` / ${workers?.configured ?? 0}`} note={workers?.observed === null ? "probe evidence unavailable" : workers?.detail ?? "not observed"} alert={workers?.status !== "healthy"} />
      <Metric label="Structured cycles" value={counts?.cycles ?? 0} note={`${counts?.accepted_cycles ?? 0} accepted`} />
      <Metric label="Pending variants" value={counts?.pending_variants ?? 0} note="review-gated · non-executable" alert={(counts?.pending_variants ?? 0) > 0} />
      <Metric label="Training corpora" value={counts?.training_corpora ?? 0} note={`${operations?.training.accepted_cycles ?? 0}/${operations?.training.threshold ?? 0} current threshold`} />
    </section>
    <div className="operations-grid">
      <section className="panel"><PanelHeader icon={ServerCog} overline="PROCESS SEPARATION" title="Control and worker planes" /><div className="component-list">
        <ComponentRow name="FastAPI control plane" status={operations?.control_plane.api.status ?? "unknown"} detail={operations?.control_plane.api.detail ?? "No observation"} />
        <ComponentRow name="Inngest orchestrator" status={operations?.control_plane.orchestrator.status ?? "unknown"} detail={`queue ${operations?.control_plane.orchestrator.queue_depth ?? "unknown"} · ${operations?.control_plane.orchestrator.detail ?? "No observation"}`} />
        <ComponentRow name="Registry" status={operations?.control_plane.registry.status ?? "unknown"} detail={`${operations?.control_plane.registry.backend ?? "unknown"} · ${operations?.control_plane.registry.detail ?? "No observation"}`} />
        <ComponentRow name="Headless workers" status={workers?.status ?? "unknown"} detail={`${workers?.observed ?? "?"} responsive of ${workers?.configured ?? "?"} configured`} action={<button onClick={() => void probe()} disabled={acting}>{acting ? "Probing" : "Probe"}</button>} />
      </div></section>
      <section className="panel"><PanelHeader icon={Database} overline="STRUCTURED DATA" title="Registry inventory" /><div className="inventory-grid">
        <Inventory label="Families" value={counts?.families ?? 0} /><Inventory label="Strategies" value={counts?.strategies ?? 0} /><Inventory label="Cycles" value={counts?.cycles ?? 0} /><Inventory label="Accepted" value={counts?.accepted_cycles ?? 0} /><Inventory label="Variants" value={counts?.pending_variants ?? 0} /><Inventory label="Corpora" value={counts?.training_corpora ?? 0} />
      </div></section>
      <section className="panel storage-panel"><PanelHeader icon={HardDrive} overline="HOST-BACKED DATA" title="Physical storage" /><div className="storage-list">{Object.entries(operations?.storage.stores ?? {}).map(([name, item]) => <div key={name}><span>{name}</span><b>{item.files} files</b><small>{formatBytes(item.bytes)}</small></div>)}</div><div className="storage-foot"><span>Object backend <b>{operations?.storage.object_backend ?? "unknown"}</b></span><span>Versioning <b>{operations?.storage.object_versioning ? "enabled" : "not configured"}</b></span></div></section>
      <section className="panel"><PanelHeader icon={ShieldCheck} overline="MODEL GOVERNANCE" title={operations?.model.runtime_detector_id ?? operations?.model.detector_id ?? "No model"} /><div className="component-list"><ComponentRow name="Serving state" status={operations?.model.runtime_verified ? "healthy" : "degraded"} detail={operations?.model.runtime_verified ? `Runtime verified ${operations.model.runtime_detector_id}` : `Runtime fallback ${operations?.model.runtime_detector_id ?? "unknown"}`} /><ComponentRow name="Latest challenger" status={operations?.model.latest_evaluation?.installed ? "healthy" : operations?.model.latest_evaluation ? "degraded" : "unknown"} detail={operations?.model.latest_evaluation ? `${operations.model.latest_evaluation.candidate_id} · ${operations.model.latest_evaluation.installed ? "promoted" : "retained"} · ${operations.model.latest_evaluation.evaluation_protocol}` : "No persisted evaluation receipt"} /><ComponentRow name="Backup posture" status={operations?.backups.status ?? "unknown"} detail={operations?.backups.detail ?? "No backup evidence"} /></div></section>
    </div>
    <section className="panel variant-panel"><PanelHeader icon={GitBranch} overline="RESIDUAL QUEUE" title="Bounded family proposals" />{operations?.pending_variants.length ? operations.pending_variants.map((variant) => <div className="variant-row" key={variant.proposal_id}><div><StatusPill status={variant.status} /><strong>{variant.candidate_family_slug.replaceAll("_", " ")}</strong><p>From {variant.parent_family_slug.replaceAll("_", " ")} · source {variant.source_cycle_id}</p></div><div>{variant.changes.map((change) => <code key={change.field}>{change.field}: {String(change.previous_value)} → {String(change.proposed_value)}</code>)}</div><b>NON-EXECUTABLE</b></div>) : <EmptyState title="No residual proposals" copy="Run a partial or blind APP scenario to populate this review queue." />}</section>
  </>;
}

function ComponentRow({ name, status, detail, action }: { name: string; status: string; detail: string; action?: ReactNode }) {
  return <div className="component-row"><span className={`health-dot health-${status}`} /><div><strong>{name}</strong><small>{detail}</small></div><StatusPill status={status} />{action}</div>;
}

function Inventory({ label, value }: { label: string; value: number }) { return <div><span>{label}</span><b>{value}</b></div>; }
function formatBytes(bytes: number) { return bytes < 1024 ? `${bytes} B` : bytes < 1024 ** 2 ? `${(bytes / 1024).toFixed(1)} KiB` : `${(bytes / 1024 ** 2).toFixed(1)} MiB`; }

function Metric({ label, value, suffix = "", note, alert }: { label: string; value: number; suffix?: string; note: string; alert?: boolean }) {
  return <div className={`metric ${alert ? "metric-alert" : ""}`}><span>{label}</span><div><NumberFlow value={value} format={{ maximumFractionDigits: 1 }} /><em>{suffix}</em></div><small>{note}</small></div>;
}

function PanelHeader({ icon: Icon, overline, title, action }: { icon: typeof Activity; overline: string; title: string; action?: string }) {
  return <header className="panel-header"><div className="panel-icon"><Icon size={16} /></div><div><span>{overline}</span><h2>{title}</h2></div>{action && <button>{action} <ChevronRight size={13} /></button>}</header>;
}

function CycleSelector({ cycles, selected, onSelect }: { cycles: CycleSummary[]; selected: string | null; onSelect: (id: string) => void }) {
  return <div className="cycle-selector">{cycles.slice(0, 10).map((cycle) => <button key={cycle.cycle_id} className={selected === cycle.cycle_id ? "selected" : ""} onClick={() => onSelect(cycle.cycle_id)}><span>{cycle.family.replaceAll("_", " ")}</span><StatusPill status={cycle.coverage} /><small>{cycle.cycle_id.slice(-8)}</small></button>)}</div>;
}

function AttackLab({ cycles, detail, selected, onSelect }: { cycles: CycleSummary[]; detail: CycleDetail | null; selected: string | null; onSelect: (id: string) => void }) {
  return <>
    <PageTitle kicker="Red team · campaign evidence" title="Attack Lab" copy="A replayable AI-assisted scam campaign. Off-site preparation remains hidden; the target environment emits only evidence a bank or payment network could observe." />
    <div className="lab-layout"><CycleSelector cycles={cycles} selected={selected} onSelect={onSelect} /><section className="panel dossier">
      {detail ? <><div className="dossier-head"><div><span>STRATEGY DOSSIER</span><h2>{detail.strategy.attack_family.replaceAll("_", " ")}</h2></div><StatusPill status={detail.gate_result.coverage} /></div>
        <div className="objective"><span>FRAUD OBJECTIVE</span><p>{detail.strategy.fraud_objective}</p></div>
        <div className="tag-row"><code>{detail.detection_track.replaceAll("_", " ")}</code><code>{detail.feature_schema_version}</code><code>{detail.strategy.f3.tactic}</code>{detail.strategy.f3.techniques.map((t) => <code key={t}>{t}</code>)}</div>
        <div className="sequence"><h3>Behavioral sequence</h3>{detail.strategy.behavioral_sequence.map((step, i) => <div className="sequence-step" key={step}><b>{String(i + 1).padStart(2, "0")}</b><span>{step}</span><i /></div>)}</div>
        <div className="dossier-grid"><div><span>GENAI LEVERAGE</span><p>{detail.strategy.genai_leverage}</p></div><div><span>EVIDENCE CAPABILITIES</span><p>{detail.evidence_capabilities.join(" · ") || "not recorded"}</p></div></div>
      </> : <EmptyState title="Select a cycle" copy="Choose an archived run from the evidence ledger." />}
    </section></div>
  </>;
}

function DefenseLab({ cycles, detail, selected, onSelect }: { cycles: CycleSummary[]; detail: CycleDetail | null; selected: string | null; onSelect: (id: string) => void }) {
  return <>
    <PageTitle kicker="Blue team · blind investigation" title="Defense Lab" copy="The investigator sees events, not the attacker's playbook. Every conclusion must cite an event ID." />
    <div className="lab-layout"><CycleSelector cycles={cycles} selected={selected} onSelect={onSelect} /><section className="panel dossier defense-dossier">
      {detail ? <><div className="verdict-band"><div><span>BLIND VERDICT</span><h2>{detail.blue_report.verdict}</h2></div><div className="confidence"><b>{pct(detail.blue_report.confidence)}</b><small>confidence</small></div></div>
        <h3 className="section-label">Signals & evidence</h3><div className="signal-grid">{detail.blue_report.signals.map((signal) => <div className="signal-card" key={signal.name}><div><strong>{signal.name.replaceAll("_", " ")}</strong><b>{pct(signal.strength)}</b></div><p>{signal.description}</p><div>{signal.evidence_refs.slice(0, 5).map((ref) => <code key={ref}>{ref}</code>)}</div></div>)}</div>
        {detail.graph_assessment && <><h3 className="section-label">Beneficiary risk graph</h3><div className="signal-grid">{Object.entries(detail.graph_assessment.features).map(([name, value]) => <div className="signal-card" key={name}><div><strong>{name.replaceAll("_", " ")}</strong><b>{value.toFixed(2)}</b></div><p>{detail.graph_assessment?.scopes.join(" + ")} · snapshot {detail.graph_assessment?.snapshot_id}</p><div>{detail.graph_assessment?.evidence_event_ids.slice(0, 5).map((ref) => <code key={ref}>{ref}</code>)}</div></div>)}</div></>}
        <h3 className="section-label">Recommended mitigations</h3><ol className="mitigation-list">{detail.blue_report.mitigations.map((item) => <li key={item}>{item}</li>)}</ol>
      </> : <EmptyState title="Select a cycle" copy="Evidence will appear here." />}
    </section></div>
  </>;
}

function ModelDashboard({ model, cycles }: { model: ModelCard | null; cycles: CycleSummary[] }) {
  const data = cycles.slice().reverse().map((cycle, index) => ({ index: index + 1, score: cycle.gate_score * 100 }));
  const metrics = model?.metrics ?? {};
  return <>
    <PageTitle kicker="Champion / challenger" title="Model Registry" copy="A candidate cannot touch the gate until it passes a sealed temporal, family-disjoint or external holdout, calibration, control and latency gates." />
    <section className="metric-strip model-strip"><Metric label="ROC-AUC" value={(metrics.roc_auc ?? 0) * 100} suffix="%" note="attack-family holdout" /><Metric label="PR-AUC" value={(metrics.pr_auc ?? 0) * 100} suffix="%" note="positive-class quality" /><Metric label="Brier score" value={metrics.brier ?? 0} note="lower is better" /><Metric label="P95 latency" value={metrics.p95_latency_ms ?? 0} suffix=" ms" note="budget: 100 ms" /></section>
    <div className="model-grid"><section className="panel chart-panel"><PanelHeader icon={Gauge} overline="MODEL FEEDBACK" title="Gate score by cycle" /><div className="chart-wrap"><ResponsiveContainer width="100%" height="100%"><AreaChart data={data}><defs><linearGradient id="score" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#ea4d3d" stopOpacity={0.5}/><stop offset="1" stopColor="#ea4d3d" stopOpacity={0}/></linearGradient></defs><CartesianGrid stroke="#34362f" vertical={false}/><XAxis dataKey="index" tick={{ fill: "#8e9086", fontSize: 11 }} axisLine={false}/><YAxis domain={[0,100]} tick={{ fill: "#8e9086", fontSize: 11 }} axisLine={false}/><Tooltip contentStyle={{ background: "#191b18", border: "1px solid #383a34", borderRadius: 8 }} /><Area type="monotone" dataKey="score" stroke="#ea4d3d" strokeWidth={2} fill="url(#score)" /></AreaChart></ResponsiveContainer></div></section>
      <section className="panel promotion-panel"><PanelHeader icon={Database} overline="INSTALLED ARTIFACT" title={model?.detector_id ?? "No model"} /><div className="promotion-status"><ShieldCheck size={28}/><strong>{model?.promoted ? "PROMOTED" : model?.legacy_compatible ? "COMPATIBILITY MODE" : model?.schema_compatible === false ? "INCOMPATIBLE" : "BASELINE"}</strong><span>{model?.legacy_compatible ? `legacy ${model.compatibility_policy?.replaceAll("_", " ")}` : model?.kind ?? "rules"}</span></div><div className="gate-checks">{["ROC-AUC ≥ .85","Recall@FPR ≥ .50","Brier ≤ .25","P95 ≤ 100ms","Control FP ≤ .15","Feature schema compatible"].map((gate) => <div key={gate}><i /><span>{gate}</span><b>{model?.promoted ? "PASS" : model?.legacy_compatible && gate === "Feature schema compatible" ? "ADAPTED" : "PENDING"}</b></div>)}</div></section>
    </div>
  </>;
}

function GapMiner({ coverage, gaps }: { coverage: Coverage | null; gaps: Gap[] }) {
  return <>
    <PageTitle kicker="Residual intelligence" title="Gap Miner" copy="Coverage deficits, false negatives and low-confidence slices are converted into the next red-team objective." />
    <div className="gap-layout"><section className="panel gap-ledger"><PanelHeader icon={Target} overline="RANKED QUEUE" title="Research objectives" />{gaps.map((gap, i) => <div className="gap-row" key={gap.brief_id}><span className="gap-rank">{String(i+1).padStart(2,"0")}</span><div><strong>{gap.suggested_family.replaceAll("_", " ")}</strong><p>{gap.objective}</p><div>{gap.target_f3_cells.map((c) => <code key={c}>{c}</code>)}</div></div><b>{Math.round(gap.priority*100)}</b></div>)}</section><section className="panel coverage-map"><PanelHeader icon={Radar} overline="F3 v1.1" title="Coverage pressure" />{coverage?.cells.map((cell) => <div className="coverage-line" key={cell.slug}><div><strong>{cell.name}</strong><small>{cell.cycles} cycles · {cell.techniques_tested}/{cell.techniques_total} techniques</small></div><div className="coverage-bar"><i style={{ width: `${Math.max(3, cell.techniques_tested / Math.max(cell.techniques_total,1) * 100)}%` }} /></div><StatusPill status={cell.status} /></div>)}</section></div>
  </>;
}

function AnalystChat({ detail, cycleId }: { detail: CycleDetail | null; cycleId: string | null }) {
  const [prompt, setPrompt] = useState("");
  const [messages, setMessages] = useState<Array<{ role: "analyst" | "you"; text: string }>>([{ role: "analyst", text: "I can explain the selected cycle, its evidence and defensive gaps. I will not provide operational attack instructions." }]);
  const [sending, setSending] = useState(false);
  async function send() {
    const value = prompt.trim();
    if (!value || sending) return;
    setMessages((m) => [...m, { role: "you", text: value }]);
    setPrompt("");
    setSending(true);
    try {
      const response = await api.chat(value, cycleId);
      const refs = response.evidence_refs.length ? ` Evidence: ${response.evidence_refs.slice(0, 4).join(", ")}.` : "";
      setMessages((m) => [...m, { role: "analyst", text: `${response.answer}${refs}` }]);
      if (response.refused) toast.warning("Defense-only policy applied");
    } catch (error) {
      toast.error("Analyst unavailable", { description: error instanceof Error ? error.message : "Unknown error" });
    } finally {
      setSending(false);
    }
  }
  return <><PageTitle kicker="Guarded analyst model" title="Analyst Chat" copy="Second-line reasoning over structured case artifacts. Explanations cite evidence; authorization decisions remain with the calibrated detector." /><section className="chat-shell panel"><div className="chat-context"><Sparkles size={16}/><div><span>CONTEXT</span><strong>{detail?.strategy.attack_family.replaceAll("_"," ") ?? "No cycle selected"}</strong></div><i>DEFENSE ONLY</i></div><div className="messages">{messages.map((m,i) => <div className={`message message-${m.role}`} key={i}><span>{m.role === "analyst" ? "FORGE" : "YOU"}</span><p>{m.text}</p></div>)}</div><div className="chat-input"><input value={prompt} onChange={(e) => setPrompt(e.target.value)} onKeyDown={(e) => { if(e.key === "Enter") void send(); }} placeholder="Ask about signals, uncertainty or mitigation…" disabled={sending}/><button onClick={() => void send()} disabled={sending}>{sending ? "Thinking…" : "Send"} <ChevronRight size={15}/></button></div></section></>;
}

function EmptyState({ title, copy }: { title: string; copy: string }) { return <div className="empty"><FlaskConical size={24}/><strong>{title}</strong><p>{copy}</p></div>; }
