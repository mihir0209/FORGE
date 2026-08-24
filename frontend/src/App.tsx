import { useEffect, useState } from "react";
import {
  Activity,
  Bot,
  BrainCircuit,
  ChevronRight,
  Crosshair,
  Database,
  FlaskConical,
  Gauge,
  Menu,
  Radar,
  RefreshCw,
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
import type { Coverage, CycleDetail, CycleSummary, Gap, ModelCard, View } from "./types";

const nav: Array<{ id: View; label: string; icon: typeof Activity }> = [
  { id: "overview", label: "Control room", icon: Activity },
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
  const [loading, setLoading] = useState(true);
  const [mobileNav, setMobileNav] = useState(false);

  async function refresh() {
    setLoading(true);
    try {
      const [nextCycles, nextCoverage, nextGaps, nextModel] = await Promise.all([
        api.cycles(), api.coverage(), api.gaps(), api.model()
      ]);
      setCycles(nextCycles);
      setCoverage(nextCoverage);
      setGaps(nextGaps);
      setModel(nextModel);
      if (!selectedCycle && nextCycles[0]) selectCycle(nextCycles[0].cycle_id);
    } catch (error) {
      toast.error("Backend unavailable", { description: error instanceof Error ? error.message : "Unknown error" });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void refresh(); }, []);

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
          <div className="live-dot" /><span>PIPELINE ONLINE</span>
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
            <div><strong>{cycle.family.replaceAll("_", " ")}</strong><small>{cycle.tactic} · {cycle.rail}/{cycle.channel}</small></div>
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
        <div className="mini-metrics"><span>Recall <b>{fmt(model?.metrics?.recall)}</b></span><span>P95 <b>{fmt(model?.metrics?.p95_latency_ms, 1)}ms</b></span><span>State <b>{model?.promoted ? "PROMOTED" : "BASELINE"}</b></span></div>
      </section>
      <section className="panel gap-mini-panel">
        <PanelHeader icon={Target} overline="NEXT OBJECTIVE" title="Gap miner" />
        {gaps[0] ? <div className="gap-callout"><span>Priority {Math.round(gaps[0].priority * 100)}</span><p>{gaps[0].objective}</p><div>{gaps[0].target_f3_cells.slice(0, 4).map((cell) => <code key={cell}>{cell}</code>)}</div></div> : <EmptyState title="No ranked gaps" copy="Run a cycle to seed the research queue." />}
      </section>
    </div>
  </>;
}

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
        <div className="tag-row"><code>{detail.strategy.f3.tactic}</code>{detail.strategy.f3.techniques.map((t) => <code key={t}>{t}</code>)}</div>
        <div className="sequence"><h3>Behavioral sequence</h3>{detail.strategy.behavioral_sequence.map((step, i) => <div className="sequence-step" key={step}><b>{String(i + 1).padStart(2, "0")}</b><span>{step}</span><i /></div>)}</div>
        <div className="dossier-grid"><div><span>GENAI LEVERAGE</span><p>{detail.strategy.genai_leverage}</p></div><div><span>EVASION HYPOTHESIS</span><p>{detail.strategy.evasion_hypothesis}</p></div></div>
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
        <h3 className="section-label">Recommended mitigations</h3><ol className="mitigation-list">{detail.blue_report.mitigations.map((item) => <li key={item}>{item}</li>)}</ol>
      </> : <EmptyState title="Select a cycle" copy="Evidence will appear here." />}
    </section></div>
  </>;
}

function ModelDashboard({ model, cycles }: { model: ModelCard | null; cycles: CycleSummary[] }) {
  const data = cycles.slice().reverse().map((cycle, index) => ({ index: index + 1, score: cycle.gate_score * 100 }));
  const metrics = model?.metrics ?? {};
  return <>
    <PageTitle kicker="Champion / challenger" title="Model Registry" copy="A candidate cannot touch the gate until it passes a sealed temporal or unseen-family holdout, calibration, control and latency gates." />
    <section className="metric-strip model-strip"><Metric label="ROC-AUC" value={(metrics.roc_auc ?? 0) * 100} suffix="%" note="attack-family holdout" /><Metric label="PR-AUC" value={(metrics.pr_auc ?? 0) * 100} suffix="%" note="positive-class quality" /><Metric label="Brier score" value={metrics.brier ?? 0} note="lower is better" /><Metric label="P95 latency" value={metrics.p95_latency_ms ?? 0} suffix=" ms" note="budget: 100 ms" /></section>
    <div className="model-grid"><section className="panel chart-panel"><PanelHeader icon={Gauge} overline="MODEL FEEDBACK" title="Gate score by cycle" /><div className="chart-wrap"><ResponsiveContainer width="100%" height="100%"><AreaChart data={data}><defs><linearGradient id="score" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#ea4d3d" stopOpacity={0.5}/><stop offset="1" stopColor="#ea4d3d" stopOpacity={0}/></linearGradient></defs><CartesianGrid stroke="#34362f" vertical={false}/><XAxis dataKey="index" tick={{ fill: "#8e9086", fontSize: 11 }} axisLine={false}/><YAxis domain={[0,100]} tick={{ fill: "#8e9086", fontSize: 11 }} axisLine={false}/><Tooltip contentStyle={{ background: "#191b18", border: "1px solid #383a34", borderRadius: 8 }} /><Area type="monotone" dataKey="score" stroke="#ea4d3d" strokeWidth={2} fill="url(#score)" /></AreaChart></ResponsiveContainer></div></section>
      <section className="panel promotion-panel"><PanelHeader icon={Database} overline="INSTALLED ARTIFACT" title={model?.detector_id ?? "No model"} /><div className="promotion-status"><ShieldCheck size={28}/><strong>{model?.promoted ? "PROMOTED" : model?.schema_compatible === false ? "INCOMPATIBLE" : "BASELINE"}</strong><span>{model?.kind ?? "rules"}</span></div><div className="gate-checks">{["ROC-AUC ≥ .85","Recall@FPR ≥ .50","Brier ≤ .25","P95 ≤ 100ms","Control FP ≤ .15","Feature schema compatible"].map((gate) => <div key={gate}><i /><span>{gate}</span><b>{model?.promoted ? "PASS" : "PENDING"}</b></div>)}</div></section>
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
