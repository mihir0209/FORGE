# FORGE — Context

**FORGE = Fraud Offense-defense Research and Generation Engine.**
A closed-loop adversarial laboratory for payment fraud: a red-team agent composes novel
GenAI-powered attack strategies against the MITRE F3 taxonomy, a sandboxed simulator
executes them into labeled synthetic traces, a blue-team agent investigates trace-only
(blind), a calibrated ML detector scores everything through a feedback gate, and a gap
miner turns residual blind spots into the next research objective.

Mastercard Innovation Challenge @ GFF 2026 — AI Defense Lab for Payment Security.

## Domain glossary

| Term | Definition |
|---|---|
| **StrategySpec** | The red team's validated attack hypothesis (strict JSON contract). |
| **ActionPlan** | Ordered typed tool calls that the red-team actor executes as a synthetic user inside the sandbox. |
| **WorldSeed** | Master seed + world params; derives every RNG deterministically. |
| **Trace** | Ordered, labeled events from one simulation run; ground truth attached. |
| **ObservedTraceView** | The trace as defenders may see it — ground-truth fields nulled by construction (`trace.observed_view()` is the only constructor). |
| **Signal** | Typed indicator (name, evidence_refs, strength ∈ [0,1]) derived from an ObservedTraceView by a signal primitive; single definition lives in `forge.signals` and is consumed by both blue-team verdicts and detector features. |
| **MediaObservation** | Defender-visible facts extracted from a media artifact (hashes, codec/container facts, timing and versioned model scores) without generation truth. |
| **ArtifactProvenance** | Internal receipt linking an artifact to its tool, model/workflow, inputs, seed and checksums; hidden from blue-team views. |
| **BlueReport** | Blue team's structured verdict: signals, evidence_refs, motifs, mitigations, confidence, verdict ∈ {defeated, partial, missed}, uncovered_gaps. |
| **GateResult** | Incumbent detector's score/action/reason codes + coverage ∈ {covered, partial, blind_spot}. |
| **CycleRecord** | Immutable aggregate of one full adversarial cycle + provenance. |
| **GapBrief** | Ranked next-research objective derived from residuals. |
| **Incumbent / Candidate** | Installed detector vs challenger awaiting promotion. |
| **PromotionVerdict** | Pass/fail of the full quality-gate suite before incumbent swap. |
| **RunSupervisor** | Durable admission/drain/finalization state for a bounded multi-day research run. |

## Architecture invariants (do not violate)

1. Business logic never imports `inngest` — only `forge.pipeline` does.
2. `blueteam.investigate()` accepts only `ObservedTraceView`. Blindness is a type error.
3. All modules speak `forge.contracts`; contracts import nothing internal.
4. Events carry IDs + small payloads (<64 KiB); artifacts live under `data/`.
5. Determinism: fixed `PYTHONHASHSEED`, per-subsystem RNGs from `WorldSeed`, pinned deps.
