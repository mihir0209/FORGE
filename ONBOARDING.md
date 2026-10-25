# FORGE — Onboarding & Architecture Guide

Welcome to **FORGE** (**Fraud Offense-defense Research and Generation Engine**), an adversarial closed-loop research and defense laboratory for payment security developed for the Mastercard Innovation Challenge @ GFF 2026.

---

## 1. High-Level Architecture & Mission

FORGE operates as an automated, closed-loop adversarial tournament across multiple fraud tracks (behavioral payment fraud, AI-assisted authorized push payment (APP) fraud, and bank-controlled media authenticity):

```
       ┌────────────────────────────────────────────────────────┐
       │                 Gap Miner (forge.gapmine)              │
       │       Identifies deficits against MITRE F3 taxonomy    │
       └──────────────────────────┬─────────────────────────────┘
                                  │ GapBrief / EvCycleRequested
                                  ▼
       ┌────────────────────────────────────────────────────────┐
       │                 Red Team (forge.redteam)               │
       │      Generates novel GenAI attack hypotheses (F3)      │
       └──────────────────────────┬─────────────────────────────┘
                                  │ StrategySpec / ActionPlan
                                  ▼
       ┌────────────────────────────────────────────────────────┐
       │             Simulator & Actor Sandbox                  │
       │  (forge.simulate / forge.actor_sandbox / forge.media)  │
       │     Generates synthetic traces + deterministic RNG     │
       └───────────┬────────────────────────────────────────────┘
                   │ SyntheticTrace (ground truth attached)
                   │ .observed_view() (nulls ground truth)
                   ▼
       ┌────────────────────────────────────────────────────────┐
       │                Blue Team (forge.blueteam)              │
       │     Blind investigation & signal derivation (typesafe) │
       └──────────────────────────┬─────────────────────────────┘
                                  │ BlueReport (signals, verdict)
                                  ▼
       ┌────────────────────────────────────────────────────────┐
       │                 Detector Gate (forge.detect)           │
       │     Scores blind trace features via Incumbent Model    │
       └──────────────────────────┬─────────────────────────────┘
                                  │ GateResult (Score, Action, Coverage)
                                  ▼
       ┌────────────────────────────────────────────────────────┐
       │         Registry, Variant Miner & Model Retraining     │
       │    (forge.kb, forge.detect.train, forge.detect.promotion)
       │    Persists cycle, creates proposals, trains challenger │
       └────────────────────────────────────────────────────────┘
```

### The Closed Loop Workflow

1. **Gap Mining (`forge.gapmine`)**: Periodically or on-demand, scans the MITRE Fight Fraud Framework (F3 v1.1) coverage matrix and current cycle history in the registry, ranking blind spots into `GapBrief` targets.
2. **Red Team Generation (`forge.redteam`)**: Formulates novel attack strategies (`StrategySpec`) adhering to the F3 taxonomy, validating novelty against past strategies using Jaccard/MinHash fingerprinting.
3. **Execution & Simulation (`forge.simulate` & `forge.actor_sandbox`)**: Executes behavioral sequences against a deterministic merchant/customer synthetic world or runs multi-step synthetic APP scams with media fixtures (audio/video/document synthesized via `ffmpeg`). Produces `SyntheticTrace` with attached `GroundTruth`.
4. **Blind Defense Investigation (`forge.blueteam`)**: Converts the trace to defender-visible `ObservedTraceView` (blindness guaranteed by construction). Evaluates signals (velocity bursts, off-hours activity, beneficiary graph anomalies, scam intervention overrides) to produce a `BlueReport`.
5. **Detector Gate (`forge.detect`)**: Evaluates tabular features against the incumbent detector (`RuleBaselineDetector` or calibrated LightGBM), outputting a `GateResult` with coverage (`covered`, `partial`, or `blind_spot`).
6. **Retraining & Promotion (`forge.detect.train`, `forge.detect.promotion`)**: When unhandled residual attacks hit training thresholds, generates versioned parquet datasets with family-disjoint holdouts, trains challenger LightGBM models, and verifies strict quality gates (ROC-AUC, Brier score, latency budget, false positive controls) before promoting to incumbent.

---

## 2. Directory Structure

```
FORGE/
├── configs/
│   └── settings.yaml            # Runtime settings (pipeline, gate, detector thresholds)
├── deploy/
│   ├── docker-compose.*.yml     # Bind-mounted host-backed service configs
│   ├── backup.sh                # Backup creation script (PG, Redis, MinIO, artifacts)
│   ├── verify-backup.sh         # Backup verification in isolated temporary state
│   └── prepare-data.sh          # Data directory setup
├── docs/
│   ├── adr/                     # Architecture Decision Records
│   │   ├── 0001-inngest-blinded-types-pydantic-ai.md
│   │   └── 0002-multitrack-feature-schema.md
│   └── DEMO.md                  # Judge and demonstration scripts
├── frontend/                    # Vite + React 19 + TypeScript judge dashboard
│   ├── src/
│   │   ├── components/          # Reusable UI components (Metric, PageTitle, etc.)
│   │   ├── App.tsx              # Main dashboard views & Emil Kowalski motion system
│   │   ├── api.ts               # Typed client connecting to FastAPI backend
│   │   ├── store.ts             # Zustand state management
│   │   └── types.ts             # Frontend contract definitions
│   ├── package.json
│   └── vite.config.ts
├── scripts/
│   └── vendor-pin.sh            # Git submodule checkout & checksum verification
├── src/
│   └── forge/
│       ├── actor_sandbox.py     # Sandbox executing ActionPlans for APP fraud
│       ├── api/                 # FastAPI web endpoints, read models, and analyst chat
│       ├── app_scam_runner.py   # AI-assisted APP scam cycle coordinator
│       ├── artifacts.py         # Local & S3/MinIO artifact storage adapters
│       ├── benchmark/           # Benchmark generation and evaluation protocol
│       ├── blueteam/            # Blue team blind investigation logic
│       ├── cli/                 # `forge` CLI entrypoints
│       ├── config.py            # Pydantic Settings loaded from YAML & .env
│       ├── contracts/           # Pydantic models (StrategySpec, Trace, GateResult, etc.)
│       ├── cycle_runner.py      # Offline adversarial cycle runner
│       ├── data_quality.py      # Trace audit, checksum, and LLM readiness checks
│       ├── detect/              # Detectors, feature extraction, mule rings, training & promotion
│       │   └── mule_ring.py     # Directed graph cycle detection & fan-out/fan-in funds pooling
│       ├── families.py          # Fraud family definitions & immutable registry
│       ├── feature_schema.py    # Multi-track versioned feature schema union
│       ├── gapmine/             # F3 deficit ranking and gap brief mining
│       ├── graph_store.py       # Graph event store for beneficiary networks
│       ├── ids.py               # Deterministic ID generators
│       ├── kb/                  # Knowledge base loaders (F3 STIX, skills, registries)
│       ├── media/               # Synthetic media adapters & ffmpeg generators
│       ├── operations/          # Cluster supervisor, worker health & notifications
│       ├── payment_rails.py     # Payment rail profiles (Faster Payments, UPI, etc.)
│       ├── pipeline/            # Inngest durable workflow definitions & stage runners
│       ├── reasoning/           # Pydantic AI LLM clients & telemetry
│       ├── redteam/             # Red team attack composition & novelty validation
│       ├── research_mcp.py      # Model Context Protocol tools for research
│       ├── research_snapshots.py# Immutable snapshot store for research citations
│       ├── risk_graph.py        # Beneficiary risk graph analysis
│       ├── signals/             # Heuristic signal primitives (bursts, off-hours, etc.)
│       ├── simulate/            # Synthetic payment world, generator, merchant/customer engine
│       │   └── generator.py     # Micro-burst, geo-velocity spoof & smurfing generator
│       ├── benchmark.py         # High-volume streaming benchmark runner
│       └── storage.py           # Artifact persistence on disk (JSON payloads)
├── tests/                       # Complete pytest suite (unit, integration, contracts)
├── vendor/
│   ├── fight-fraud-framework/   # MITRE F3 v1.1 STIX submodule
│   └── skills/                  # Anthropic Cybersecurity Skills library submodule
├── pyproject.toml               # Python project configuration (uv, hatchling, ruff, pyright)
└── uv.lock                      # Pinned Python dependencies
```

---

## 3. Core Architectural Invariants

Always uphold these six non-negotiable rules:

1. **Inngest Isolation**: Business logic modules (`redteam`, `simulate`, `blueteam`, `detect`, `gapmine`) must **never** import `inngest`. Only `forge.pipeline` coordinates with Inngest.
2. **Type-Enforced Blindness**: `blueteam.investigate()` takes **only** `ObservedTraceView`. `SyntheticTrace.observed_view()` is the sole constructor, nulling ground-truth fields (`is_attack_step`, `attack_stage`) by construction. Passing raw traces causes compile-time and run-time type errors.
3. **Pure Contracts**: All internal modules communicate via `forge.contracts`. Contract models import nothing internal from the rest of `forge`.
4. **Lightweight Events, Heavy Artifacts**: Inngest events contain IDs and small metadata (<64 KiB). Heavy payloads (raw traces, media fixtures, dataset parquets, model pickles) live under `data/` or S3/MinIO.
5. **Strict Determinism**: Master RNG is derived deterministically from `WorldSeed`. Per-subsystem seeds ensure reproducible traces and zero flaky tests.
6. **Versioned Multi-Track Schemas**: Detectors and cycles declare `DetectionTrack`, `EvidenceCapability`, and `FeatureSchema`. Historical schemas are adapted explicitly; unknown schemas are rejected.

---

## 4. Local Development & Runtime Environment

### Prerequisites
- **Python**: 3.13 (or 3.12+)
- **uv**: Modern fast package manager
- **Node.js**: v20+ and npm
- **FFmpeg**: Required for media fixture generation (`sudo apt install ffmpeg`)
- **Git Submodules**: Vendored knowledge bases

### Initial Setup

```bash
# 1. Update and verify git submodules
./scripts/vendor-pin.sh

# 2. Create Python 3.13 virtual environment with uv
uv venv --python 3.13
uv sync --python 3.13

# 3. Install frontend dependencies
cd frontend && npm ci && cd ..
```

---

## 5. Daily Workflows & Commands

### Running Tests and Quality Gates

```bash
# Run complete test suite
uv run pytest

# Run Python linter
uv run ruff check

# Run Python strict type checker
uv run pyright

# Run frontend linter and build
npm --prefix frontend run lint
npm --prefix frontend run build
```

### Running the Services

#### Option A: Offline Cycle Execution (Fastest for testing)
```bash
# Run one behavioral payment fraud cycle
uv run forge cycle --seed 42

# Run an AI-assisted APP scam cycle
uv run forge app-scam-cycle --seed 42 --variant safe_account

# Run data audit
uv run forge data-audit --run-id unsupervised

# Run high-volume streaming benchmark
uv run python src/forge/benchmark.py --volume 5000
```

#### Option B: Full Web & API Stack
```bash
# 1. Build frontend bundle
npm --prefix frontend run build

# 2. Run FastAPI API server (serves frontend at / and API at /api)
FORGE_REGISTRY_PATH=data/registry.sqlite uv run uvicorn forge.api.app:app --port 8000

# 3. (Optional) Run Vite dev server with proxy during UI development
npm --prefix frontend run dev
```

#### Option C: Inngest Durable Orchestration
```bash
# Terminal 1: FastAPI app serving Inngest endpoint
FORGE_REGISTRY_PATH=data/registry.sqlite uv run uvicorn forge.api.app:app --port 8000

# Terminal 2: Inngest dev server
npx -y inngest-cli@latest dev --sdk-url http://127.0.0.1:8000/api/inngest

# Trigger a cycle via event
curl -X POST http://127.0.0.1:8288/e/dev -H 'Content-Type: application/json' \
  -d '{"name":"cycle.requested","data":{"seed":42}}'
```

---

## 6. Key Data Contracts & Schemas

| Model | Module | Role |
|---|---|---|
| `StrategySpec` | `forge.contracts` | Red-team attack hypothesis (MITRE F3 mapped, behavioral sequence) |
| `ActionPlan` | `forge.contracts` | Ordered typed tool calls executed in the sandbox |
| `SyntheticTrace` | `forge.contracts` | Full simulation trace with attached `GroundTruth` |
| `ObservedTraceView` | `forge.contracts` | Defender-safe trace view without ground-truth labels |
| `Signal` | `forge.contracts` | Heuristic indicator (name, evidence_refs, strength ∈ [0,1]) |
| `BlueReport` | `forge.contracts` | Blue team verdict (`defeated`, `partial`, `missed`), signals, mitigations |
| `GateResult` | `forge.contracts` | Incumbent detector score, reason codes, action, coverage |
| `CycleRecord` | `forge.contracts` | Complete immutable record of one adversarial cycle |
| `GapBrief` | `forge.contracts` | Target objective for next research cycle derived from blind spots |
| `CandidateReport` | `forge.contracts` | Trained detector candidate awaiting quality gate evaluation |
| `PromotionVerdict`| `forge.contracts` | Outcome of quality gate tests before incumbent swap |
