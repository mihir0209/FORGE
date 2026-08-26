# FORGE — Judge Demonstration Script & Walkthrough

Mastercard Innovation Challenge @ Global Fintech Fest 2026  
**AI Defense Lab for Payment Security**

---

## 1. Executive Walkthrough Overview

FORGE (Fraud Offense-defense Research and Generation Engine) is a closed-loop adversarial research laboratory designed to continuously stress-test and harden financial defense models against emerging, GenAI-orchestrated payment fraud.

### The Judge-Visible Loop in 4 Steps:
1. **Identify**: Red team analyzes MITRE F3 taxonomy gaps and causal risk graphs to synthesize novel attack hypotheses (`StrategySpec`).
2. **Generate**: Sandboxed simulator executes the strategy with multimodal synthetic actors (voice, portrait, video, non-routable banking events), emitting an immutable, labeled `SyntheticTrace`.
3. **Defend**: Blue team conducts a **trace-only blind investigation** (`ObservedTraceView`), outputting structured evidence refs, heuristics, motifs, and mitigations (`BlueReport`).
4. **Learn**: Incumbent detector scores the trace via multi-track feature schemas. If coverage gaps emerge, the gap miner prioritizes new research targets, triggering gated model retraining.

---

## 2. Live Demo Script (Step-by-Step)

### Step 1: Open the FORGE Dashboard
- Navigate to `http://localhost:8000/` (or the deployed VPS URL).
- The dashboard is powered by a production Vite/React frontend reading directly from live FastAPI read models (zero mock data).

### Step 2: Explore the Closed Loop
1. Click the **Closed Loop** tab.
2. Select an active cycle (e.g., `cycle-mm-5002` or `deepfake_executive_bec`).
3. **Inspect the Red Team Strategy**:
   - Note the F3 mapping (`TA0001` - `TA0011`), channel (`wire_transfer` / `faster_payments`), and GenAI leverage mechanisms.
4. **Inspect the Blue Team Blind Investigation**:
   - Verify that the blue team only saw `ObservedTraceView` (ground truth was nulled by construction).
   - Review the extracted evidence references, causal graph motifs, and confidence scoring.
5. **Inspect the Model Feedback Gate**:
   - Review calibrated probabilities, action recommendations (`review`, `decline`, `step_up`), reason codes, and coverage classification (`covered`, `partial`, `blind_spot`).

### Step 3: Explore the Strategy Repository
1. Navigate to the **Strategies** tab (`/api/strategies`).
2. Filter strategies by fraud family, F3 tactic, or detection track (`behavioral_payment_fraud`, `ai_assisted_app_fraud`, `media_authenticity`).
3. Click on any strategy card to view:
   - Full JSON payload and canonical Markdown representation.
   - Associated media artifacts and SHA-256 provenance receipts.
   - Latest BlueReport findings and residual defense gaps.

### Step 4: Causal Risk Graph & Multi-Track Detection
1. Open the **Causal Graph** view to visualize attack progression across synthetic entities (device, IP ASN, voice clone, destination mule account).
2. Note the multi-track feature contract:
   - Track 1: Behavioral transaction and velocity anomalies.
   - Track 2: AI-assisted conversational pressure and social engineering signals.
   - Track 3: Media authenticity and synthetic artifact forensics.

### Step 5: Operations & Durability
1. Navigate to the **Operations** tab.
2. Inspect the supervisor metrics:
   - Active / Queued cycles and storage utilization.
   - Recurring campaign slot status (10-minute cadence, family rotation).
   - Inngest worker replicas (5 connected workers with retry backoff).
   - Backup & restore status: Logical PG dumps, Redis RDB, MinIO mirroring, and SHA-256 integrity verification receipts.

---

## 3. CLI Reproduction & Verification Commands

Judges and evaluators can verify all claims directly from the terminal:

### 1. Run an Offline Adversarial Cycle
```bash
uv run forge cycle --family deepfake_executive_bec --seed 42
```

### 2. Run an AI-Assisted APP Scam Actor Cycle
```bash
uv run forge app-scam-cycle --family ai_bank_impersonation --seed 101
```

### 3. Verify Run-Scoped Trace Integrity & Blindness
```bash
uv run forge data-audit --run-id <RUN_ID>
```
*Confirms artifact resolution, SHA-256 checksums, SyntheticTrace schema round-trip, defender blindness, and evidence link validity.*

### 4. Execute the Model Training & Gated Promotion Pipeline
```bash
uv run forge train
```
*Evaluates the candidate detector against 6 promotion gates (ROC-AUC, PR-AUC, low-FPR recall, calibration, latency, regression).*

### 5. Run the Automated Test Suite
```bash
uv run pytest
```
*Executes all 116 tests across blindness contracts, multi-track detection, pipeline stages, risk graphs, and supervisor operations.*
