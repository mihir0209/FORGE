# FORGE

**Fraud Offense-defense Research and Generation Engine.**

A closed-loop adversarial laboratory for payment fraud — Mastercard Innovation
Challenge @ GFF 2026 (AI Defense Lab for Payment Security).

```
red team composes novel GenAI attack strategies (MITRE F3-indexed)
        → sandboxed synthetic payment world executes them into labeled traces
        → blue team investigates trace-only (blind by type system)
        → calibrated ML detector scores everything through a feedback gate
        → gap miner turns residual blind spots into the next research objective
```

## Quick start

```bash
uv sync                       # pinned deps
./scripts/vendor-pin.sh       # verify F3 v1.1 + skills KB pins
uv run pytest -q              # contracts & blindness tests
```

## Durable pipeline (Inngest)

```bash
# terminal 1 — the app (FastAPI + inngest serve at /api/inngest)
FORGE_REGISTRY_PATH=data/registry.sqlite uv run uvicorn forge.api.app:app --port 8000

# terminal 2 — the dev server (queues, retries, concurrency, cron)
npx -y inngest-cli@latest dev --sdk-url http://127.0.0.1:8000/api/inngest

# trigger one adversarial cycle
curl -X POST http://127.0.0.1:8288/e/dev -H 'Content-Type: application/json' \
  -d '{"name":"cycle.requested","data":{"seed":42}}'
```

Flow: `gap.mine` (cron) → `cycle.requested` → compose → simulate → investigate →
gate.scored → finalize → `cycle.accepted` (+ `corpus.threshold_reached`).
Simulate/investigate/gate run under per-`attack_family` concurrency keys.
Duplicate fingerprints are dropped at compose; offline equivalent:
`uv run forge cycle --seed 42`.

## Host-backed container storage

Docker persists all runtime state directly under the repository's ignored `data/`
directory: PostgreSQL under `data/services/postgres`, Redis under
`data/services/redis`, MinIO under `data/services/minio`, and FORGE artifacts and
research receipts under their existing `data/` paths.

```bash
./deploy/prepare-data.sh
docker compose --env-file deploy/vps.env -f docker-compose.vps.yml up -d
```

For a bounded unattended run, set a new `FORGE_RUN_ID`, set
`FORGE_RUN_DURATION_HOURS=48`, enable `FORGE_CAMPAIGN_ENABLED=1`, and configure
the campaign family rotation in `deploy/vps.env`. The durable ten-minute
campaign tick claims each run/time slot atomically, emits deterministic unique
requests, and stops admitting work when the supervisor enters drain state.

Create and verify a point-in-time backup without replacing live data:

```bash
./deploy/backup.sh
./deploy/verify-backup.sh data/backups/<UTC-timestamp>
```

The backup contains logical PostgreSQL dumps, a Redis RDB snapshot, a MinIO
object mirror, a runtime artifact archive, and SHA-256 checksums. Verification
restores both databases under temporary names, validates the Redis snapshot,
restores MinIO into a temporary bucket, checks schemas and checksums, and reads
the artifact archive before deleting temporary resources. Backup creation uses
a short maintenance window that stops API, workers and Inngest to establish one
cross-store boundary, then restarts them automatically. Copy the verified
directory off-host; local verification alone is not an off-host backup.

Set `FORGE_OPERATOR_TOKEN` in `deploy/vps.env` to enable the dashboard's demo
and worker-probe actions. In the browser, store the same value under the
`forgeOperatorToken` local-storage key. If the server token is absent, mutation
endpoints return `503`; an incorrect token returns `403`.

On every startup, the one-shot `forge-bootstrap` service idempotently imports
`data/registry.sqlite` and approved definitions under `data/families/` into
PostgreSQL before the API and workers start. Source files remain unchanged and
continue to provide a portable local backup.

**Upgrading from the previous named-volume deployment:** stop the stack and
export PostgreSQL (`pg_dump`), MinIO objects (`mc mirror`), and any required
Redis state before switching to this bind-mounted Compose file. Restore those
exports under `data/services/` or into the freshly started services. Compose
does not automatically migrate the old `postgres-data`, `redis-data`, or
`minio-data` named volumes; starting the new layout without an export leaves
those old volumes intact but detached from the running services.

Residual APP failures automatically create bounded, non-executable family
proposals in the registry. Review them with `uv run forge variant-list --db
data/registry.sqlite`. After the proposal's source references have immutable
research snapshots, activate it explicitly with `forge variant-approve`; no
proposal executes before that approval step.

## Judge-facing dashboard

```bash
cd frontend
npm install
npm run dev                   # Vite on :5173, proxies /api to FastAPI

# production bundle (served automatically by FastAPI at /)
npm run build
cd ..
uv run uvicorn forge.api.app:app --port 8000
```

Surfaces: Control Room, Closed Loop, Strategy Repository, Operations, Attack
Lab, Defense Lab, Model Registry, Gap Miner, F3 Coverage Matrix, and guarded
Analyst Chat. The Strategy Repository pairs each persisted red-team hypothesis
with its latest blind blue-team handling and provides readable and canonical
Markdown views. All views read the configured live registry and model artifacts;
there is no mock-data path.

The deployed system separates presentation from execution:

- FastAPI serves the React dashboard and read/control endpoints.
- The dashboard can enqueue only reviewed competition demos and worker probes.
- Inngest owns durable scheduling, retries, and event fan-out.
- Headless worker containers execute simulation, investigation, scoring, variant
  derivation, and training; the web process does not execute those stages.

The `Closed Loop` view presents Identify → Generate → Defend → Learn for one
selected cycle. The `Operations` view reports observed worker probes, queue and
registry health, structured-record counts, host-backed artifact inventories,
model governance, pending review-gated variants, and backup posture. It reports
unknown or not configured states rather than inferring health from configuration.

`uv run forge data-audit --run-id "$FORGE_RUN_ID"` validates checksum-bearing
trace references, schema round trips, defender blindness and blue-team evidence
links. It reports LLM readiness separately and fails that gate while targets
remain heuristic, duplicated or below the reviewed-corpus threshold.

## Layout

- `src/forge/contracts` — pydantic models; the only shared dependency.
- `src/forge/{kb,reasoning,redteam,simulate,blueteam,detect,gapmine}` — business logic.
- `src/forge/pipeline` — the ONLY place that imports inngest.
- `src/forge/api`, `src/forge/cli` — entry points (FastAPI mount + offline cycle runner).
- `vendor/` — pinned knowledge bases: MITRE Fight Fraud Framework v1.1, community skills library.
- `.agent/plans/` — build plans; `docs/adr/` — decision records.

## Invariants

1. Business logic never imports inngest.
2. `blueteam.investigate()` accepts only `ObservedTraceView` — blindness is a type error.
3. All modules speak `forge.contracts`.
4. Events stay small (<64 KiB); artifacts under `data/`.
5. Determinism: fixed hash seed, per-subsystem RNGs from `WorldSeed`.

License: TBD before public repo push. Third-party: F3 (Apache-2.0, © 2026 MITRE,
PR_25-02691-6), skills library (Apache-2.0, © Mahipal Jangra).
