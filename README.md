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
