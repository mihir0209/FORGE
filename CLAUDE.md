# CLAUDE.md — FORGE Project Guide

FORGE (Fraud Offense-defense Research and Generation Engine) is a closed-loop adversarial research and evaluation laboratory for payment security (Mastercard Innovation Challenge @ GFF 2026).

---

## Non-Negotiable Invariants

1. **Inngest Isolation**: Only `src/forge/pipeline` may import `inngest`. Domain logic must stay free of orchestration dependencies.
2. **Type-Enforced Blindness**: `blueteam.investigate()` accepts only `ObservedTraceView`. `SyntheticTrace.observed_view()` is the sole constructor; it strips ground-truth labels by design.
3. **Pure Contracts**: All internal modules communicate through `forge.contracts`. Contract models never import internal modules.
4. **Lightweight Events, Heavy Artifacts**: Events contain identifiers and small references (<64 KiB). Heavy payloads (raw traces, media fixtures, dataset parquets, models) live under `data/` or object storage.
5. **Strict Determinism**: Master RNG derives from `WorldSeed`. Subsystem-specific RNG derivations prevent test flakiness and ensure reproducible traces.
6. **Multi-Track Schemas**: Every cycle stores its `DetectionTrack`, `EvidenceCapability`, and `FeatureSchema`. Historical schemas adapt explicitly; unknown schemas are rejected.

---

## Build & Test Commands

### Setup
```bash
# Verify and initialize knowledge base submodules
./scripts/vendor-pin.sh

# Python environment (Python 3.13)
uv venv --python 3.13
uv sync --python 3.13

# Frontend dependencies
npm --prefix frontend ci
```

### Testing & Validation
```bash
# Run backend pytest suite
uv run pytest

# Run Python linter & typechecker
uv run ruff check
uv run pyright

# Run frontend linter & production bundle build
npm --prefix frontend run lint
npm --prefix frontend run build
```

### Execution
```bash
# Run one offline behavioral cycle
uv run forge cycle --seed 42

# Run an AI-assisted APP scam cycle
uv run forge app-scam-cycle --seed 42 --variant safe_account

# Run data audit
uv run forge data-audit --run-id unsupervised

# Run streaming transaction detection benchmark
uv run python src/forge/benchmark.py --volume 5000

# Launch API server (serves frontend at / and API at /api)
FORGE_REGISTRY_PATH=data/registry.sqlite uv run uvicorn forge.api.app:app --port 8000

# Launch frontend dev server
npm --prefix frontend run dev
```

---

## Code & Design Conventions

### Python (`src/forge`, `tests`)
- **Version**: Python >= 3.12, < 3.14 (target: Python 3.13).
- **Type Checking**: Pyright strict mode (`typeCheckingMode = "strict"`). Annotate all function signatures and public exports.
- **Data Models**: Use Pydantic v2 `BaseModel` with `ConfigDict(extra="forbid", frozen=True)` for immutable contracts.
- **Error Handling**: Use explicit typed exceptions (`ValueError`, `HTTPException`). Avoid catching bare exceptions; use `contextlib.suppress(...)` where intentional.
- **Ruff Rules**: `E`, `F`, `I`, `UP`, `B`, `SIM`, `TCH`, `RUF` with max line length 100.
- **Imports**: Group standard library, third-party, and first-party imports. Keep contracts pure.

### Frontend (`frontend`)
- **Stack**: React 19, TypeScript ~5.7, Vite 6, Framer Motion, Zustand, Sonner, NumberFlow.
- **Style**: Dark high-contrast theme, CSS variables (`--bg`, `--ink`, `--line`). Emil Kowalski motion system (`motion`, `AnimatePresence`).
- **State**: Centralized via Zustand (`useLabStore`).
- **API**: Typed Fetch client in `frontend/src/api.ts` connecting to FastAPI backend.
