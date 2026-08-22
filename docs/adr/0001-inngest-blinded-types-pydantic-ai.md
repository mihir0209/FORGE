# ADR-0001: Inngest as the sole durable-execution owner

Date: 2026-08-22 · Status: accepted

## Context
FORGE needs queues, retries, concurrency control, cron and threshold-triggered training
without us operating Redis/celery inside a 9-day competition window. Candidate layers:
Inngest (Python SDK 0.5.19), LangGraph checkpointers, Temporal, celery+redis, hand-rolled.

## Decision
Adopt **Inngest** as the ONLY component owning durability. Business logic lives in plain
typed modules; `forge.pipeline` wraps them in `ctx.step.run`. Self-hosted dev server for
local runs; single-binary `inngest start` documented as the prod path.

## Consequences
- **No other library may attach its own persistence**: no LangGraph checkpointers, no
  MAF Workflows/CheckpointStorage, no OpenAI Agents SDK temporal extra. One replay story.
- Concurrency keys (`event.data.attack_family`) give worker diversification for free.
- Events carry IDs + references (<64 KiB); artifacts on disk under `data/`.
- Evidence: `.agent/research/inngest-python-sdk-2026-08-22.md`;
  double-durability analysis in `.agent/research/agent-frameworks-comparison-2026-08-22.md`.

# ADR-0002: Blindness enforced by the type system

Date: 2026-08-22 · Status: accepted

## Context
The blue team must investigate trace-only. Reviewer-enforced discipline rots under
deadline pressure; a leaked ground-truth field silently invalidates evaluation realism.

## Decision
`SyntheticTrace.observed_view()` is the ONLY constructor of `ObservedTraceView`, and it
nulls `is_attack_step` / `attack_stage` on every event copy. `blueteam.investigate()`
accepts only `ObservedTraceView`. Passing raw traces is a type error caught by pyright
strict and by a dedicated unit test.

# ADR-0003: Pydantic AI as the in-step LLM layer

Date: 2026-08-22 · Status: accepted

## Context
Team proposed coding-agent runtimes as orchestrators (opencode runtime, pi coding agent,
deepseek-harness). Research classification: all are terminal coding harnesses whose
benchmarks (SWE-bench/Terminal-Bench) measure repo-editing, not schema-gated loop
reliability — category error for FORGE. Framework bake-off (verified versions, 2026-08-22):
Pydantic AI 2.33 vs OpenAI Agents SDK 0.22 vs MAF 1.15; benchmark landscape shows NO
leaderboard ranks orchestrators on short structured-output loops, while MAS studies
(MAST 41–87% failure rates; MAFBench up to 117× latency overhead) penalize heavyweight
frameworks.

## Decision
Use **Pydantic AI 2.33** inside steps: declarative `output_type=` + built-in validation
retries, stateless-per-call (zero durability conflict with Inngest memoization),
widest provider registry (OpenAI default, Anthropic fallback, vLLM later for the
fine-tuned analyst). Typed refusal handling wraps provider refusals into
`forge.reasoning` errors. Do NOT adopt MAF or LangGraph (own persistence ⇒ double
durability). Revisit `deepseek-harness` only after its Python SDK leaves dev preview,
and only if it grows schema-gated outputs.

Evidence: `.agent/research/named-runtimes-classification-2026-08-22.md`,
`.agent/research/benchmarks-landscape-agents-2026-08-22.md`,
`.agent/research/agent-frameworks-comparison-2026-08-22.md`.
