"""Red team compose: GapBrief + KB hits -> validated, novel StrategySpec."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from forge.contracts.contracts import (
    DraftStrategy,
    F3Mapping,
    GapBrief,
    KBHit,
    LifecycleStage,
    NoveltyVerdict,
    Provenance,
    SafetyClass,
    StrategySpec,
)
from forge.kb import Registry, f3_matrix

if TYPE_CHECKING:
    from forge.reasoning import ReasoningClient

_SYSTEM = """You are the red-team researcher of FORGE, a defensive fraud laboratory.
All attacks exist only inside a sandboxed synthetic payment world; you must never
produce operational instructions against real targets. Compose ONE novel attack
strategy as structured output that is novel, plausible, observable and simulator-
feasible. Ground it in the provided MITRE F3 context."""


def _prompt(brief: GapBrief, hits: list[KBHit]) -> str:
    ctx = "\n".join(f"- [{h.source}] {h.title}: {h.detail}" for h in hits[:12])
    return (
        f"Research objective (ranked gap):\n  {brief.objective}\n"
        f"Suggested family: {brief.suggested_family}\n\n"
        f"Relevant F3/skill context:\n{ctx}\n\n"
        "Emit one DraftStrategy. behavioral_sequence entries are short verb phrases "
        "(e.g. 'new device login', 'small test payment', 'burst of rapid payments', "
        "'request refund')."
    )


def compose_draft(
    draft: DraftStrategy,
    *,
    strategy_id: str,
    provider: str = "scripted",
    model: str = "fixture",
) -> StrategySpec:
    """Deterministic path: enrich a given draft into a full StrategySpec."""
    spec = _to_spec(draft, strategy_id=strategy_id, provider=provider, model=model)
    violations = validate(spec)
    if violations:
        raise ValueError(f"invalid strategy {strategy_id}: {violations}")
    return spec


def compose(
    brief: GapBrief,
    hits: list[KBHit],
    reasoning: ReasoningClient,
    *,
    strategy_id: str,
    provider: str = "scripted",
    model: str = "fixture",
) -> StrategySpec:
    draft = reasoning.complete(DraftStrategy, _SYSTEM, _prompt(brief, hits))
    return compose_draft(draft, strategy_id=strategy_id, provider=provider, model=model)


def _to_spec(draft: DraftStrategy, *, strategy_id: str, provider: str, model: str) -> StrategySpec:
    clean_family = draft.attack_family.lower().strip().replace("-", "_")
    return StrategySpec(
        strategy_id=strategy_id,
        fraud_objective=draft.fraud_objective,
        attack_family=clean_family,
        f3=F3Mapping(tactic=draft.f3_tactic, techniques=draft.f3_techniques),
        rail=draft.rail,
        channel=draft.channel,
        lifecycle_stages=draft.lifecycle_stages,
        entities=draft.entities,
        behavioral_sequence=draft.behavioral_sequence,
        genai_leverage=draft.genai_leverage,
        evasion_hypothesis=draft.evasion_hypothesis,
        expected_signals=draft.expected_signals,
        safety_class=SafetyClass.SYNTHETIC_RESEARCH,
        novelty_rationale=draft.novelty_rationale,
        provenance=Provenance(provider=provider, model=model),
    )


# --------------------------------------------------------------------------
# Validation — deterministic checks beyond pydantic
# --------------------------------------------------------------------------

_STAGE_HINTS: dict[LifecycleStage, tuple[str, ...]] = {
    LifecycleStage.ONBOARDING: ("onboard", "account open", "register", "enroll", "create"),
    LifecycleStage.AUTHENTICATION: ("login", "log in", "auth", "session", "credential", "proxy", "device", "cookie", "token"),
    LifecycleStage.PAYMENT: ("pay", "purchase", "transfer", "transaction", "deposit", "bet", "wager", "send", "fund"),
    LifecycleStage.REFUND: ("refund", "chargeback", "dispute", "reversal", "claim"),
    LifecycleStage.SETTLEMENT: ("settle", "settlement", "batch", "clear"),
    LifecycleStage.CASH_OUT: ("cash-out", "cashout", "cash out", "withdraw", "atm", "crypto", "wallet", "payout", "liquidat", "drain", "extract", "conversion", "off-ramp"),
}


def validate(spec: StrategySpec) -> list[str]:
    problems: list[str] = []
    matrix = f3_matrix()

    if matrix.tactic_by_slug(spec.f3.tactic) is None:
        problems.append(f"unknown F3 tactic slug '{spec.f3.tactic}'")
    for tid in spec.f3.techniques:
        tech = matrix.technique(tid)
        if tech is None:
            problems.append(f"unknown F3 technique '{tid}'")
        elif tech.tactic != spec.f3.tactic:
            problems.append(f"technique '{tid}' belongs to '{tech.tactic}', not '{spec.f3.tactic}'")

    text = " ".join(spec.behavioral_sequence).lower()
    for stage in spec.lifecycle_stages:
        hints = _STAGE_HINTS.get(stage, ())
        if not any(h in text or h in stage.value for h in hints):
            problems.append(f"no behavioral hint supports lifecycle stage '{stage.value}'")

    # normalize attack_family if LLM emitted hyphens or uppercase
    family_cleaned = spec.attack_family.lower().replace("-", "_")
    if not re.fullmatch(r"[a-z0-9_]{3,50}", family_cleaned):
        problems.append("attack_family must be snake_case identifier")

    if spec.safety_class == SafetyClass.RESTRICTED:
        problems.append("restricted-safety strategies never execute")
    return problems


def novelty(spec: StrategySpec, registry: Registry) -> NoveltyVerdict:
    twins = registry.similar(spec.fingerprint())
    family_n = registry.same_family_count(spec.attack_family)
    if twins:
        return NoveltyVerdict(
            novel=False,
            reason=f"fingerprint matches existing {twins[0].strategy_id}",
            exact_duplicate=True,
            same_family_count=family_n,
        )
    return NoveltyVerdict(
        novel=True,
        reason="fingerprint unseen",
        same_family_count=family_n,
    )
