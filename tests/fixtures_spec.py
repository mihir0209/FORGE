"""Shared StrategySpec fixture for tests and replay tooling."""

from __future__ import annotations

from typing import Any

from forge.contracts.contracts import (
    F3Mapping,
    LifecycleStage,
    Provenance,
    StrategySpec,
)


def make_spec(**over: Any) -> StrategySpec:
    base: dict[str, Any] = dict(
        strategy_id="s_refund_01",
        fraud_objective="drain via refund abuse after small test payments",
        attack_family="refund_abuse",
        f3=F3Mapping(tactic="positioning", techniques=["F1005.003"]),
        rail="upi",
        channel="web",
        lifecycle_stages=[
            LifecycleStage.AUTHENTICATION,
            LifecycleStage.PAYMENT,
            LifecycleStage.REFUND,
            LifecycleStage.CASH_OUT,
        ],
        behavioral_sequence=[
            "new device login at night",
            "small test payment to new payee",
            "burst of rapid payments",
            "request refund for each",
        ],
        genai_leverage="synthetic complaint narratives",
        evasion_hypothesis="mimic grocery rhythm, off-hour cash-out",
        novelty_rationale="combination novel in registry",
        provenance=Provenance(provider="scripted", model="fixture"),
    )
    base.update(over)
    return StrategySpec.model_validate(base)
