"""Register one AI-assisted APP scam cycle in the normal FORGE registry."""

from __future__ import annotations

from typing import TYPE_CHECKING

from forge.actor_sandbox import ActorSandbox
from forge.blueteam import investigate
from forge.contracts.contracts import (
    CycleRecord,
    F3Mapping,
    LifecycleStage,
    Provenance,
    StrategySpec,
    WorldSeed,
)
from forge.detect import gate_score, trace_features
from forge.detect.incumbent import load_incumbent
from forge.redteam.actor import execute_strategy

if TYPE_CHECKING:
    from forge.artifacts import ArtifactStore
    from forge.kb import Registry


def app_scam_strategy(seed: int) -> StrategySpec:
    return StrategySpec(
        strategy_id=f"strategy-app-{seed}",
        fraud_objective=(
            "use AI-assisted impersonation outside the bank channel to coach a customer "
            f"into a high-risk UPI payment (run seed {seed})"
        ),
        attack_family="ai_assisted_app_scam",
        f3=F3Mapping(tactic="monetization", techniques=["F1010"]),
        rail="upi",
        channel="mobile_banking",
        prerequisites=["simulated customer", "off-site impersonation media", "mule beneficiary"],
        lifecycle_stages=[LifecycleStage.AUTHENTICATION, LifecycleStage.PAYMENT],
        entities={"simulated_attackers": 1, "simulated_customers": 1, "mule_accounts": 1},
        behavioral_sequence=[
            "prepare impersonation media outside the bank channel",
            "coach customer into opening the genuine banking app",
            "add a first-time beneficiary by pasting supplied details",
            "override payee verification and targeted scam warning",
            "attempt a balance-depleting payment to a risky beneficiary",
        ],
        genai_leverage="voice/video impersonation and adaptive payment coaching",
        evasion_hypothesis="the genuine customer and device pass authentication while intent is coerced",
        expected_signals=[
            "first_time_payee",
            "behavioral_coaching_risk",
            "beneficiary_network_risk",
            "warning_override",
            "balance_depletion",
        ],
        novelty_rationale="cross-layer AI impersonation, customer behavior, and mule-network trace",
        provenance=Provenance(provider="fixture", model="ai-assisted-app-scam-v1"),
    )


def run_app_scam_cycle(
    *, seed: int, cycle_id: str, registry: Registry, store: ArtifactStore
) -> CycleRecord:
    strategy = app_scam_strategy(seed)
    sandbox_result = execute_strategy(
        strategy,
        cycle_id=cycle_id,
        seed=WorldSeed(master_seed=seed),
        sandbox=ActorSandbox(store),
    )
    trace = sandbox_result.trace
    observed = trace.observed_view()
    report = investigate(observed)
    gate = gate_score(observed, load_incumbent())
    trace_artifact = store.put_json("traces", trace.trace_id, trace.model_dump(mode="json"))
    record = CycleRecord(
        cycle_id=cycle_id,
        run_id=f"app-scam-{seed}",
        strategy=strategy,
        trace_ref=trace_artifact.uri,
        blue_report=report,
        gate_result=gate,
        detector_features=trace_features(observed),
        accepted=gate.coverage.value != "covered",
    )
    registry.record_cycle(record)
    return record
