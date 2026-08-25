"""Register one AI-assisted APP scam cycle in the normal FORGE registry."""

from __future__ import annotations

from typing import TYPE_CHECKING

from forge.actor_sandbox import ActorSandbox
from forge.blueteam import investigate
from forge.contracts.contracts import (
    CycleRecord,
    DetectionTrack,
    EvidenceCapability,
    LifecycleStage,
    Provenance,
    StrategySpec,
    WorldSeed,
)
from forge.detect import gate_score, trace_features
from forge.detect.incumbent import load_incumbent
from forge.families import build_app_plan, family_registry_from_env
from forge.feature_schema import FEATURE_SCHEMA_VERSION

if TYPE_CHECKING:
    from forge.artifacts import ArtifactStore
    from forge.kb import Registry


_VARIANTS = {"safe_account": "ai_bank_impersonation", "family_emergency": "ai_family_emergency", "investment_coaching": "ai_investment_coaching"}


def app_scam_strategy(seed: int, variant: str = "safe_account") -> StrategySpec:
    slug = _VARIANTS.get(variant, variant)
    family = family_registry_from_env().get(slug)
    return StrategySpec(
        strategy_id=f"strategy-app-{slug}-{seed}",
        fraud_objective=(
            "use AI-assisted impersonation outside the bank channel to coach a customer "
            f"into a high-risk UPI payment (run seed {seed})"
        ),
        attack_family=family.slug,
        f3=family.f3,
        rail=family.rail,
        channel=family.channel,
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
        genai_leverage=family.genai_leverage,
        evasion_hypothesis=family.evasion_hypothesis,
        expected_signals=[
            "first_time_payee",
            "behavioral_coaching_risk",
            "beneficiary_network_risk",
            "warning_override",
            "balance_depletion",
        ],
        novelty_rationale="cross-layer AI impersonation, customer behavior, and mule-network trace",
        provenance=Provenance(provider="fixture", model="ai-assisted-app-scam-v1"),
        family_version=family.version,
        family_definition_sha256=family.definition_sha256,
    )


def run_app_scam_cycle(
    *,
    seed: int,
    cycle_id: str,
    registry: Registry,
    store: ArtifactStore,
    variant: str = "safe_account",
) -> CycleRecord:
    strategy = app_scam_strategy(seed, variant)
    family = family_registry_from_env().get(strategy.attack_family, strategy.family_version)
    sandbox_result = ActorSandbox(store).execute(
        build_app_plan(family, cycle_id), WorldSeed(master_seed=seed), cycle_id=cycle_id
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
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        detection_track=DetectionTrack.AI_ASSISTED_APP,
        evidence_capabilities=[
            EvidenceCapability.DEVICE_INTEGRITY,
            EvidenceCapability.APP_BEHAVIOR,
            EvidenceCapability.PAYEE_VERIFICATION,
            EvidenceCapability.BENEFICIARY_NETWORK,
            EvidenceCapability.SYSTEM_CALL_STATE,
        ],
        graph_assessment=(sandbox_result.graph_assessments[-1] if sandbox_result.graph_assessments else None),
        accepted=gate.coverage.value != "covered",
    )
    registry.record_cycle(record)
    return record
