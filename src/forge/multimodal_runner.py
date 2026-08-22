"""Register one multimodal actor-sandbox cycle in the normal FORGE registry."""

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
from forge.detect import RuleBaselineDetector, gate_score
from forge.redteam.actor import execute_strategy

if TYPE_CHECKING:
    from forge.artifacts import ArtifactStore
    from forge.kb import Registry


def multimodal_strategy(seed: int) -> StrategySpec:
    return StrategySpec(
        strategy_id=f"strategy-mm-{seed}",
        fraud_objective=(
            "use synthetic audio/video impersonation during a video call to induce "
            "a sandbox UPI payment"
        ),
        attack_family="deepfake_video_call_payment",
        f3=F3Mapping(tactic="monetization", techniques=["F1010"]),
        rail="upi",
        channel="video_call",
        prerequisites=["synthetic victim", "synthetic media", "non-routable call"],
        lifecycle_stages=[LifecycleStage.AUTHENTICATION, LifecycleStage.PAYMENT],
        entities={"synthetic_attackers": 1, "synthetic_victims": 1},
        behavioral_sequence=[
            "generate synthetic portrait audio and video",
            "start video call from unseen network",
            "present generated media",
            "initiate payment during active call",
            "end call",
        ],
        genai_leverage="synthetic image, speech and video generation",
        evasion_hypothesis="unknown network plus plausible media session",
        expected_signals=[
            "unknown_peer_network",
            "media_liveness_anomaly",
            "transaction_during_call",
        ],
        novelty_rationale="cross-channel deepfake-assisted payment trace",
        provenance=Provenance(provider="fixture", model="ffmpeg-fixture-v1"),
    )


def run_multimodal_cycle(
    *, seed: int, cycle_id: str, registry: Registry, store: ArtifactStore
) -> CycleRecord:
    strategy = multimodal_strategy(seed)
    sandbox_result = execute_strategy(
        strategy,
        cycle_id=cycle_id,
        seed=WorldSeed(master_seed=seed),
        sandbox=ActorSandbox(store),
    )
    trace = sandbox_result.trace
    report = investigate(trace.observed_view())
    gate = gate_score(trace.observed_view(), RuleBaselineDetector())
    trace_artifact = store.put_json("traces", trace.trace_id, trace.model_dump(mode="json"))
    record = CycleRecord(
        cycle_id=cycle_id,
        run_id=f"multimodal-{seed}",
        strategy=strategy,
        trace_ref=trace_artifact.uri,
        blue_report=report,
        gate_result=gate,
        accepted=True,
    )
    registry.record_cycle(record)
    return record
