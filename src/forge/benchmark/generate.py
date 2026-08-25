"""Generate paired Benchmark V1 rows from shared latent worlds."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from forge.actor_sandbox import ActorSandbox
from forge.app_scam_runner import app_scam_strategy
from forge.artifacts import LocalArtifactStore
from forge.benchmark.protocol import BenchmarkSource
from forge.blueteam import investigate
from forge.contracts.contracts import (
    CycleRecord,
    DetectionTrack,
    EvidenceCapability,
    ScenarioPurpose,
    WorldSeed,
)
from forge.detect import RuleBaselineDetector, gate_score, trace_features
from forge.families import build_app_plan
from forge.feature_schema import FEATURE_SCHEMA_VERSION

if TYPE_CHECKING:
    from pathlib import Path

    from forge.contracts.contracts import FraudFamilyDefinition


def generate_pair(
    family: FraudFamilyDefinition,
    *,
    seed: int,
    output_root: Path,
) -> list[BenchmarkSource]:
    """Create fraud/control/hard-negative/low-signal rows from one pair world."""
    pair_id = f"pair_{family.slug}_{seed}"
    world_id = f"world_{hashlib.sha256(f'{family.definition_sha256}:{seed}'.encode()).hexdigest()[:16]}"
    store = LocalArtifactStore(output_root / "objects")

    records = {
        purpose: _execute_purpose(family, seed, f"{pair_id}-{purpose.value}", store, purpose)
        for purpose in ScenarioPurpose
    }
    observed_at = datetime(2026, 1, 1, tzinfo=UTC)
    return [
        BenchmarkSource(cycle=cycle, scenario_id=f"{pair_id}-{purpose.value}", world_id=world_id,
                        pair_id=pair_id, purpose=purpose, observed_at=observed_at)
        for purpose, cycle in records.items()
    ]


def _execute_purpose(
    family: FraudFamilyDefinition,
    seed: int,
    cycle_id: str,
    store: LocalArtifactStore,
    purpose: ScenarioPurpose,
) -> CycleRecord:
    plan = build_app_plan(family, cycle_id, seed, purpose=purpose.value)
    result = ActorSandbox(store).execute(
        plan,
        WorldSeed(master_seed=seed),
        cycle_id=cycle_id,
        purpose=purpose,
    )
    view = result.trace.observed_view()
    report = investigate(view)
    gate = gate_score(view, RuleBaselineDetector())
    strategy = app_scam_strategy(seed, family=family)
    trace_artifact = store.put_json(
        "traces", result.trace.trace_id, result.trace.model_dump(mode="json")
    )
    return CycleRecord(
        cycle_id=cycle_id, run_id=f"benchmark-{purpose.value}-{seed}", strategy=strategy,
        trace_ref=trace_artifact.uri, blue_report=report, gate_result=gate,
        detector_features=trace_features(view), feature_schema_version=FEATURE_SCHEMA_VERSION,
        detection_track=DetectionTrack.AI_ASSISTED_APP,
        evidence_capabilities=[EvidenceCapability.DEVICE_INTEGRITY, EvidenceCapability.APP_BEHAVIOR,
                               EvidenceCapability.PAYEE_VERIFICATION, EvidenceCapability.BENEFICIARY_NETWORK,
                               EvidenceCapability.SYSTEM_CALL_STATE],
        graph_assessment=result.graph_assessments[-1] if result.graph_assessments else None,
        accepted=purpose in {ScenarioPurpose.ATTACK, ScenarioPurpose.LOW_SIGNAL_ATTACK},
    )
