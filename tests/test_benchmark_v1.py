# pyright: reportMissingTypeStubs=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pandas as pd
import pytest

from forge.benchmark import BenchmarkSource, ProtocolConfig, build_benchmark, verify_benchmark
from forge.contracts.contracts import (
    Action,
    BenchmarkSlice,
    BlueReport,
    Coverage,
    CycleRecord,
    DetectionTrack,
    EvidenceCapability,
    GateResult,
    Provenance,
    ScenarioPurpose,
    Verdict,
)
from forge.feature_schema import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from tests.fixtures_spec import make_spec


def _sources() -> list[BenchmarkSource]:
    purposes = list(ScenarioPurpose)
    result: list[BenchmarkSource] = []
    for family_index, family in enumerate(("development_family", "sealed_family")):
        for purpose_index, purpose in enumerate(purposes):
            ordinal = family_index * len(purposes) + purpose_index
            features = {name: float(ordinal * 100 + index) for index, name in enumerate(FEATURE_NAMES)}
            cycle = CycleRecord(
                cycle_id=f"cycle-{ordinal}",
                run_id="benchmark-test",
                strategy=make_spec(
                    strategy_id=f"strategy-{ordinal}",
                    attack_family=family,
                    family_version="1.2.3",
                    family_definition_sha256=f"definition-{family}",
                    rail="upi" if family_index == 0 else "swift",
                    channel="web" if family_index == 0 else "branch",
                ),
                trace_ref=f"trace-{ordinal}",
                blue_report=BlueReport(
                    investigator_id="test",
                    confidence=0.5,
                    verdict=Verdict.PARTIAL,
                    provenance=Provenance(provider="test", model="test"),
                ),
                gate_result=GateResult(
                    detector_id="test",
                    score=0.5,
                    action=Action.REVIEW,
                    coverage=Coverage.PARTIAL,
                    latency_ms=1.0,
                    similarity_to_known=0.0,
                ),
                detector_features=features,
                feature_schema_version=FEATURE_SCHEMA_VERSION,
                detection_track=DetectionTrack.BEHAVIORAL_PAYMENT,
                evidence_capabilities=[
                    EvidenceCapability.PAYMENT_HISTORY,
                    EvidenceCapability.APP_BEHAVIOR,
                ],
                accepted=True,
            )
            result.append(
                BenchmarkSource(
                    cycle=cycle,
                    scenario_id=f"scenario-{ordinal}",
                    world_id=f"world-{family_index}",
                    pair_id=f"pair-{family_index}",
                    purpose=purpose,
                    observed_at=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(days=family_index),
                )
            )
    return result


def _capabilities() -> dict[str, EvidenceCapability]:
    return {
        name: (
            EvidenceCapability.PAYMENT_HISTORY
            if name == "burst"
            else EvidenceCapability.APP_BEHAVIOR
        )
        for name in FEATURE_NAMES
    }


def test_builds_content_addressed_pair_atomic_protocol(tmp_path: Path) -> None:
    manifest = build_benchmark(
        _sources(),
        feature_capabilities=_capabilities(),
        config=ProtocolConfig(
            sealed_families=frozenset({"sealed_family"}),
            development_folds=3,
            temporal_ood_after=datetime(2026, 1, 2, tzinfo=UTC),
            ood_rails=frozenset({"swift"}),
            ood_channels=frozenset({"branch"}),
        ),
        output_root=tmp_path,
    )
    root = tmp_path / manifest.dataset_id
    assert verify_benchmark(root) == manifest
    assert len({row.fold for row in manifest.rows if row.family_slug == "development_family"}) == 1
    assert all(row.fold is None for row in manifest.rows if row.family_slug == "sealed_family")
    assert len(manifest.slices[BenchmarkSlice.TEMPORAL_OOD]) == 4

    frames = [pd.read_parquet(root / artifact.path) for artifact in manifest.artifacts]
    rows = pd.concat(frames)
    assert rows["row_id"].is_unique
    assert rows["feature_sha256"].is_unique
    assert set(rows.groupby("pair_id")["split"].nunique()) == {1}

    rebuilt = build_benchmark(
        list(reversed(_sources())),
        feature_capabilities=_capabilities(),
        config=ProtocolConfig(
            sealed_families=frozenset({"sealed_family"}),
            development_folds=3,
            temporal_ood_after=datetime(2026, 1, 2, tzinfo=UTC),
            ood_rails=frozenset({"swift"}),
            ood_channels=frozenset({"branch"}),
        ),
        output_root=tmp_path,
    )
    assert rebuilt.dataset_id == manifest.dataset_id

    artifact = root / manifest.artifacts[0].path
    artifact.write_bytes(artifact.read_bytes() + b"tampered")
    with pytest.raises(ValueError, match="checksum mismatch"):
        verify_benchmark(root)


def test_ablation_removes_values_and_marks_unavailable(tmp_path: Path) -> None:
    manifest = build_benchmark(
        _sources(),
        feature_capabilities=_capabilities(),
        config=ProtocolConfig(
            sealed_families=frozenset({"sealed_family"}),
            ablated_capabilities=frozenset({EvidenceCapability.PAYMENT_HISTORY}),
        ),
        output_root=tmp_path,
    )
    frame = pd.read_parquet(tmp_path / manifest.dataset_id / "development.parquet")
    assert bool(frame["burst"].isna().all())
    assert not bool(frame["burst__available"].any())
    assert bool(frame["new_device"].notna().all())
    assert bool(frame["new_device__available"].all())
    assert all(not row.capability_mask[EvidenceCapability.PAYMENT_HISTORY] for row in manifest.rows)


def test_rejects_duplicate_scenarios_and_feature_vectors(tmp_path: Path) -> None:
    sources = _sources()
    duplicate_scenario = sources[1].model_copy(update={"scenario_id": sources[0].scenario_id})
    with pytest.raises(ValueError, match="duplicate scenario_id"):
        build_benchmark(
            [sources[0], duplicate_scenario, *sources[2:]],
            feature_capabilities=_capabilities(),
            config=ProtocolConfig(sealed_families=frozenset({"sealed_family"})),
            output_root=tmp_path,
        )

    duplicate_cycle = sources[4].cycle.model_copy(
        update={"cycle_id": "different-cycle", "detector_features": sources[0].cycle.detector_features}
    )
    duplicate_feature = sources[4].model_copy(update={"cycle": duplicate_cycle})
    manifest = build_benchmark(
        [*sources[:4], duplicate_feature, *sources[5:]],
        feature_capabilities=_capabilities(),
        config=ProtocolConfig(sealed_families=frozenset({"sealed_family"})),
        output_root=tmp_path,
    )
    assert max(row.feature_equivalence_size for row in manifest.rows) == 2


def test_rejects_incomplete_pairs_missing_metadata_and_low_fpr_claim(tmp_path: Path) -> None:
    sources = _sources()
    with pytest.raises(ValueError, match="must contain exactly one"):
        build_benchmark(
            sources[:-1],
            feature_capabilities=_capabilities(),
            config=ProtocolConfig(sealed_families=frozenset({"sealed_family"})),
            output_root=tmp_path,
        )


def test_generated_counterfactuals_are_trace_derived(tmp_path: Path) -> None:
    from forge.benchmark.generate import generate_pair
    from forge.detect import trace_features
    from forge.families import FamilyRegistry

    sources = generate_pair(
        FamilyRegistry().get("deepfake_executive_bec"), seed=77, output_root=tmp_path
    )
    for source in sources:
        from forge.contracts.contracts import SyntheticTrace

        trace = SyntheticTrace.model_validate_json(Path(source.cycle.trace_ref).read_text())
        assert trace_features(trace.observed_view()) == source.cycle.detector_features

    missing_definition = sources[0].cycle.model_copy(
        update={
            "strategy": sources[0].cycle.strategy.model_copy(
                update={"family_definition_sha256": None}
            )
        }
    )
    with pytest.raises(ValueError, match="missing family_definition_sha256"):
        build_benchmark(
            [sources[0].model_copy(update={"cycle": missing_definition}), *sources[1:]],
            feature_capabilities=_capabilities(),
            config=ProtocolConfig(
                sealed_families=frozenset({"deepfake_executive_bec"})
            ),
            output_root=tmp_path,
        )

    with pytest.raises(ValueError, match="at least 1000"):
        build_benchmark(
            [*sources, *_sources()[:4]],
            feature_capabilities=_capabilities(),
            config=ProtocolConfig(
                sealed_families=frozenset({"deepfake_executive_bec"}),
                low_fpr_claim=0.001,
            ),
            output_root=tmp_path,
        )
