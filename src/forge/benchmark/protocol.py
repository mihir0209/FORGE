# pyright: reportMissingTypeStubs=false, reportUnknownMemberType=false
"""Content-addressed paired benchmark construction and protocol validation."""

from __future__ import annotations

import hashlib
import json
import math
import shutil
from collections import defaultdict
from datetime import datetime  # noqa: TC003 - Pydantic resolves this annotation at runtime.
from typing import TYPE_CHECKING, Annotated

import pandas as pd
from pydantic import BaseModel, ConfigDict, Field

from forge.contracts.contracts import (
    BenchmarkArtifact,
    BenchmarkManifest,
    BenchmarkRowMetadata,
    BenchmarkSlice,
    BenchmarkSplit,
    CycleRecord,
    EvidenceCapability,
    ScenarioPurpose,
)
from forge.feature_schema import FEATURE_NAMES, FEATURE_SCHEMA_VERSION

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path

BENCHMARK_PROTOCOL_VERSION = "forge-benchmark-v1"
_PURPOSES = frozenset(ScenarioPurpose)


class BenchmarkSource(BaseModel):
    """A cycle plus benchmark identity that cannot be inferred safely from it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cycle: CycleRecord
    scenario_id: Annotated[str, Field(min_length=1)]
    world_id: Annotated[str, Field(min_length=1)]
    pair_id: Annotated[str, Field(min_length=1)]
    purpose: ScenarioPurpose
    observed_at: datetime


class ProtocolConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sealed_families: frozenset[str] = Field(min_length=1)
    sealed_templates: frozenset[str] = Field(default_factory=frozenset)
    development_folds: int = Field(default=5, ge=3)
    temporal_ood_after: datetime | None = None
    ood_rails: frozenset[str] = Field(default_factory=frozenset)
    ood_channels: frozenset[str] = Field(default_factory=frozenset)
    ablated_capabilities: frozenset[EvidenceCapability] = Field(
        default_factory=lambda: frozenset[EvidenceCapability]()
    )
    low_fpr_claim: float | None = Field(default=None, gt=0.0, lt=1.0)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _fold(family: str, folds: int) -> int:
    return int(hashlib.sha256(family.encode()).hexdigest()[:16], 16) % folds


def _feature_payload(
    cycle: CycleRecord,
    feature_capabilities: Mapping[str, EvidenceCapability],
    ablated: frozenset[EvidenceCapability],
) -> tuple[dict[str, float | bool | None], str, dict[EvidenceCapability, bool]]:
    if cycle.feature_schema_version != FEATURE_SCHEMA_VERSION:
        raise ValueError(
            f"cycle {cycle.cycle_id} uses {cycle.feature_schema_version}, expected {FEATURE_SCHEMA_VERSION}"
        )
    if set(cycle.detector_features) != set(FEATURE_NAMES):
        raise ValueError(f"cycle {cycle.cycle_id} has an incomplete detector feature vector")
    if set(feature_capabilities) != set(FEATURE_NAMES):
        raise ValueError("feature_capabilities must map every feature in the schema")

    declared = set(cycle.evidence_capabilities)
    values: dict[str, float | bool | None] = {}
    hash_values: dict[str, dict[str, float | bool | None]] = {}
    for name in FEATURE_NAMES:
        capability = feature_capabilities[name]
        available = capability in declared and capability not in ablated
        value = float(cycle.detector_features[name]) if available else None
        values[name] = value
        values[f"{name}__available"] = available
        hash_values[name] = {"available": available, "value": value}

    all_capabilities = set(EvidenceCapability)
    mask = {capability: capability in declared and capability not in ablated for capability in all_capabilities}
    return values, _digest(hash_values), mask


def _validate_groups(sources: Sequence[BenchmarkSource]) -> None:
    groups: dict[str, list[BenchmarkSource]] = defaultdict(list)
    for source in sources:
        groups[source.pair_id].append(source)
    for pair_id, group in groups.items():
        purposes = [source.purpose for source in group]
        if len(group) != len(_PURPOSES) or len(set(purposes)) != len(_PURPOSES):
            raise ValueError(
                f"pair {pair_id} must contain exactly one attack, matched control, "
                "hard negative, and low-signal attack"
            )
        families = {source.cycle.strategy.attack_family for source in group}
        if len(families) != 1:
            raise ValueError(f"pair {pair_id} crosses attack families")


def _validate_negative_support(rows: Sequence[dict[str, object]], claim: float | None) -> None:
    if claim is None:
        return
    required = math.ceil(1.0 / claim)
    for split in BenchmarkSplit.DEVELOPMENT, BenchmarkSplit.SEALED_TEST:
        negatives = sum(row["split"] == split.value and row["label"] == 0 for row in rows)
        if negatives < required:
            raise ValueError(
                f"{split.value} has {negatives} negatives; at least {required} are required "
                f"to claim FPR {claim:g}"
            )


def build_benchmark(
    sources: Sequence[BenchmarkSource],
    *,
    feature_capabilities: Mapping[str, EvidenceCapability],
    config: ProtocolConfig,
    output_root: Path,
) -> BenchmarkManifest:
    """Build Benchmark V1 parquet splits and a content-addressed manifest."""
    if not sources:
        raise ValueError("benchmark requires at least one paired group")
    _validate_groups(sources)
    output_root.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, object]] = []
    metadata: list[BenchmarkRowMetadata] = []
    seen_scenarios: set[str] = set()
    slices: dict[BenchmarkSlice, list[str]] = {item: [] for item in BenchmarkSlice}

    for source in sources:
        cycle = source.cycle
        family = cycle.strategy.attack_family
        family_hash = cycle.strategy.family_definition_sha256
        if not family_hash:
            raise ValueError(f"cycle {cycle.cycle_id} is missing family_definition_sha256")
        if source.scenario_id in seen_scenarios:
            raise ValueError(f"duplicate scenario_id: {source.scenario_id}")
        seen_scenarios.add(source.scenario_id)

        values, feature_hash, capability_mask = _feature_payload(
            cycle, feature_capabilities, config.ablated_capabilities
        )

        fold = _fold(family, config.development_folds)
        if family in config.sealed_families or cycle.strategy.scenario_template in config.sealed_templates:
            split = BenchmarkSplit.SEALED_TEST
            fold = None
        elif fold == 0:
            split = BenchmarkSplit.CALIBRATION
        elif fold == 1:
            split = BenchmarkSplit.DEVELOPMENT
        else:
            split = BenchmarkSplit.TRAIN
        identity = {
            "scenario_id": source.scenario_id,
            "world_id": source.world_id,
            "pair_id": source.pair_id,
            "purpose": source.purpose.value,
            "cycle_id": cycle.cycle_id,
            "feature_sha256": feature_hash,
        }
        row_id = f"br_{_digest(identity)[:24]}"
        label = int(source.purpose in {ScenarioPurpose.ATTACK, ScenarioPurpose.LOW_SIGNAL_ATTACK})
        row: dict[str, object] = {
            "row_id": row_id,
            "scenario_id": source.scenario_id,
            "world_id": source.world_id,
            "pair_id": source.pair_id,
            "purpose": source.purpose.value,
            "family_slug": family,
            "family": family,
            "track": cycle.detection_track.value,
            "capabilities": sorted(capability.value for capability, available in capability_mask.items() if available),
            "label": label,
            "split": split.value,
            "fold": fold,
            "feature_sha256": feature_hash,
        }
        row.update(values)
        rows.append(row)
        metadata.append(
            BenchmarkRowMetadata(
                row_id=row_id,
                scenario_id=source.scenario_id,
                world_id=source.world_id,
                pair_id=source.pair_id,
                family_slug=family,
                family_version=cycle.strategy.family_version,
                family_definition_sha256=family_hash,
                scenario_template=cycle.strategy.scenario_template,
                purpose=source.purpose,
                split=split,
                fold=fold,
                detection_track=cycle.detection_track,
                payment_rail=cycle.strategy.rail,
                channel=cycle.strategy.channel,
                capability_mask=capability_mask,
                graph_snapshot_sha256=(
                    cycle.graph_assessment.snapshot_sha256 if cycle.graph_assessment else None
                ),
                source_refs=[cycle.cycle_id, cycle.trace_ref],
                feature_sha256=feature_hash,
            )
        )
        if config.temporal_ood_after is not None and source.observed_at >= config.temporal_ood_after:
            slices[BenchmarkSlice.TEMPORAL_OOD].append(row_id)
        if cycle.strategy.rail in config.ood_rails:
            slices[BenchmarkSlice.RAIL_OOD].append(row_id)
        if cycle.strategy.channel in config.ood_channels:
            slices[BenchmarkSlice.CHANNEL_OOD].append(row_id)

    family_splits: dict[str, set[str]] = defaultdict(set)
    pair_splits: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        family_splits[str(row["family_slug"])].add(str(row["split"]))
        pair_splits[str(row["pair_id"])].add(str(row["split"]))
    if any(len(values) != 1 for values in pair_splits.values()):
        raise ValueError("pairs cannot cross splits")
    if any(len(values) != 1 for values in family_splits.values()):
        raise ValueError("families cannot cross benchmark splits")
    present_families = set(family_splits)
    if not config.sealed_families <= present_families:
        missing = sorted(config.sealed_families - present_families)
        raise ValueError(f"sealed families absent from sources: {missing}")
    if not (present_families - config.sealed_families):
        raise ValueError("benchmark requires at least one development family")
    _validate_negative_support(rows, config.low_fpr_claim)

    equivalence_counts: dict[str, int] = defaultdict(int)
    for row in rows:
        equivalence_counts[str(row["feature_sha256"])] += 1
    metadata = [
        item.model_copy(update={"feature_equivalence_size": equivalence_counts[item.feature_sha256]})
        for item in metadata
    ]
    for row in rows:
        row["feature_equivalence_size"] = equivalence_counts[str(row["feature_sha256"])]

    columns = [
        "row_id", "scenario_id", "world_id", "pair_id", "purpose", "family_slug",
        "family", "track", "capabilities", "label", "split", "fold", "feature_sha256", "feature_equivalence_size",
        *FEATURE_NAMES, *(f"{name}__available" for name in FEATURE_NAMES),
    ]
    stage = output_root / f".building-{_digest([row['row_id'] for row in rows])[:12]}"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)
    artifacts: list[BenchmarkArtifact] = []
    for split in (
        BenchmarkSplit.TRAIN,
        BenchmarkSplit.CALIBRATION,
        BenchmarkSplit.DEVELOPMENT,
        BenchmarkSplit.SEALED_TEST,
    ):
        path = stage / f"{split.value}.parquet"
        split_rows = [row for row in rows if row["split"] == split.value]
        pd.DataFrame(split_rows, columns=columns).sort_values("row_id").to_parquet(path, index=False)
        data = path.read_bytes()
        artifacts.append(
            BenchmarkArtifact(
                split=split,
                path=path.name,
                sha256=hashlib.sha256(data).hexdigest(),
                byte_size=len(data),
                rows=len(split_rows),
            )
        )

    manifest_seed = {
        "protocol_version": BENCHMARK_PROTOCOL_VERSION,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "feature_capabilities": {
            name: feature_capabilities[name].value for name in sorted(feature_capabilities)
        },
        "ablated_capabilities": sorted(item.value for item in config.ablated_capabilities),
        "development_folds": config.development_folds,
        "sealed_families": sorted(config.sealed_families),
        "sealed_templates": sorted(config.sealed_templates),
        "rows": [item.model_dump(mode="json") for item in sorted(metadata, key=lambda x: x.row_id)],
        "slices": {key.value: sorted(value) for key, value in slices.items()},
        "artifacts": [item.model_dump(mode="json") for item in artifacts],
    }
    metadata_sha256 = _digest(manifest_seed)
    dataset_id = f"benchmark_v1_{metadata_sha256[:24]}"
    manifest = BenchmarkManifest.model_validate(
        {**manifest_seed, "dataset_id": dataset_id, "metadata_sha256": metadata_sha256}
    )
    manifest_bytes = _canonical(manifest.model_dump(mode="json"))
    (stage / "manifest.json").write_bytes(manifest_bytes)

    target = output_root / dataset_id
    if target.exists():
        shutil.rmtree(stage)
        if verify_benchmark(target) != manifest:
            raise ValueError(f"existing benchmark does not match {dataset_id}")
    else:
        stage.replace(target)
    return manifest


def verify_benchmark(root: Path) -> BenchmarkManifest:
    """Verify every artifact byte and recompute the dataset identity from metadata."""
    manifest = BenchmarkManifest.model_validate_json((root / "manifest.json").read_bytes())
    for artifact in manifest.artifacts:
        data = (root / artifact.path).read_bytes()
        if len(data) != artifact.byte_size or hashlib.sha256(data).hexdigest() != artifact.sha256:
            raise ValueError(f"benchmark artifact checksum mismatch: {artifact.path}")
    seed = manifest.model_dump(mode="json", exclude={"dataset_id", "metadata_sha256"})
    digest = _digest(seed)
    if digest != manifest.metadata_sha256 or manifest.dataset_id != f"benchmark_v1_{digest[:24]}":
        raise ValueError("benchmark metadata or dataset_id mismatch")
    if root.name != manifest.dataset_id:
        raise ValueError("benchmark directory does not match dataset_id")
    return manifest


def negative_support_for_fpr(negative_count: int, claimed_fpr: float) -> bool:
    """Return whether a sample can resolve the claimed FPR at one-event granularity."""
    if not 0.0 < claimed_fpr < 1.0:
        raise ValueError("claimed_fpr must be between zero and one")
    return negative_count >= math.ceil(1.0 / claimed_fpr)
