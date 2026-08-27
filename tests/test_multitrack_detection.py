"""Multi-track schema compatibility and paper-ready family holdouts."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from forge.actor_sandbox import ActorSandbox, ai_assisted_app_scam_plan, legitimate_app_payment_plan
from forge.app_scam_runner import app_scam_strategy, run_app_scam_cycle
from forge.artifacts import LocalArtifactStore
from forge.contracts.contracts import DetectionTrack, WorldSeed
from forge.detect import trace_features
from forge.feature_schema import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, adapt_features
from forge.kb import SQLiteRegistry
from forge.signals import all_signals


def test_known_legacy_schema_adapts_by_name() -> None:
    legacy = {
        "burst": 0.8,
        "new_device": 0.6,
        "refund_pressure": 0.0,
        "off_hours_focus": 0.2,
        "cashout_pressure": 0.1,
        "volume": 0.4,
    }
    adapted = adapt_features(legacy, "legacy-behavioral-v1")
    assert tuple(adapted) == FEATURE_NAMES
    assert adapted["burst"] == 0.8
    assert adapted["beneficiary_network_risk"] == 0.0

    app_v1 = {name: 0.1 for name in (*FEATURE_NAMES[:6], *FEATURE_NAMES[9:])}
    assert adapt_features(app_v1, "app-scam-v1")["media_liveness_anomaly"] == 0.0


def test_unknown_schema_fails_closed() -> None:
    with pytest.raises(ValueError, match="unknown feature schema"):
        adapt_features({"mystery": 1.0}, "unknown-v9")


def test_known_legacy_model_loads_as_compatibility_ensemble(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from forge.detect.incumbent import load_incumbent

    source = Path("data/models/candidates/cand_73007063.joblib")
    pointer_source = Path("data/models/incumbent.json")
    if not source.exists() or not pointer_source.exists():
        pytest.skip("local legacy artifact not available")
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path))
    model_root = tmp_path / "models"
    candidates = model_root / "candidates"
    candidates.mkdir(parents=True)
    target = candidates / source.name
    shutil.copy2(source, target)
    pointer = json.loads(pointer_source.read_text())
    pointer["artifact_path"] = str(target)
    (model_root / "incumbent.json").write_text(json.dumps(pointer))

    detector = load_incumbent()
    assert detector.detector_id.startswith("compatible:")
    features = {name: 0.0 for name in FEATURE_NAMES}
    features["beneficiary_network_risk"] = 1.0
    assert detector.score_features(features) > 0.0


@pytest.mark.parametrize(
    ("variant", "family"),
    [
        ("safe_account", "ai_bank_impersonation"),
        ("family_emergency", "ai_family_emergency"),
        ("investment_coaching", "ai_investment_coaching"),
    ],
)
def test_app_variants_have_distinct_families(variant: str, family: str) -> None:
    assert app_scam_strategy(1, variant).attack_family == family


def test_legitimate_call_control_does_not_trigger_app_risk(tmp_path: Path) -> None:
    sandbox = ActorSandbox(LocalArtifactStore(tmp_path / "objects"))
    result = sandbox.execute(
        legitimate_app_payment_plan("control", "control-1", active_call=True),
        WorldSeed(master_seed=1),
        cycle_id="control-1",
    )
    names = {signal.name for signal in all_signals(result.trace.observed_view())}
    assert names == {"active_external_call"}
    assert trace_features(result.trace.observed_view())["active_external_call"] == 0.35


def test_family_holdout_manifest_is_deterministic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from forge.cycle_runner import run_offline_cycle
    from forge.detect import dataset as dataset_module
    from forge.detect.dataset import build_family_holdout_dataset
    from forge.redteam.fixtures import draft_for_tactic

    monkeypatch.setattr(dataset_module, "DATASETS_ROOT", tmp_path / "datasets")
    registry = SQLiteRegistry(tmp_path / "registry.sqlite")
    store = LocalArtifactStore(tmp_path / "objects")
    for repeat in range(2):
        for index, variant in enumerate(
            ("safe_account", "family_emergency", "investment_coaching")
        ):
            seed = 100 + repeat * 10 + index
            run_app_scam_cycle(
                seed=seed,
                cycle_id=f"cycle-{variant}-{repeat}",
                registry=registry,
                store=store,
                variant=variant,
            )
    run_offline_cycle(501, registry, draft=draft_for_tactic("reconnaissance"))
    run_offline_cycle(502, registry, draft=draft_for_tactic("stealth"))

    first = build_family_holdout_dataset(
        registry,
        n_negatives_per_split=4,
        dataset_seed=7,
        calibration_family="ai_family_emergency",
        test_family="ai_investment_coaching",
    )
    second = build_family_holdout_dataset(
        registry,
        n_negatives_per_split=4,
        dataset_seed=7,
        calibration_family="ai_family_emergency",
        test_family="ai_investment_coaching",
    )
    assert first.dataset_id == second.dataset_id
    assert first.split_protocol == "attack-family-disjoint-holdout"
    assert first.feature_schema_version == FEATURE_SCHEMA_VERSION
    assert len(first.held_out_families) == 2
    assert first.split_positive_counts == {"train": 4, "calib": 2, "test": 2}
    assert first.included_tracks == [
        DetectionTrack.AI_ASSISTED_APP,
        DetectionTrack.BEHAVIORAL_PAYMENT,
    ]
    assert first.train_tracks == [
        DetectionTrack.AI_ASSISTED_APP,
        DetectionTrack.BEHAVIORAL_PAYMENT,
    ]
    manifest = json.loads(Path(first.manifest_path or "").read_text())
    assert manifest["sha256"] in first.dataset_id or first.dataset_id.endswith(
        manifest["sha256"][:10]
    )
    assert {row["track"] for row in manifest["rows"] if row["label"] == 1} == {
        DetectionTrack.AI_ASSISTED_APP.value,
        DetectionTrack.BEHAVIORAL_PAYMENT.value,
    }


def test_family_holdout_prefers_families_with_promotion_sized_samples(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from forge.detect import dataset as dataset_module
    from forge.detect.dataset import build_family_holdout_dataset

    monkeypatch.setattr(dataset_module, "DATASETS_ROOT", tmp_path / "datasets")
    registry = SQLiteRegistry(tmp_path / "registry.sqlite")
    store = LocalArtifactStore(tmp_path / "objects")
    variants = ("safe_account", "family_emergency", "investment_coaching")
    for index, variant in enumerate(variants):
        repeats = 20 if variant != "investment_coaching" else 2
        for repeat in range(repeats):
            run_app_scam_cycle(
                seed=1000 + index * 100 + repeat,
                cycle_id=f"cycle-{variant}-{repeat}",
                registry=registry,
                store=store,
                variant=variant,
            )

    ref = build_family_holdout_dataset(registry, n_negatives_per_split=4)

    assert set(ref.held_out_families) == {"ai_bank_impersonation", "ai_family_emergency"}
    assert ref.split_positive_counts["calib"] == 20
    assert ref.split_positive_counts["test"] == 20


def test_internal_preparation_remains_hidden_for_every_variant(tmp_path: Path) -> None:
    sandbox = ActorSandbox(LocalArtifactStore(tmp_path / "objects"))
    for variant in ("safe_account", "family_emergency", "investment_coaching"):
        result = sandbox.execute(
            ai_assisted_app_scam_plan("strategy", f"cycle-{variant}", variant=variant),
            WorldSeed(master_seed=2),
            cycle_id=f"cycle-{variant}",
        )
        observed = result.trace.observed_view().model_dump_json().lower()
        assert "media.generated" not in observed
        assert "synthetic" not in observed
