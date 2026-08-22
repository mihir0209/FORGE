# pyright: reportMissingTypeStubs=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false
"""P4: dataset builder, LightGBM training, promotion gates, incumbent pointer."""

from pathlib import Path

import pandas as pd
import pytest

from forge.contracts.contracts import WorldSeed
from forge.detect import trace_features
from forge.kb import SQLiteRegistry
from forge.simulate import build_legit_trace, simulate
from tests.fixtures_spec import make_spec


def _registry_with_cycles(tmp_path: Path, n_cycles: int = 8) -> SQLiteRegistry:
    """In-process corpus generation (no subprocess WAL issues)."""
    from forge.cycle_runner import run_offline_cycle
    from forge.gapmine import rank
    from forge.redteam.fixtures import draft_for_tactic

    reg = SQLiteRegistry(tmp_path / "reg.sqlite")
    for seed in range(60, 60 + n_cycles):
        briefs = rank(reg)
        tactic = briefs[0].suggested_family.removesuffix("_family") if briefs else "monetization"
        draft = draft_for_tactic(tactic)
        run_offline_cycle(seed, reg, draft=draft)
    return reg


def test_dataset_builder_produces_versioned_splits(tmp_path: Path) -> None:
    from forge.detect.dataset import build_dataset

    reg = _registry_with_cycles(tmp_path, n_cycles=8)
    ref = build_dataset(reg, n_negatives=24, dataset_seed=0)

    assert ref.rows == 32  # 8 positives (one per distinct) + 24 negatives
    for p in [ref.train_path, ref.calib_path, ref.test_path]:
        df = pd.read_parquet(p)
        assert set(df.columns) == {
            "burst",
            "new_device",
            "refund_pressure",
            "off_hours_focus",
            "cashout_pressure",
            "volume",
            "label",
        }
        assert df["label"].nunique() == 2  # both classes present in each split


def test_train_produces_candidate_with_metrics(tmp_path: Path) -> None:
    from forge.detect.dataset import build_dataset
    from forge.detect.train import train_detector

    reg = _registry_with_cycles(tmp_path, n_cycles=8)
    ref = build_dataset(reg, n_negatives=40, dataset_seed=1)
    report = train_detector(ref, n_estimators=40)

    assert report.roc_auc >= 0.80
    assert report.p95_latency_ms < 100
    assert Path(report.artifact_path).exists()
    assert report.artifact_path.endswith(".joblib")


def test_promotion_evaluates_and_installs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from forge.detect.dataset import build_dataset
    from forge.detect.incumbent import load_incumbent
    from forge.detect.promotion import evaluate, install_if_passed
    from forge.detect.train import train_detector

    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path))

    reg = _registry_with_cycles(tmp_path, n_cycles=8)
    ref = build_dataset(reg, n_negatives=40, dataset_seed=2)
    report = train_detector(ref, n_estimators=40)

    verdict = evaluate(report, reg)
    assert verdict.passed is True
    assert verdict.checks["roc_auc_ge_0.85"] is True

    ok = install_if_passed(report, verdict)
    assert ok is True

    det = load_incumbent()
    assert det.detector_id == report.candidate_id

    # gate now uses the incumbent: attack scores higher than legit
    attack_view = simulate(make_spec(), WorldSeed(master_seed=999)).trace.observed_view()
    legit_view = build_legit_trace(WorldSeed(master_seed=999)).observed_view()
    assert det.score_features(trace_features(attack_view)) > det.score_features(
        trace_features(legit_view)
    )


def test_promotion_fails_when_candidate_is_trivial(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A degenerate candidate (e.g. all-zero predictions) should not promote."""
    from forge.contracts.contracts import CandidateReport, DatasetRef
    from forge.detect.promotion import evaluate

    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path))
    reg = _registry_with_cycles(tmp_path, n_cycles=4)

    fake = CandidateReport(
        candidate_id="cand_fake",
        dataset=DatasetRef(
            dataset_id="ds_fake",
            train_path="x",
            calib_path="x",
            test_path="x",
            rows=10,
        ),
        precision=0.0,
        recall=0.0,
        f1=0.0,
        roc_auc=0.50,
        pr_auc=0.50,
        recall_at_fpr_1e3=0.0,
        recall_at_fpr_1e2=0.0,
        brier=0.40,
        p50_latency_ms=1.0,
        p95_latency_ms=1.0,
        artifact_path="/nonexistent.joblib",
    )
    verdict = evaluate(fake, reg)
    assert verdict.passed is False
