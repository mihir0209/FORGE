"""Tests for Adversarial Concept Drift & Distribution Shift Detector."""

import pytest
import random
from forge.concept_drift import (
    PageHinkleyConfig,
    PageHinkleyDetector,
    compute_two_sample_ks,
    ConceptDriftEngine,
    DriftSeverity,
)


def test_page_hinkley_stationary_vs_abrupt_shift():
    random.seed(42)
    cfg = PageHinkleyConfig(delta=0.01, threshold=25.0)
    detector = PageHinkleyDetector(cfg)

    # 1. Stationary zero-mean residuals
    for _ in range(150):
        val = random.gauss(0.0, 0.5)
        drift, stat = detector.update(val)
        assert not drift
        assert stat < 20.0

    # 2. Abrupt mean shift (fraud attack starts producing large prediction errors)
    drift_triggered = False
    for _ in range(100):
        val = random.gauss(3.5, 0.8)
        drift, stat = detector.update(val)
        if drift:
            drift_triggered = True
            break

    assert drift_triggered, "Page-Hinkley must detect abrupt shift in residuals"


def test_two_sample_ks_identical_vs_divergent_distributions():
    random.seed(42)
    # Identical standard normal
    s1 = [random.gauss(0.0, 1.0) for _ in range(100)]
    s2 = [random.gauss(0.0, 1.0) for _ in range(100)]
    d_stat, p_val = compute_two_sample_ks(s1, s2)

    assert d_stat < 0.25
    assert p_val > 0.05

    # Divergent distribution (shifted mean)
    s3 = [random.gauss(2.5, 1.0) for _ in range(100)]
    d_stat_div, p_val_div = compute_two_sample_ks(s1, s3)

    assert d_stat_div > 0.60
    assert p_val_div < 0.01


def test_concept_drift_engine_holistic_lifecycle():
    random.seed(42)
    engine = ConceptDriftEngine(
        reference_window_size=100,
        streaming_window_size=50,
        ph_config=PageHinkleyConfig(delta=0.02, threshold=20.0),
        ks_alpha=0.05,
    )

    baseline = [random.gauss(0.1, 0.05) for _ in range(100)]
    engine.set_reference_distribution(baseline)

    # Stream stationary data
    for _ in range(40):
        report = engine.update(random.gauss(0.1, 0.05))

    assert report.severity in {DriftSeverity.STABLE, DriftSeverity.WARNING}
    assert not report.requires_retraining

    # Stream hostile drifted distribution
    drift_found = False
    for _ in range(60):
        val = random.gauss(0.85, 0.10)
        report = engine.update(val)
        if report.severity == DriftSeverity.DRIFT_DETECTED:
            drift_found = True
            assert report.requires_retraining
            assert "Adversarial concept drift detected" in report.description
            break

    assert drift_found, "Engine must trigger DRIFT_DETECTED on sustained hostile distribution shift"
