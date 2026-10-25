"""Adversarial Model Drift & Concept Drift Detector for FORGE.

Monitors streaming fraud prediction scores and transaction feature streams
to detect adversarial distribution shifts using the Page-Hinkley cumulative sum test
and two-sample Kolmogorov-Smirnov (KS) distribution divergence tests.
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Sequence, Tuple


class DriftSeverity(str, Enum):
    STABLE = "STABLE"
    WARNING = "WARNING"
    DRIFT_DETECTED = "DRIFT_DETECTED"


@dataclass
class PageHinkleyConfig:
    delta: float = 0.005  # Tolerance parameter
    threshold: float = 50.0  # Detection threshold lambda
    alpha: float = 0.999  # Forgetting factor / exponential decay


@dataclass
class DriftMetricReport:
    step_count: int
    severity: DriftSeverity
    page_hinkley_stat: float
    ks_statistic: float
    ks_p_value: float
    running_mean_error: float
    requires_retraining: bool
    description: str


class PageHinkleyDetector:
    """Online sequential cumulative sum detector for sudden and gradual mean shifts."""

    def __init__(self, config: Optional[PageHinkleyConfig] = None) -> None:
        self.config = config or PageHinkleyConfig()
        self.reset()

    def reset(self) -> None:
        self.sample_count = 0
        self.mean = 0.0
        self.cum_sum = 0.0
        self.min_cum_sum = 0.0
        self.drift_detected = False

    def update(self, error_value: float) -> Tuple[bool, float]:
        """Update with a new error/residual and return (is_drift, ph_statistic)."""
        self.sample_count += 1
        # Incremental mean
        self.mean += (error_value - self.mean) / self.sample_count

        # Cumulative difference from mean with delta margin
        self.cum_sum += (error_value - self.mean - self.config.delta)

        if self.cum_sum < self.min_cum_sum:
            self.min_cum_sum = self.cum_sum

        ph_stat = self.cum_sum - self.min_cum_sum

        if ph_stat > self.config.threshold:
            self.drift_detected = True
            return True, ph_stat

        return False, ph_stat


def compute_two_sample_ks(sample1: Sequence[float], sample2: Sequence[float]) -> Tuple[float, float]:
    """Compute two-sample Kolmogorov-Smirnov statistic D and approximate asymptotic p-value."""
    n1 = len(sample1)
    n2 = len(sample2)

    if n1 == 0 or n2 == 0:
        return 0.0, 1.0

    s1 = sorted(sample1)
    s2 = sorted(sample2)

    # All unique values sorted
    all_values = sorted(set(s1 + s2))

    idx1 = 0
    idx2 = 0
    d_max = 0.0

    for val in all_values:
        while idx1 < n1 and s1[idx1] <= val:
            idx1 += 1
        while idx2 < n2 and s2[idx2] <= val:
            idx2 += 1

        cdf1 = idx1 / n1
        cdf2 = idx2 / n2
        dist = abs(cdf1 - cdf2)
        if dist > d_max:
            d_max = dist

    # Effective sample size
    en = math.sqrt((n1 * n2) / (n1 + n2))
    # Asymptotic approximation for p-value using Kolmogorov distribution
    lambda_val = (en + 0.12 + 0.11 / en) * d_max

    if lambda_val <= 0:
        p_val = 1.0
    elif lambda_val >= 3.0:
        p_val = 0.0
    else:
        # Sum first 5 terms of Kolmogorov series: 2 * sum_{k=1}^inf (-1)^{k-1} exp(-2 * k^2 * lambda^2)
        sum_terms = 0.0
        for k in range(1, 6):
            sum_terms += ((-1) ** (k - 1)) * math.exp(-2.0 * (k ** 2) * (lambda_val ** 2))
        p_val = max(0.0, min(1.0, 2.0 * sum_terms))

    return round(d_max, 4), round(p_val, 4)


class ConceptDriftEngine:
    """Holistic concept and distribution drift monitor for streaming fraud scorers."""

    def __init__(
        self,
        reference_window_size: int = 200,
        streaming_window_size: int = 100,
        ph_config: Optional[PageHinkleyConfig] = None,
        ks_alpha: float = 0.05,
    ) -> None:
        self.reference_window_size = reference_window_size
        self.streaming_window_size = streaming_window_size
        self.ks_alpha = ks_alpha

        self.reference_data: List[float] = []
        self.streaming_buffer: deque[float] = deque(maxlen=streaming_window_size)
        self.ph_detector = PageHinkleyDetector(ph_config)
        self.step = 0

    def set_reference_distribution(self, baseline_samples: Sequence[float]) -> None:
        """Initialize the baseline reference distribution."""
        self.reference_data = list(baseline_samples[-self.reference_window_size :])
        self.ph_detector.reset()

    def update(self, score_or_residual: float) -> DriftMetricReport:
        """Stream a single score/residual and evaluate drift condition."""
        self.step += 1
        self.streaming_buffer.append(score_or_residual)

        # 1. Update Page-Hinkley sequential residual tracker
        ph_drift, ph_stat = self.ph_detector.update(score_or_residual)

        # 2. If buffer has reached streaming window size, compute two-sample KS test
        ks_stat = 0.0
        ks_p_val = 1.0

        if len(self.reference_data) >= 20 and len(self.streaming_buffer) >= 20:
            ks_stat, ks_p_val = compute_two_sample_ks(self.reference_data, list(self.streaming_buffer))

        ks_drift = ks_p_val < self.ks_alpha and ks_stat > 0.25

        # Determine severity and retraining decision
        if ph_drift or ks_drift:
            severity = DriftSeverity.DRIFT_DETECTED
            retrain = True
            desc = (
                f"Adversarial concept drift detected! PH-stat={ph_stat:.2f}, "
                f"KS-D={ks_stat:.3f} (p={ks_p_val:.4f}). Immediate retraining recommended."
            )
        elif ph_stat > (self.ph_detector.config.threshold * 0.6) or ks_p_val < (self.ks_alpha * 2):
            severity = DriftSeverity.WARNING
            retrain = False
            desc = (
                f"Elevated drift warning: PH-stat={ph_stat:.2f}, KS-D={ks_stat:.3f}. "
                "Monitoring distribution closely."
            )
        else:
            severity = DriftSeverity.STABLE
            retrain = False
            desc = "Data distribution and scoring residuals remain stationary."

        return DriftMetricReport(
            step_count=self.step,
            severity=severity,
            page_hinkley_stat=round(ph_stat, 4),
            ks_statistic=ks_stat,
            ks_p_value=ks_p_val,
            running_mean_error=round(self.ph_detector.mean, 4),
            requires_retraining=retrain,
            description=desc,
        )
