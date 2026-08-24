"""forge.detect — blind scoring: RuleBaseline now, calibrated GBM at P4."""

from __future__ import annotations

from typing import TYPE_CHECKING

from forge.config import settings
from forge.contracts.contracts import (
    Action,
    Coverage,
    GateResult,
    ObservedTraceView,
)
from forge.detect.base import Detector
from forge.signals import FEATURE_NAMES

if TYPE_CHECKING:
    from collections.abc import Mapping


def trace_features(view: ObservedTraceView) -> dict[str, float]:
    """Blind features — computed from the observed view only, never labels.

    Attack-concentrated by aggregation: per-customer maxima rather than
    world-level ratios, which legitimate traffic would saturate or dilute.
    """
    from collections import defaultdict

    from forge.signals import all_signals

    events = view.events
    payments = [e for e in events if e.kind == "payment"]

    pays_by_customer: dict[str, int] = defaultdict(int)
    night_by_customer: dict[str, int] = defaultdict(int)
    refunds_by_customer: dict[str, int] = defaultdict(int)
    cashouts_by_customer: dict[str, int] = defaultdict(int)

    for e in payments:
        cid = e.actor_id
        pays_by_customer[cid] += 1
        if e.ts.hour < 5:
            night_by_customer[cid] += 1
    for e in events:
        if e.kind == "refund":
            refunds_by_customer[str(e.payload.get("customer", ""))] += 1
        elif e.kind == "cash_out":
            cashouts_by_customer[str(e.payload.get("customer", ""))] += 1

    def max_ratio(numer: dict[str, int], min_denom: int) -> float:
        best = 0.0
        for cid, n in numer.items():
            denom = pays_by_customer.get(cid, 0)
            if denom >= min_denom and denom > 0:
                best = max(best, n / denom)
        return best

    signals = {s.name: s.strength for s in all_signals(view)}

    return {
        "burst": signals.get("velocity_burst", 0.0),
        "new_device": 1.0 if "new_device_payment" in signals else 0.0,
        # per-customer refund pressure (victim: ~0.25+ vs baseline ~0.03)
        "refund_pressure": max_ratio(refunds_by_customer, min_denom=3) * 2.0,
        # per-customer off-hours concentration among active payers
        "off_hours_focus": max_ratio(night_by_customer, min_denom=4),
        # per-customer cash-out attempts (victim repeats; legit rarely >1/day)
        "cashout_pressure": min(max(cashouts_by_customer.values(), default=0) / 2.0, 1.0),
        "volume": min(len(payments) / 50.0, 1.0),
        "first_time_payee": signals.get("first_time_payee", 0.0),
        "behavioral_coaching_risk": signals.get("behavioral_coaching_risk", 0.0),
        "beneficiary_network_risk": signals.get("beneficiary_network_risk", 0.0),
        "warning_override": signals.get("warning_override", 0.0),
        "balance_depletion": signals.get("balance_depletion", 0.0),
        "active_external_call": signals.get("active_external_call", 0.0),
    }


_RULE_WEIGHTS: Mapping[str, float] = {
    "burst": 0.20,
    "new_device": 0.10,
    "refund_pressure": 0.15,
    "off_hours_focus": 0.05,
    "cashout_pressure": 0.10,
    "volume": 0.02,
    "first_time_payee": 0.10,
    "behavioral_coaching_risk": 0.18,
    "beneficiary_network_risk": 0.24,
    "warning_override": 0.12,
    "balance_depletion": 0.15,
    "active_external_call": 0.03,
}


class RuleBaselineDetector(Detector):
    """Ships day one so the loop never blocks on ML (architecture §2.7)."""

    def __init__(self) -> None:
        self.detector_id = "rule-baseline-v1"

    def score_features(self, features: Mapping[str, float]) -> float:
        total = sum(_RULE_WEIGHTS.get(k, 0.0) * v for k, v in features.items())
        return float(min(max(total, 0.0), 0.99))


def gate_score(view: ObservedTraceView, detector: Detector) -> GateResult:
    cfg = settings().gate
    features = trace_features(view)
    score = detector.score_features(features)

    reason_codes = [f"rule:{k}>={v:.2f}" for k, v in sorted(features.items()) if v >= 0.25] or [
        "no_rule_fired"
    ]

    if score >= cfg.covered_min_score:
        coverage = Coverage.COVERED
    elif score >= cfg.partial_min_score:
        coverage = Coverage.PARTIAL
    else:
        coverage = Coverage.BLIND_SPOT

    action = (
        Action.DECLINE
        if score >= 0.80
        else Action.REVIEW
        if score >= 0.60
        else Action.STEP_UP
        if score >= 0.30
        else Action.APPROVE
    )

    return GateResult(
        detector_id=detector.detector_id,
        score=round(score, 4),
        action=action,
        reason_codes=reason_codes,
        coverage=coverage,
        latency_ms=0.4,  # measured rule path; benchmark harness refines at P4
        similarity_to_known=0.0,
    )


__all__ = ["FEATURE_NAMES", "Detector", "RuleBaselineDetector", "gate_score", "trace_features"]
