"""Blindness is a type error: ObservedTraceView must never carry ground truth."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from forge.contracts.contracts import (
    ActorKind,
    EvidenceScope,
    F3Mapping,
    FidelityReport,
    GroundTruth,
    LifecycleStage,
    ObservedTraceView,
    Provenance,
    StrategySpec,
    SyntheticTrace,
    TraceEvent,
    WorldSeed,
)


def _event(i: int, attack: bool = False) -> TraceEvent:
    return TraceEvent(
        event_id=f"e{i}",
        ts=datetime(2026, 8, 22, tzinfo=UTC),
        actor_kind=ActorKind.CUSTOMER,
        actor_id="c1",
        kind="payment",
        payload={"amount": 100 + i},
        is_attack_step=attack,
        attack_stage=LifecycleStage.PAYMENT if attack else None,
    )


def _fidelity() -> FidelityReport:
    return FidelityReport(
        psi_amount=0.01,
        ks_timestamp_gap=0.02,
        graph_density_delta=0.03,
        temporal_autocorr=0.04,
        reachability_ok=True,
    )


def _trace() -> SyntheticTrace:
    return SyntheticTrace(
        trace_id="t1",
        seed=WorldSeed(master_seed=42),
        events=[_event(0), _event(1, attack=True)],
        ground_truth=GroundTruth(strategy_id="s1", fingerprint="ab12"),
        fidelity=_fidelity(),
    )


def test_observed_view_strips_ground_truth() -> None:
    view = _trace().observed_view()
    assert all(e.is_attack_step is False for e in view.events)
    assert all(e.attack_stage is None for e in view.events)


def test_observed_view_cannot_be_constructed_with_labels() -> None:
    with pytest.raises(ValidationError):
        ObservedTraceView(trace_id="t", events=[_event(0, attack=True)])


def test_original_trace_is_untouched_by_view_construction() -> None:
    t = _trace()
    _ = t.observed_view()
    assert t.events[1].is_attack_step is True
    assert t.events[1].attack_stage == LifecycleStage.PAYMENT


def test_observed_view_drops_internal_events() -> None:
    trace = _trace()
    internal = _event(2).model_copy(update={"evidence_scope": EvidenceScope.INTERNAL})
    filtered = trace.model_copy(update={"events": [*trace.events, internal]}).observed_view()
    assert "e2" not in filtered.event_ids


def test_observed_view_rejects_internal_scope() -> None:
    with pytest.raises(ValidationError):
        ObservedTraceView(
            trace_id="t",
            events=[_event(0).model_copy(update={"evidence_scope": EvidenceScope.INTERNAL})],
        )


def _spec(**over: object) -> StrategySpec:
    base = dict(
        strategy_id="s1",
        fraud_objective="drain via refunds",
        attack_family="refund_abuse",
        f3=F3Mapping(tactic="positioning", techniques=["F1005.003"]),
        rail="card",
        channel="web",
        lifecycle_stages=[LifecycleStage.PAYMENT, LifecycleStage.REFUND],
        behavioral_sequence=["open_session", "pay_small", "request_refund"],
        genai_leverage="synthetic complaint text",
        evasion_hypothesis="mimic category rhythm",
        novelty_rationale="new combination",
        provenance=Provenance(provider="openai", model="gpt-4o-mini"),
    )
    base.update(over)  # type: ignore[arg-type]
    return StrategySpec.model_validate(base)


def test_strategy_fingerprint_is_stable_and_sensitive() -> None:
    s = _spec()
    assert s.fingerprint() == _spec().fingerprint()
    assert s.fingerprint() != _spec(channel="mobile").fingerprint()


def test_extra_fields_are_forbidden() -> None:
    with pytest.raises(ValidationError):
        TraceEvent(
            event_id="e9",
            ts=datetime(2026, 8, 22, tzinfo=UTC),
            actor_kind=ActorKind.CUSTOMER,
            actor_id="c1",
            kind="payment",
            payload={},
            sneaky=True,  # type: ignore[call-arg]
        )
