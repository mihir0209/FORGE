"""Conformance tests for causal graph persistence and query identity."""

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from forge.contracts.contracts import GraphEvent, GraphQuery, GraphScope
from forge.graph_store import GraphConflictError, InMemoryGraphStore, SQLiteGraphStore
from forge.risk_graph import TemporalRiskGraph, graph_for_motif, make_graph_event

NOW = datetime(2026, 8, 25, 12, tzinfo=UTC)


def _event(
    minutes: int,
    *,
    institution: str = "bank-a",
    source: str = "sender",
    destination: str = "payee",
    kind: str = "payment.settled",
    available_at: datetime | None = None,
    amount: int = 100,
) -> GraphEvent:
    event_time = NOW - timedelta(minutes=minutes)
    return make_graph_event(
        event_time=event_time,
        available_at=available_at or event_time,
        kind=kind,
        institution_id=institution,
        source_account_ref=source,
        destination_account_ref=destination,
        amount_minor=amount,
    )


@pytest.mark.parametrize("adapter", ["memory", "sqlite"])
def test_event_store_is_append_only_and_replay_is_idempotent(
    adapter: str, tmp_path: Path
) -> None:
    store = InMemoryGraphStore() if adapter == "memory" else SQLiteGraphStore(tmp_path / "graph.db")
    event = _event(10)
    store.append(event)
    store.append(event)
    assert store.events() == [event]

    conflict = event.model_copy(update={"amount_minor": 999})
    with pytest.raises(GraphConflictError, match="event conflict"):
        store.append(conflict)


def test_sqlite_reload_replays_events_and_snapshot(tmp_path: Path) -> None:
    path = tmp_path / "graph.db"
    store = SQLiteGraphStore(path)
    graph = TemporalRiskGraph([_event(10)], store=store)
    query = GraphQuery(
        beneficiary_ref="payee",
        decision_at=NOW,
        scopes=[GraphScope.LOCAL_BANK],
        local_institution_id="bank-a",
    )
    first = graph.assess_query(query)
    store.close()

    reloaded_store = SQLiteGraphStore(path)
    second = TemporalRiskGraph.reload(reloaded_store).assess_query(query)
    assert second == first
    snapshot = reloaded_store.load_snapshot(first.snapshot_id)
    assert snapshot is not None
    assert snapshot.snapshot_sha256 == first.snapshot_sha256
    assert hashlib.sha256(snapshot.canonical_json.encode()).hexdigest() == snapshot.snapshot_sha256
    assert snapshot.event_ids == [store_event.event_id for store_event in reloaded_store.events()]


def test_future_and_delayed_events_are_excluded_until_available() -> None:
    graph = TemporalRiskGraph(
        [
            _event(10),
            _event(-1, source="future"),
            _event(
                24 * 60,
                source="label-source",
                kind="fraud.label.observed",
                available_at=NOW + timedelta(days=1),
                amount=0,
            ),
        ]
    )
    assessment = graph.assess(
        "payee", NOW, [GraphScope.LOCAL_BANK], local_institution_id="bank-a"
    )
    assert assessment.features["unique_senders_1h"] == 1
    assert assessment.features["known_fraud_labels"] == 0


def test_local_scope_isolated_from_consortium() -> None:
    graph = TemporalRiskGraph(
        [_event(10, institution="bank-a", source="a"), _event(9, institution="bank-b", source="b")]
    )
    local = graph.assess(
        "payee", NOW, [GraphScope.LOCAL_BANK], local_institution_id="bank-a"
    )
    consortium = graph.assess("payee", NOW, [GraphScope.CONSORTIUM])
    assert local.features["unique_senders_1h"] == 1
    assert consortium.features["unique_senders_1h"] == 2
    assert local.snapshot_id != consortium.snapshot_id


def test_snapshot_is_reproducible_and_bound_to_full_query() -> None:
    events = [_event(10)]
    first = TemporalRiskGraph(events).assess(
        "payee", NOW, [GraphScope.LOCAL_BANK], local_institution_id="bank-a"
    )
    repeated = TemporalRiskGraph(list(reversed(events))).assess(
        "payee", NOW, [GraphScope.LOCAL_BANK], local_institution_id="bank-a"
    )
    other_beneficiary = TemporalRiskGraph(events).assess(
        "other", NOW, [GraphScope.LOCAL_BANK], local_institution_id="bank-a"
    )
    other_version = TemporalRiskGraph(events).assess(
        "payee",
        NOW,
        [GraphScope.LOCAL_BANK],
        local_institution_id="bank-a",
        feature_version="beneficiary-risk-v2",
    )
    reordered_scopes = TemporalRiskGraph(events).assess(
        "payee",
        NOW,
        [GraphScope.CONSORTIUM, GraphScope.LOCAL_BANK],
        local_institution_id="bank-a",
    )
    canonical_scopes = TemporalRiskGraph(events).assess(
        "payee",
        NOW,
        [GraphScope.LOCAL_BANK, GraphScope.CONSORTIUM],
        local_institution_id="bank-a",
    )
    assert first.snapshot_id == repeated.snapshot_id
    assert first.snapshot_sha256 == repeated.snapshot_sha256
    assert first.snapshot_id != other_beneficiary.snapshot_id
    assert first.snapshot_id != other_version.snapshot_id
    assert reordered_scopes.snapshot_id == canonical_scopes.snapshot_id


def test_event_ids_are_deterministic_and_content_addressed() -> None:
    first = _event(10)
    assert _event(10).event_id == first.event_id
    assert _event(10, amount=101).event_id != first.event_id
    assert first.event_id.startswith("ge_")
    assert len(first.event_id) == 67


def test_pass_through_uses_aligned_two_hour_windows() -> None:
    graph = TemporalRiskGraph(
        [
            _event(180, amount=10_000),
            _event(60, amount=200),
            _event(30, source="payee", destination="offramp", kind="cash_out", amount=100),
        ]
    )
    assessment = graph.assess(
        "payee", NOW, [GraphScope.LOCAL_BANK], local_institution_id="bank-a"
    )
    assert assessment.features["rapid_pass_through_ratio"] == 0.5


def test_unknown_motif_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown graph motif"):
        graph_for_motif("invented", "payee", NOW)
