"""Causal temporal beneficiary graph for pre-authorization assessment."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from typing import Any

from forge.contracts.contracts import (
    BeneficiaryGraphAssessment,
    GraphEvent,
    GraphQuery,
    GraphScope,
    GraphSnapshot,
)
from forge.graph_store import GraphEventStore, InMemoryGraphStore

FEATURE_VERSION = "beneficiary-risk-v1"
KNOWN_MOTIFS = frozenset({"established_account", "mule_fanin", "rapid_passthrough", "young_account"})


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def deterministic_event_id(
    *,
    event_time: datetime,
    available_at: datetime,
    kind: str,
    institution_id: str,
    source_account_ref: str | None = None,
    destination_account_ref: str | None = None,
    device_ref: str | None = None,
    identity_ref: str | None = None,
    amount_minor: int = 0,
    attributes: dict[str, Any] | None = None,
) -> str:
    """Derive an event ID from every immutable event field."""
    payload = {
        "amount_minor": amount_minor,
        "attributes": attributes or {},
        "available_at": available_at.isoformat(),
        "destination_account_ref": destination_account_ref,
        "device_ref": device_ref,
        "event_time": event_time.isoformat(),
        "identity_ref": identity_ref,
        "institution_id": institution_id,
        "kind": kind,
        "source_account_ref": source_account_ref,
    }
    return f"ge_{hashlib.sha256(_canonical(payload).encode()).hexdigest()}"


def make_graph_event(**values: Any) -> GraphEvent:
    event_id = deterministic_event_id(**values)
    return GraphEvent(event_id=event_id, **values)


class TemporalRiskGraph:
    def __init__(
        self, events: list[GraphEvent] | None = None, *, store: GraphEventStore | None = None
    ) -> None:
        self.store = store or InMemoryGraphStore()
        for event in events or []:
            self.store.append(event)

    @classmethod
    def reload(cls, store: GraphEventStore) -> TemporalRiskGraph:
        return cls(store=store)

    @property
    def events(self) -> list[GraphEvent]:
        return sorted(
            self.store.events(), key=lambda event: (event.event_time, event.available_at, event.event_id)
        )

    def append(self, event: GraphEvent) -> None:
        self.store.append(event)

    def assess_query(self, query: GraphQuery) -> BeneficiaryGraphAssessment:
        known = [
            event
            for event in self.events
            if event.event_time < query.decision_at and event.available_at <= query.decision_at
        ]
        if GraphScope.CONSORTIUM not in query.scopes:
            known = [
                event for event in known if event.institution_id == query.local_institution_id
            ]

        beneficiary = query.beneficiary_ref
        relevant_accounts = {beneficiary}
        direct = [
            event
            for event in known
            if event.source_account_ref == beneficiary
            or event.destination_account_ref == beneficiary
        ]
        for event in direct:
            if event.source_account_ref:
                relevant_accounts.add(event.source_account_ref)
            if event.destination_account_ref:
                relevant_accounts.add(event.destination_account_ref)
        known = [
            event
            for event in known
            if event in direct
            or event.source_account_ref in relevant_accounts
            or event.destination_account_ref in relevant_accounts
        ]
        inbound = [
            event
            for event in known
            if event.destination_account_ref == beneficiary and event.kind == "payment.settled"
        ]
        outbound = [
            event
            for event in known
            if event.source_account_ref == beneficiary
            and event.kind in {"payment.settled", "cash_out"}
        ]
        recent_in_1h = [
            event for event in inbound if event.event_time >= query.decision_at - timedelta(hours=1)
        ]
        recent_in_2h = [
            event for event in inbound if event.event_time >= query.decision_at - timedelta(hours=2)
        ]
        recent_out_2h = [
            event for event in outbound if event.event_time >= query.decision_at - timedelta(hours=2)
        ]
        opened = [
            event
            for event in known
            if event.kind == "account.opened" and event.destination_account_ref == beneficiary
        ]
        age = (query.decision_at - opened[0].event_time).days if opened else 3650
        inbound_value_2h = sum(event.amount_minor for event in recent_in_2h)
        outbound_value_2h = sum(event.amount_minor for event in recent_out_2h)
        pass_through = (
            min(outbound_value_2h / inbound_value_2h, 1.0) if inbound_value_2h else 0.0
        )
        labeled = [
            event
            for event in known
            if event.kind == "fraud.label.observed"
            and event.destination_account_ref == beneficiary
        ]
        features = {
            "account_age_days": float(age),
            "unique_senders_1h": float(
                len({event.source_account_ref for event in recent_in_1h})
            ),
            "rapid_pass_through_ratio": pass_through,
            "outbound_events_2h": float(len(recent_out_2h)),
            "known_fraud_labels": float(len(labeled)),
        }
        features["network_risk_score"] = min(
            1.0,
            0.3 * min(features["unique_senders_1h"] / 5, 1)
            + 0.35 * pass_through
            + 0.2 * (age < 14)
            + 0.15 * bool(labeled),
        )

        canonical_json = _canonical(
            {
                "events": [event.model_dump(mode="json") for event in known],
                "query": {
                    **query.model_dump(mode="json", exclude={"scopes"}),
                    "scopes": sorted(scope.value for scope in query.scopes),
                },
            }
        )
        digest = hashlib.sha256(canonical_json.encode()).hexdigest()
        snapshot = GraphSnapshot(
            snapshot_id=f"gs_{digest}",
            snapshot_sha256=digest,
            query=query,
            event_ids=[event.event_id for event in known],
            canonical_json=canonical_json,
        )
        self.store.persist_snapshot(snapshot)
        evidence = recent_in_2h + recent_out_2h + opened + labeled
        return BeneficiaryGraphAssessment(
            assessment_id=f"ga_{digest}",
            beneficiary_ref=beneficiary,
            decision_at=query.decision_at,
            scopes=query.scopes,
            snapshot_id=snapshot.snapshot_id,
            snapshot_sha256=digest,
            features=features,
            evidence_event_ids=list(dict.fromkeys(event.event_id for event in evidence)),
        )

    def assess(
        self,
        beneficiary_ref: str,
        decision_at: object,
        scopes: list[GraphScope],
        *,
        local_institution_id: str | None = None,
        feature_version: str = FEATURE_VERSION,
    ) -> BeneficiaryGraphAssessment:
        if not isinstance(decision_at, datetime):
            raise TypeError("decision_at must be datetime")
        if (
            GraphScope.LOCAL_BANK in scopes
            and GraphScope.CONSORTIUM not in scopes
            and local_institution_id is None
        ):
            institutions = {event.institution_id for event in self.events}
            if len(institutions) != 1:
                raise ValueError("local_bank scope requires local_institution_id")
            local_institution_id = next(iter(institutions))
        return self.assess_query(
            GraphQuery(
                beneficiary_ref=beneficiary_ref,
                decision_at=decision_at,
                scopes=scopes,
                local_institution_id=local_institution_id,
                feature_version=feature_version,
            )
        )


def graph_for_motif(
    motif: str,
    beneficiary_ref: str,
    decision_at: object,
    *,
    store: GraphEventStore | None = None,
) -> TemporalRiskGraph:
    if not isinstance(decision_at, datetime):
        raise TypeError("decision_at must be datetime")
    if motif not in KNOWN_MOTIFS:
        raise ValueError(f"unknown graph motif: {motif}")
    opened_days = 5 if motif in {"mule_fanin", "young_account"} else 400
    events = [
        make_graph_event(
            event_time=decision_at - timedelta(days=opened_days),
            available_at=decision_at - timedelta(days=opened_days),
            kind="account.opened",
            institution_id="bank-b",
            destination_account_ref=beneficiary_ref,
        )
    ]
    senders = 8 if motif == "mule_fanin" else 2
    for index in range(senders):
        event_time = decision_at - timedelta(minutes=50 - index)
        events.append(
            make_graph_event(
                event_time=event_time,
                available_at=event_time,
                kind="payment.settled",
                institution_id="bank-b",
                source_account_ref=f"sender-{index}",
                destination_account_ref=beneficiary_ref,
                amount_minor=10000,
            )
        )
    if motif in {"mule_fanin", "rapid_passthrough"}:
        event_time = decision_at - timedelta(minutes=5)
        events.append(
            make_graph_event(
                event_time=event_time,
                available_at=event_time,
                kind="cash_out",
                institution_id="bank-b",
                source_account_ref=beneficiary_ref,
                destination_account_ref="offramp-1",
                amount_minor=60000,
            )
        )
    return TemporalRiskGraph(events, store=store)
