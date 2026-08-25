"""Causal temporal beneficiary graph for pre-authorization assessment."""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta

from forge.contracts.contracts import BeneficiaryGraphAssessment, GraphEvent, GraphScope


class TemporalRiskGraph:
    def __init__(self, events: list[GraphEvent]) -> None:
        self.events = sorted(events, key=lambda e: (e.event_time, e.available_at, e.event_id))

    def assess(
        self, beneficiary_ref: str, decision_at: object, scopes: list[GraphScope]
    ) -> BeneficiaryGraphAssessment:
        from datetime import datetime

        if not isinstance(decision_at, datetime):
            raise TypeError("decision_at must be datetime")
        known = [e for e in self.events if e.event_time < decision_at and e.available_at <= decision_at]
        inbound = [e for e in known if e.destination_account_ref == beneficiary_ref and e.kind == "payment.settled"]
        outbound = [e for e in known if e.source_account_ref == beneficiary_ref and e.kind in {"payment.settled", "cash_out"}]
        recent_in = [e for e in inbound if e.event_time >= decision_at - timedelta(hours=1)]
        recent_out = [e for e in outbound if e.event_time >= decision_at - timedelta(hours=2)]
        opened = [e for e in known if e.kind == "account.opened" and e.destination_account_ref == beneficiary_ref]
        age = (decision_at - opened[0].event_time).days if opened else 3650
        in_value = sum(e.amount_minor for e in inbound)
        out_value = sum(e.amount_minor for e in outbound)
        pass_through = min(out_value / in_value, 1.0) if in_value else 0.0
        labeled = [e for e in known if e.kind == "fraud.label.observed" and e.destination_account_ref == beneficiary_ref]
        features = {
            "account_age_days": float(age),
            "unique_senders_1h": float(len({e.source_account_ref for e in recent_in})),
            "rapid_pass_through_ratio": pass_through,
            "outbound_events_2h": float(len(recent_out)),
            "known_fraud_labels": float(len(labeled)),
        }
        score = min(1.0, 0.3 * min(features["unique_senders_1h"] / 5, 1) + 0.35 * pass_through + 0.2 * (age < 14) + 0.15 * bool(labeled))
        features["network_risk_score"] = score
        body = json.dumps([e.model_dump(mode="json") for e in known], sort_keys=True, default=str)
        digest = hashlib.sha256(body.encode()).hexdigest()
        return BeneficiaryGraphAssessment(
            assessment_id=f"ga_{digest[:12]}", beneficiary_ref=beneficiary_ref,
            decision_at=decision_at, scopes=scopes, snapshot_id=f"gs_{digest[:12]}",
            snapshot_sha256=digest, features=features,
            evidence_event_ids=[e.event_id for e in recent_in + recent_out + opened + labeled],
        )


def graph_for_motif(motif: str, beneficiary_ref: str, decision_at: object) -> TemporalRiskGraph:
    from datetime import datetime

    if not isinstance(decision_at, datetime):
        raise TypeError("decision_at must be datetime")
    opened_days = 5 if motif in {"mule_fanin", "young_account"} else 400
    events = [GraphEvent(event_id="g-open", event_time=decision_at-timedelta(days=opened_days), available_at=decision_at-timedelta(days=opened_days), kind="account.opened", institution_id="bank-b", destination_account_ref=beneficiary_ref)]
    senders = 8 if motif == "mule_fanin" else 2
    for i in range(senders):
        events.append(GraphEvent(event_id=f"g-in-{i}", event_time=decision_at-timedelta(minutes=50-i), available_at=decision_at-timedelta(minutes=50-i), kind="payment.settled", institution_id="bank-a", source_account_ref=f"sender-{i}", destination_account_ref=beneficiary_ref, amount_minor=10000))
    if motif in {"mule_fanin", "rapid_passthrough"}:
        events.append(GraphEvent(event_id="g-out", event_time=decision_at-timedelta(minutes=5), available_at=decision_at-timedelta(minutes=5), kind="cash_out", institution_id="bank-b", source_account_ref=beneficiary_ref, destination_account_ref="offramp-1", amount_minor=60000))
    return TemporalRiskGraph(events)
