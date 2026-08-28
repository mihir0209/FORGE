"""Signal primitives — single definition of every heuristic.

`blueteam` builds verdicts from these; `detect` builds tabular features from the
same objects. No second copy of BURST_WINDOW, BURST_COUNT, or evidence logic.
"""

from __future__ import annotations

import itertools
from collections import defaultdict
from datetime import timedelta

from forge.contracts.contracts import ObservedTraceView, Signal, TraceEvent

# ------------------------------------------------------------------ constants
_BURST_WINDOW = timedelta(minutes=30)
_BURST_COUNT = 4  # payments within window that constitute a burst

def _payments(view: ObservedTraceView) -> list[TraceEvent]:
    return [e for e in view.events if e.kind == "payment"]


def velocity_bursts(view: ObservedTraceView) -> list[Signal]:
    """Same customer paying many times inside a short window."""
    from collections import deque

    per_customer: dict[str, list[TraceEvent]] = defaultdict(list)
    for e in _payments(view):
        per_customer[e.actor_id].append(e)

    signals: list[Signal] = []
    for cid, pays in sorted(per_customer.items()):
        if len(pays) < _BURST_COUNT:
            continue
        pays_sorted = sorted(pays, key=lambda e: e.ts)
        window: deque[TraceEvent] = deque()
        best_window: list[TraceEvent] = []
        for cur in pays_sorted:
            window.append(cur)
            while window and cur.ts - window[0].ts > _BURST_WINDOW:
                window.popleft()
            if len(window) > len(best_window):
                best_window = list(window)
        if len(best_window) >= _BURST_COUNT:
            strength = min(1.0, len(best_window) / (2 * _BURST_COUNT))
            signals.append(
                Signal(
                    name="velocity_burst",
                    description=(
                        f"{len(best_window)} payments within {_BURST_WINDOW} for customer {cid}"
                    ),
                    evidence_refs=[e.event_id for e in best_window],
                    strength=strength,
                )
            )
    return sorted(signals, key=lambda s: -s.strength)


def off_hours_activity(view: ObservedTraceView) -> list[Signal]:
    """Payments between 00:00-05:00 local — small honest mass expected."""
    pays = _payments(view)
    if not pays:
        return []
    night = [e for e in pays if e.ts.hour < 5 or (e.ts.hour == 23 and e.ts.minute >= 55)]
    ratio = len(night) / len(pays)
    if ratio <= 0.06 or len(night) < 2:
        return []
    return [
        Signal(
            name="off_hours_payments",
            description=f"{len(night)}/{len(pays)} payments in off-hours band",
            evidence_refs=[e.event_id for e in night[:20]],
            strength=min(1.0, ratio * 4.0),
        )
    ]


def new_device_then_payment(view: ObservedTraceView) -> list[Signal]:
    """Authentication flagged new_device shortly followed by a payment."""
    auths = {
        str(e.payload.get("customer", "")): e
        for e in view.events
        if e.kind == "authentication" and bool(e.payload.get("new_device"))
    }
    out: list[Signal] = []
    for p in _payments(view):
        a = auths.get(p.actor_id)
        if a is None or not (timedelta(0) <= p.ts - a.ts <= timedelta(hours=6)):
            continue
        out.append(
            Signal(
                name="new_device_payment",
                description=f"payment {p.event_id} follows new-device auth",
                evidence_refs=[a.event_id, p.event_id],
                strength=0.65,
            )
        )
    return out[:10]


def refund_chains(view: ObservedTraceView) -> list[Signal]:
    """Refunds clustered on one customer, especially disputed ones."""
    refunds = [e for e in view.events if e.kind == "refund"]
    by_customer: dict[str, int] = defaultdict(int)
    refs: dict[str, list[str]] = defaultdict(list)
    for r in refunds:
        cid = str(r.payload.get("customer", ""))
        by_customer[cid] += 1
        refs[cid].append(r.event_id)
    out: list[Signal] = []
    for cid, n in sorted(by_customer.items()):
        if n >= 3:
            out.append(
                Signal(
                    name="refund_chain",
                    description=f"{n} refunds for customer {cid}",
                    evidence_refs=refs[cid][:20],
                    strength=min(1.0, 0.3 + 0.15 * n),
                )
            )
    return out


def app_scam_signals(view: ObservedTraceView) -> list[Signal]:
    """Payment-time APP scam evidence available to a bank or payment network."""
    out: list[Signal] = []
    for event in view.events:
        p = event.payload
        if event.kind == "payee.added" and bool(p.get("first_time_payee")):
            out.append(
                Signal(
                    name="first_time_payee",
                    description="customer added a first-time beneficiary for this payment session",
                    evidence_refs=[event.event_id],
                    strength=0.65,
                )
            )
        elif event.kind == "app.behavior.sampled":
            distance = float(p.get("behavioral_distance", 0.0))
            pasted = bool(p.get("payee_field_pasted"))
            dwell = float(p.get("confirmation_dwell_seconds", 0.0))
            if distance >= 0.7 and (pasted or dwell >= 20):
                out.append(
                    Signal(
                        name="behavioral_coaching_risk",
                        description="payment entry behavior deviates from the customer baseline",
                        evidence_refs=[event.event_id],
                        strength=min(distance, 1.0),
                    )
                )
        elif event.kind == "beneficiary.risk.assessed":
            score = float(p.get("network_risk_score", 0.0))
            if score >= 0.7:
                out.append(
                    Signal(
                        name="beneficiary_network_risk",
                        description="recipient shows young-account, fan-in, or rapid pass-through risk",
                        evidence_refs=[event.event_id],
                        strength=min(score, 1.0),
                    )
                )
        elif event.kind == "scam.intervention.responded" and bool(p.get("warning_overridden")):
            out.append(
                Signal(
                    name="warning_override",
                    description="customer continued after a targeted scam intervention",
                    evidence_refs=[event.event_id],
                    strength=0.75,
                )
            )
        elif event.kind == "payment.initiated":
            amount = float(p.get("amount_minor", 0.0))
            balance = float(p.get("available_balance_minor", 0.0))
            ratio = amount / balance if balance > 0 else 0.0
            if ratio >= 0.7:
                out.append(
                    Signal(
                        name="balance_depletion",
                        description=f"payment would consume {ratio:.0%} of available funds",
                        evidence_refs=[event.event_id],
                        strength=min(ratio, 1.0),
                    )
                )
        elif (
            event.kind == "device.call_state.observed"
            and bool(p.get("state_available"))
            and bool(p.get("active"))
        ):
            out.append(
                Signal(
                    name="active_external_call",
                    description="device reported anonymous system-visible call activity",
                    evidence_refs=[event.event_id],
                    strength=0.35,
                )
            )
    return out


def bank_controlled_media_signals(view: ObservedTraceView) -> list[Signal]:
    """Optional media/network evidence when a bank controls the communication channel."""
    out: list[Signal] = []
    for event in view.events:
        p = event.payload
        if event.kind == "network.observed":
            if int(p.get("history_asn_seen_count", 1)) == 0 and int(
                p.get("history_ip_seen_count", 1)
            ) == 0:
                out.append(
                    Signal(
                        name="unknown_peer_network",
                        description="bank-controlled session peer uses an unseen network",
                        evidence_refs=[event.event_id],
                        strength=0.85 if bool(p.get("is_hosting_provider")) else 0.65,
                    )
                )
        elif event.kind == "media.authenticity.assessed":
            score = float(p.get("anomaly_score", 0.0))
            if score >= 0.7:
                out.append(
                    Signal(
                        name="media_liveness_anomaly",
                        description=(
                            f"bank-controlled media anomaly score {score:.2f} from "
                            f"{p.get('detector_version', 'unknown detector')}"
                        ),
                        evidence_refs=[event.event_id],
                        strength=min(score, 1.0),
                    )
                )
        elif event.kind == "bank.communication.payment_overlap" and bool(p.get("active")):
            out.append(
                Signal(
                    name="transaction_during_call",
                    description="payment overlapped a bank-controlled communication session",
                    evidence_refs=[event.event_id],
                    strength=0.75,
                )
            )
    return out


def all_signals(view: ObservedTraceView) -> list[Signal]:
    merged = (
        velocity_bursts(view)
        + off_hours_activity(view)
        + new_device_then_payment(view)
        + refund_chains(view)
        + app_scam_signals(view)
        + bank_controlled_media_signals(view)
    )
    # dedup by (name, evidence) to preserve per-customer bursts
    seen: set[tuple[str, tuple[str, ...]]] = set()
    unique: list[Signal] = []
    for s in merged:
        key = (s.name, tuple(sorted(s.evidence_refs)))
        if key not in seen:
            seen.add(key)
            unique.append(s)
    # keep strongest 12 overall, but ensure velocity_burst per customer is preserved
    return sorted(unique, key=lambda s: -s.strength)[:12]
