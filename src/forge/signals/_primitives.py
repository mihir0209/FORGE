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

# Canonical feature list derived from these primitives.
# `detect` must not hand-maintain a second copy.
FEATURE_NAMES: tuple[str, ...] = (
    "burst",
    "new_device",
    "refund_pressure",
    "off_hours_focus",
    "cashout_pressure",
    "volume",
    "unknown_peer_network",
    "media_liveness_anomaly",
    "transaction_during_call",
)


def _payments(view: ObservedTraceView) -> list[TraceEvent]:
    return [e for e in view.events if e.kind == "payment"]


def velocity_bursts(view: ObservedTraceView) -> list[Signal]:
    """Same customer paying many times inside a short window."""
    per_customer: dict[str, list[TraceEvent]] = defaultdict(list)
    for e in _payments(view):
        per_customer[e.actor_id].append(e)

    signals: list[Signal] = []
    for cid, pays in sorted(per_customer.items()):
        if len(pays) < _BURST_COUNT:
            continue
        pays_sorted = sorted(pays, key=lambda e: e.ts)
        best_run: list[TraceEvent] = []
        run: list[TraceEvent] = [pays_sorted[0]]
        for prev, cur in itertools.pairwise(pays_sorted):
            if cur.ts - prev.ts <= _BURST_WINDOW:
                run.append(cur)
            else:
                best_run = max(best_run, run, key=len)
                run = [cur]
        best_run = max(best_run, run, key=len)
        if len(best_run) >= _BURST_COUNT:
            strength = min(1.0, len(best_run) / (2 * _BURST_COUNT))
            signals.append(
                Signal(
                    name="velocity_burst",
                    description=(
                        f"{len(best_run)} payments within {_BURST_WINDOW} for customer {cid}"
                    ),
                    evidence_refs=[e.event_id for e in best_run],
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


def unknown_peer_network(view: ObservedTraceView) -> list[Signal]:
    """Peer IP/ASN/device never appeared in prior synthetic history."""
    out: list[Signal] = []
    for event in view.events:
        if event.kind != "network.observed":
            continue
        asn_seen = int(event.payload.get("history_asn_seen_count", 1))
        ip_seen = int(event.payload.get("history_ip_seen_count", 1))
        device_seen = int(event.payload.get("history_device_seen_count", 1))
        hosting = bool(event.payload.get("is_hosting_provider"))
        if asn_seen == 0 and ip_seen == 0:
            strength = 0.85 if hosting and device_seen == 0 else 0.65
            out.append(
                Signal(
                    name="unknown_peer_network",
                    description=(
                        "call peer uses an unseen network/ASN"
                        + (" classified as hosting" if hosting else "")
                    ),
                    evidence_refs=[event.event_id],
                    strength=strength,
                )
            )
    return out


def media_liveness_anomaly(view: ObservedTraceView) -> list[Signal]:
    """Versioned media/liveness adapter reports a high anomaly score."""
    out: list[Signal] = []
    for event in view.events:
        if event.kind != "webrtc.rtp_stats":
            continue
        score = float(event.payload.get("liveness_anomaly_score", 0.0))
        if score >= 0.7:
            out.append(
                Signal(
                    name="media_liveness_anomaly",
                    description=(
                        f"video liveness anomaly score {score:.2f} from "
                        f"{event.payload.get('detector_version', 'unknown detector')}"
                    ),
                    evidence_refs=[event.event_id],
                    strength=min(score, 1.0),
                )
            )
    return out


def transaction_during_call(view: ObservedTraceView) -> list[Signal]:
    """Payment lifecycle overlaps an active call with matching session/call IDs."""
    starts: dict[str, TraceEvent] = {}
    ends: dict[str, TraceEvent] = {}
    for event in view.events:
        call_id = str(event.payload.get("call_id", ""))
        if event.kind == "call.started" and call_id:
            starts[call_id] = event
        elif event.kind == "call.ended" and call_id:
            ends[call_id] = event

    out: list[Signal] = []
    for event in view.events:
        if event.kind not in {"payment.initiated", "payment.authorized"}:
            continue
        call_id = str(event.payload.get("call_id", ""))
        start = starts.get(call_id)
        end = ends.get(call_id)
        if start is not None and start.ts <= event.ts and (end is None or event.ts <= end.ts):
            refs = [start.event_id, event.event_id]
            if end is not None:
                refs.append(end.event_id)
            out.append(
                Signal(
                    name="transaction_during_call",
                    description="payment authorized while the communication session was active",
                    evidence_refs=refs,
                    strength=0.9,
                )
            )
    return out


def all_signals(view: ObservedTraceView) -> list[Signal]:
    merged = (
        velocity_bursts(view)
        + off_hours_activity(view)
        + new_device_then_payment(view)
        + refund_chains(view)
        + unknown_peer_network(view)
        + media_liveness_anomaly(view)
        + transaction_during_call(view)
    )
    seen: set[str] = set()
    unique = [s for s in merged if not (s.name in seen or seen.add(s.name))]
    return sorted(unique, key=lambda s: -s.strength)[:12]
