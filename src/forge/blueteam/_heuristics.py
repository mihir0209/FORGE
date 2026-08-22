"""Deterministic heuristic miners over ObservedTraceView (blind by type)."""

from __future__ import annotations

import itertools
from collections import defaultdict
from datetime import timedelta

from forge.contracts.contracts import ObservedTraceView, Signal, TraceEvent

_BURST_WINDOW = timedelta(minutes=30)
_BURST_COUNT = 4  # payments within window that constitute a burst


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


def all_signals(view: ObservedTraceView) -> list[Signal]:
    merged = (
        velocity_bursts(view)
        + off_hours_activity(view)
        + new_device_then_payment(view)
        + refund_chains(view)
    )
    seen: set[str] = set()
    unique = [s for s in merged if not (s.name in seen or seen.add(s.name))]
    return sorted(unique, key=lambda s: -s.strength)[:12]
