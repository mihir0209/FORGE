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
    "first_time_payee",
    "behavioral_coaching_risk",
    "beneficiary_network_risk",
    "warning_override",
    "balance_depletion",
    "active_external_call",
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


def all_signals(view: ObservedTraceView) -> list[Signal]:
    merged = (
        velocity_bursts(view)
        + off_hours_activity(view)
        + new_device_then_payment(view)
        + refund_chains(view)
        + app_scam_signals(view)
    )
    seen: set[str] = set()
    unique = [s for s in merged if not (s.name in seen or seen.add(s.name))]
    return sorted(unique, key=lambda s: -s.strength)[:12]
