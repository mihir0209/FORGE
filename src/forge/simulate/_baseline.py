"""Baseline legitimate behavior: the world as it behaves when nobody attacks it.

Event flow follows the payment lifecycle: onboarding -> authentication -> payment,
with occasional refunds tied to recent payments, rare cash-outs for a fixed customer
subset, and a daily settlement sweep per merchant. Output is sorted by timestamp;
event ids are sequential and deterministic under pinned dependencies.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import numpy as np

from forge.contracts.contracts import ActorKind, TraceEvent, WorldSeed
from forge.simulate._rng import derive_rng
from forge.simulate._world import (
    CATEGORIES,
    Customer,
    Merchant,
    World,
    draw_amount,
    draw_hour,
)


class BaselineEngine:
    def __init__(
        self,
        world: World,
        seed: WorldSeed,
        start: datetime,
        n_days: int,
    ) -> None:
        self._world = world
        self._seed = seed
        self._start = start.astimezone(UTC)
        self._n_days = n_days
        self._rng = derive_rng(seed, "baseline")
        self._seq = 0
        self._last_payment_by_customer: dict[str, tuple[TraceEvent, Merchant]] = {}
        self._cashout_customers = self._pick_cashout_subset()

    def run(self) -> list[TraceEvent]:
        events: list[TraceEvent] = []
        by_id = {m.merchant_id: m for m in self._world.merchants}

        for day in range(self._n_days):
            date = self._start + timedelta(days=day)
            weekend = date.weekday() >= 5
            for c in self._world.customers:
                if day == c.opened_day:
                    events.append(self._onboard(c, day))
                lam = max(0.0, (c.weekly_lambda / 7.0) * self._weekend_factor(c, weekend))
                for _ in range(int(self._rng.poisson(lam))):
                    m = by_id[self._pick_merchant(c)]
                    events.extend(self._transaction(c, m, day))
                if c.customer_id in self._cashout_customers and self._rng.random() < 0.10:
                    events.append(self._cash_out(c, day))
            events.extend(self._settlements(day))
        return sorted(events, key=lambda e: e.ts)

    # ------------------------------------------------------------------ emit

    def _emit(self, prefix: str, **fields: object) -> TraceEvent:
        self._seq += 1
        return TraceEvent(event_id=f"{prefix}{self._seq:07d}", **fields)  # type: ignore[arg-type]

    def _onboard(self, c: Customer, day: int) -> TraceEvent:
        return self._emit(
            "ob",
            ts=self._at(day, float(self._rng.uniform(9, 20))),
            actor_kind=ActorKind.CUSTOMER,
            actor_id=c.customer_id,
            kind="onboarding",
            payload={"channel": "web"},
        )

    def _transaction(self, c: Customer, m: Merchant, day: int) -> list[TraceEvent]:
        cat = m.category
        hour = draw_hour(self._rng, cat)
        amount = round(draw_amount(self._rng, cat), 2)
        device = c.device_ids[int(self._rng.integers(0, len(c.device_ids)))]

        auth_ts = self._at(day, hour)
        pay_ts = auth_ts + timedelta(seconds=float(self._rng.integers(4, 40)))
        auth = self._emit(
            "au",
            ts=auth_ts,
            actor_kind=ActorKind.DEVICE,
            actor_id=device,
            kind="authentication",
            payload={"customer": c.customer_id},
        )
        payment = self._emit(
            "pm",
            ts=pay_ts,
            actor_kind=ActorKind.CUSTOMER,
            actor_id=c.customer_id,
            kind="payment",
            payload={
                "merchant": m.merchant_id,
                "category": cat.name,
                "amount": amount,
                "device": device,
            },
        )
        self._last_payment_by_customer[c.customer_id] = (payment, m)

        out = [auth, payment]
        if self._rng.random() < 0.03:
            out.append(self._refund(c, m))
        return out

    def _refund(self, c: Customer, m: Merchant) -> TraceEvent:
        payment, _ = self._last_payment_by_customer[c.customer_id]
        refund_ts = payment.ts + timedelta(hours=float(self._rng.integers(2, 72)))
        return self._emit(
            "rf",
            ts=refund_ts,
            actor_kind=ActorKind.MERCHANT,
            actor_id=m.merchant_id,
            kind="refund",
            payload={
                "customer": c.customer_id,
                "amount": round(float(payment.payload["amount"]) * 0.5, 2),
                "ref_event": payment.event_id,
            },
        )

    def _cash_out(self, c: Customer, day: int) -> TraceEvent:
        return self._emit(
            "co",
            ts=self._at(day, float(self._rng.uniform(8, 22))),
            actor_kind=ActorKind.SYSTEM,
            actor_id="rail",
            kind="cash_out",
            payload={
                "customer": c.customer_id,
                "channel": "atm_like",
                "amount": round(float(self._rng.uniform(20, 300)), 2),
            },
        )

    def _settlements(self, day: int) -> list[TraceEvent]:
        ts = self._at(day, 23.75)
        return [
            self._emit(
                "st",
                ts=ts + timedelta(seconds=i),
                actor_kind=ActorKind.SYSTEM,
                actor_id="rail",
                kind="settlement",
                payload={"merchant": m.merchant_id},
            )
            for i, m in enumerate(self._world.merchants)
        ]

    # --------------------------------------------------------------- helpers

    def _pick_cashout_subset(self) -> set[str]:
        return {c.customer_id for c in self._world.customers if self._rng.random() < 0.08}

    def _pick_merchant(self, c: Customer) -> str:
        affinities = c.affinity_merchant_ids
        return affinities[int(self._rng.integers(0, len(affinities)))]

    def _weekend_factor(self, c: Customer, weekend: bool) -> float:
        if not weekend:
            return 1.0
        by_id = {m.merchant_id: m for m in self._world.merchants}
        cats = [by_id[mid].category.name for mid in c.affinity_merchant_ids]
        profile = {p.name: p for p in CATEGORIES}
        factors = [profile[n].weekend_multiplier for n in cats if n in profile]
        return float(np.mean(factors)) if factors else 1.0

    def _at(self, day: int, hour: float) -> datetime:
        base = self._start + timedelta(days=day)
        h = min(int(hour), 23)
        minute = int((hour - h) * 60)
        second = int(((hour - h) * 60 - minute) * 60)
        return base.replace(hour=h, minute=min(minute, 59), second=min(second, 59))
