"""Attack injection: walks the strategy's lifecycle, emitting labeled events.

The injector appends a parallel event stream that the assembler merges by
timestamp — baseline events are never mutated. Every injected event carries the
label channel (is_attack_step=True, attack_stage=<stage>), and refund primitives
attach to earlier attack payments when they exist.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import numpy as np

from forge.contracts.contracts import (
    ActorKind,
    LifecycleStage,
    StrategySpec,
    TraceEvent,
    WorldSeed,
)
from forge.simulate._rng import derive_rng
from forge.simulate._world import (
    CategoryProfile,
    Customer,
    Merchant,
    World,
    draw_hour,
    scaled_amount,
)


@dataclass(frozen=True)
class InjectionResult:
    events: list[TraceEvent]
    reachability_ok: bool

    @property
    def attack_event_ids(self) -> list[str]:
        return [e.event_id for e in self.events]


# keyword -> primitive hints from the strategy's own words
_PAY_SMALL = ("small", "low", "test", "probe")
_PAY_LARGE = ("large", "big", "high", "drain", "max", "sweep")
_AUTH = ("session", "login", "log-in", "auth", "credential", "password")
_BENEFICIARY = ("beneficiar", "payee", "add")
_REFUND = ("refund", "chargeback", "dispute", "reversal")
_CASH_OUT = ("cash-out", "cashout", "cash_out", "atm", "withdraw", "mule")
_OFF_HOURS = ("off-hour", "offhour", "night", "odd", "unusual", "late", "quiet")
_BURST = ("burst", "rapid", "multiple", "series", "velocity")

_STAGE_DEFAULT: dict[LifecycleStage, str] = {
    LifecycleStage.ONBOARDING: "account_open",
    LifecycleStage.AUTHENTICATION: "device_auth",
    LifecycleStage.PAYMENT: "payment",
    LifecycleStage.REFUND: "refund",
    LifecycleStage.SETTLEMENT: "settlement_pull",
    LifecycleStage.CASH_OUT: "cash_out",
}


class AttackInjector:
    def __init__(self, world: World, seed: WorldSeed) -> None:
        self._world = world
        self._seed = seed
        self._rng = derive_rng(seed, "inject")
        self._seq = 0

    def inject(
        self,
        spec: StrategySpec,
        start: datetime,
        n_days: int,
    ) -> InjectionResult:
        rng_victim = derive_rng(self._seed, f"victim:{spec.strategy_id}")
        victim = self._world.customers[int(rng_victim.integers(0, len(self._world.customers)))]
        device = victim.device_ids[0]

        text = " ".join([*spec.behavioral_sequence, spec.evasion_hypothesis]).lower()
        window_day = min(n_days // 2 + int(self._rng.integers(0, 3)), n_days - 1)
        off_hours = any(k in text for k in _OFF_HOURS)

        events: list[TraceEvent] = []
        seen_stages: set[str] = set()
        last_payment: TraceEvent | None = None

        for stage in spec.lifecycle_stages:
            primitive = _route(stage, text)
            before = len(events)

            if primitive == "payment":
                new_pays = self._payments(
                    victim=victim,
                    device=device,
                    text=text,
                    start=start,
                    day=window_day,
                    off_hours=off_hours,
                    stage=stage,
                )
                events.extend(new_pays)
                last_payment = new_pays[-1] if new_pays else last_payment
            elif primitive == "refund":
                if last_payment is not None:
                    events.append(self._refund(victim, last_payment, stage))
                else:
                    events.append(
                        self._plain(
                            stage=stage,
                            cid=victim.customer_id,
                            start=start,
                            day=window_day,
                            hour=self._hour(off_hours, None),
                            kind="refund_request",
                            payload={"customer": victim.customer_id, "amount_hint": "unanchored"},
                        )
                    )
            elif primitive == "cash_out":
                for i in range(int(self._rng.integers(1, 4))):
                    events.append(
                        self._plain(
                            stage=stage,
                            cid=victim.customer_id,
                            start=start,
                            day=window_day,
                            hour=self._hour(off_hours, None),
                            kind="cash_out",
                            payload={
                                "customer": victim.customer_id,
                                "channel": "atm_like",
                                "amount": round(float(self._rng.uniform(150, 900)), 2),
                                "attempt": i + 1,
                            },
                        )
                    )
            elif primitive == "beneficiary_add":
                events.append(
                    self._plain(
                        stage=stage,
                        cid=victim.customer_id,
                        start=start,
                        day=window_day,
                        hour=self._hour(off_hours, None),
                        kind="beneficiary_add",
                        payload={
                            "customer": victim.customer_id,
                            "external_account": "xref_unknown",
                        },
                    )
                )
            elif primitive == "device_auth":
                events.append(
                    self._emit(
                        ts=self._at(start, window_day, self._hour(off_hours, None)),
                        actor_kind=ActorKind.DEVICE,
                        actor_id=device,
                        kind="authentication",
                        stage=stage,
                        payload={"customer": victim.customer_id, "new_device": True},
                    )
                )
            elif primitive == "account_open":
                events.append(
                    self._plain(
                        stage=stage,
                        cid=victim.customer_id,
                        start=start,
                        day=window_day,
                        hour=self._hour(off_hours, None),
                        kind="onboarding",
                        payload={"channel": "web", "note": "attack_onboarding"},
                    )
                )
            else:  # settlement_pull
                events.append(
                    self._plain(
                        stage=stage,
                        cid=victim.customer_id,
                        start=start,
                        day=window_day,
                        hour=23.9,
                        kind="settlement",
                        payload={"customer": victim.customer_id, "pull": True},
                    )
                )

            if len(events) > before:
                seen_stages.add(stage.value)

        reachable = all(s.value in seen_stages for s in spec.lifecycle_stages)
        return InjectionResult(events=events, reachability_ok=reachable)

    # ------------------------------------------------------------- internals

    def _emit(
        self,
        *,
        ts: datetime,
        actor_kind: ActorKind,
        actor_id: str,
        kind: str,
        payload: dict[str, object],
        stage: LifecycleStage,
    ) -> TraceEvent:
        self._seq += 1
        return TraceEvent(
            event_id=f"atk{self._seq:07d}",
            ts=ts,
            actor_kind=actor_kind,
            actor_id=actor_id,
            kind=kind,
            payload=payload,
            is_attack_step=True,
            attack_stage=stage,
        )

    def _refund(
        self,
        victim: Customer,
        payment: TraceEvent,
        stage: LifecycleStage,
    ) -> TraceEvent:
        """Dispute against an earlier attack payment, shortly after it lands."""
        refund_ts = payment.ts + timedelta(minutes=float(self._rng.integers(30, 4320)))
        return self._emit(
            ts=refund_ts,
            actor_kind=ActorKind.MERCHANT,
            actor_id=str(payment.payload.get("merchant", "unknown")),
            kind="refund",
            payload={
                "customer": victim.customer_id,
                "amount": round(float(payment.payload["amount"]) * 0.5, 2),
                "ref_event": payment.event_id,
                "disputed": True,
            },
            stage=stage,
        )

    def _plain(
        self,
        *,
        stage: LifecycleStage,
        cid: str,
        start: datetime,
        day: int,
        hour: float,
        kind: str,
        payload: dict[str, object],
    ) -> TraceEvent:
        return self._emit(
            ts=self._at(start, day, hour),
            actor_kind=ActorKind.CUSTOMER,
            actor_id=cid,
            kind=kind,
            payload=payload,
            stage=stage,
        )

    def _payments(
        self,
        *,
        victim: Customer,
        device: str,
        text: str,
        start: datetime,
        day: int,
        off_hours: bool,
        stage: LifecycleStage,
    ) -> list[TraceEvent]:
        scale = (
            0.25
            if any(k in text for k in _PAY_SMALL)
            else (4.0 if any(k in text for k in _PAY_LARGE) else 1.0)
        )
        burst = any(k in text for k in _BURST)
        count = int(self._rng.integers(3, 6)) if burst else 1

        merchant = self._affinity_merchant(victim)
        base_hour = self._hour(off_hours, merchant.category)
        out: list[TraceEvent] = []
        for i in range(count):
            hour = min(base_hour + i * 0.25, 23.98)  # bursts pack into ~15-min steps
            out.append(
                self._emit(
                    ts=self._at(start, day, hour),
                    actor_kind=ActorKind.CUSTOMER,
                    actor_id=victim.customer_id,
                    kind="payment",
                    stage=stage,
                    payload={
                        "merchant": merchant.merchant_id,
                        "category": merchant.category.name,
                        "amount": round(scaled_amount(self._rng, merchant.category, scale), 2),
                        "device": device,
                        "burst": burst,
                    },
                )
            )
        return out

    def _affinity_merchant(self, c: Customer) -> Merchant:
        mids = c.affinity_merchant_ids
        mid = mids[int(self._rng.integers(0, len(mids)))]
        by_id = {m.merchant_id: m for m in self._world.merchants}
        return by_id[mid]

    def _hour(self, off_hours: bool, cat: CategoryProfile | None) -> float:
        if off_hours:
            return float(np.clip(self._rng.uniform(0.0, 5.0), 0.0, 23.98))
        return draw_hour(self._rng, cat)

    def _at(self, start: datetime, day_offset: int, hour: float) -> datetime:
        base = start.astimezone(UTC) + timedelta(days=day_offset)
        h = min(int(hour), 23)
        minute = min(int((hour - h) * 60), 59)
        second = int(self._rng.integers(0, 60))
        return base.replace(hour=h, minute=minute, second=second)


def _route(stage: LifecycleStage, text: str) -> str:
    """Lifecycle stage anchors the primitive; attacker's words tune parameters."""
    if stage == LifecycleStage.ONBOARDING and any(k in text for k in _BENEFICIARY):
        return "beneficiary_add"
    return _STAGE_DEFAULT[stage]
