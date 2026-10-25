# pyright: reportMissingTypeStubs=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownParameterType=false, reportMissingTypeArgument=false, reportArgumentType=false
"""Adversarial transaction attack generator and fuzzing simulator for FORGE."""

from __future__ import annotations

import hashlib
import math
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any

import numpy as np
from pydantic import Field

from forge.contracts.contracts import (
    ActorKind,
    GraphEvent,
    LifecycleStage,
    Strict,
    TraceEvent,
)
from forge.feature_schema import FEATURE_NAMES

if TYPE_CHECKING:
    from collections.abc import Sequence


class AttackMode(StrEnum):
    """Adversarial attack generation modes."""

    BURST = "burst"
    SPOOF = "spoof"
    STRUCTURING = "structuring"


class AdversarialTransaction(Strict):
    """Schema-validated synthetic adversarial transaction event."""

    transaction_id: str
    timestamp: datetime
    source_account: str
    destination_account: str
    amount: float = Field(gt=0.0)
    amount_minor: int = Field(gt=0)
    currency: str = "USD"
    attack_mode: AttackMode
    channel: str = "mobile_banking"
    payment_rail: str = "ach"
    device_id: str
    ip_address: str
    user_agent: str
    location: str
    is_fraud: bool = True
    attributes: dict[str, Any] = Field(default_factory=dict)
    features: dict[str, float] = Field(default_factory=dict)

    def to_feature_dict(self) -> dict[str, float]:
        """Produce the standardized 15-feature representation per feature_schema.py."""
        out: dict[str, float] = {}
        for name in FEATURE_NAMES:
            val = float(self.features.get(name, 0.0))
            if math.isnan(val) or math.isinf(val):
                val = 0.0
            out[name] = max(0.0, val)
        return out

    def to_graph_event(self, institution_id: str = "bank-forge") -> GraphEvent:
        """Convert into a FORGE canonical GraphEvent."""
        return GraphEvent(
            event_id=self.transaction_id,
            event_time=self.timestamp,
            available_at=self.timestamp,
            kind="payment.settled",
            institution_id=institution_id,
            source_account_ref=self.source_account,
            destination_account_ref=self.destination_account,
            device_ref=self.device_id,
            amount_minor=self.amount_minor,
            attributes={
                **self.attributes,
                "attack_mode": self.attack_mode.value,
                "is_fraud": self.is_fraud,
            },
        )

    def to_trace_event(
        self, stage: LifecycleStage = LifecycleStage.PAYMENT
    ) -> TraceEvent:
        """Convert into a FORGE SyntheticTrace TraceEvent."""
        return TraceEvent(
            event_id=self.transaction_id,
            ts=self.timestamp,
            actor_kind=ActorKind.CUSTOMER,
            actor_id=self.source_account,
            kind="payment",
            payload={
                "customer": self.source_account,
                "merchant": self.destination_account,
                "amount": self.amount,
                "device": self.device_id,
                "attack_mode": self.attack_mode.value,
                **self.attributes,
            },
            is_attack_step=self.is_fraud,
            attack_stage=stage if self.is_fraud else None,
        )


class AdversarialAttackGenerator:
    """High-throughput generator and fuzzer for synthetic adversarial transactions."""

    def __init__(self, seed: int = 42) -> None:
        self.seed = seed
        self._rng = np.random.default_rng(seed)
        self._seq = 0
        self._base_time = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)

    def generate_transaction(
        self,
        mode: AttackMode,
        *,
        base_time: datetime | None = None,
        source_account: str | None = None,
        destination_account: str | None = None,
        amount: float | None = None,
        **overrides: Any,
    ) -> AdversarialTransaction:
        """Generate a single schema-validated transaction tailored to the attack mode."""
        self._seq += 1
        t_ref = base_time or (self._base_time + timedelta(seconds=self._seq * 5))
        tx_id = f"tx_adv_{self._seq:08d}_{hashlib.sha256(f'{self.seed}:{self._seq}'.encode()).hexdigest()[:8]}"

        src = source_account or f"acc_victim_{self._rng.integers(1000, 9999)}"
        dst = destination_account or f"acc_mule_{self._rng.integers(1000, 9999)}"
        device_id = f"dev_{self._rng.integers(10000, 99999)}"
        ip_addr = f"198.51.100.{self._rng.integers(1, 254)}"

        features: dict[str, float] = {name: 0.0 for name in FEATURE_NAMES}
        attrs: dict[str, Any] = {}

        if mode == AttackMode.BURST:
            amt = amount if amount is not None else float(round(float(self._rng.uniform(15.0, 750.0)), 2))
            features["burst"] = float(round(float(self._rng.uniform(0.70, 0.99)), 4))
            features["volume"] = float(round(float(self._rng.uniform(0.60, 0.95)), 4))
            features["cashout_pressure"] = float(round(float(self._rng.uniform(0.30, 0.85)), 4))
            features["off_hours_focus"] = float(round(float(self._rng.uniform(0.10, 0.70)), 4))
            features["refund_pressure"] = float(round(float(self._rng.uniform(0.05, 0.40)), 4))
            attrs["burst_batch_id"] = f"burst_grp_{self._rng.integers(100, 999)}"
            attrs["velocity_tps"] = float(round(float(self._rng.uniform(10.0, 50.0)), 2))

        elif mode == AttackMode.SPOOF:
            amt = amount if amount is not None else float(round(float(self._rng.uniform(500.0, 15000.0)), 2))
            features["new_device"] = 1.0
            features["unknown_peer_network"] = float(round(float(self._rng.uniform(0.75, 1.0)), 4))
            features["media_liveness_anomaly"] = float(round(float(self._rng.uniform(0.60, 0.98)), 4))
            features["transaction_during_call"] = float(round(float(self._rng.uniform(0.65, 1.0)), 4))
            features["active_external_call"] = 1.0 if self._rng.random() > 0.3 else 0.0
            features["first_time_payee"] = 1.0
            features["behavioral_coaching_risk"] = float(round(float(self._rng.uniform(0.55, 0.95)), 4))
            attrs["spoofed_device"] = True
            attrs["proxy_detected"] = True
            attrs["vpn_asn"] = f"AS{self._rng.integers(10000, 60000)}"
            attrs["liveness_confidence"] = float(round(float(self._rng.uniform(0.01, 0.25)), 3))

        else:  # AttackMode.STRUCTURING
            # Smurfing / structuring intentionally kept just under $10,000 threshold
            target_threshold = 10000.0
            delta = float(round(float(self._rng.uniform(10.0, 950.0)), 2))
            amt = amount if amount is not None else round(target_threshold - delta, 2)
            features["balance_depletion"] = float(round(float(self._rng.uniform(0.70, 0.99)), 4))
            features["cashout_pressure"] = float(round(float(self._rng.uniform(0.65, 0.95)), 4))
            features["beneficiary_network_risk"] = float(round(float(self._rng.uniform(0.55, 0.92)), 4))
            features["volume"] = float(round(float(self._rng.uniform(0.50, 0.85)), 4))
            features["warning_override"] = float(round(float(self._rng.uniform(0.20, 0.80)), 4))
            features["first_time_payee"] = float(round(float(self._rng.uniform(0.50, 1.0)), 4))
            attrs["threshold_evasion_target"] = target_threshold
            attrs["delta_to_threshold"] = round(target_threshold - amt, 2)
            attrs["structuring_cluster_id"] = f"smurf_ring_{self._rng.integers(100, 999)}"

        amt_minor = round(amt * 100)
        if amt_minor <= 0:
            amt_minor = 100
            amt = 1.0

        tx_payload: dict[str, Any] = {
            "transaction_id": tx_id,
            "timestamp": t_ref,
            "source_account": src,
            "destination_account": dst,
            "amount": amt,
            "amount_minor": amt_minor,
            "currency": "USD",
            "attack_mode": mode,
            "channel": "mobile_banking",
            "payment_rail": "ach",
            "device_id": device_id,
            "ip_address": ip_addr,
            "user_agent": "Mozilla/5.0 (AdversarialBot/2.0)",
            "location": "US-NY",
            "is_fraud": True,
            "attributes": attrs,
            "features": features,
        }
        tx_payload.update(overrides)
        return AdversarialTransaction(**tx_payload)

    def generate_batch(
        self,
        count: int,
        modes: Sequence[AttackMode] | None = None,
        seed: int | None = None,
    ) -> list[AdversarialTransaction]:
        """Rapidly generate a batch of adversarial transactions distributed across modes."""
        if count <= 0:
            return []
        rng = np.random.default_rng(seed if seed is not None else self.seed)
        selected_modes = list(modes) if modes else [AttackMode.BURST, AttackMode.SPOOF, AttackMode.STRUCTURING]
        mode_choices = rng.choice(selected_modes, size=count)

        batch: list[AdversarialTransaction] = []
        base_t = self._base_time

        # Pre-generate vectorized random arrays for speed
        src_ints = rng.integers(1000, 9999, size=count)
        dst_ints = rng.integers(1000, 9999, size=count)
        dev_ints = rng.integers(10000, 99999, size=count)
        ip_last_octets = rng.integers(1, 254, size=count)
        burst_amts = rng.uniform(15.0, 750.0, size=count)
        spoof_amts = rng.uniform(500.0, 15000.0, size=count)
        structuring_deltas = rng.uniform(10.0, 950.0, size=count)
        uniform_scalars = rng.uniform(0.5, 0.98, size=(count, 6))

        for i in range(count):
            self._seq += 1
            mode = AttackMode(str(mode_choices[i]))
            t_ref = base_t + timedelta(seconds=i * 2)
            tx_id = f"tx_adv_{self._seq:08d}"

            features: dict[str, float] = {name: 0.0 for name in FEATURE_NAMES}
            attrs: dict[str, Any] = {}

            if mode == AttackMode.BURST:
                amt = float(round(float(burst_amts[i]), 2))
                features["burst"] = float(round(float(uniform_scalars[i, 0]), 4))
                features["volume"] = float(round(float(uniform_scalars[i, 1]), 4))
                features["cashout_pressure"] = float(round(float(uniform_scalars[i, 2]), 4))
                features["off_hours_focus"] = float(round(float(uniform_scalars[i, 3] * 0.7), 4))
                features["refund_pressure"] = float(round(float(uniform_scalars[i, 4] * 0.4), 4))
                attrs["burst_batch_id"] = f"burst_grp_{i % 50}"
                attrs["velocity_tps"] = 25.0

            elif mode == AttackMode.SPOOF:
                amt = float(round(float(spoof_amts[i]), 2))
                features["new_device"] = 1.0
                features["unknown_peer_network"] = float(round(float(uniform_scalars[i, 0]), 4))
                features["media_liveness_anomaly"] = float(round(float(uniform_scalars[i, 1]), 4))
                features["transaction_during_call"] = float(round(float(uniform_scalars[i, 2]), 4))
                features["active_external_call"] = 1.0 if uniform_scalars[i, 3] > 0.6 else 0.0
                features["first_time_payee"] = 1.0
                features["behavioral_coaching_risk"] = float(round(float(uniform_scalars[i, 4]), 4))
                attrs["spoofed_device"] = True
                attrs["proxy_detected"] = True

            else:  # AttackMode.STRUCTURING
                amt = float(round(10000.0 - float(structuring_deltas[i]), 2))
                features["balance_depletion"] = float(round(float(uniform_scalars[i, 0]), 4))
                features["cashout_pressure"] = float(round(float(uniform_scalars[i, 1]), 4))
                features["beneficiary_network_risk"] = float(round(float(uniform_scalars[i, 2]), 4))
                features["volume"] = float(round(float(uniform_scalars[i, 3]), 4))
                features["first_time_payee"] = 1.0
                attrs["threshold_evasion_target"] = 10000.0
                attrs["delta_to_threshold"] = round(10000.0 - amt, 2)

            batch.append(
                AdversarialTransaction(
                    transaction_id=tx_id,
                    timestamp=t_ref,
                    source_account=f"acc_src_{src_ints[i]}",
                    destination_account=f"acc_dst_{dst_ints[i]}",
                    amount=amt,
                    amount_minor=round(amt * 100),
                    currency="USD",
                    attack_mode=mode,
                    channel="mobile_banking",
                    payment_rail="ach",
                    device_id=f"dev_{dev_ints[i]}",
                    ip_address=f"198.51.100.{ip_last_octets[i]}",
                    user_agent="Mozilla/5.0 (AdversarialBot/2.0)",
                    location="US-NY",
                    is_fraud=True,
                    attributes=attrs,
                    features=features,
                )
            )

        return batch

    def fuzz_transactions(
        self,
        count: int,
        seed: int | None = None,
        noise_scale: float = 0.05,
    ) -> list[AdversarialTransaction]:
        """Fuzz transaction features, amounts, and timing with controlled random noise."""
        batch = self.generate_batch(count=count, seed=seed)
        rng = np.random.default_rng(seed if seed is not None else self.seed + 100)

        fuzzed: list[AdversarialTransaction] = []
        for tx in batch:
            fuzzed_features = dict(tx.features)
            for k, v in fuzzed_features.items():
                jitter = float(rng.normal(0.0, noise_scale))
                fuzzed_features[k] = float(min(1.0, max(0.0, v + jitter)))

            # Jitter amount by +/- 2%
            amt_jitter = float(rng.uniform(0.98, 1.02))
            new_amount = max(0.01, round(tx.amount * amt_jitter, 2))

            # Jitter timestamp by seconds
            sec_jitter = int(rng.integers(-30, 30))
            new_ts = tx.timestamp + timedelta(seconds=sec_jitter)

            fuzzed.append(
                tx.model_copy(
                    update={
                        "amount": new_amount,
                        "amount_minor": round(new_amount * 100),
                        "timestamp": new_ts,
                        "features": fuzzed_features,
                    }
                )
            )
        return fuzzed
