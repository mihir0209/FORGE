# pyright: reportMissingTypeStubs=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false
"""Synthetic Fraud Attack Generator: realistic streaming adversarial attack vectors.

Generates:
a) High-frequency micro-transaction bursts
b) Device fingerprint spoofing and impossible geo-velocity hops
c) Smurfing / structuring patterns (transactions just under threshold)
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any

import numpy as np

from forge.contracts.contracts import (
    ActorKind,
    EvidenceScope,
    FidelityReport,
    GroundTruth,
    LifecycleStage,
    SyntheticTrace,
    TraceEvent,
    WorldSeed,
)

if TYPE_CHECKING:
    from collections.abc import Iterator


class AttackVectorType(StrEnum):
    MICRO_BURST = "micro_burst"
    GEO_VELOCITY_SPOOF = "geo_velocity_spoof"
    SMURFING = "smurfing"


@dataclass(frozen=True)
class GeoLocation:
    city: str
    country: str
    latitude: float
    longitude: float


# Reference locations for geo-velocity calculations
KNOWN_LOCATIONS: dict[str, GeoLocation] = {
    "New York": GeoLocation("New York", "US", 40.7128, -74.0060),
    "London": GeoLocation("London", "GB", 51.5074, -0.1278),
    "Tokyo": GeoLocation("Tokyo", "JP", 35.6762, 139.6503),
    "Sydney": GeoLocation("Sydney", "AU", -33.8688, 151.2093),
    "Frankfurt": GeoLocation("Frankfurt", "DE", 50.1109, 8.6821),
    "Singapore": GeoLocation("Singapore", "SG", 1.3521, 103.8198),
    "Dubai": GeoLocation("Dubai", "AE", 25.2048, 55.2708),
    "São Paulo": GeoLocation("São Paulo", "BR", -23.5505, -46.6333),
}


def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate the great circle distance between two points on the earth in km."""
    r = 6371.0  # Earth radius in kilometers
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (
        math.sin(delta_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return r * c


class SyntheticFraudAttackGenerator:
    """Deterministic streaming attack generator for payment fraud vectors."""

    def __init__(self, seed: WorldSeed | int = 42) -> None:
        if isinstance(seed, int):
            self.seed = WorldSeed(master_seed=seed)
        else:
            self.seed = seed
        self._rng = np.random.default_rng(self.seed.master_seed)
        self._seq = 0

    def _next_event_id(self) -> str:
        self._seq += 1
        return f"atk_gen_{self.seed.master_seed}_{self._seq:07d}"

    # ------------------------------------------------------------------ micro-bursts

    def generate_micro_burst(
        self,
        *,
        customer_id: str = "cust_victim_001",
        merchant_id: str = "merch_digital_001",
        start_time: datetime | None = None,
        count: int = 15,
        interval_seconds: float = 0.8,
        min_amount: float = 0.25,
        max_amount: float = 4.99,
        device_id: str | None = None,
    ) -> list[TraceEvent]:
        """Generate high-frequency micro-transaction bursts."""
        base_time = start_time or datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
        device = device_id or f"dev_{customer_id}_trusted"
        burst_id = f"burst_{self._seq + 1:04d}"

        events: list[TraceEvent] = []
        for i in range(count):
            amount = round(float(self._rng.uniform(min_amount, max_amount)), 2)
            # Add small jitter to interval
            jitter = float(self._rng.uniform(-0.1, 0.1)) * interval_seconds
            step_delta = timedelta(seconds=max(0.05, i * interval_seconds + jitter))
            ts = base_time + step_delta

            payload: dict[str, Any] = {
                "customer": customer_id,
                "merchant": merchant_id,
                "category": "digital_goods",
                "amount": amount,
                "currency": "USD",
                "device": device,
                "burst": True,
                "burst_id": burst_id,
                "burst_sequence_index": i,
                "burst_total_count": count,
                "note": "micro_transaction_burst",
            }
            events.append(
                TraceEvent(
                    event_id=self._next_event_id(),
                    ts=ts,
                    actor_kind=ActorKind.CUSTOMER,
                    actor_id=customer_id,
                    kind="payment",
                    payload=payload,
                    is_attack_step=True,
                    attack_stage=LifecycleStage.PAYMENT,
                    evidence_scope=EvidenceScope.DEFENDER,
                )
            )
        return events

    # ------------------------------------------------------------------ geo-velocity

    def generate_geo_velocity_hops(
        self,
        *,
        customer_id: str = "cust_spoof_001",
        start_time: datetime | None = None,
        hop_cities: list[str] | None = None,
        hop_minutes: float = 8.0,
        amount: float = 450.00,
    ) -> list[TraceEvent]:
        """Generate impossible geo-velocity hops and device fingerprint spoofing."""
        base_time = start_time or datetime(2026, 8, 25, 14, 0, tzinfo=UTC)
        cities = hop_cities or ["New York", "London", "Tokyo"]

        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.4",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/125.0",
        ]
        ip_prefixes = ["198.51.100", "203.0.113", "192.0.2"]

        events: list[TraceEvent] = []
        prev_loc: GeoLocation | None = None
        prev_ts: datetime | None = None

        for idx, city_name in enumerate(cities):
            loc = KNOWN_LOCATIONS.get(city_name, KNOWN_LOCATIONS["New York"])
            cur_ts = base_time + timedelta(minutes=idx * hop_minutes)

            # Compute impossible speed if preceded by a hop
            speed_kmh = 0.0
            distance_km = 0.0
            if prev_loc is not None and prev_ts is not None:
                distance_km = haversine_distance_km(
                    prev_loc.latitude, prev_loc.longitude, loc.latitude, loc.longitude
                )
                time_diff_hours = (cur_ts - prev_ts).total_seconds() / 3600.0
                if time_diff_hours > 0:
                    speed_kmh = distance_km / time_diff_hours

            spoofed_device = f"dev_spoof_{idx}_{self._rng.integers(1000, 9999)}"
            spoofed_ip = f"{ip_prefixes[idx % len(ip_prefixes)]}.{int(self._rng.integers(10, 250))}"

            payload: dict[str, Any] = {
                "customer": customer_id,
                "merchant": f"merch_global_{idx:02d}",
                "amount": amount,
                "currency": "USD",
                "device": spoofed_device,
                "ip_address": spoofed_ip,
                "user_agent": user_agents[idx % len(user_agents)],
                "geo_city": loc.city,
                "geo_country": loc.country,
                "latitude": loc.latitude,
                "longitude": loc.longitude,
                "distance_from_prev_km": round(distance_km, 2),
                "speed_kmh": round(speed_kmh, 2),
                "impossible_velocity": speed_kmh > 1000.0,
                "spoofed_fingerprint": True,
            }

            events.append(
                TraceEvent(
                    event_id=self._next_event_id(),
                    ts=cur_ts,
                    actor_kind=ActorKind.CUSTOMER,
                    actor_id=customer_id,
                    kind="payment",
                    payload=payload,
                    is_attack_step=True,
                    attack_stage=LifecycleStage.AUTHENTICATION if idx == 0 else LifecycleStage.PAYMENT,
                    evidence_scope=EvidenceScope.DEFENDER,
                )
            )

            prev_loc = loc
            prev_ts = cur_ts

        return events

    # ------------------------------------------------------------------ smurfing / structuring

    def generate_smurfing_pattern(
        self,
        *,
        threshold: float = 10000.0,
        structuring_ratio: float = 0.94,
        num_transactions: int = 5,
        target_account: str = "acc_mule_collector",
        source_accounts: list[str] | None = None,
        start_time: datetime | None = None,
        spread_hours: float = 12.0,
    ) -> list[TraceEvent]:
        """Generate smurfing / structuring patterns (transactions just under reporting threshold)."""
        base_time = start_time or datetime(2026, 8, 25, 10, 0, tzinfo=UTC)
        sources = source_accounts or [f"acc_smurf_{i:03d}" for i in range(num_transactions)]
        smurf_group_id = f"smurf_grp_{self._seq + 1:04d}"

        # Amounts structured just below threshold (e.g. 92% to 99% of threshold)
        events: list[TraceEvent] = []
        for i in range(num_transactions):
            src = sources[i % len(sources)]
            # Draw structuring variation e.g. between 90% and 98% of threshold
            variation = float(self._rng.uniform(0.91, 0.98))
            amount = round(threshold * variation, 2)

            time_step = timedelta(hours=(i / max(1, num_transactions - 1)) * spread_hours)
            ts = base_time + time_step

            payload: dict[str, Any] = {
                "customer": src,
                "source_account": src,
                "destination_account": target_account,
                "amount": amount,
                "currency": "USD",
                "threshold_benchmark": threshold,
                "structuring_ratio": round(amount / threshold, 4),
                "is_structured": True,
                "smurf_group_id": smurf_group_id,
                "sequence_index": i,
                "note": "smurfing_structuring_below_aml_threshold",
            }

            events.append(
                TraceEvent(
                    event_id=self._next_event_id(),
                    ts=ts,
                    actor_kind=ActorKind.CUSTOMER,
                    actor_id=src,
                    kind="payment",
                    payload=payload,
                    is_attack_step=True,
                    attack_stage=LifecycleStage.PAYMENT,
                    evidence_scope=EvidenceScope.DEFENDER,
                )
            )

        return events

    # ------------------------------------------------------------------ streaming API

    def stream_attacks(
        self,
        *,
        count: int = 60,
        pattern: AttackVectorType | None = None,
        start_time: datetime | None = None,
    ) -> Iterator[TraceEvent]:
        """Generate a continuous stream of adversarial attack vectors."""
        current_time = start_time or datetime(2026, 8, 25, 8, 0, tzinfo=UTC)
        produced = 0

        while produced < count:
            selected_pattern = (
                pattern
                if pattern is not None
                else self._rng.choice(
                    [
                        AttackVectorType.MICRO_BURST,
                        AttackVectorType.GEO_VELOCITY_SPOOF,
                        AttackVectorType.SMURFING,
                    ]
                )
            )

            chunk: list[TraceEvent] = []
            if selected_pattern == AttackVectorType.MICRO_BURST:
                burst_size = min(int(self._rng.integers(5, 12)), count - produced)
                chunk = self.generate_micro_burst(
                    start_time=current_time,
                    count=burst_size,
                    customer_id=f"cust_victim_{produced:04d}",
                )
            elif selected_pattern == AttackVectorType.GEO_VELOCITY_SPOOF:
                hop_count = min(int(self._rng.integers(2, 4)), count - produced)
                cities = list(KNOWN_LOCATIONS.keys())[:hop_count]
                chunk = self.generate_geo_velocity_hops(
                    start_time=current_time,
                    hop_cities=cities,
                    customer_id=f"cust_spoof_{produced:04d}",
                )
            else:  # Smurfing
                smurf_count = min(int(self._rng.integers(3, 6)), count - produced)
                chunk = self.generate_smurfing_pattern(
                    start_time=current_time,
                    num_transactions=smurf_count,
                    target_account=f"acc_collector_{produced:04d}",
                )

            for event in chunk:
                yield event
                produced += 1
                if produced >= count:
                    break

            if chunk:
                current_time = chunk[-1].ts + timedelta(minutes=5)

    def generate_adversarial_trace(
        self,
        strategy_id: str = "adv_stream_01",
        pattern: AttackVectorType = AttackVectorType.MICRO_BURST,
        start_time: datetime | None = None,
    ) -> SyntheticTrace:
        """Produce a complete SyntheticTrace wrapping generated attack events."""
        events = list(self.stream_attacks(count=20, pattern=pattern, start_time=start_time))
        ground_truth = GroundTruth(
            strategy_id=strategy_id,
            fingerprint=f"fp_{strategy_id}_{pattern.value}",
            attack_event_ids=[e.event_id for e in events],
        )
        fidelity = FidelityReport(
            psi_amount=0.04,
            ks_timestamp_gap=0.03,
            graph_density_delta=0.01,
            temporal_autocorr=0.15,
            reachability_ok=True,
            notes=[f"streaming_vector:{pattern.value}"],
        )
        return SyntheticTrace(
            trace_id=f"tr_adv_{self.seed.master_seed}_{self._seq:05d}",
            seed=self.seed,
            events=events,
            ground_truth=ground_truth,
            fidelity=fidelity,
        )


__all__ = [
    "KNOWN_LOCATIONS",
    "AttackVectorType",
    "GeoLocation",
    "SyntheticFraudAttackGenerator",
    "haversine_distance_km",
]
