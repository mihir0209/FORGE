"""Synthetic payment world: identities, merchants, devices, households, graph."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import numpy as np
from faker import Faker

from forge.simulate._rng import derive_int, derive_rng

if TYPE_CHECKING:
    from forge.contracts.contracts import WorldSeed


@dataclass(frozen=True)
class CategoryProfile:
    """Behavioral fingerprint of a merchant category (PaySim-style external params)."""

    name: str
    log_amount_mean: float  # ln of median ticket
    log_amount_sigma: float
    tail_probability: float  # share of draws replaced by pareto tail
    tail_scale: float
    mean_hour: float
    hour_spread: float
    weekend_multiplier: float  # activity lift on Sat/Sun
    weekly_tx_per_active: float


CATEGORIES: tuple[CategoryProfile, ...] = (
    CategoryProfile("grocery", 5.5, 0.55, 0.005, 900, 18.0, 4.0, 1.35, 2.6),
    CategoryProfile("fuel", 5.3, 0.35, 0.002, 500, 9.5, 3.0, 0.90, 1.8),
    CategoryProfile("restaurant", 6.0, 0.50, 0.004, 700, 20.0, 2.5, 1.45, 1.7),
    CategoryProfile("electronics", 8.2, 0.80, 0.060, 3000, 16.0, 4.5, 1.25, 0.25),
    CategoryProfile("travel", 9.0, 0.90, 0.100, 6000, 11.0, 5.0, 1.30, 0.15),
    CategoryProfile("digital_goods", 5.0, 0.90, 0.010, 400, 22.5, 3.5, 1.05, 2.2),
    CategoryProfile("utilities", 6.2, 0.30, 0.001, 350, 10.0, 2.0, 0.95, 0.9),
)


@dataclass
class Merchant:
    merchant_id: str
    name: str
    category: CategoryProfile


@dataclass
class Device:
    device_id: str
    household_id: str


@dataclass
class Customer:
    customer_id: str
    display_name: str
    household_id: str
    device_ids: list[str]
    affinity_merchant_ids: list[str]
    opened_day: int  # onboarding day offset within horizon
    weekly_lambda: float  # baseline tx frequency


@dataclass
class World:
    customers: list[Customer] = field(default_factory=list[Customer])
    merchants: list[Merchant] = field(default_factory=list[Merchant])
    devices: list[Device] = field(default_factory=list[Device])

    def customer(self, customer_id: str) -> Customer:
        for c in self.customers:
            if c.customer_id == customer_id:
                return c
        raise KeyError(customer_id)


class WorldBuilder:
    """Builds the world from a WorldSeed. Deterministic under pinned deps."""

    def __init__(self, seed: WorldSeed, n_customers: int, n_merchants: int) -> None:
        self._seed = seed
        self._n_customers = n_customers
        self._n_merchants = n_merchants
        self._fake = Faker("en_IN")
        self._fake.seed_instance(derive_int(seed, "faker"))

    def build(self) -> World:
        rng_m = derive_rng(self._seed, "merchants")
        rng_c = derive_rng(self._seed, "customers")
        rng_d = derive_rng(self._seed, "devices")

        world = World()

        for i in range(self._n_merchants):
            cat = CATEGORIES[int(rng_m.integers(0, len(CATEGORIES)))]
            world.merchants.append(
                Merchant(
                    merchant_id=f"m{i:04d}",
                    name=self._fake.company(),
                    category=cat,
                )
            )

        n_households = max(1, self._n_customers // 3)
        for i in range(self._n_customers):
            hid = f"h{i % n_households:04d}"
            n_devices = int(rng_d.integers(1, 3))
            devices = [f"d{hid}_{k}" for k in range(n_devices)]
            for d in devices:
                if all(x.device_id != d for x in world.devices):
                    world.devices.append(Device(device_id=d, household_id=hid))
            k = int(rng_c.integers(3, 7))
            picks = rng_c.choice(len(world.merchants), size=k, replace=False)
            affinities = sorted(world.merchants[int(j)].merchant_id for j in picks)
            world.customers.append(
                Customer(
                    customer_id=f"c{i:05d}",
                    display_name=self._fake.name(),
                    household_id=hid,
                    device_ids=devices,
                    affinity_merchant_ids=affinities,
                    opened_day=int(rng_c.integers(0, 3)),
                    weekly_lambda=float(max(0.6, rng_c.normal(4.0, 1.8))),
                )
            )
        return world


def merchant_by_id(world: World) -> dict[str, Merchant]:
    return {m.merchant_id: m for m in world.merchants}


def pick_affinity(world: World, rng: np.random.Generator) -> tuple[Customer, Merchant]:
    c = world.customers[int(rng.integers(0, len(world.customers)))]
    mid = c.affinity_merchant_ids[int(rng.integers(0, len(c.affinity_merchant_ids)))]
    by_id = merchant_by_id(world)
    return c, by_id[mid]


# ---------------------------------------------------------------------------
# Pure behavioral draws — the single source of truth for category semantics.
# Used by the baseline engine, the attack injector, and fidelity references.
# ---------------------------------------------------------------------------


def draw_amount(rng: np.random.Generator, cat: CategoryProfile) -> float:
    """Heavy-tailed ticket size: lognormal body with a pareto replacement tail."""
    body = rng.lognormal(cat.log_amount_mean, cat.log_amount_sigma)
    if rng.random() < cat.tail_probability:
        tail = (rng.pareto(1.2) + 1) * cat.tail_scale
        return float(max(body, tail))
    return float(body)


def draw_hour(rng: np.random.Generator, cat: CategoryProfile | None) -> float:
    """Hour-of-day; falls back to a generic midday profile when category unknown."""
    h = rng.normal(cat.mean_hour, cat.hour_spread) if cat is not None else rng.normal(14.0, 5.0)
    if rng.random() < 0.04:  # small off-hours mass keeps tails realistic
        h = rng.uniform(0, 5)
    return float(np.clip(h, 0.0, 23.98))


def scaled_amount(rng: np.random.Generator, cat: CategoryProfile, scale: float) -> float:
    """Attack sizing relative to the category's natural ticket."""
    return float(np.clip(draw_amount(rng, cat) * scale, 1.0, 250_000.0))
