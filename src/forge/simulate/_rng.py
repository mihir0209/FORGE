"""Deterministic RNG derivation.

Never use Python's builtin hash() for seeding — str hashes are process-randomized.
Stable tag hashing uses crc32; subsystem streams derive from the master seed only.
"""

from __future__ import annotations

import zlib
from typing import TYPE_CHECKING

import numpy as np

if TYPE_CHECKING:
    from forge.contracts.contracts import WorldSeed


def _tag(tag: str) -> int:
    return zlib.crc32(tag.encode()) & 0xFFFFFFFF


def derive_rng(seed: WorldSeed, subsystem: str) -> np.random.Generator:
    """Independent stream per subsystem; same inputs -> same stream, always."""
    return np.random.default_rng([seed.master_seed & 0xFFFFFFFF, _tag(subsystem)])


def derive_int(seed: WorldSeed, subsystem: str) -> int:
    return int(derive_rng(seed, f"{subsystem}:seed").integers(0, 2**31 - 1))
