"""Deterministic identifiers shared by offline runner and pipeline."""

from __future__ import annotations

from hashlib import sha256


def strategy_id_for(seed: int) -> str:
    return f"s_off_{sha256(str(seed).encode()).hexdigest()[:10]}"


def cycle_id_base(strategy_id: str, seed: int) -> str:
    return f"cy_{sha256(f'{strategy_id}:{seed}'.encode()).hexdigest()[:12]}"
