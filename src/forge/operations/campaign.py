"""Deterministic bounded campaign requests for unattended supervised runs."""

from __future__ import annotations

import os
import zlib
from datetime import UTC, datetime

from forge.contracts.contracts import EvCycleRequested, RunState, ev_dict
from forge.gapmine import rank
from forge.kb import registry_from_env
from forge.operations.runtime import supervisor_from_env

DEFAULT_FAMILIES = (
    "ai_bank_impersonation",
    "deepfake_executive_bec",
    "agent_prompt_injection_payment_hijack",
    "ai_family_emergency",
    "ai_investment_coaching",
    "synthetic_kyc_account_factory",
)


def campaign_tick(now: datetime | None = None) -> list[dict[str, object]]:
    """Claim and build one restart-safe campaign slot, or return no work."""
    if os.environ.get("FORGE_CAMPAIGN_ENABLED", "0").lower() not in {"1", "true", "yes"}:
        return []
    supervisor = supervisor_from_env()
    if supervisor is None:
        return []
    state = supervisor.start(now)
    if state.state != RunState.RUNNING:
        return []

    now = now or datetime.now(UTC)
    interval = int(os.environ.get("FORGE_CAMPAIGN_INTERVAL_MINUTES", "10"))
    if interval < 10 or interval % 10:
        raise ValueError("FORGE_CAMPAIGN_INTERVAL_MINUTES must be a multiple of 10")
    configured = tuple(
        item.strip()
        for item in os.environ.get("FORGE_CAMPAIGN_FAMILIES", ",".join(DEFAULT_FAMILIES)).split(",")
        if item.strip()
    )
    if not configured:
        raise ValueError("FORGE_CAMPAIGN_FAMILIES must contain at least one family")
    per_slot = max(1, int(os.environ.get("FORGE_CAMPAIGN_FAMILIES_PER_SLOT", "3")))
    slot = int(now.timestamp()) // (interval * 60)
    slot_id = f"{state.run_id}:{interval}:{slot}"

    requests: list[dict[str, object]] = []
    for index in range(min(per_slot, len(configured))):
        family = configured[(slot * per_slot + index) % len(configured)]
        seed = zlib.crc32(f"{slot_id}:{family}".encode()) & 0x7FFFFFFF
        requests.append(
            ev_dict(
                EvCycleRequested(
                    seed=seed,
                    scenario="ai_assisted_app_scam",
                    family_slug=family,
                )
            )
        )
    behavioral_per_slot = max(0, int(os.environ.get("FORGE_CAMPAIGN_BEHAVIORAL_PER_SLOT", "1")))
    briefs = rank(registry_from_env(), limit=behavioral_per_slot)
    for brief in briefs:
        seed = zlib.crc32(f"{slot_id}:behavioral:{brief.brief_id}".encode()) & 0x7FFFFFFF
        requests.append(ev_dict(EvCycleRequested(seed=seed, brief_id=brief.brief_id)))
    return requests
