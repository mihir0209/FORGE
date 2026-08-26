"""API-safe commands that enqueue fixed workflows into the durable control plane."""

from __future__ import annotations

import secrets
from typing import Any, cast

import inngest

from forge.contracts.contracts import EvCycleRequested, ev_dict
from forge.pipeline.client import client


async def enqueue_competition_demo() -> dict[str, object]:
    families = (
        "ai_bank_impersonation",
        "deepfake_executive_bec",
        "agent_prompt_injection_payment_hijack",
    )
    requests = [
        (
            secrets.randbits(31),
            family,
        )
        for family in families
    ]
    events = [
        inngest.Event(
            name="cycle.requested",
            data=cast(
                "dict[str, Any]",
                ev_dict(
                    EvCycleRequested(
                        seed=seed,
                        scenario="ai_assisted_app_scam",
                        family_slug=family,
                        family_version="1.0.0",
                    )
                ),
            ),
        )
        for seed, family in requests
    ]
    event_ids = await client.send(events)
    return {
        "event_ids": event_ids,
        "scenarios": [
            {"seed": seed, "family_slug": family} for seed, family in requests
        ],
        "families": list(families),
    }


async def enqueue_worker_probes(count: int = 5) -> dict[str, object]:
    probes = [
        inngest.Event(
            name="worker.probe",
            data={"probe_id": f"probe-{secrets.token_hex(8)}", "hold_seconds": 3},
        )
        for _ in range(count)
    ]
    return {"event_ids": await client.send(probes), "requested": count}
