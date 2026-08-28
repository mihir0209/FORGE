"""Live reasoning client assembly — env-driven, fixture-free.

Set FORGE_LIVE_LLM=1 (plus OPENAI_API_KEY / OPENAI_BASE_URL from .env) to have
pipeline stages compose via the real model. Without it, everything stays on
deterministic fixtures.
"""

from __future__ import annotations

import os

from forge.config import load_env_file
from forge.reasoning import ChainedReasoningClient, PydanticAIClient, ReasoningClient


def live_enabled() -> bool:
    return os.environ.get("FORGE_LIVE_LLM", "").lower() in {"1", "true", "yes"}


def default_client(*, team: str = "unknown", stage: str = "complete") -> ReasoningClient | None:
    load_env_file()
    if not live_enabled():
        return None
    if not os.environ.get("OPENAI_API_KEY"):
        return None
    from forge.kb import registry_from_env

    telemetry = registry_from_env()
    model = os.environ.get("FORGE_LLM_MODEL", "mimo-v2.5")
    clients: list[PydanticAIClient] = [
        PydanticAIClient(f"openai:{model}", telemetry=telemetry, team=team, stage=stage)
    ]
    # fallback to mimo-v2.5 when primary is gpt-family (gateway often refuses gpt-family but serves mimo)
    fallback_model = os.environ.get("FORGE_LLM_FALLBACK_MODEL", "mimo-v2.5")
    if fallback_model and fallback_model != model:
        clients.append(
            PydanticAIClient(f"openai:{fallback_model}", telemetry=telemetry, team=team, stage=stage)
        )
    if os.environ.get("ANTHROPIC_API_KEY"):
        clients.append(
            PydanticAIClient(
                "anthropic:claude-haiku-4-5", telemetry=telemetry, team=team, stage=stage
            )
        )
    return ChainedReasoningClient(*clients)  # type: ignore[arg-type]
