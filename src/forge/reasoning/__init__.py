"""forge.reasoning — the LLM seam (ADR-0003)."""

from __future__ import annotations

from forge.reasoning.adapters import PydanticAIClient
from forge.reasoning.base import (
    ProviderDown,
    ReasoningClient,
    ReasoningError,
    RefusalError,
    SchemaViolation,
)
from forge.reasoning.scripted import ScriptedReasoningClient


class ChainedReasoningClient:
    """Primary with fallbacks; first success wins, typed errors chain."""

    def __init__(self, *clients: ReasoningClient) -> None:
        assert clients
        self._clients = clients

    @property
    def name(self) -> str:
        return "+".join(c.name for c in self._clients)

    def complete[T](self, schema: type[T], system: str, user: str) -> T:
        last: Exception | None = None
        for client in self._clients:
            try:
                return client.complete(schema, system, user)  # type: ignore[type-var]
            except Exception as exc:
                last = exc
        raise ProviderDown(f"all providers failed for {schema.__name__}: {last}")


__all__ = [
    "ChainedReasoningClient",
    "ProviderDown",
    "PydanticAIClient",
    "ReasoningClient",
    "ReasoningError",
    "RefusalError",
    "SchemaViolation",
    "ScriptedReasoningClient",
]
