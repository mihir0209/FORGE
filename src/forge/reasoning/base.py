"""The LLM seam: one small interface, many adapters (see ADR-0003)."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel


class ReasoningError(Exception):
    """Base class for structured LLM failures."""


class RefusalError(ReasoningError):
    """The provider declined on safety grounds."""


class SchemaViolation(ReasoningError):
    """Output failed schema validation after retries."""


class ProviderDown(ReasoningError):
    """Network/auth/quota failure at the provider boundary."""


@runtime_checkable
class ReasoningClient(Protocol):
    """complete(schema, system, user) -> validated instance of schema."""

    @property
    def name(self) -> str: ...

    def complete[T: BaseModel](self, schema: type[T], system: str, user: str) -> T: ...
