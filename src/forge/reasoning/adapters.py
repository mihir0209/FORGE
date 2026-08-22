"""Pydantic AI adapters — OpenAI default, Anthropic fallback (ADR-0003).

Stateless-per-call: no persistence of its own, so Inngest stays the single
durability owner. Lazy imports keep `forge.reasoning` importable without keys.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ValidationError
from pydantic_core import ValidationError as CoreValidationError

from forge.reasoning.base import ProviderDown, RefusalError, SchemaViolation

if TYPE_CHECKING:
    from pydantic_ai.models import Model

_RETRIES = 2


class PydanticAIClient:
    def __init__(self, model: str) -> None:
        self._model = model
        self._agent_model: Model[Any] | str = model
        if model.startswith("openai:"):
            # OpenAI-compatible gateways frequently implement Chat Completions
            # but not the newer Responses API. Force the compatible adapter.
            from pydantic_ai.models.openai import OpenAIChatModel
            from pydantic_ai.providers.openai import OpenAIProvider

            self._agent_model = OpenAIChatModel(
                model.removeprefix("openai:"), provider=OpenAIProvider()
            )

    @property
    def name(self) -> str:
        return self._model

    def complete[T: BaseModel](self, schema: type[T], system: str, user: str) -> T:
        from pydantic_ai import Agent
        from pydantic_ai.exceptions import UnexpectedModelBehavior

        agent = Agent(
            self._agent_model,
            output_type=schema,
            system_prompt=system,
            retries=_RETRIES,
        )
        try:
            result = agent.run_sync(user)
        except (ValidationError, CoreValidationError) as exc:
            raise SchemaViolation(f"{schema.__name__}: {exc}") from exc
        except UnexpectedModelBehavior as exc:
            raise RefusalError(str(exc)) from exc
        except Exception as exc:  # httpx/auth/quota and friends
            raise ProviderDown(f"{self._model}: {type(exc).__name__}: {exc}") from exc

        out: Any = result.output
        assert isinstance(out, schema)
        return out
