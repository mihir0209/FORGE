"""Pydantic AI adapters — OpenAI default, Anthropic fallback (ADR-0003).

Stateless-per-call: no persistence of its own, so Inngest stays the single
durability owner. Lazy imports keep `forge.reasoning` importable without keys.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from pydantic import BaseModel, ValidationError
from pydantic_core import ValidationError as CoreValidationError

from forge.reasoning.base import ProviderDown, RefusalError, SchemaViolation

if TYPE_CHECKING:
    from pydantic_ai.models import Model

    from forge.kb import Registry

_RETRIES = 2
logger = logging.getLogger(__name__)


class PydanticAIClient:
    def __init__(
        self,
        model: str,
        *,
        telemetry: Registry | None = None,
        team: str = "unknown",
        stage: str = "complete",
    ) -> None:
        self._model = model
        self._telemetry = telemetry
        self._team = team
        self._stage = stage
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

        call_id = f"llm-{uuid4().hex}"
        started_at = datetime.now(UTC)
        started = time.perf_counter()
        provider, _, model = self._model.partition(":")
        logger.info(
            "LLM request started team=%s stage=%s provider=%s model=%s schema=%s call_id=%s",
            self._team, self._stage, provider, model or self._model, schema.__name__, call_id,
        )
        agent = Agent(
            self._agent_model,
            output_type=schema,
            system_prompt=system,
            retries=_RETRIES,
        )
        try:
            result = agent.run_sync(user)
        except (ValidationError, CoreValidationError) as exc:
            self._record(call_id, started_at, started, schema, "schema_violation", type(exc).__name__)
            raise SchemaViolation(f"{schema.__name__}: {exc}") from exc
        except UnexpectedModelBehavior as exc:
            self._record(call_id, started_at, started, schema, "refusal", type(exc).__name__)
            raise RefusalError(str(exc)) from exc
        except Exception as exc:  # httpx/auth/quota and friends
            self._record(call_id, started_at, started, schema, "provider_down", type(exc).__name__)
            raise ProviderDown(f"{self._model}: {type(exc).__name__}: {exc}") from exc

        out: Any = result.output
        assert isinstance(out, schema)
        usage = result.usage
        self._record(call_id, started_at, started, schema, "success", usage=usage)
        return out

    def _record(
        self,
        call_id: str,
        started_at: datetime,
        started: float,
        schema: type[BaseModel],
        status: str,
        error_type: str | None = None,
        *,
        usage: Any = None,
    ) -> None:
        from forge.contracts.contracts import LLMCall

        provider, _, model = self._model.partition(":")
        call = LLMCall(
            call_id=call_id,
            started_at=started_at,
            duration_ms=(time.perf_counter() - started) * 1000,
            team=self._team,
            stage=self._stage,
            provider=provider,
            model=model or self._model,
            schema_name=schema.__name__,
            status=status,
            requests=getattr(usage, "requests", None),
            input_tokens=getattr(usage, "input_tokens", None),
            output_tokens=getattr(usage, "output_tokens", None),
            cache_read_tokens=getattr(usage, "cache_read_tokens", None),
            cache_write_tokens=getattr(usage, "cache_write_tokens", None),
            tool_calls=getattr(usage, "tool_calls", None),
            run_id=os.environ.get("FORGE_RUN_ID"),
            cycle_id=os.environ.get("FORGE_CYCLE_ID"),
            error_type=error_type,
        )
        level = logging.INFO if status == "success" else logging.WARNING
        logger.log(
            level,
            "LLM request finished team=%s stage=%s provider=%s model=%s status=%s duration_ms=%.1f call_id=%s",
            self._team, self._stage, provider, model or self._model, status, call.duration_ms, call_id,
        )
        if self._telemetry is not None:
            try:
                self._telemetry.record_llm_call(call)
            except Exception:
                logger.exception("Unable to persist LLM telemetry call_id=%s", call_id)
