"""Deterministic fixture client — no network, fails loudly when queue is dry."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class ScriptedReasoningClient:
    def __init__(self) -> None:
        self._queues: dict[str, list[BaseModel]] = {}
        self.calls: list[tuple[str, str, str]] = []

    def queue(self, *instances: BaseModel) -> None:
        for inst in instances:
            self._queues.setdefault(type(inst).__name__, []).append(inst)

    @property
    def name(self) -> str:
        return "scripted"

    def complete[T: BaseModel](self, schema: type[T], system: str, user: str) -> T:
        self.calls.append((schema.__name__, system[:64], user[:64]))
        q = self._queues.get(schema.__name__)
        if not q:
            raise AssertionError(f"no scripted response queued for {schema.__name__}")
        out: Any = q.pop(0)
        assert isinstance(out, schema)
        return out
