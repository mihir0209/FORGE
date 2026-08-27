from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from forge.api import read_models
from forge.api.app import create_app
from forge.contracts.contracts import LLMCall
from forge.kb import InMemoryRegistry, SQLiteRegistry


def _call(call_id: str, *, status: str, age: int = 0) -> LLMCall:
    return LLMCall(
        call_id=call_id,
        started_at=datetime.now(UTC) - timedelta(seconds=age),
        duration_ms=100 + age,
        team="blue",
        stage="investigate",
        provider="openai",
        model="test-model",
        schema_name="BlueAssessment",
        status=status,
        requests=1,
        input_tokens=10,
        output_tokens=5,
    )


def test_llm_call_registry_parity_and_immutability(tmp_path: Path) -> None:
    for registry in (InMemoryRegistry(), SQLiteRegistry(tmp_path / "registry.sqlite")):
        older = _call("older", status="provider_down", age=10)
        newer = _call("newer", status="success")
        registry.record_llm_call(older)
        registry.record_llm_call(newer)
        registry.record_llm_call(newer)

        assert [call.call_id for call in registry.llm_calls()] == ["newer", "older"]
        assert [call.call_id for call in registry.llm_calls(limit=1, offset=1)] == ["older"]


def test_llm_telemetry_api_summarizes_without_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = InMemoryRegistry()
    registry.record_llm_call(_call("failure", status="provider_down", age=10))
    registry.record_llm_call(_call("success", status="success"))
    monkeypatch.setattr(read_models, "registry", lambda: registry)

    response = TestClient(create_app()).get("/api/llm-telemetry")

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["calls"] == 2
    assert body["summary"]["successful"] == 1
    assert body["summary"]["failed"] == 1
    assert body["summary"]["input_tokens"] == 20
    assert "prompt" not in response.text.lower()
    assert "completion" not in response.text.lower()
