"""Dynamic family registration, causal graph assessment, and optional MCP discovery."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from forge.contracts.contracts import (
    DetectionTrack,
    F3Mapping,
    GraphEvent,
    GraphScope,
    ToolKind,
)
from forge.families import FamilyRegistry, build_app_plan
from forge.research_mcp import available_mcp_servers
from forge.risk_graph import TemporalRiskGraph


def test_dynamic_family_registers_without_runtime_branch(tmp_path: Path) -> None:
    builtin = FamilyRegistry().get("ai_bank_impersonation")
    payload = builtin.model_dump()
    payload.update(slug="ai_invoice_avatar", title="AI invoice avatar", definition_sha256="pending")
    # Reuse the canonical helper behavior by writing then loading through the registry.
    from forge.families import define_family

    family = define_family(**{k: v for k, v in payload.items() if k != "definition_sha256"})
    registry = FamilyRegistry(tmp_path)
    registry.register(family)
    loaded = registry.get("ai_invoice_avatar")
    assert loaded.definition_sha256 == family.definition_sha256
    assert build_app_plan(loaded, "cycle-new").actions

    reloaded = FamilyRegistry(tmp_path).get("ai_invoice_avatar")
    assert reloaded.definition_sha256 == family.definition_sha256


def test_family_version_is_immutable(tmp_path: Path) -> None:
    from forge.families import define_family

    family = define_family(
        slug="ai_new_family", version="1.0.0", title="New", description="New family",
        detection_track=DetectionTrack.AI_ASSISTED_APP,
        f3=F3Mapping(tactic="monetization", techniques=["F1010"]), rail="upi", channel="mobile_banking",
        genai_leverage="agentic coaching", evasion_hypothesis="new behavior",
        allowed_tools=[ToolKind.APP_SESSION_START], scenario_defaults={}, research_refs=[],
    )
    registry = FamilyRegistry(tmp_path)
    registry.register(family)
    conflicting = family.model_copy(update={"title": "Changed", "definition_sha256": "0" * 64})
    with pytest.raises(ValueError):
        registry.register(conflicting)


def test_graph_excludes_future_and_unavailable_events() -> None:
    now = datetime(2026, 8, 25, tzinfo=UTC)
    events = [
        GraphEvent(event_id="past", event_time=now-timedelta(minutes=10), available_at=now-timedelta(minutes=9), kind="payment.settled", institution_id="b", source_account_ref="s1", destination_account_ref="payee", amount_minor=100),
        GraphEvent(event_id="future", event_time=now+timedelta(seconds=1), available_at=now+timedelta(seconds=1), kind="payment.settled", institution_id="b", source_account_ref="s2", destination_account_ref="payee", amount_minor=100),
        GraphEvent(event_id="delayed", event_time=now-timedelta(days=1), available_at=now+timedelta(days=1), kind="fraud.label.observed", institution_id="b", destination_account_ref="payee"),
    ]
    assessment = TemporalRiskGraph(events).assess("payee", now, [GraphScope.LOCAL_BANK])
    assert assessment.features["unique_senders_1h"] == 1
    assert assessment.features["known_fraud_labels"] == 0
    assert assessment.evidence_event_ids == ["past"]


def test_mcp_server_absent_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TINYFISH_API_KEY", raising=False)
    assert available_mcp_servers() == []
    monkeypatch.setenv("TINYFISH_API_KEY", "configured")
    assert [server.name for server in available_mcp_servers()] == ["tinyfish"]
