"""Unattended campaign and persisted-data quality gates."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

from forge.artifacts import LocalArtifactStore
from forge.contracts.contracts import RunState, RunSupervisorConfig
from forge.cycle_runner import run_offline_cycle
from forge.data_quality import audit_registry
from forge.kb import InMemoryRegistry
from forge.operations import campaign
from forge.operations.supervisor import RunSupervisor
from forge.redteam.fixtures import default_draft
from forge.storage import ensure_dirs


def _supervisor(tmp_path: Path, now: datetime) -> RunSupervisor:
    return RunSupervisor(
        RunSupervisorConfig(
            run_id="run-48h",
            starts_at=now,
            ends_at=now + timedelta(hours=48),
            max_cycles=100,
            max_storage_bytes=10_000_000_000,
            queue_capacity=20,
        ),
        LocalArtifactStore(tmp_path / "objects"),
        tmp_path / "run-state.json",
    )


def test_campaign_tick_is_restart_safe_and_rotates_families(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
    supervisor = _supervisor(tmp_path, now)
    monkeypatch.setenv("FORGE_CAMPAIGN_ENABLED", "1")
    monkeypatch.setenv("FORGE_CAMPAIGN_INTERVAL_MINUTES", "10")
    monkeypatch.setenv("FORGE_CAMPAIGN_FAMILIES", "ai_bank_impersonation,ai_family_emergency")
    monkeypatch.setenv("FORGE_CAMPAIGN_FAMILIES_PER_SLOT", "1")
    monkeypatch.setenv("FORGE_CAMPAIGN_BEHAVIORAL_PER_SLOT", "0")
    monkeypatch.setattr(campaign, "supervisor_from_env", lambda: supervisor)

    first = campaign.campaign_tick(now)
    assert len(first) == 1
    assert campaign.campaign_tick(now + timedelta(minutes=5)) == first
    second = campaign.campaign_tick(now + timedelta(minutes=10))
    assert len(second) == 1
    assert first[0]["seed"] != second[0]["seed"]
    assert first[0]["family_slug"] != second[0]["family_slug"]


def test_completed_cycle_key_is_not_readmitted(tmp_path: Path) -> None:
    now = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
    supervisor = _supervisor(tmp_path, now)
    supervisor.start(now)
    assert supervisor.admit(cycle_key="cycle:1", queue_depth=0, storage_reservation=10, now=now)
    supervisor.cycle_started("cycle:1")
    supervisor.cycle_completed(cycle_key="cycle:1")
    assert not supervisor.admit(
        cycle_key="cycle:1", queue_depth=0, storage_reservation=10, now=now
    )


def test_released_admission_restores_capacity(tmp_path: Path) -> None:
    now = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
    supervisor = _supervisor(tmp_path, now)
    supervisor.start(now)
    assert supervisor.admit(cycle_key="duplicate", queue_depth=0, storage_reservation=10, now=now)
    state = supervisor.release_admission("duplicate", storage_reservation=10)
    assert state.admitted_cycles == 0
    assert state.storage_bytes == 0
    assert state.queued_cycles == 0
    assert supervisor.release_admission("duplicate", storage_reservation=10) == state


def test_draining_waits_for_queued_cycles(tmp_path: Path) -> None:
    now = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
    supervisor = _supervisor(tmp_path, now)
    supervisor.start(now)
    assert supervisor.admit(cycle_key="queued", queue_depth=0, storage_reservation=10, now=now)
    state = supervisor.tick(now + timedelta(hours=49))
    assert state.state == RunState.DRAINING
    assert supervisor.tick(now + timedelta(hours=49, minutes=1)).state == RunState.DRAINING
    supervisor.release_admission("queued", storage_reservation=10)
    assert supervisor.tick(now + timedelta(hours=49, minutes=2)).state == RunState.FINALIZING


def test_data_audit_verifies_trace_and_blocks_unreviewed_llm_corpus(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path))
    ensure_dirs.cache_clear()
    registry = InMemoryRegistry()
    record = run_offline_cycle(42, registry, draft=default_draft())

    result = audit_registry(registry)
    assert result["integrity_ready"] is True
    assert result["llm_ready"] is False
    assert result["valid_cycles"] == 1

    trace_path = tmp_path / "artifacts" / record.trace_ref
    trace_path.write_text("{}")
    failed = audit_registry(registry)
    assert failed["integrity_ready"] is False
    assert failed["failures"][0]["errors"] == ["trace_checksum_mismatch"]
