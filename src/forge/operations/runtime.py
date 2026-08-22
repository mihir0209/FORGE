"""Run supervisor / SMTP composition root from deployment environment."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from forge.artifacts import LocalArtifactStore
from forge.contracts.contracts import RunSupervisorConfig
from forge.operations.email import EmailNotifier
from forge.operations.supervisor import (
    LocalRunStateStore,
    PostgresRunStateStore,
    RunSupervisor,
)


def supervisor_from_env() -> RunSupervisor | None:
    run_id = os.environ.get("FORGE_RUN_ID")
    if not run_id:
        return None
    now = datetime.now(UTC)
    dsn = os.environ.get("FORGE_DATABASE_URL")
    state_store = (
        PostgresRunStateStore(dsn)
        if dsn
        else LocalRunStateStore(
            Path(os.environ.get("FORGE_DATA_DIR", "data")) / "runs" / run_id / "state.json"
        )
    )
    stop_at = os.environ.get("FORGE_STOP_AT")
    ends_at = (
        datetime.fromisoformat(stop_at.replace("Z", "+00:00"))
        if stop_at
        else now + timedelta(hours=int(os.environ.get("FORGE_RUN_DURATION_HOURS", "96")))
    )
    existing = state_store.load(run_id)
    if existing is not None:
        ends_at = existing.deadline_at
    config = RunSupervisorConfig(
        run_id=run_id,
        starts_at=(existing.started_at or now) if existing else now,
        ends_at=ends_at,
        max_cycles=int(os.environ.get("FORGE_MAX_CYCLES", "1000")),
        max_storage_bytes=int(os.environ.get("FORGE_MAX_STORAGE_BYTES", str(500 * 1024**3))),
        queue_capacity=int(os.environ.get("FORGE_QUEUE_CAPACITY", "100")),
    )
    return RunSupervisor(
        config,
        LocalArtifactStore(),
        state_store=state_store,
    )


def notifier_from_env() -> EmailNotifier:
    root = Path(os.environ.get("FORGE_DATA_DIR", "data")) / "notifications"
    return EmailNotifier(root)
