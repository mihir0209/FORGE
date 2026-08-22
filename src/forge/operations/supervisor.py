"""RunSupervisor state machine and terminal artifact manifest."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol

from forge.contracts.contracts import (
    ArtifactManifest,
    ManifestEntry,
    RunState,
    RunSupervisorConfig,
    RunSupervisorState,
)

if TYPE_CHECKING:
    from pathlib import Path

    from forge.artifacts import LocalArtifactStore


class RunStateStore(Protocol):
    def load(self, run_id: str) -> RunSupervisorState | None: ...
    def save(self, state: RunSupervisorState) -> None: ...


class LocalRunStateStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)

    def load(self, run_id: str) -> RunSupervisorState | None:
        if not self.path.exists():
            return None
        state = RunSupervisorState.model_validate_json(self.path.read_text())
        return state if state.run_id == run_id else None

    def save(self, state: RunSupervisorState) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(state.model_dump_json(indent=2))
        tmp.replace(self.path)


class PostgresRunStateStore:
    """Atomic compare-and-swap state for five concurrent workers."""

    def __init__(self, dsn: str) -> None:
        import psycopg

        self.conn = psycopg.connect(dsn, autocommit=False)
        with self.conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS forge_run_state (
                  run_id TEXT PRIMARY KEY,
                  version INTEGER NOT NULL,
                  payload JSONB NOT NULL
                )
                """
            )
        self.conn.commit()

    def load(self, run_id: str) -> RunSupervisorState | None:
        with self.conn.cursor() as cur:
            cur.execute("SELECT payload FROM forge_run_state WHERE run_id=%s", (run_id,))
            row = cur.fetchone()
        self.conn.rollback()
        return RunSupervisorState.model_validate(row[0]) if row else None

    def save(self, state: RunSupervisorState) -> None:
        from psycopg.types.json import Jsonb

        with self.conn.transaction(), self.conn.cursor() as cur:
            cur.execute(
                """
                    INSERT INTO forge_run_state(run_id,version,payload)
                    VALUES (%s,%s,%s)
                    ON CONFLICT (run_id) DO UPDATE
                      SET version=EXCLUDED.version,payload=EXCLUDED.payload
                      WHERE forge_run_state.version = EXCLUDED.version - 1
                    """,
                (state.run_id, state.version, Jsonb(state.model_dump(mode="json"))),
            )
            if cur.rowcount != 1:
                raise RuntimeError("concurrent run-state update; retry durable step")


class RunSupervisor:
    def __init__(
        self,
        config: RunSupervisorConfig,
        store: LocalArtifactStore,
        state_path: Path | None = None,
        state_store: RunStateStore | None = None,
    ) -> None:
        self.config = config
        self.store = store
        if state_store is None and state_path is None:
            raise ValueError("state_path or state_store is required")
        self.state_store = state_store or LocalRunStateStore(state_path)  # type: ignore[arg-type]

    def start(self, now: datetime | None = None) -> RunSupervisorState:
        existing = self.load()
        if existing is not None:
            return existing
        now = now or datetime.now(UTC)
        state = RunSupervisorState(
            run_id=self.config.run_id,
            state=RunState.RUNNING if now >= self.config.starts_at else RunState.SCHEDULED,
            version=1,
            started_at=now if now >= self.config.starts_at else None,
            deadline_at=self.config.ends_at,
        )
        return self._save(state)

    def admit(
        self, *, queue_depth: int, storage_reservation: int, now: datetime | None = None
    ) -> bool:
        now = now or datetime.now(UTC)
        state = self.load_required()
        queue_ratio = queue_depth / self.config.queue_capacity
        allowed = (
            state.state == RunState.RUNNING
            and now < self.config.ends_at
            and state.admitted_cycles < self.config.max_cycles
            and state.storage_bytes + storage_reservation < self.config.max_storage_bytes
            and queue_ratio < self.config.queue_full_threshold
        )
        if allowed:
            self._save(
                state.model_copy(
                    update={
                        "version": state.version + 1,
                        "admitted_cycles": state.admitted_cycles + 1,
                        "queued_cycles": state.queued_cycles + 1,
                        "storage_bytes": state.storage_bytes + storage_reservation,
                    }
                )
            )
        elif queue_ratio >= self.config.queue_full_threshold and not state.queue_alert_open:
            self._save(
                state.model_copy(update={"version": state.version + 1, "queue_alert_open": True})
            )
        return allowed

    def cycle_started(self) -> RunSupervisorState:
        state = self.load_required()
        return self._save(
            state.model_copy(
                update={
                    "version": state.version + 1,
                    "queued_cycles": max(0, state.queued_cycles - 1),
                    "active_cycles": state.active_cycles + 1,
                }
            )
        )

    def release_admission(self) -> RunSupervisorState:
        """Release a reserved slot when compose terminates (e.g. duplicate)."""
        state = self.load_required()
        return self._save(
            state.model_copy(
                update={
                    "version": state.version + 1,
                    "queued_cycles": max(0, state.queued_cycles - 1),
                }
            )
        )

    def cycle_completed(self, actual_storage_bytes: int = 0) -> RunSupervisorState:
        state = self.load_required()
        next_state = state.model_copy(
            update={
                "version": state.version + 1,
                "active_cycles": max(0, state.active_cycles - 1),
                "completed_cycles": state.completed_cycles + 1,
                "storage_bytes": max(state.storage_bytes, actual_storage_bytes),
            }
        )
        if next_state.completed_cycles >= self.config.max_cycles:
            next_state = next_state.model_copy(
                update={"state": RunState.DRAINING, "stop_reason": "max_cycles"}
            )
        return self._save(next_state)

    def tick(self, now: datetime | None = None) -> RunSupervisorState:
        now = now or datetime.now(UTC)
        state = self.load_required()
        if state.state == RunState.SCHEDULED and now >= self.config.starts_at:
            return self._save(
                state.model_copy(
                    update={
                        "state": RunState.RUNNING,
                        "version": state.version + 1,
                        "started_at": now,
                    }
                )
            )
        if state.state == RunState.RUNNING and now >= self.config.ends_at:
            return self._save(
                state.model_copy(
                    update={
                        "state": RunState.DRAINING,
                        "version": state.version + 1,
                        "stop_requested_at": now,
                        "stop_reason": "deadline",
                    }
                )
            )
        if state.state == RunState.DRAINING and state.active_cycles == 0:
            return self._save(
                state.model_copy(
                    update={"state": RunState.FINALIZING, "version": state.version + 1}
                )
            )
        return state

    def finalize(self, kind_roots: dict[str, Path]) -> ArtifactManifest:
        state = self.load_required()
        if state.state not in {RunState.FINALIZING, RunState.DRAINING}:
            raise ValueError(f"cannot finalize from {state.state}")
        entries: list[ManifestEntry] = []
        for kind, root in sorted(kind_roots.items()):
            if not root.exists():
                continue
            for path in sorted(p for p in root.rglob("*") if p.is_file()):
                data = path.read_bytes()
                entries.append(
                    ManifestEntry(
                        ref=str(path),
                        sha256=hashlib.sha256(data).hexdigest(),
                        byte_size=len(data),
                        kind=kind,
                    )
                )
        terminal = RunState.EXPIRED if state.stop_reason == "deadline" else RunState.COMPLETED
        body = {
            "run_id": state.run_id,
            "state": terminal.value,
            "entries": [e.model_dump(mode="json") for e in entries],
        }
        manifest_hash = hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        manifest = ArtifactManifest(
            run_id=state.run_id,
            state=terminal,
            entries=entries,
            manifest_sha256=manifest_hash,
        )
        ref = self.store.put_json("manifests", state.run_id, manifest.model_dump(mode="json"))
        self._save(
            state.model_copy(
                update={
                    "state": terminal,
                    "version": state.version + 1,
                    "terminal_manifest_ref": ref.uri,
                    "terminal_manifest_sha256": ref.sha256,
                }
            )
        )
        return manifest

    def load(self) -> RunSupervisorState | None:
        return self.state_store.load(self.config.run_id)

    def load_required(self) -> RunSupervisorState:
        state = self.load()
        if state is None:
            raise ValueError("run supervisor has not been started")
        return state

    def _save(self, state: RunSupervisorState) -> RunSupervisorState:
        self.state_store.save(state)
        return state
