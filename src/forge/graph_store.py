"""Append-only persistence adapters for causal graph events and snapshots."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Protocol

from forge.contracts.contracts import GraphEvent, GraphSnapshot


class GraphConflictError(ValueError):
    """An immutable graph identifier was reused with different content."""


class GraphEventStore(Protocol):
    def append(self, event: GraphEvent) -> None: ...
    def events(self) -> list[GraphEvent]: ...
    def persist_snapshot(self, snapshot: GraphSnapshot) -> None: ...
    def load_snapshot(self, snapshot_id: str) -> GraphSnapshot | None: ...


def _same_payload(left: GraphEvent | GraphSnapshot, right_json: str) -> bool:
    return left.model_dump_json() == right_json


class InMemoryGraphStore:
    def __init__(self) -> None:
        self._events: dict[str, GraphEvent] = {}
        self._snapshots: dict[str, GraphSnapshot] = {}

    def append(self, event: GraphEvent) -> None:
        current = self._events.get(event.event_id)
        if current is not None and current != event:
            raise GraphConflictError(f"graph event conflict: {event.event_id}")
        self._events[event.event_id] = event

    def events(self) -> list[GraphEvent]:
        return list(self._events.values())

    def persist_snapshot(self, snapshot: GraphSnapshot) -> None:
        current = self._snapshots.get(snapshot.snapshot_id)
        if current is not None and current != snapshot:
            raise GraphConflictError(f"graph snapshot conflict: {snapshot.snapshot_id}")
        self._snapshots[snapshot.snapshot_id] = snapshot

    def load_snapshot(self, snapshot_id: str) -> GraphSnapshot | None:
        return self._snapshots.get(snapshot_id)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS graph_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS graph_snapshots (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  snapshot_id TEXT NOT NULL UNIQUE,
  snapshot_sha256 TEXT NOT NULL,
  payload TEXT NOT NULL
);
"""


class SQLiteGraphStore:
    def __init__(self, path: Path | str) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def append(self, event: GraphEvent) -> None:
        payload = event.model_dump_json()
        row = self._conn.execute(
            "SELECT payload FROM graph_events WHERE event_id=?", (event.event_id,)
        ).fetchone()
        if row is not None:
            if not _same_payload(event, str(row[0])):
                raise GraphConflictError(f"graph event conflict: {event.event_id}")
            return
        self._conn.execute(
            "INSERT INTO graph_events(event_id,payload) VALUES (?,?)", (event.event_id, payload)
        )
        self._conn.commit()

    def events(self) -> list[GraphEvent]:
        rows = self._conn.execute("SELECT payload FROM graph_events ORDER BY sequence").fetchall()
        return [GraphEvent.model_validate_json(row[0]) for row in rows]

    def persist_snapshot(self, snapshot: GraphSnapshot) -> None:
        payload = snapshot.model_dump_json()
        row = self._conn.execute(
            "SELECT payload FROM graph_snapshots WHERE snapshot_id=?", (snapshot.snapshot_id,)
        ).fetchone()
        if row is not None:
            if not _same_payload(snapshot, str(row[0])):
                raise GraphConflictError(f"graph snapshot conflict: {snapshot.snapshot_id}")
            return
        self._conn.execute(
            "INSERT INTO graph_snapshots(snapshot_id,snapshot_sha256,payload) VALUES (?,?,?)",
            (snapshot.snapshot_id, snapshot.snapshot_sha256, payload),
        )
        self._conn.commit()

    def load_snapshot(self, snapshot_id: str) -> GraphSnapshot | None:
        row = self._conn.execute(
            "SELECT payload FROM graph_snapshots WHERE snapshot_id=?", (snapshot_id,)
        ).fetchone()
        return GraphSnapshot.model_validate_json(row[0]) if row is not None else None

    def close(self) -> None:
        self._conn.close()


def graph_store_from_env() -> GraphEventStore:
    return SQLiteGraphStore(
        Path(os.environ.get("FORGE_DATA_DIR", "data")) / "risk-graph.sqlite"
    )
