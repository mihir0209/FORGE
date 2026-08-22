"""Strategy/cycle registry — Protocol with two adapters (memory, SQLite WAL)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.contracts.contracts import CycleRecord, StrategySpec


class Registry:
    """Interface: append + query accepted knowledge. See ADR-0001 seams."""

    def record_strategy(self, spec: StrategySpec) -> None: ...
    def similar(self, fingerprint: str) -> list[StrategySpec]: ...
    def same_family_count(self, attack_family: str) -> int: ...
    def record_cycle(self, record: CycleRecord) -> None: ...
    def cycles(self) -> list[CycleRecord]: ...
    def strategy_count(self) -> int: ...


class InMemoryRegistry(Registry):
    def __init__(self) -> None:
        self._specs: dict[str, StrategySpec] = {}
        self._cycles: list[CycleRecord] = []

    def record_strategy(self, spec: StrategySpec) -> None:
        self._specs[spec.strategy_id] = spec

    def similar(self, fingerprint: str) -> list[StrategySpec]:
        return [s for s in self._specs.values() if s.fingerprint() == fingerprint]

    def same_family_count(self, attack_family: str) -> int:
        return sum(1 for s in self._specs.values() if s.attack_family == attack_family)

    def record_cycle(self, record: CycleRecord) -> None:
        self._cycles.append(record)
        self.record_strategy(record.strategy)

    def cycles(self) -> list[CycleRecord]:
        return list(self._cycles)

    def strategy_count(self) -> int:
        return len(self._specs)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS specs (
  strategy_id TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL,
  attack_family TEXT NOT NULL,
  json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_specs_fp ON specs(fingerprint);
CREATE TABLE IF NOT EXISTS cycles (
  cycle_id TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL,
  accepted INTEGER NOT NULL,
  coverage TEXT NOT NULL,
  json TEXT NOT NULL
);
"""


class SQLiteRegistry(Registry):
    def __init__(self, path: Path | str) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def record_strategy(self, spec: StrategySpec) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO specs VALUES (?,?,?,?)",
            (
                spec.strategy_id,
                spec.fingerprint(),
                spec.attack_family,
                spec.model_dump_json(),
            ),
        )
        self._conn.commit()

    def _all_specs(self) -> list[StrategySpec]:
        rows = self._conn.execute("SELECT json FROM specs").fetchall()
        return [StrategySpec.model_validate_json(r[0]) for r in rows]

    def similar(self, fingerprint: str) -> list[StrategySpec]:
        rows = self._conn.execute(
            "SELECT json FROM specs WHERE fingerprint=?", (fingerprint,)
        ).fetchall()
        return [StrategySpec.model_validate_json(r[0]) for r in rows]

    def same_family_count(self, attack_family: str) -> int:
        (n,) = self._conn.execute(
            "SELECT COUNT(*) FROM specs WHERE attack_family=?", (attack_family,)
        ).fetchone()
        return int(n)

    def record_cycle(self, record: CycleRecord) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO cycles VALUES (?,?,?,?,?)",
            (
                record.cycle_id,
                record.strategy.fingerprint(),
                int(record.accepted),
                record.gate_result.coverage.value,
                json.dumps(record.model_dump(mode="json")),
            ),
        )
        self.record_strategy(record.strategy)
        self._conn.commit()

    def cycles(self) -> list[CycleRecord]:
        rows = self._conn.execute("SELECT json FROM cycles ORDER BY rowid").fetchall()
        return [CycleRecord.model_validate(json.loads(r[0])) for r in rows]

    def strategy_count(self) -> int:
        (n,) = self._conn.execute("SELECT COUNT(*) FROM specs").fetchone()
        return int(n)
