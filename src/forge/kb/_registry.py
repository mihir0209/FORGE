# pyright: reportMissingTypeStubs=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportArgumentType=false
"""Strategy/cycle registry — Protocol with memory, SQLite and PostgreSQL adapters."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

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


class PostgresRegistry(Registry):
    """Concurrent production adapter with atomic strategy uniqueness."""

    def __init__(self, dsn: str) -> None:
        import psycopg

        self._conn = psycopg.connect(dsn, autocommit=False)
        with self._conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS forge_specs (
                  fingerprint TEXT PRIMARY KEY,
                  strategy_id TEXT NOT NULL,
                  attack_family TEXT NOT NULL,
                  payload JSONB NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_forge_specs_family
                  ON forge_specs(attack_family);
                CREATE INDEX IF NOT EXISTS ix_forge_specs_strategy
                  ON forge_specs(strategy_id);
                CREATE TABLE IF NOT EXISTS forge_cycles (
                  sequence BIGINT GENERATED ALWAYS AS IDENTITY,
                  cycle_id TEXT PRIMARY KEY,
                  fingerprint TEXT NOT NULL,
                  accepted BOOLEAN NOT NULL,
                  coverage TEXT NOT NULL,
                  payload JSONB NOT NULL
                );
                """
            )
        self._conn.commit()

    def record_strategy(self, spec: StrategySpec) -> None:
        with self._conn.transaction(), self._conn.cursor() as cur:
            self._upsert_strategy(cur, spec)

    def _upsert_strategy(self, cur: Any, spec: StrategySpec) -> None:
        from psycopg.types.json import Jsonb

        cur.execute(
            """
                INSERT INTO forge_specs(fingerprint,strategy_id,attack_family,payload)
                VALUES (%s,%s,%s,%s)
                ON CONFLICT (fingerprint) DO UPDATE
                  SET payload=EXCLUDED.payload, strategy_id=EXCLUDED.strategy_id
            """,
            (
                spec.fingerprint(),
                spec.strategy_id,
                spec.attack_family,
                Jsonb(spec.model_dump(mode="json")),
            ),
        )

    def similar(self, fingerprint: str) -> list[StrategySpec]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT payload FROM forge_specs WHERE fingerprint=%s",
                (fingerprint,),
            )
            return [StrategySpec.model_validate(row[0]) for row in cur.fetchall()]

    def same_family_count(self, attack_family: str) -> int:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM forge_specs WHERE attack_family=%s",
                (attack_family,),
            )
            row = cur.fetchone()
            return int(row[0]) if row else 0

    def record_cycle(self, record: CycleRecord) -> None:
        from psycopg.types.json import Jsonb

        with self._conn.transaction(), self._conn.cursor() as cur:
            self._upsert_strategy(cur, record.strategy)
            cur.execute(
                """
                    INSERT INTO forge_cycles(cycle_id,fingerprint,accepted,coverage,payload)
                    VALUES (%s,%s,%s,%s,%s)
                    ON CONFLICT (cycle_id) DO NOTHING
                """,
                (
                    record.cycle_id,
                    record.strategy.fingerprint(),
                    record.accepted,
                    record.gate_result.coverage.value,
                    Jsonb(record.model_dump(mode="json")),
                ),
            )

    def cycles(self) -> list[CycleRecord]:
        with self._conn.cursor() as cur:
            cur.execute("SELECT payload FROM forge_cycles ORDER BY sequence")
            return [CycleRecord.model_validate(row[0]) for row in cur.fetchall()]

    def strategy_count(self) -> int:
        with self._conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM forge_specs")
            row = cur.fetchone()
            return int(row[0]) if row else 0
