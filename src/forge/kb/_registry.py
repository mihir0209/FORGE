# pyright: reportMissingTypeStubs=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportArgumentType=false
"""Family, strategy, and cycle registry with memory, SQLite, and PostgreSQL adapters."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from forge.contracts.contracts import (
    CycleRecord,
    FamilyVariantProposal,
    FraudFamilyDefinition,
    LLMCall,
    StrategySpec,
)


class Registry:
    """Interface: append + query accepted knowledge. See ADR-0001 seams."""

    def record_strategy(self, spec: StrategySpec) -> None: ...
    def strategies(self) -> list[StrategySpec]: ...
    def record_family(self, family: FraudFamilyDefinition) -> None: ...
    def families(self) -> list[FraudFamilyDefinition]: ...
    def similar(self, fingerprint: str) -> list[StrategySpec]: ...
    def same_family_count(self, attack_family: str) -> int: ...
    def record_cycle(self, record: CycleRecord) -> None: ...
    def cycle(self, cycle_id: str) -> CycleRecord | None: ...
    def cycles(self) -> list[CycleRecord]: ...
    def record_variant_proposal(self, proposal: FamilyVariantProposal) -> None: ...
    def variant_proposal(self, proposal_id: str) -> FamilyVariantProposal | None: ...
    def variant_proposals(self) -> list[FamilyVariantProposal]: ...
    def claim_training_corpus(self, corpus_sha256: str, cycle_count: int) -> bool: ...
    def training_corpora(self) -> list[tuple[str, int]]: ...
    def record_llm_call(self, call: LLMCall) -> None: ...
    def llm_calls(self, *, limit: int | None = None, offset: int = 0) -> list[LLMCall]: ...
    def strategy_count(self) -> int: ...


class InMemoryRegistry(Registry):
    def __init__(self) -> None:
        self._specs: dict[str, StrategySpec] = {}
        self._families: dict[tuple[str, str], FraudFamilyDefinition] = {}
        self._cycles: list[CycleRecord] = []
        self._proposals: dict[str, FamilyVariantProposal] = {}
        self._training_corpora: set[str] = set()
        self._llm_calls: dict[str, LLMCall] = {}

    def record_strategy(self, spec: StrategySpec) -> None:
        self._specs[spec.strategy_id] = spec

    def strategies(self) -> list[StrategySpec]:
        return sorted(self._specs.values(), key=lambda spec: spec.strategy_id)

    def record_family(self, family: FraudFamilyDefinition) -> None:
        key = (family.slug, family.version)
        current = self._families.get(key)
        if current and current.definition_sha256 != family.definition_sha256:
            raise ValueError("family version is immutable")
        self._families[key] = family

    def families(self) -> list[FraudFamilyDefinition]:
        return sorted(self._families.values(), key=lambda family: (family.slug, family.version))

    def similar(self, fingerprint: str) -> list[StrategySpec]:
        return [s for s in self._specs.values() if s.fingerprint() == fingerprint]

    def same_family_count(self, attack_family: str) -> int:
        return sum(1 for s in self._specs.values() if s.attack_family == attack_family)

    def record_cycle(self, record: CycleRecord) -> None:
        self._cycles.append(record)
        self.record_strategy(record.strategy)

    def cycles(self) -> list[CycleRecord]:
        return list(self._cycles)

    def cycle(self, cycle_id: str) -> CycleRecord | None:
        return next((cycle for cycle in self._cycles if cycle.cycle_id == cycle_id), None)

    def record_variant_proposal(self, proposal: FamilyVariantProposal) -> None:
        current = self._proposals.get(proposal.proposal_id)
        if current and current != proposal:
            raise ValueError("variant proposal is immutable")
        source = next(
            (item for item in self._proposals.values() if item.source_cycle_id == proposal.source_cycle_id),
            None,
        )
        if source and source != proposal:
            raise ValueError("source cycle already has a variant proposal")
        self._proposals[proposal.proposal_id] = proposal

    def variant_proposals(self) -> list[FamilyVariantProposal]:
        return sorted(self._proposals.values(), key=lambda proposal: proposal.proposal_id)

    def variant_proposal(self, proposal_id: str) -> FamilyVariantProposal | None:
        return self._proposals.get(proposal_id)

    def claim_training_corpus(self, corpus_sha256: str, cycle_count: int) -> bool:
        del cycle_count
        if corpus_sha256 in self._training_corpora:
            return False
        self._training_corpora.add(corpus_sha256)
        return True

    def training_corpora(self) -> list[tuple[str, int]]:
        return sorted((digest, 0) for digest in self._training_corpora)

    def record_llm_call(self, call: LLMCall) -> None:
        current = self._llm_calls.get(call.call_id)
        if current and current != call:
            raise ValueError("LLM call receipt is immutable")
        self._llm_calls[call.call_id] = call

    def llm_calls(self, *, limit: int | None = None, offset: int = 0) -> list[LLMCall]:
        calls = sorted(self._llm_calls.values(), key=lambda call: call.started_at, reverse=True)
        return calls[offset:] if limit is None else calls[offset : offset + limit]

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
CREATE TABLE IF NOT EXISTS families (
  slug TEXT NOT NULL,
  version TEXT NOT NULL,
  definition_sha256 TEXT NOT NULL,
  json TEXT NOT NULL,
  PRIMARY KEY (slug, version)
);
CREATE TABLE IF NOT EXISTS cycles (
  cycle_id TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL,
  accepted INTEGER NOT NULL,
  coverage TEXT NOT NULL,
  json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS family_variant_proposals (
  proposal_id TEXT PRIMARY KEY,
  proposal_sha256 TEXT NOT NULL UNIQUE,
  source_cycle_id TEXT NOT NULL UNIQUE,
  parent_family_slug TEXT NOT NULL,
  candidate_family_slug TEXT NOT NULL,
  json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS training_corpora (
  corpus_sha256 TEXT PRIMARY KEY,
  cycle_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS llm_calls (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  call_id TEXT NOT NULL UNIQUE,
  started_at TEXT NOT NULL,
  status TEXT NOT NULL,
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  stage TEXT NOT NULL,
  json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_llm_calls_started_at ON llm_calls(started_at);
"""


class SQLiteRegistry(Registry):
    def __init__(self, path: Path | str, *, readonly: bool = False) -> None:
        path = Path(path)
        self._readonly = readonly
        if readonly:
            self._conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(path)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def _require_writable(self) -> None:
        if self._readonly:
            raise ValueError("registry is read-only")

    def record_strategy(self, spec: StrategySpec) -> None:
        self._require_writable()
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

    def record_family(self, family: FraudFamilyDefinition) -> None:
        self._require_writable()
        row = self._conn.execute(
            "SELECT definition_sha256 FROM families WHERE slug=? AND version=?",
            (family.slug, family.version),
        ).fetchone()
        if row and row[0] != family.definition_sha256:
            raise ValueError("family version is immutable")
        self._conn.execute(
            "INSERT OR IGNORE INTO families VALUES (?,?,?,?)",
            (
                family.slug,
                family.version,
                family.definition_sha256,
                family.model_dump_json(),
            ),
        )
        self._conn.commit()

    def families(self) -> list[FraudFamilyDefinition]:
        rows = self._conn.execute(
            "SELECT json FROM families ORDER BY slug, version"
        ).fetchall()
        return [FraudFamilyDefinition.model_validate_json(row[0]) for row in rows]

    def _all_specs(self) -> list[StrategySpec]:
        rows = self._conn.execute("SELECT json FROM specs").fetchall()
        return [StrategySpec.model_validate_json(r[0]) for r in rows]

    def strategies(self) -> list[StrategySpec]:
        rows = self._conn.execute("SELECT json FROM specs ORDER BY strategy_id").fetchall()
        return [StrategySpec.model_validate_json(row[0]) for row in rows]

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
        self._require_writable()
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

    def cycle(self, cycle_id: str) -> CycleRecord | None:
        row = self._conn.execute("SELECT json FROM cycles WHERE cycle_id=?", (cycle_id,)).fetchone()
        return CycleRecord.model_validate(json.loads(row[0])) if row else None

    def record_variant_proposal(self, proposal: FamilyVariantProposal) -> None:
        self._require_writable()
        row = self._conn.execute(
            "SELECT json FROM family_variant_proposals WHERE proposal_id=? OR source_cycle_id=?",
            (proposal.proposal_id, proposal.source_cycle_id),
        ).fetchone()
        if row:
            if FamilyVariantProposal.model_validate_json(row[0]) != proposal:
                raise ValueError("variant proposal is immutable")
            return
        self._conn.execute(
            "INSERT INTO family_variant_proposals VALUES (?,?,?,?,?,?)",
            (
                proposal.proposal_id,
                proposal.proposal_sha256,
                proposal.source_cycle_id,
                proposal.parent_family_slug,
                proposal.candidate_family.slug,
                proposal.model_dump_json(),
            ),
        )
        self._conn.commit()

    def variant_proposals(self) -> list[FamilyVariantProposal]:
        rows = self._conn.execute(
            "SELECT json FROM family_variant_proposals ORDER BY proposal_id"
        ).fetchall()
        return [FamilyVariantProposal.model_validate_json(row[0]) for row in rows]

    def variant_proposal(self, proposal_id: str) -> FamilyVariantProposal | None:
        row = self._conn.execute(
            "SELECT json FROM family_variant_proposals WHERE proposal_id=?", (proposal_id,)
        ).fetchone()
        return FamilyVariantProposal.model_validate_json(row[0]) if row else None

    def claim_training_corpus(self, corpus_sha256: str, cycle_count: int) -> bool:
        self._require_writable()
        cursor = self._conn.execute(
            "INSERT OR IGNORE INTO training_corpora VALUES (?,?)",
            (corpus_sha256, cycle_count),
        )
        self._conn.commit()
        return cursor.rowcount == 1

    def training_corpora(self) -> list[tuple[str, int]]:
        rows = self._conn.execute(
            "SELECT corpus_sha256, cycle_count FROM training_corpora ORDER BY corpus_sha256"
        ).fetchall()
        return [(str(digest), int(count)) for digest, count in rows]

    def record_llm_call(self, call: LLMCall) -> None:
        self._require_writable()
        row = self._conn.execute("SELECT json FROM llm_calls WHERE call_id=?", (call.call_id,)).fetchone()
        if row:
            if LLMCall.model_validate_json(row[0]) != call:
                raise ValueError("LLM call receipt is immutable")
            return
        self._conn.execute(
            "INSERT INTO llm_calls(call_id,started_at,status,provider,model,stage,json) VALUES (?,?,?,?,?,?,?)",
            (call.call_id, call.started_at.isoformat(), call.status, call.provider, call.model, call.stage, call.model_dump_json()),
        )
        self._conn.commit()

    def llm_calls(self, *, limit: int | None = None, offset: int = 0) -> list[LLMCall]:
        sql = "SELECT json FROM llm_calls ORDER BY sequence DESC LIMIT ? OFFSET ?"
        rows = self._conn.execute(sql, (-1 if limit is None else limit, offset)).fetchall()
        return [LLMCall.model_validate_json(row[0]) for row in rows]

    def strategy_count(self) -> int:
        (n,) = self._conn.execute("SELECT COUNT(*) FROM specs").fetchone()
        return int(n)


class PostgresRegistry(Registry):
    """Concurrent production adapter with atomic strategy uniqueness."""

    def __init__(self, dsn: str) -> None:
        import psycopg

        self._conn = psycopg.connect(dsn, autocommit=True)
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
                CREATE TABLE IF NOT EXISTS forge_families (
                  slug TEXT NOT NULL,
                  version TEXT NOT NULL,
                  definition_sha256 TEXT NOT NULL,
                  payload JSONB NOT NULL,
                  PRIMARY KEY (slug, version)
                );
                CREATE TABLE IF NOT EXISTS forge_cycles (
                  sequence BIGINT GENERATED ALWAYS AS IDENTITY,
                  cycle_id TEXT PRIMARY KEY,
                  fingerprint TEXT NOT NULL,
                  accepted BOOLEAN NOT NULL,
                  coverage TEXT NOT NULL,
                  payload JSONB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS forge_family_variant_proposals (
                  proposal_id TEXT PRIMARY KEY,
                  proposal_sha256 TEXT NOT NULL UNIQUE,
                  source_cycle_id TEXT NOT NULL UNIQUE,
                  parent_family_slug TEXT NOT NULL,
                  candidate_family_slug TEXT NOT NULL,
                  payload JSONB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS forge_training_corpora (
                  corpus_sha256 TEXT PRIMARY KEY,
                  cycle_count INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS forge_llm_calls (
                  sequence BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                  call_id TEXT NOT NULL UNIQUE,
                  started_at TIMESTAMPTZ NOT NULL,
                  status TEXT NOT NULL,
                  provider TEXT NOT NULL,
                  model TEXT NOT NULL,
                  stage TEXT NOT NULL,
                  payload JSONB NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_forge_llm_calls_started_at
                  ON forge_llm_calls(started_at);
                """
            )

    def record_strategy(self, spec: StrategySpec) -> None:
        with self._conn.cursor() as cur:
            self._upsert_strategy(cur, spec)

    def record_family(self, family: FraudFamilyDefinition) -> None:
        from psycopg.types.json import Jsonb

        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT definition_sha256 FROM forge_families WHERE slug=%s AND version=%s",
                (family.slug, family.version),
            )
            row = cur.fetchone()
            if row and row[0] != family.definition_sha256:
                raise ValueError("family version is immutable")
            cur.execute(
                """
                    INSERT INTO forge_families(slug,version,definition_sha256,payload)
                    VALUES (%s,%s,%s,%s)
                    ON CONFLICT (slug,version) DO UPDATE
                      SET payload=forge_families.payload
                    WHERE forge_families.definition_sha256=EXCLUDED.definition_sha256
                """,
                (
                    family.slug,
                    family.version,
                    family.definition_sha256,
                    Jsonb(family.model_dump(mode="json")),
                ),
            )
            if cur.rowcount != 1:
                raise ValueError("family version is immutable")

    def families(self) -> list[FraudFamilyDefinition]:
        with self._conn.cursor() as cur:
            cur.execute("SELECT payload FROM forge_families ORDER BY slug, version")
            return [FraudFamilyDefinition.model_validate(row[0]) for row in cur.fetchall()]

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

    def strategies(self) -> list[StrategySpec]:
        with self._conn.cursor() as cur:
            cur.execute("SELECT payload FROM forge_specs ORDER BY strategy_id")
            return [StrategySpec.model_validate(row[0]) for row in cur.fetchall()]

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

        with self._conn.cursor() as cur:
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

    def cycle(self, cycle_id: str) -> CycleRecord | None:
        with self._conn.cursor() as cur:
            cur.execute("SELECT payload FROM forge_cycles WHERE cycle_id=%s", (cycle_id,))
            row = cur.fetchone()
            return CycleRecord.model_validate(row[0]) if row else None

    def record_variant_proposal(self, proposal: FamilyVariantProposal) -> None:
        from psycopg.types.json import Jsonb

        with self._conn.cursor() as cur:
            cur.execute(
                """
                    INSERT INTO forge_family_variant_proposals(
                      proposal_id,proposal_sha256,source_cycle_id,parent_family_slug,
                      candidate_family_slug,payload
                    ) VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING
                """,
                (
                    proposal.proposal_id,
                    proposal.proposal_sha256,
                    proposal.source_cycle_id,
                    proposal.parent_family_slug,
                    proposal.candidate_family.slug,
                    Jsonb(proposal.model_dump(mode="json")),
                ),
            )
            if cur.rowcount == 1:
                return
            cur.execute(
                """
                    SELECT payload FROM forge_family_variant_proposals
                    WHERE proposal_id=%s OR source_cycle_id=%s
                """,
                (proposal.proposal_id, proposal.source_cycle_id),
            )
            row = cur.fetchone()
            if row is None or FamilyVariantProposal.model_validate(row[0]) != proposal:
                raise ValueError("variant proposal is immutable")

    def variant_proposals(self) -> list[FamilyVariantProposal]:
        with self._conn.cursor() as cur:
            cur.execute("SELECT payload FROM forge_family_variant_proposals ORDER BY proposal_id")
            return [FamilyVariantProposal.model_validate(row[0]) for row in cur.fetchall()]

    def variant_proposal(self, proposal_id: str) -> FamilyVariantProposal | None:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT payload FROM forge_family_variant_proposals WHERE proposal_id=%s",
                (proposal_id,),
            )
            row = cur.fetchone()
            return FamilyVariantProposal.model_validate(row[0]) if row else None

    def claim_training_corpus(self, corpus_sha256: str, cycle_count: int) -> bool:
        with self._conn.cursor() as cur:
            cur.execute(
                """
                    INSERT INTO forge_training_corpora(corpus_sha256,cycle_count)
                    VALUES (%s,%s) ON CONFLICT DO NOTHING
                """,
                (corpus_sha256, cycle_count),
            )
            return cur.rowcount == 1

    def training_corpora(self) -> list[tuple[str, int]]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT corpus_sha256, cycle_count FROM forge_training_corpora ORDER BY corpus_sha256"
            )
            return [(str(digest), int(count)) for digest, count in cur.fetchall()]

    def record_llm_call(self, call: LLMCall) -> None:
        from psycopg.types.json import Jsonb

        with self._conn.cursor() as cur:
            cur.execute("SELECT payload FROM forge_llm_calls WHERE call_id=%s", (call.call_id,))
            row = cur.fetchone()
            if row:
                if LLMCall.model_validate(row[0]) != call:
                    raise ValueError("LLM call receipt is immutable")
                return
            cur.execute(
                """INSERT INTO forge_llm_calls(
                     call_id,started_at,status,provider,model,stage,payload
                   ) VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                (call.call_id, call.started_at, call.status, call.provider, call.model, call.stage, Jsonb(call.model_dump(mode="json"))),
            )

    def llm_calls(self, *, limit: int | None = None, offset: int = 0) -> list[LLMCall]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT payload FROM forge_llm_calls ORDER BY sequence DESC LIMIT %s OFFSET %s",
                (limit, offset),
            )
            return [LLMCall.model_validate(row[0]) for row in cur.fetchall()]

    def strategy_count(self) -> int:
        with self._conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM forge_specs")
            row = cur.fetchone()
            return int(row[0]) if row else 0
