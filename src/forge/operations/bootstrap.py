"""Idempotently import host-backed FORGE data into the runtime database."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from pathlib import Path

from forge.families import BUILTIN_FAMILIES, FamilyRegistry
from forge.kb import PostgresRegistry, SQLiteRegistry


def bootstrap_database(
    *,
    source_path: Path,
    families_root: Path,
    database_url: str,
) -> dict[str, int]:
    """Import local knowledge into PostgreSQL without changing source files."""
    target = PostgresRegistry(database_url)
    counts = {
        "families": 0,
        "strategies": 0,
        "cycles": 0,
        "proposals": 0,
        "training_corpora": 0,
    }

    if source_path.exists():
        with tempfile.TemporaryDirectory(prefix="forge-bootstrap-") as temporary:
            snapshot = Path(temporary) / source_path.name
            source_connection = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True)
            snapshot_connection = sqlite3.connect(snapshot)
            try:
                source_connection.backup(snapshot_connection)
            finally:
                snapshot_connection.close()
                source_connection.close()
            source = SQLiteRegistry(snapshot)
            for family in source.families():
                target.record_family(family)
                counts["families"] += 1
            for strategy in source.strategies():
                target.record_strategy(strategy)
                counts["strategies"] += 1
            for cycle in source.cycles():
                target.record_cycle(cycle)
                counts["cycles"] += 1
            for proposal in source.variant_proposals():
                target.record_variant_proposal(proposal)
                counts["proposals"] += 1
            for digest, cycle_count in source.training_corpora():
                target.claim_training_corpus(digest, cycle_count)
                counts["training_corpora"] += 1

    if families_root.exists():
        catalog = FamilyRegistry(families_root, require_approval=True)
        builtins = {(family.slug, family.version) for family in BUILTIN_FAMILIES}
        for family in catalog.list():
            if (family.slug, family.version) in builtins:
                continue
            target.record_family(family)
            counts["families"] += 1

    return counts


def main() -> int:
    data_root = Path(os.environ.get("FORGE_DATA_DIR", "/app/data"))
    database_url = os.environ["FORGE_DATABASE_URL"]
    counts = bootstrap_database(
        source_path=Path(
            os.environ.get("FORGE_BOOTSTRAP_SQLITE", str(data_root / "registry.sqlite"))
        ),
        families_root=data_root / "families",
        database_url=database_url,
    )
    print(json.dumps({"status": "ok", "imported": counts}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
