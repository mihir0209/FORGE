"""forge.kb — knowledge base facade: F3 matrix, skills library, registry."""

from __future__ import annotations

from forge.contracts.contracts import KBHit, KBQuery
from forge.kb._f3 import F3Matrix, f3_matrix
from forge.kb._registry import InMemoryRegistry, PostgresRegistry, Registry, SQLiteRegistry
from forge.kb._skills import fraud_skills


def search(query: KBQuery) -> list[KBHit]:
    """Deterministic retrieval across F3 techniques and mapped skills."""
    matrix = f3_matrix()
    hits: list[KBHit] = []

    for t in matrix.techniques:
        if query.tactic and t.tactic != query.tactic:
            continue
        if query.technique_ids and t.technique_id not in query.technique_ids:
            continue
        hits.append(
            KBHit(
                source="f3",
                ref=t.technique_id,
                title=f"{t.technique_id} {t.name} [{t.tactic}]",
                detail=f"fraud_native={t.fraud_native}",
                score=1.0 if query.technique_ids else 0.5,
            )
        )

    skills = fraud_skills()
    for s in skills:
        overlap = (
            bool(set(s.techniques) & set(query.technique_ids))
            if query.technique_ids
            else (bool(query.tactic and query.tactic in s.tactics))
        )
        if not (query.tactic or query.technique_ids):
            continue
        if overlap:
            hits.append(
                KBHit(
                    source="skill",
                    ref=s.name,
                    title=f"skill: {s.name}",
                    detail=f"domain={s.domain}",
                    score=0.8,
                )
            )

    hits.sort(key=lambda h: (-h.score, h.ref))
    return hits[: max(query.limit, 0)] or _fallback_hits(query)


def registry_from_env() -> Registry:
    import os
    from pathlib import Path

    dsn = os.environ.get("FORGE_DATABASE_URL")
    if dsn:
        return PostgresRegistry(dsn)
    path = Path(os.environ.get("FORGE_REGISTRY_PATH", "data/registry.sqlite"))
    return SQLiteRegistry(path)


def _fallback_hits(query: KBQuery) -> list[KBHit]:
    matrix = f3_matrix()
    tac = matrix.tactic_by_slug(query.tactic or "")
    if tac is None:
        return []
    return [KBHit(source="f3", ref=tac.slug, title=f"{tac.tactic_id} {tac.name}", score=0.4)]


__all__ = [
    "F3Matrix",
    "InMemoryRegistry",
    "PostgresRegistry",
    "Registry",
    "SQLiteRegistry",
    "f3_matrix",
    "fraud_skills",
    "registry_from_env",
    "search",
]
