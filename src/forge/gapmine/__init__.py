"""forge.gapmine — residual analysis into ranked next-research objectives."""

from __future__ import annotations

from forge.contracts.contracts import Coverage, GapBrief
from forge.kb import Registry, f3_matrix


def rank(registry: Registry, limit: int = 3) -> list[GapBrief]:
    """Coverage deficits first; deterministic ordering by (deficit desc, slug)."""
    matrix = f3_matrix()
    cycles = registry.cycles()

    per_tactic: dict[str, dict[str, int]] = {
        t.slug: {"strategies": 0, "blind": 0} for t in matrix.tactics
    }
    for c in cycles:
        slug = c.strategy.f3.tactic
        if slug not in per_tactic:
            continue
        per_tactic[slug]["strategies"] += 1
        if c.gate_result.coverage == Coverage.BLIND_SPOT:
            per_tactic[slug]["blind"] += 1

    briefs: list[GapBrief] = []
    for i, tac in enumerate(matrix.tactics):
        stats = per_tactic[tac.slug]
        if stats["strategies"] == 0:
            _deficit, priority = 1.0, 0.95 - 0.01 * i
            objective = (
                f"No coverage attempts in F3 tactic '{tac.name}' "
                f"({tac.slug}); compose the first strategy family."
            )
        elif stats["blind"] > 0:
            _deficit, priority = 0.7, 0.8 - 0.01 * i
            objective = (
                f"{stats['blind']} blind-spot cycle(s) under '{tac.name}'; "
                "diversify variants around uncovered stages."
            )
        else:
            continue
        briefs.append(
            GapBrief(
                brief_id=f"gap_{tac.slug}",
                objective=objective,
                target_f3_cells=[t.technique_id for t in matrix.techniques_of(tac.slug)[:6]],
                suggested_family=f"{tac.slug}_family",
                priority=priority,
                rationale=f"strategies={stats['strategies']} blind={stats['blind']}",
            )
        )
    return sorted(briefs, key=lambda b: -b.priority)[:limit]
