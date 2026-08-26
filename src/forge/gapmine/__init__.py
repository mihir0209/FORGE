"""forge.gapmine — residual analysis into ranked next-research objectives."""

from __future__ import annotations

import hashlib
import json

from forge.contracts.contracts import (
    Coverage,
    CycleRecord,
    FamilyEvidenceStatus,
    FamilyVariantProposal,
    FraudFamilyDefinition,
    GapBrief,
    ResidualKind,
    VariantChange,
    Verdict,
)
from forge.kb import Registry, f3_matrix


def rank(registry: Registry, limit: int = 3) -> list[GapBrief]:
    """Coverage deficits first; deterministic ordering by (deficit desc, slug)."""
    matrix = f3_matrix()
    cycles = registry.cycles()

    per_tactic: dict[str, dict[str, int]] = {
        t.slug: {"strategies": 0, "blind": 0, "partial": 0, "blue": 0, "gaps": 0}
        for t in matrix.tactics
    }
    for c in cycles:
        slug = c.strategy.f3.tactic
        if slug not in per_tactic:
            continue
        per_tactic[slug]["strategies"] += 1
        if c.gate_result.coverage == Coverage.BLIND_SPOT:
            per_tactic[slug]["blind"] += 1
        elif c.gate_result.coverage == Coverage.PARTIAL:
            per_tactic[slug]["partial"] += 1
        if c.blue_report.verdict in {Verdict.PARTIAL, Verdict.MISSED}:
            per_tactic[slug]["blue"] += 1
        per_tactic[slug]["gaps"] += len(set(c.blue_report.uncovered_gaps))

    briefs: list[GapBrief] = []
    for i, tac in enumerate(matrix.tactics):
        stats = per_tactic[tac.slug]
        if stats["strategies"] == 0:
            _deficit, priority = 1.0, 0.95 - 0.01 * i
            objective = (
                f"No coverage attempts in F3 tactic '{tac.name}' "
                f"({tac.slug}); compose the first strategy family."
            )
        elif any(stats[key] > 0 for key in ("blind", "partial", "blue", "gaps")):
            _deficit = (
                stats["blind"] + 0.7 * stats["partial"] + stats["blue"] + 0.2 * stats["gaps"]
            )
            priority = min(0.99, 0.7 + 0.03 * _deficit)
            objective = (
                f"Residuals under '{tac.name}': blind={stats['blind']}, "
                f"partial={stats['partial']}, blue={stats['blue']}, gaps={stats['gaps']}; "
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
                rationale=" ".join(f"{key}={value}" for key, value in stats.items()),
            )
        )
    return sorted(briefs, key=lambda brief: (-brief.priority, brief.brief_id))[:limit]


def propose_variant(
    cycle: CycleRecord,
    parent: FraudFamilyDefinition,
) -> FamilyVariantProposal | None:
    """Derive one bounded, non-executable low-signal candidate from a residual."""
    kinds: list[ResidualKind] = []
    if cycle.gate_result.coverage == Coverage.PARTIAL:
        kinds.append(ResidualKind.GATE_PARTIAL)
    elif cycle.gate_result.coverage == Coverage.BLIND_SPOT:
        kinds.append(ResidualKind.GATE_BLIND_SPOT)
    if cycle.blue_report.verdict == Verdict.PARTIAL:
        kinds.append(ResidualKind.BLUE_PARTIAL)
    elif cycle.blue_report.verdict == Verdict.MISSED:
        kinds.append(ResidualKind.BLUE_MISSED)
    gaps = sorted({gap.strip() for gap in cycle.blue_report.uncovered_gaps if gap.strip()})
    if gaps:
        kinds.append(ResidualKind.BLUE_UNCOVERED_GAP)
    if not kinds:
        return None
    if cycle.strategy.family_definition_sha256 != parent.definition_sha256:
        raise ValueError("source strategy does not match parent family definition")

    strong = bool(
        {ResidualKind.GATE_BLIND_SPOT, ResidualKind.BLUE_MISSED} & set(kinds)
    )
    defaults = dict(parent.scenario_defaults)
    changes: list[VariantChange] = []

    def change(field: str, value: bool | int | float | str) -> None:
        previous = defaults.get(field)
        if previous is None or previous == value:
            return
        defaults[field] = value
        changes.append(
            VariantChange(
                field=field,
                previous_value=previous,
                proposed_value=value,
                rule_id="bounded-low-signal-v1",
            )
        )

    distance = float(defaults.get("behavioral_distance", 0.5))
    change("behavioral_distance", round(max(0.0, distance - (0.15 if strong else 0.08)), 4))
    amount = int(defaults.get("amount_minor", 1))
    change("amount_minor", max(1, round(amount * 0.9)))
    if strong:
        change("warning_overridden", False)
        change("call_active", False)
        change("graph_motif", "established_account")
    if not changes:
        return None

    seed = {
        "source_cycle_id": cycle.cycle_id,
        "parent_definition_sha256": parent.definition_sha256,
        "residual_kinds": sorted(kind.value for kind in kinds),
        "changes": [item.model_dump(mode="json") for item in changes],
    }
    identity = hashlib.sha256(
        json.dumps(seed, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    suffix = identity[:10]
    slug = f"{parent.slug[:52]}_v_{suffix}"

    from forge.families import define_family

    candidate_values = parent.model_dump(mode="json", exclude={"definition_sha256"})
    candidate_values.update(
        slug=slug,
        version="1.0.0",
        title=f"{parent.title} residual variant",
        description=f"Bounded low-signal variant derived from cycle {cycle.cycle_id}.",
        evidence_status=FamilyEvidenceStatus.EXPERIMENTAL,
        scenario_defaults=defaults,
    )
    candidate = define_family(**candidate_values)
    unsigned = {
        **seed,
        "candidate_family": candidate.model_dump(mode="json"),
        "uncovered_gaps": gaps,
        "gate_reason_codes": sorted(set(cycle.gate_result.reason_codes)),
    }
    digest = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return FamilyVariantProposal(
        proposal_id=f"variant_{digest[:24]}",
        proposal_sha256=digest,
        source_cycle_id=cycle.cycle_id,
        source_strategy_id=cycle.strategy.strategy_id,
        parent_family_slug=parent.slug,
        parent_family_version=parent.version,
        parent_definition_sha256=parent.definition_sha256,
        residual_kinds=kinds,
        gate_coverage=cycle.gate_result.coverage,
        blue_verdict=cycle.blue_report.verdict,
        uncovered_gaps=gaps,
        gate_reason_codes=sorted(set(cycle.gate_result.reason_codes)),
        changes=changes,
        candidate_family=candidate,
        created_at=cycle.recorded_at,
    )


def fallback_brief() -> GapBrief:
    """Deterministic default objective when ranking yields nothing."""
    matrix = f3_matrix()
    tac = matrix.tactics[0]
    return GapBrief(
        brief_id="gap_default",
        objective=f"first coverage for {tac.name}",
        target_f3_cells=[],
        suggested_family=f"{tac.slug}_family",
        priority=0.5,
        rationale="registry empty or fully covered without blind spots",
    )


__all__ = ["fallback_brief", "propose_variant", "rank"]
