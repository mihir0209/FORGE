"""Judge-facing read models over the registry and model artifacts."""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import Any, cast

from forge.gapmine import rank
from forge.kb import SQLiteRegistry, f3_matrix


def registry() -> SQLiteRegistry:
    path = Path(os.environ.get("FORGE_REGISTRY_PATH", "data/registry.sqlite"))
    return SQLiteRegistry(path)


def cycles() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for cycle in reversed(registry().cycles()):
        out.append(
            {
                "cycle_id": cycle.cycle_id,
                "run_id": cycle.run_id,
                "recorded_at": cycle.recorded_at.isoformat(),
                "accepted": cycle.accepted,
                "strategy_id": cycle.strategy.strategy_id,
                "family": cycle.strategy.attack_family,
                "tactic": cycle.strategy.f3.tactic,
                "techniques": cycle.strategy.f3.techniques,
                "rail": cycle.strategy.rail,
                "channel": cycle.strategy.channel,
                "blue_verdict": cycle.blue_report.verdict.value,
                "blue_confidence": cycle.blue_report.confidence,
                "signals": [s.model_dump(mode="json") for s in cycle.blue_report.signals],
                "gate_score": cycle.gate_result.score,
                "gate_action": cycle.gate_result.action.value,
                "coverage": cycle.gate_result.coverage.value,
                "detector_id": cycle.gate_result.detector_id,
            }
        )
    return out


def cycle_detail(cycle_id: str) -> dict[str, Any] | None:
    for cycle in registry().cycles():
        if cycle.cycle_id == cycle_id:
            return cycle.model_dump(mode="json")
    return None


def coverage() -> dict[str, Any]:
    matrix = f3_matrix()
    records = registry().cycles()
    cells: list[dict[str, Any]] = []
    for tactic in matrix.tactics:
        tactic_cycles = [c for c in records if c.strategy.f3.tactic == tactic.slug]
        counts = Counter(c.gate_result.coverage.value for c in tactic_cycles)
        tested = {t for c in tactic_cycles for t in c.strategy.f3.techniques}
        total = len(matrix.techniques_of(tactic.slug))
        cells.append(
            {
                "id": tactic.tactic_id,
                "name": tactic.name,
                "slug": tactic.slug,
                "techniques_total": total,
                "techniques_tested": len(tested),
                "cycles": len(tactic_cycles),
                "coverage": dict(counts),
                "status": "uncovered"
                if not tactic_cycles
                else "blind_spot"
                if counts.get("blind_spot")
                else "partial"
                if counts.get("partial")
                else "covered",
            }
        )
    return {
        "summary": {
            "tactics_tested": sum(1 for c in cells if c["cycles"]),
            "tactics_total": len(cells),
            "techniques_tested": sum(c["techniques_tested"] for c in cells),
            "techniques_total": len(matrix.techniques),
        },
        "cells": cells,
    }


def gaps() -> list[dict[str, Any]]:
    return [b.model_dump(mode="json") for b in rank(registry(), limit=8)]


def model_card() -> dict[str, Any]:
    data_dir = Path(os.environ.get("FORGE_DATA_DIR", "data"))
    pointer = data_dir / "models" / "incumbent.json"
    if not pointer.exists():
        return {"detector_id": "rule-baseline-v1", "kind": "rules", "promoted": False}
    meta: dict[str, Any] = json.loads(pointer.read_text())
    report_path = data_dir / "models" / "candidates" / f"{meta['candidate_id']}.json"
    report = (
        cast("dict[str, Any]", json.loads(report_path.read_text())) if report_path.exists() else {}
    )
    return {
        "detector_id": meta["candidate_id"],
        "kind": "lightgbm-calibrated",
        "promoted": True,
        "artifact_path": meta["artifact_path"],
        "metrics": report,
    }


def f3_view() -> dict[str, Any]:
    matrix = f3_matrix()
    return {
        "version": "1.1",
        "tactics": [
            {
                **tactic.model_dump(mode="json"),
                "techniques": [
                    t.model_dump(mode="json") for t in matrix.techniques_of(tactic.slug)
                ],
            }
            for tactic in matrix.tactics
        ],
    }
