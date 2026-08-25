# pyright: reportMissingTypeStubs=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false
"""Machine-readable and paper-oriented benchmark report rendering."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

import pandas as pd

if TYPE_CHECKING:
    from pathlib import Path


def write_report(output_dir: Path, report: dict[str, Any]) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "report.json"
    csv_path = output_dir / "metrics.csv"
    markdown_path = output_dir / "report.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    rows: list[dict[str, object]] = []
    for model_name, model in sorted(report["models"].items()):
        for slice_kind in ("overall", "by_track", "by_family"):
            slices = {"all": model[slice_kind]} if slice_kind == "overall" else model[slice_kind]
            for slice_name, metrics in sorted(slices.items()):
                rows.append({"model": model_name, "slice": slice_kind, "value": slice_name, **metrics})
    pd.DataFrame(rows).to_csv(csv_path, index=False)

    lines = ["# FORGE Multi-model Benchmark", "", "No candidate was promoted by this run.", ""]
    lines.extend(
        [
            "| Model | ROC AUC | PR AUC | Brier | Matched-control FPR | Ambiguous rows |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for model_name, model in sorted(report["models"].items()):
        overall = model["overall"]
        lines.append(
            f"| {model_name} | {_fmt(overall['roc_auc'])} | {_fmt(overall['pr_auc'])} | "
            f"{_fmt(overall['brier'])} | {_fmt(model.get('matched_control_fpr'))} | "
            f"{int(model.get('observability', {}).get('ambiguous_rows', 0))} |"
        )
    markdown_path.write_text("\n".join(lines) + "\n")
    return {"json": str(json_path), "csv": str(csv_path), "markdown": str(markdown_path)}


def _fmt(value: object) -> str:
    return "NA" if value is None else f"{float(cast('Any', value)):.4f}"
