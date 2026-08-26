"""Fail-closed persisted-cycle integrity and LLM-readiness audit."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from forge.artifacts import ArtifactRef, artifact_store_from_env
from forge.contracts.contracts import SyntheticTrace
from forge.storage import artifacts_root

if TYPE_CHECKING:
    from forge.contracts.contracts import CycleRecord
    from forge.kb import Registry


def audit_registry(registry: Registry, *, run_id: str | None = None) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    input_hashes: list[str] = []
    reviewed_targets = 0
    for cycle in registry.cycles():
        if run_id is not None and cycle.run_id != run_id:
            continue
        errors: list[str] = []
        trace: SyntheticTrace | None = None
        data: bytes | None = None
        if not cycle.trace_sha256:
            errors.append("missing_trace_sha256")
        try:
            data = _read_trace(cycle)
        except (OSError, ValueError, KeyError, AssertionError) as exc:
            errors.append(f"unresolved_trace:{type(exc).__name__}")
        if data is not None and cycle.trace_sha256:
            digest = hashlib.sha256(data).hexdigest()
            if digest != cycle.trace_sha256:
                errors.append("trace_checksum_mismatch")
            else:
                try:
                    trace = SyntheticTrace.model_validate_json(data)
                except ValueError:
                    errors.append("invalid_synthetic_trace")
        if trace is not None:
            observed = trace.observed_view()
            known = set(observed.event_ids)
            cited = {
                ref for signal in cycle.blue_report.signals for ref in signal.evidence_refs
            }
            if not cited <= known:
                errors.append("blue_evidence_outside_observed_trace")
            visible = observed.model_dump(mode="json")
            encoded = json.dumps(visible, sort_keys=True, separators=(",", ":"))
            if "ground_truth" in visible or any(
                event.private_payload or event.is_attack_step or event.attack_stage is not None
                for event in observed.events
            ):
                errors.append("ground_truth_leak")
            input_hashes.append(hashlib.sha256(encoded.encode()).hexdigest())
        if cycle.blue_report.provenance.provider == "human_reviewed":
            reviewed_targets += 1
        rows.append({"cycle_id": cycle.cycle_id, "errors": errors})

    failed = [row for row in rows if row["errors"]]
    duplicate_inputs = len(input_hashes) - len(set(input_hashes))
    llm_blockers: list[str] = []
    if failed:
        llm_blockers.append("cycle integrity failures exist")
    if reviewed_targets != len(rows):
        llm_blockers.append("not every blue-team target has independent review provenance")
    if duplicate_inputs:
        llm_blockers.append("duplicate defender-visible inputs exist")
    if len(rows) < 1000:
        llm_blockers.append("fewer than 1000 training records")
    return {
        "schema_version": "forge-data-audit-v1",
        "run_id": run_id,
        "cycles": len(rows),
        "valid_cycles": len(rows) - len(failed),
        "invalid_cycles": len(failed),
        "unique_observed_inputs": len(set(input_hashes)),
        "duplicate_observed_inputs": duplicate_inputs,
        "independently_reviewed_targets": reviewed_targets,
        "integrity_ready": bool(rows) and not failed,
        "llm_ready": bool(rows) and not llm_blockers,
        "llm_blockers": llm_blockers,
        "failures": failed,
    }


def _read_trace(cycle: CycleRecord) -> bytes:
    ref = cycle.trace_ref
    if ref.startswith("s3://"):
        assert cycle.trace_sha256 is not None
        artifact = ArtifactRef(
            artifact_id=cycle.cycle_id,
            uri=ref,
            sha256=cycle.trace_sha256,
            media_type="application/json",
            byte_size=0,
        )
        return artifact_store_from_env().read_bytes(artifact)
    path = Path(ref)
    if path.is_absolute() or path.exists():
        return path.read_bytes()
    return (artifacts_root() / ref).read_bytes()
