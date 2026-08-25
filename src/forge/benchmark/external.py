"""External component benchmark manifests; never coerce raw modalities into tabular rows."""

from __future__ import annotations

import hashlib
import json
import tarfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ExternalComponentManifest:
    benchmark_id: str
    modality: str
    source_url: str
    license_id: str
    artifact_path: str
    artifact_bytes: int
    checksum_algorithm: str
    expected_checksum: str
    observed_checksum: str
    protocol_files: int
    media_included: bool
    evaluation_metrics: dict[str, float] | None = None


def validate_asvspoof5_protocols(
    archive: Path,
    *,
    expected_md5: str = "865d0e894ea9f686f0f37e5ae3ae3616",
) -> ExternalComponentManifest:
    """Validate the official protocol-only ASVspoof 5 artifact."""
    data = archive.read_bytes()
    observed = hashlib.md5(data, usedforsecurity=False).hexdigest()
    if observed != expected_md5:
        raise ValueError("ASVspoof 5 protocol checksum mismatch")
    with tarfile.open(archive, "r:gz") as bundle:
        members = [member for member in bundle.getmembers() if member.isfile()]
        names = [member.name.lower() for member in members]
    required = {"asvspoof5.train.tsv", "asvspoof5.eval.track_1.tsv"}
    if not required <= set(names):
        raise ValueError("ASVspoof 5 archive is missing required protocol files")
    return ExternalComponentManifest(
        benchmark_id="asvspoof5-protocols-v0.1",
        modality="audio_anti_spoofing",
        source_url=(
            "https://zenodo.org/api/records/14498691/files/"
            "ASVspoof5_protocols.tar.gz/content"
        ),
        license_id="ODC-By-1.0",
        artifact_path=str(archive),
        artifact_bytes=len(data),
        checksum_algorithm="md5",
        expected_checksum=expected_md5,
        observed_checksum=observed,
        protocol_files=len(members),
        media_included=False,
    )


def write_external_manifest(manifest: ExternalComponentManifest, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest.__dict__, indent=2, sort_keys=True) + "\n")


def load_external_manifest(path: Path) -> ExternalComponentManifest:
    return ExternalComponentManifest(**json.loads(path.read_text()))


def external_component_evaluated(path: Path) -> bool:
    manifest = load_external_manifest(path)
    artifact = Path(manifest.artifact_path)
    if not artifact.exists():
        return False
    if manifest.checksum_algorithm == "md5":
        observed = hashlib.md5(artifact.read_bytes(), usedforsecurity=False).hexdigest()
    else:
        observed = hashlib.sha256(artifact.read_bytes()).hexdigest()
    metrics = manifest.evaluation_metrics or {}
    return (
        observed == manifest.expected_checksum == manifest.observed_checksum
        and manifest.media_included
        and {"model_id", "metric_name", "metric_value", "predictions_sha256"} <= set(metrics)
    )
