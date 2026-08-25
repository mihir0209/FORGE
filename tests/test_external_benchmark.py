import hashlib
import io
import tarfile
from pathlib import Path

import pytest

from forge.benchmark.external import (
    external_component_evaluated,
    validate_asvspoof5_protocols,
    write_external_manifest,
)


def test_external_protocol_adapter_checks_content_and_modality(tmp_path: Path) -> None:
    archive = tmp_path / "protocols.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        content = b"sample_id label\n"
        for name in ("ASVspoof5.train.tsv", "ASVspoof5.eval.track_1.tsv"):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            bundle.addfile(info, io.BytesIO(content))
    checksum = hashlib.md5(archive.read_bytes(), usedforsecurity=False).hexdigest()
    manifest = validate_asvspoof5_protocols(archive, expected_md5=checksum)
    assert manifest.modality == "audio_anti_spoofing"
    assert manifest.media_included is False
    path = tmp_path / "manifest.json"
    write_external_manifest(manifest, path)
    assert external_component_evaluated(path) is False


def test_external_protocol_adapter_fails_checksum(tmp_path: Path) -> None:
    archive = tmp_path / "bad.tar.gz"
    archive.write_bytes(b"bad")
    with pytest.raises(ValueError, match="checksum"):
        validate_asvspoof5_protocols(archive)
