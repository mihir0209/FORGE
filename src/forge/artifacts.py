# pyright: reportMissingTypeStubs=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportArgumentType=false
"""Immutable artifact storage adapters for media, traces and exports."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Protocol

from forge.contracts.contracts import ArtifactRef


class ArtifactStore(Protocol):
    def put_bytes(
        self, kind: str, artifact_id: str, data: bytes, media_type: str
    ) -> ArtifactRef: ...
    def read_bytes(self, artifact: ArtifactRef) -> bytes: ...

    def put_json(self, kind: str, artifact_id: str, value: dict[str, Any]) -> ArtifactRef: ...


class LocalArtifactStore:
    """Atomic, hash-verified local adapter used by CI and single-process mode."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or Path(os.environ.get("FORGE_DATA_DIR", "data")) / "objects"
        self.root.mkdir(parents=True, exist_ok=True)

    def put_bytes(self, kind: str, artifact_id: str, data: bytes, media_type: str) -> ArtifactRef:
        digest = hashlib.sha256(data).hexdigest()
        suffix = _suffix(media_type)
        path = self.root / kind / f"{artifact_id}-{digest[:12]}{suffix}"
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError(f"artifact conflict at {path}")
        else:
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_bytes(data)
            tmp.replace(path)
        return ArtifactRef(
            artifact_id=artifact_id,
            uri=str(path),
            sha256=digest,
            media_type=media_type,
            byte_size=len(data),
        )

    def put_json(self, kind: str, artifact_id: str, value: dict[str, Any]) -> ArtifactRef:
        data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        return self.put_bytes(kind, artifact_id, data, "application/json")

    def read_bytes(self, artifact: ArtifactRef) -> bytes:
        data = Path(artifact.uri).read_bytes()
        if hashlib.sha256(data).hexdigest() != artifact.sha256:
            raise ValueError(f"artifact checksum mismatch: {artifact.artifact_id}")
        return data


class S3ArtifactStore:
    """Production S3/MinIO adapter with immutable keys and SHA-256 metadata."""

    def __init__(self) -> None:
        import boto3

        self.bucket = os.environ["S3_BUCKET"]
        self.client = boto3.client(
            "s3",
            endpoint_url=os.environ.get("S3_ENDPOINT_URL"),
            region_name=os.environ.get("S3_REGION", "us-east-1"),
            aws_access_key_id=os.environ.get("S3_ACCESS_KEY_ID"),
            aws_secret_access_key=os.environ.get("S3_SECRET_ACCESS_KEY"),
        )

    def put_bytes(self, kind: str, artifact_id: str, data: bytes, media_type: str) -> ArtifactRef:
        digest = hashlib.sha256(data).hexdigest()
        key = f"{kind}/{artifact_id}-{digest[:12]}{_suffix(media_type)}"
        checksum = base64.b64encode(hashlib.sha256(data).digest()).decode()
        self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=data,
            ContentType=media_type,
            ChecksumSHA256=checksum,
            Metadata={"sha256": digest, "artifact-id": artifact_id},
        )
        head = self.client.head_object(Bucket=self.bucket, Key=key)
        if head.get("Metadata", {}).get("sha256") != digest:
            raise ValueError(f"S3 checksum metadata mismatch for {key}")
        return ArtifactRef(
            artifact_id=artifact_id,
            uri=f"s3://{self.bucket}/{key}",
            sha256=digest,
            media_type=media_type,
            byte_size=len(data),
        )

    def read_bytes(self, artifact: ArtifactRef) -> bytes:
        prefix = f"s3://{self.bucket}/"
        if not artifact.uri.startswith(prefix):
            raise ValueError("artifact does not belong to configured bucket")
        key = artifact.uri.removeprefix(prefix)
        data: bytes = self.client.get_object(Bucket=self.bucket, Key=key)["Body"].read()
        if hashlib.sha256(data).hexdigest() != artifact.sha256:
            raise ValueError(f"artifact checksum mismatch: {artifact.artifact_id}")
        return data

    def put_json(self, kind: str, artifact_id: str, value: dict[str, Any]) -> ArtifactRef:
        data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        return self.put_bytes(kind, artifact_id, data, "application/json")


def artifact_store_from_env() -> ArtifactStore:
    if os.environ.get("S3_BUCKET"):
        return S3ArtifactStore()
    return LocalArtifactStore()


def _suffix(media_type: str) -> str:
    return {
        "image/png": ".png",
        "audio/wav": ".wav",
        "video/mp4": ".mp4",
        "application/json": ".json",
        "message/rfc822": ".eml",
    }.get(media_type, ".bin")
