"""Artifact store: events carry refs; heavy payloads live here (invariant #4)."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from hashlib import sha256
from pathlib import Path
from typing import Any, cast

_KINDS = ("specs", "traces", "reports", "summaries")


def artifacts_root() -> Path:
    env = os.environ.get("FORGE_DATA_DIR")
    root = Path(env) if env else Path(__file__).resolve().parents[2] / "data"
    return root / "artifacts"


@lru_cache(maxsize=1)
def ensure_dirs() -> None:
    for kind in _KINDS:
        (artifacts_root() / kind).mkdir(parents=True, exist_ok=True)


def save_artifact(kind: str, art_id: str, payload: dict[str, Any]) -> str:
    """Persist JSON under {root}/{kind}/{id}.json; returns relative ref."""
    ensure_dirs()
    if kind not in _KINDS:
        raise ValueError(f"unknown artifact kind '{kind}'")
    # prevent path traversal via art_id
    if "/" in art_id or "\\" in art_id or ".." in art_id:
        raise ValueError(f"invalid artifact id '{art_id}'")
    rel = f"{kind}/{art_id}.json"
    path = artifacts_root() / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    tmp.replace(path)
    return rel


def load_artifact(ref: str) -> dict[str, Any]:
    # prevent traversal via ref
    if ".." in ref or "\\" in ref:
        raise ValueError(f"invalid artifact ref '{ref}'")
    if ref.startswith("/"):
        path = Path(ref)
        data_root = artifacts_root().resolve().parent
        try:
            path.resolve().relative_to(data_root)
        except ValueError:
            from forge.artifacts import LocalArtifactStore, artifact_store_from_env

            store = artifact_store_from_env()
            if isinstance(store, LocalArtifactStore):
                try:
                    path.resolve().relative_to(store.root.resolve())
                except ValueError as exc:
                    raise ValueError(f"artifact ref escapes root: {ref}") from exc
            else:
                raise ValueError(f"artifact ref escapes root: {ref}") from None
    else:
        path = artifacts_root() / ref
        # ensure resolved path is under artifacts_root
        try:
            path.resolve().relative_to(artifacts_root().resolve())
        except ValueError as exc:
            raise ValueError(f"artifact ref escapes root: {ref}") from exc
    return cast("dict[str, Any]", json.loads(path.read_text()))


def artifact_sha256(ref: str) -> str:
    return sha256((artifacts_root() / ref).read_bytes()).hexdigest()
