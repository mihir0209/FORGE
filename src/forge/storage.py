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
    rel = f"{kind}/{art_id}.json"
    path = artifacts_root() / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True))
    return rel


def load_artifact(ref: str) -> dict[str, Any]:
    path = artifacts_root() / ref
    return cast("dict[str, Any]", json.loads(path.read_text()))


def artifact_sha256(ref: str) -> str:
    return sha256((artifacts_root() / ref).read_bytes()).hexdigest()
