"""Runtime settings loaded once from configs/settings.yaml (see file header)."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict


class RunCfg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id_prefix: str
    workers: int


class DetectCfg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    calibration_method: str
    min_calib_rows: int
    fpr_targets: list[float]
    latency_p95_budget_ms: float
    promote_requires_all_gates: bool


class GateCfg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    covered_min_score: float
    partial_min_score: float
    similarity_duplicate_max: float


class PipelineCfg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    training_threshold_min: int
    training_threshold_max: int
    concurrency_per_family: int
    cycle_timeout_minutes: int


class ProvidersCfg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    default: str
    fallback: str
    model: str = "mimo-v2.5"
    max_schema_retries: int


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run: RunCfg
    detect: DetectCfg
    gate: GateCfg
    pipeline: PipelineCfg
    providers: ProvidersCfg


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_env_file() -> None:
    """Parse repo-root .env into os.environ (no third-party dep). Idempotent."""
    path = _repo_root() / ".env"
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())


@lru_cache(maxsize=1)
def settings() -> Settings:
    load_env_file()
    path = Path(os.environ.get("FORGE_CONFIG", _repo_root() / "configs" / "settings.yaml"))
    data = yaml.safe_load(path.read_text())
    return Settings.model_validate(data)
