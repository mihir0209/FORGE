"""MITRE F3 v1.1 loader — canonical source is the STIX bundle.

Structure verified against vendor/fight-fraud-framework @1939f92:
  - x-mitre-tactic (8): name + x_mitre_shortname slug
  - attack-pattern (123): external_references[].external_id (F1xxx/T1xxx),
    kill_chain_phases[?].phase_name = tactic slug
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, cast

from forge.contracts.contracts import F3Tactic, F3Technique


def vendor_root() -> Path:
    env = os.environ.get("FORGE_VENDOR_DIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[3] / "vendor"


def _stix_objects() -> list[dict[str, Any]]:
    path = vendor_root() / "fight-fraud-framework" / "public" / "f3-stix-v1.1.json"
    bundle = cast("dict[str, Any]", json.loads(path.read_text(encoding="utf-8")))
    objects = cast("list[Any]", bundle["objects"])
    return [cast("dict[str, Any]", o) for o in objects]


def _external_ids(o: dict[str, Any]) -> list[str]:
    refs = cast("list[Any]", o.get("external_references", []))
    return [str(r.get("external_id", "")) for r in refs]


class F3Matrix:
    def __init__(self, tactics: list[F3Tactic], techniques: list[F3Technique]) -> None:
        self.tactics: list[F3Tactic] = tactics
        self.techniques: list[F3Technique] = techniques
        self._by_id = {t.technique_id: t for t in techniques}
        self._tactic_by_slug = {t.slug: t for t in tactics}

    @classmethod
    def load(cls) -> F3Matrix:
        objects = _stix_objects()

        tactics: list[F3Tactic] = []
        for o in objects:
            if o.get("type") != "x-mitre-tactic":
                continue
            ext = _external_ids(o)
            tactic_id = next((e for e in ext if e.startswith(("TA", "FA"))), "")
            slug = str(o.get("x_mitre_shortname", ""))
            name = str(o.get("name", ""))
            if tactic_id and slug:
                tactics.append(F3Tactic(tactic_id=tactic_id, name=name, slug=slug))

        techniques: list[F3Technique] = []
        for o in objects:
            if o.get("type") != "attack-pattern":
                continue
            ext = _external_ids(o)
            technique_id = next((e for e in ext if e[:2] in ("F1", "T1")), "")
            phases_raw = cast("list[Any]", o.get("kill_chain_phases", []))
            phases = [
                str(p["phase_name"]) for p in phases_raw if p.get("kill_chain_name") == "mitre-f3"
            ]
            if not technique_id or not phases:
                continue
            techniques.append(
                F3Technique(
                    technique_id=technique_id,
                    name=str(o.get("name", "")),
                    tactic=phases[0],
                    fraud_native=technique_id.startswith("F1"),
                )
            )
        return cls(tactics=tactics, techniques=techniques)

    def validate(self) -> None:
        assert len(self.tactics) == 8, f"expected 8 F3 tactics, got {len(self.tactics)}"
        assert len(self.techniques) == 123, (
            f"expected 123 F3 techniques, got {len(self.techniques)}"
        )

    def technique(self, technique_id: str) -> F3Technique | None:
        return self._by_id.get(technique_id)

    def tactic_by_slug(self, slug: str) -> F3Tactic | None:
        return self._tactic_by_slug.get(slug)

    def techniques_of(self, slug: str) -> list[F3Technique]:
        return [t for t in self.techniques if t.tactic == slug]


@lru_cache(maxsize=1)
def f3_matrix() -> F3Matrix:
    m = F3Matrix.load()
    m.validate()
    return m
