"""Skills library loader — index.json metadata + SKILL.md frontmatter walk.

The index carries name/domain/path for all 817 skills; the fraud-relevant
mitre_f3 mappings live in each SKILL.md YAML frontmatter. We prefilter by
substring before paying for YAML parses.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from typing import TYPE_CHECKING, Any, cast

import yaml

from forge.contracts.contracts import SkillRef
from forge.kb._f3 import vendor_root

if TYPE_CHECKING:
    from pathlib import Path

_FRONTMATTER = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.DOTALL)


def _skills_dir() -> Path:
    return vendor_root() / "skills"


def _frontmatter(path: Path) -> dict[str, Any]:
    """Parsed YAML frontmatter; {} when absent/unparseable."""
    try:
        text = path.read_text(encoding="utf-8")[:8000]
        m = _FRONTMATTER.match(text)
        if m is None or "mitre_f3" not in m.group(1):
            return {}
        parsed = cast("dict[str, Any]", yaml.safe_load(m.group(1)))
        return parsed
    except (OSError, yaml.YAMLError, AttributeError):
        return {}


@lru_cache(maxsize=1)
def skills_index() -> dict[str, str]:
    """name -> domain from index.json (count-verified against 817)."""
    raw = (_skills_dir() / "index.json").read_text()
    idx = cast("dict[str, Any]", json.loads(raw))
    entries = cast("list[Any]", idx["skills"])
    assert idx["total_skills"] == len(entries) == 817
    out: dict[str, str] = {}
    for s in entries:
        entry = cast("dict[str, Any]", s)
        out[str(entry["name"])] = str(entry.get("domain", ""))
    return out


@lru_cache(maxsize=1)
def fraud_skills() -> tuple[SkillRef, ...]:
    """Skills whose frontmatter maps to at least one F3 tactic/technique."""
    out: list[SkillRef] = []
    domains = skills_index()
    for skill_dir in sorted((_skills_dir() / "skills").iterdir()):
        fm_path = skill_dir / "SKILL.md"
        if not fm_path.exists():
            continue
        quick = fm_path.read_text(encoding="utf-8", errors="ignore")[:8000]
        if "mitre_f3" not in quick:
            continue
        fm = _frontmatter(fm_path)
        if "mitre_f3" not in fm:
            continue
        f3 = cast("dict[str, Any]", fm["mitre_f3"])
        techs_raw = cast("list[Any]", f3.get("techniques", []))
        techniques = [str(cast("dict[str, Any]", t)["id"]) for t in techs_raw]
        tactics = [str(x) for x in cast("list[Any]", f3.get("tactics", []))]
        if not techniques and not tactics:
            continue
        name = str(fm.get("name", skill_dir.name))
        out.append(
            SkillRef(
                name=name,
                domain=domains.get(name, ""),
                techniques=techniques,
                tactics=tactics,
            )
        )
    return tuple(sorted(out, key=lambda s: s.name))
