"""Benchmark V1 fraud-family catalog and reviewed scenario behavior."""

from pathlib import Path

import pytest

from forge.actor_sandbox import ActorSandbox
from forge.artifacts import LocalArtifactStore
from forge.contracts.contracts import (
    FamilyEvidenceStatus,
    FraudFamilyDefinition,
    ToolKind,
    WorldSeed,
)
from forge.families import BUILTIN_FAMILIES, FamilyRegistry, build_app_plan, define_family


def test_catalog_has_evidence_supported_immutable_families() -> None:
    assert len({family.slug for family in BUILTIN_FAMILIES}) >= 20
    assert {family.evidence_status for family in BUILTIN_FAMILIES} == {
        FamilyEvidenceStatus.DEMONSTRATED,
        FamilyEvidenceStatus.EXPERIMENTAL,
    }
    assert all(
        family.research_refs
        and all(reference.startswith("https://") for reference in family.research_refs)
        and len(family.definition_sha256) == 64
        for family in BUILTIN_FAMILIES
    )


def test_reviewed_templates_produce_genuinely_distinct_allowlisted_plans() -> None:
    registry = FamilyRegistry()
    slugs = (
        "ai_family_emergency",
        "ai_bank_impersonation",
        "deepfake_executive_bec",
        "ai_investment_coaching",
    )
    families = [registry.get(slug) for slug in slugs]
    plans = [build_app_plan(family, "cycle", 17) for family in families]

    tool_sequences = [tuple(action.tool for action in plan.actions) for plan in plans]
    assert len(set(tool_sequences)) == len(slugs)
    for family, plan in zip(families, plans, strict=True):
        assert {action.tool for action in plan.actions} <= set(family.allowed_tools)
        assert set(family.allowed_tools) <= set(ToolKind)


def test_seed_variation_is_deterministic_and_bounded() -> None:
    family = FamilyRegistry().get("ai_bank_impersonation")
    first = build_app_plan(family, "cycle-a", 101)
    repeated = build_app_plan(family, "cycle-b", 101)
    changed = build_app_plan(family, "cycle-a", 102)

    first_parameters = [action.parameters for action in first.actions]
    assert first_parameters == [action.parameters for action in repeated.actions]
    assert first_parameters != [action.parameters for action in changed.actions]

    payment = next(action for action in first.actions if action.tool == ToolKind.PAYMENT_INITIATE)
    amount = int(payment.parameters["amount_minor"])
    baseline = int(family.scenario_defaults["amount_minor"])
    assert baseline * 0.9 <= amount <= baseline * 1.1


def test_dynamic_family_reload_selects_template_without_slug_branch(tmp_path: Path) -> None:
    source = FamilyRegistry().get("deepfake_executive_bec")
    payload = source.model_dump(exclude={"definition_sha256"})
    payload.update(slug="novel_reviewed_family", version="2.0.0")
    family = define_family(**payload)
    FamilyRegistry(tmp_path).register(family)

    reloaded = FamilyRegistry(tmp_path).get("novel_reviewed_family", "2.0.0")
    plan = build_app_plan(reloaded, "dynamic", 7)
    assert plan.actions[0].tool == ToolKind.AUDIO_GENERATE
    assert reloaded.definition_sha256 == family.definition_sha256


def test_dynamic_family_plan_executes_with_safe_allowlisted_tools(tmp_path: Path) -> None:
    family = FamilyRegistry().get("ai_investment_coaching")
    plan = build_app_plan(family, "benchmark-execution", 23)
    result = ActorSandbox(LocalArtifactStore(tmp_path / "objects")).execute(
        plan, WorldSeed(master_seed=23), cycle_id="benchmark-execution"
    )
    assert result.trace.events[-1].kind == "payment.held"


def test_every_reviewed_template_executes(tmp_path: Path) -> None:
    seen: set[str] = set()
    for index, family in enumerate(FamilyRegistry().list()):
        if family.scenario_template in seen:
            continue
        seen.add(family.scenario_template)
        plan = build_app_plan(family, f"template-{index}", index + 100)
        result = ActorSandbox(LocalArtifactStore(tmp_path / "objects")).execute(
            plan, WorldSeed(master_seed=index + 100), cycle_id=f"template-{index}"
        )
        assert result.trace.fidelity.reachability_ok
    assert len(seen) >= 12


def test_family_versions_and_files_are_immutable(tmp_path: Path) -> None:
    family = FamilyRegistry().get("ai_family_emergency")
    registry = FamilyRegistry(tmp_path)
    registry.register(family)
    target = tmp_path / f"{family.slug}-{family.version}.json"
    original = target.read_bytes()

    payload = family.model_dump(exclude={"definition_sha256"})
    payload["title"] = "Conflicting title"
    conflicting = define_family(**payload)
    with pytest.raises(ValueError, match="immutable"):
        registry.register(conflicting)
    assert target.read_bytes() == original
    assert not list(tmp_path.glob(f".{target.name}.*"))


def test_unknown_template_is_rejected_before_execution() -> None:
    family = FamilyRegistry().get("ai_investment_coaching")
    payload = family.model_dump(exclude={"definition_sha256"})
    payload["scenario_template"] = "unreviewed_template"
    unreviewed: FraudFamilyDefinition = define_family(**payload)
    with pytest.raises(ValueError, match="unknown reviewed scenario template"):
        build_app_plan(unreviewed, "cycle", 1)


def test_runtime_registry_requires_approval_for_external_family(tmp_path: Path) -> None:
    source = FamilyRegistry().get("deepfake_executive_bec")
    payload = source.model_dump(exclude={"definition_sha256"})
    payload.update(slug="external_unapproved_family", version="1.0.0")
    with pytest.raises(ValueError, match="approval receipt"):
        FamilyRegistry(tmp_path / "families", require_approval=True).register(
            define_family(**payload)
        )
