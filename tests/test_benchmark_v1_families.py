"""Benchmark V1 fraud-family catalog and reviewed scenario behavior."""

from pathlib import Path

import pytest

from forge.actor_sandbox import ActorSandbox
from forge.artifacts import LocalArtifactStore
from forge.cli.main import main
from forge.contracts.contracts import (
    FamilyEvidenceStatus,
    FraudFamilyDefinition,
    ToolKind,
    WorldSeed,
)
from forge.families import BUILTIN_FAMILIES, FamilyRegistry, build_app_plan, define_family
from forge.gapmine import propose_variant
from forge.kb import SQLiteRegistry


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


def test_dynamic_family_is_reloaded_from_database(tmp_path: Path) -> None:
    source = FamilyRegistry().get("deepfake_executive_bec")
    payload = source.model_dump(exclude={"definition_sha256"})
    payload.update(slug="database_backed_family", version="1.0.0")
    family = define_family(**payload)
    database = SQLiteRegistry(tmp_path / "registry.sqlite")

    FamilyRegistry(registry=database).register(family)

    reloaded = FamilyRegistry(registry=SQLiteRegistry(tmp_path / "registry.sqlite"))
    assert reloaded.get(family.slug, family.version) == family


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


def test_family_register_cli_persists_approved_definition(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = FamilyRegistry().get("deepfake_executive_bec")
    payload = source.model_dump(exclude={"definition_sha256"})
    payload.update(slug="approved_database_family", version="1.0.0")
    family = define_family(**payload)
    families_root = tmp_path / "families"
    research_root = tmp_path / "research"
    families_root.mkdir()
    definition = families_root / f"{family.slug}-{family.version}.json"
    definition.write_text(family.model_dump_json(indent=2))

    from forge.research_snapshots import ResearchSnapshotStore

    snapshot_store = ResearchSnapshotStore(research_root)
    snapshots = [
        snapshot_store.record(
            source_url=url,
            title="Primary source",
            content=f"evidence from {url}",
            provider="test",
            parser_version="test-v1",
        )
        for url in family.research_refs
    ]
    snapshot_store.approve_family(
        family,
        [snapshot.snapshot_id for snapshot in snapshots],
        reviewer="test-reviewer",
        approved=True,
    )
    database = tmp_path / "registry.sqlite"

    assert main(
        ["family-register", "--definition", str(definition), "--db", str(database)]
    ) == 0
    assert SQLiteRegistry(database).families() == [family]
    assert family.slug in capsys.readouterr().out


def test_residual_cycle_creates_bounded_pending_variant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from forge.app_scam_runner import run_app_scam_cycle

    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FORGE_REGISTRY_PATH", str(tmp_path / "runtime.sqlite"))
    family = FamilyRegistry().get("ai_bank_impersonation")
    database = SQLiteRegistry(tmp_path / "registry.sqlite")
    cycle = run_app_scam_cycle(
        seed=401,
        cycle_id="residual-cycle",
        registry=database,
        store=LocalArtifactStore(tmp_path / "objects"),
        variant=family.slug,
    )
    proposal = propose_variant(cycle, family)
    assert proposal is not None
    assert proposal.source_cycle_id == cycle.cycle_id
    assert proposal.candidate_family.allowed_tools == family.allowed_tools
    assert proposal.candidate_family.scenario_template == family.scenario_template
    assert proposal.candidate_family.slug != family.slug
    assert {change.field for change in proposal.changes} <= {
        "behavioral_distance",
        "amount_minor",
        "warning_overridden",
        "call_active",
        "graph_motif",
    }

    database.record_variant_proposal(proposal)
    database.record_variant_proposal(proposal)
    assert database.variant_proposals() == [proposal]
    with pytest.raises(ValueError):
        FamilyRegistry().get(proposal.candidate_family.slug)
