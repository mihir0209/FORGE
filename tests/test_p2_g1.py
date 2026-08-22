"""P2/G1: KB loaders, reasoning seam, red/blue/detect, and the golden offline cycle."""

from pathlib import Path

import pytest

from forge.contracts.contracts import (
    Coverage,
    F3Mapping,
    KBQuery,
    LifecycleStage,
    Provenance,
    StrategySpec,
    Verdict,
    WorldSeed,
)
from forge.cycle_runner import run_offline_cycle
from forge.detect import RuleBaselineDetector, gate_score, trace_features
from forge.kb import InMemoryRegistry, SQLiteRegistry, f3_matrix, fraud_skills, search
from forge.redteam import compose_draft, novelty, validate
from forge.redteam.fixtures import default_draft
from forge.simulate import build_legit_trace, simulate

# ------------------------------------------------------------------ knowledge


def test_f3_matrix_shape() -> None:
    m = f3_matrix()
    m.validate()
    slugs = {t.slug for t in m.tactics}
    assert {"reconnaissance", "positioning", "monetization", "stealth"} <= slugs
    f1001 = m.technique("F1001")
    assert f1001 is not None and f1001.fraud_native
    assert m.tactic_by_slug(f1001.tactic) is not None


def test_fraud_skills_joined_via_frontmatter() -> None:
    skills = fraud_skills()
    assert len(skills) >= 80  # research verified 94 at the pinned commit
    assert any(any(t.startswith("F1") for t in s.techniques) for s in skills)


def test_kb_search_returns_hits_for_tactic() -> None:
    hits = search(KBQuery(tactic="monetization", limit=6))
    assert hits and all(h.source in ("f3", "skill") for h in hits)


# ------------------------------------------------------------------ registry


def _spec(tag: str = "a") -> StrategySpec:
    return StrategySpec(
        strategy_id=f"s_{tag}",
        fraud_objective="x",
        attack_family="refund_abuse",
        f3=F3Mapping(tactic="monetization", techniques=[]),
        rail="upi",
        channel="web",
        lifecycle_stages=[LifecycleStage.PAYMENT],
        behavioral_sequence=["payment burst"],
        genai_leverage="n/a",
        evasion_hypothesis="mimic rhythm",
        novelty_rationale="test",
        provenance=Provenance(provider="t", model="t"),
    )


def test_registry_adapters_parity(tmp_path: Path) -> None:
    s = _spec()
    for reg in (InMemoryRegistry(), SQLiteRegistry(tmp_path / "reg.sqlite")):
        reg.record_strategy(s)
        twins = reg.similar(s.fingerprint())
        assert [x.strategy_id for x in twins] == ["s_a"]
        assert reg.same_family_count("refund_abuse") == 1
        assert reg.strategy_count() == 1


# ------------------------------------------------------------------ red team


def test_validate_rejects_bad_f3_and_missing_hints() -> None:
    good = compose_draft(default_draft(), strategy_id="s_ok")

    bad_f3 = good.model_copy(
        update={"f3": F3Mapping(tactic="nonexistent_slug", techniques=["F9999"])}
    )
    problems = validate(bad_f3)
    assert any("unknown F3 tactic" in p for p in problems)
    assert any("unknown F3 technique" in p for p in problems)

    hintless = good.model_copy(
        update={
            "lifecycle_stages": [LifecycleStage.CASH_OUT],
            "behavioral_sequence": ["send a polite email"],
        }
    )
    assert validate(hintless)

    # compose_draft itself refuses invalid drafts up front
    bad_draft = default_draft().model_copy(update={"f3_tactic": "nonexistent_slug"})
    with pytest.raises(ValueError, match="invalid strategy"):
        compose_draft(bad_draft, strategy_id="s_bad")


def test_novelty_flags_exact_duplicates() -> None:
    spec = compose_draft(default_draft(), strategy_id="s_dup")
    reg = InMemoryRegistry()
    assert novelty(spec, reg).novel
    reg.record_strategy(spec)
    second = novelty(spec, reg)
    assert not second.novel and second.exact_duplicate


# ------------------------------------------------------------------- G1 e2e


@pytest.mark.parametrize("reg_kind", ["memory", "sqlite"])
def test_golden_offline_cycle(tmp_path: Path, reg_kind: str) -> None:
    reg = InMemoryRegistry() if reg_kind == "memory" else SQLiteRegistry(tmp_path / "g.sqlite")
    record = run_offline_cycle(42, reg, draft=default_draft())

    assert record.strategy.attack_family == "refund_abuse"
    assert record.accepted is True
    assert record.trace_ref.startswith("tr_")

    # evidence integrity: blue signals cite events that exist in the world
    world = simulate(record.strategy, WorldSeed(master_seed=42)).trace.observed_view()
    known = set(world.event_ids)
    for signal in record.blue_report.signals:
        assert signal.evidence_refs, f"{signal.name} lacks evidence"
        assert set(signal.evidence_refs) <= known

    assert record.blue_report.verdict in Verdict
    assert record.gate_result.detector_id == "rule-baseline-v1"
    assert record.gate_result.coverage in Coverage
    assert len(reg.cycles()) == 1


def test_second_identical_cycle_is_duplicate(tmp_path: Path) -> None:
    reg = SQLiteRegistry(tmp_path / "d.sqlite")
    r1 = run_offline_cycle(42, reg, draft=default_draft())
    r2 = run_offline_cycle(42, reg, draft=default_draft())
    assert r1.accepted is True
    assert r2.accepted is False
    assert len(reg.cycles()) == 2
    assert r1.cycle_id != r2.cycle_id


def test_gate_separates_attack_from_legit_worlds() -> None:
    seed = WorldSeed(master_seed=7)
    attack_view = simulate(_spec(), seed).trace.observed_view()
    legit_view = build_legit_trace(seed).observed_view()

    det = RuleBaselineDetector()
    s_attack = det.score_features(trace_features(attack_view))
    s_legit = det.score_features(trace_features(legit_view))
    assert s_attack > s_legit

    g_attack = gate_score(attack_view, det)
    g_legit = gate_score(legit_view, det)
    order = {Coverage.BLIND_SPOT: 0, Coverage.PARTIAL: 1, Coverage.COVERED: 2}
    assert order[g_attack.coverage] >= order[g_legit.coverage]
