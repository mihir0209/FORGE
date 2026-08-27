"""Host-backed SQLite knowledge is imported into the runtime database."""

from pathlib import Path

import pytest

from forge.contracts.contracts import LLMCall, StrategySpec
from forge.kb import SQLiteRegistry
from forge.operations import bootstrap
from forge.redteam import compose_draft
from forge.redteam.fixtures import default_draft


class _Target:
    def __init__(self) -> None:
        self.strategies: dict[str, StrategySpec] = {}
        self.cycles: set[str] = set()
        self.families: set[tuple[str, str]] = set()
        self.proposals: set[str] = set()
        self.llm_calls: set[str] = set()

    def record_strategy(self, strategy: StrategySpec) -> None:
        self.strategies[strategy.fingerprint()] = strategy

    def record_cycle(self, cycle: object) -> None:
        self.cycles.add(cycle.cycle_id)  # type: ignore[attr-defined]
        self.record_strategy(cycle.strategy)  # type: ignore[attr-defined]

    def record_family(self, family: object) -> None:
        self.families.add((family.slug, family.version))  # type: ignore[attr-defined]

    def record_variant_proposal(self, proposal: object) -> None:
        self.proposals.add(proposal.proposal_id)  # type: ignore[attr-defined]

    def claim_training_corpus(self, corpus_sha256: str, cycle_count: int) -> bool:
        del corpus_sha256, cycle_count
        return True

    def record_llm_call(self, call: LLMCall) -> None:
        self.llm_calls.add(call.call_id)


def test_bootstrap_imports_wal_visible_sqlite_without_modifying_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_path = tmp_path / "registry.sqlite"
    source = SQLiteRegistry(source_path)
    source.record_strategy(compose_draft(default_draft(), strategy_id="bootstrap-strategy"))
    before = source_path.read_bytes()
    target = _Target()

    def target_registry(_: str) -> _Target:
        return target

    monkeypatch.setattr(bootstrap, "PostgresRegistry", target_registry)

    first = bootstrap.bootstrap_database(
        source_path=source_path,
        families_root=tmp_path / "families",
        database_url="postgresql://unused",
    )
    second = bootstrap.bootstrap_database(
        source_path=source_path,
        families_root=tmp_path / "families",
        database_url="postgresql://unused",
    )

    assert first == second == {
        "families": 0,
        "strategies": 1,
        "cycles": 0,
        "proposals": 0,
        "training_corpora": 0,
        "llm_calls": 0,
    }
    assert len(target.strategies) == 1
    assert source_path.read_bytes() == before
