from datetime import UTC, datetime
from pathlib import Path

import pytest

from forge.families import FamilyRegistry
from forge.research_snapshots import ResearchSnapshotStore


def test_research_snapshot_is_content_addressed_and_required_for_approval(tmp_path: Path) -> None:
    family = FamilyRegistry().get("ai_bank_impersonation")
    store = ResearchSnapshotStore(tmp_path)
    snapshots = [
        store.record(
            source_url=url,
            title="Primary source",
            content=f"public evidence from {url}",
            provider="tinyfish-search-fetch",
            parser_version="tinyfish-fetch-v1",
            retrieved_at=datetime(2026, 8, 25, tzinfo=UTC),
        )
        for url in family.research_refs
    ]
    assert store.load(snapshots[0].snapshot_id) == snapshots[0]
    receipt = store.approve_family(
        family, [snapshot.snapshot_id for snapshot in snapshots], reviewer="test-reviewer", approved=True
    )
    assert receipt.definition_sha256 == family.definition_sha256


def test_approval_rejects_missing_primary_source(tmp_path: Path) -> None:
    family = FamilyRegistry().get("ai_bank_impersonation")
    with pytest.raises(ValueError, match="not fully snapshotted"):
        ResearchSnapshotStore(tmp_path).approve_family(
            family, [], reviewer="test-reviewer", approved=True
        )
