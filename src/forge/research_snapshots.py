"""Immutable untrusted research snapshots and family approval receipts."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from forge.contracts.contracts import FamilyApprovalReceipt, FraudFamilyDefinition, ResearchSnapshot


class ResearchSnapshotStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        *,
        source_url: str,
        title: str,
        content: str,
        provider: str,
        parser_version: str,
        retrieved_at: datetime | None = None,
    ) -> ResearchSnapshot:
        digest = hashlib.sha256(content.encode()).hexdigest()
        snapshot_id = f"research_{digest[:24]}"
        content_path = self.root / f"{snapshot_id}.txt"
        metadata_path = self.root / f"{snapshot_id}.json"
        if not content_path.exists():
            temp = content_path.with_suffix(".tmp")
            temp.write_text(content)
            temp.replace(content_path)
        snapshot = ResearchSnapshot(
            snapshot_id=snapshot_id,
            source_url=source_url,
            retrieved_at=retrieved_at or datetime.now(UTC),
            title=title,
            content_sha256=digest,
            artifact_ref=str(content_path),
            provider=provider,
            parser_version=parser_version,
        )
        if metadata_path.exists():
            existing = ResearchSnapshot.model_validate_json(metadata_path.read_text())
            if existing.content_sha256 != digest or existing.source_url != source_url:
                raise ValueError("research snapshot conflict")
            return existing
        temp = metadata_path.with_suffix(".tmp")
        temp.write_text(snapshot.model_dump_json(indent=2))
        temp.replace(metadata_path)
        return snapshot

    def load(self, snapshot_id: str) -> ResearchSnapshot:
        snapshot = ResearchSnapshot.model_validate_json(
            (self.root / f"{snapshot_id}.json").read_text()
        )
        content = Path(snapshot.artifact_ref).read_text()
        if hashlib.sha256(content.encode()).hexdigest() != snapshot.content_sha256:
            raise ValueError("research snapshot checksum mismatch")
        return snapshot

    def approve_family(
        self,
        family: FraudFamilyDefinition,
        snapshot_ids: list[str],
        *,
        reviewer: str,
        approved: bool,
    ) -> FamilyApprovalReceipt:
        snapshots = [self.load(snapshot_id) for snapshot_id in snapshot_ids]
        urls = {snapshot.source_url for snapshot in snapshots}
        if not set(family.research_refs) <= urls:
            raise ValueError("family research references are not fully snapshotted")
        receipt = FamilyApprovalReceipt(
            family_slug=family.slug,
            family_version=family.version,
            definition_sha256=family.definition_sha256,
            research_snapshot_ids=snapshot_ids,
            approved=approved,
            reviewer=reviewer,
            approved_at=datetime.now(UTC),
        )
        path = self.root / f"approval-{family.slug}-{family.version}.json"
        if path.exists():
            existing = FamilyApprovalReceipt.model_validate_json(path.read_text())
            if (
                existing.family_slug != receipt.family_slug
                or existing.family_version != receipt.family_version
                or existing.definition_sha256 != receipt.definition_sha256
                or existing.research_snapshot_ids != receipt.research_snapshot_ids
                or existing.approved != receipt.approved
                or existing.reviewer != receipt.reviewer
            ):
                raise ValueError("family approval receipt is immutable")
            return existing
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(receipt.model_dump(mode="json"), indent=2, sort_keys=True))
        temporary.replace(path)
        return receipt
