"""One complete AI-assisted APP scam actor-sandbox cycle."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from forge.actor_sandbox import ActorSandbox, ai_assisted_app_scam_plan
from forge.artifacts import LocalArtifactStore
from forge.blueteam import investigate
from forge.contracts.contracts import (
    ActionPlan,
    ContextBudgetPolicy,
    EvidenceRef,
    RunState,
    RunSupervisorConfig,
    ToolAction,
    ToolKind,
    WorldSeed,
)
from forge.operations.email import EmailNotifier
from forge.operations.supervisor import RunSupervisor
from forge.reasoning.context_budget import prepare_context
from forge.signals import all_signals


@pytest.mark.skipif(not Path("/usr/bin/ffmpeg").exists(), reason="ffmpeg required")
def test_complete_ai_assisted_app_scam_cycle(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path / "objects")
    sandbox = ActorSandbox(store)
    plan = ai_assisted_app_scam_plan("strategy-app-1", "cycle-app-1")

    result = sandbox.execute(plan, WorldSeed(master_seed=42), cycle_id="cycle-app-1")

    assert result.trace.fidelity.reachability_ok
    assert {a.media_type for a in [p.artifact for p in result.provenance]} >= {
        "image/png",
        "audio/wav",
        "video/mp4",
    }
    assert all(Path(p.artifact.uri).exists() for p in result.provenance)

    # Ground truth is present internally and absent from the defender view.
    assert any(e.private_payload for e in result.trace.events)
    observed = result.trace.observed_view()
    assert all(not e.private_payload for e in observed.events)
    assert all(not e.is_attack_step and e.attack_stage is None for e in observed.events)
    assert not any(e.kind.startswith("media.") for e in observed.events)
    assert "synthetic" not in observed.model_dump_json().lower()
    call_state = next(e for e in observed.events if e.kind == "device.call_state.observed")
    assert call_state.payload["active"] is True
    assert call_state.payload["caller_identity_available"] is False
    assert call_state.payload["provider_identity_available"] is False
    assert call_state.payload["media_available"] is False

    names = {signal.name for signal in all_signals(observed)}
    assert {
        "first_time_payee",
        "behavioral_coaching_risk",
        "beneficiary_network_risk",
        "warning_override",
        "balance_depletion",
        "active_external_call",
    } <= names
    report = investigate(observed)
    assert report.signals
    assert {ref for signal in report.signals for ref in signal.evidence_refs} <= set(
        observed.event_ids
    )


def test_app_scam_rejects_unlinked_behavior_evidence(tmp_path: Path) -> None:
    sandbox = ActorSandbox(LocalArtifactStore(tmp_path / "objects"))
    plan = ActionPlan(
        plan_id="invalid-plan",
        strategy_id="strategy-app-invalid",
        actor_id="simulated-customer-1",
        actions=[ToolAction(action_id="behavior", tool=ToolKind.BEHAVIOR_SAMPLE)],
    )

    with pytest.raises(ValueError, match="requires an app session and payee"):
        sandbox.execute(plan, WorldSeed(master_seed=42), cycle_id="cycle-app-invalid")


def test_context_compacts_before_25_percent(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path / "objects")
    evidence_bytes = b"immutable evidence"
    artifact = store.put_bytes("evidence", "e1", evidence_bytes, "text/plain")
    messages = [
        {
            "id": f"m{i}",
            "role": "user" if i % 2 == 0 else "assistant",
            "content": "hostile transcript data " * 80,
            "evidence": [
                EvidenceRef(
                    ref=artifact.artifact_id,
                    sha256=artifact.sha256,
                    media_type=artifact.media_type,
                    byte_size=artifact.byte_size,
                ).model_dump(mode="json")
            ],
        }
        for i in range(8)
    ]
    policy = ContextBudgetPolicy(
        context_window_tokens=30_000,
        max_output_tokens=800,
        fixed_safety_tokens=200,
        min_recent_turns=1,
    )
    projected = prepare_context(
        run_id="run-1",
        conversation_id="conv-1",
        agent_role="red",
        objective="execute synthetic scenario",
        messages=messages,
        policy=policy,
        store=store,
    )
    hard_cap = int(policy.context_window_tokens * 0.25)
    assert (
        projected.estimated_tokens + policy.max_output_tokens + policy.fixed_safety_tokens
        <= hard_cap
    )
    assert projected.compaction is not None
    assert projected.compaction.evidence_refs[0].sha256 == artifact.sha256


def test_supervisor_finalizes_manifest_and_email(tmp_path: Path) -> None:
    now = datetime(2026, 8, 23, tzinfo=UTC)
    store = LocalArtifactStore(tmp_path / "objects")
    config = RunSupervisorConfig(
        run_id="run-1",
        starts_at=now,
        ends_at=now + timedelta(minutes=1),
        max_cycles=1,
        max_storage_bytes=10_000_000,
        queue_capacity=5,
    )
    supervisor = RunSupervisor(config, store, tmp_path / "state.json")
    state = supervisor.start(now)
    assert state.state == RunState.RUNNING
    assert supervisor.admit(queue_depth=0, storage_reservation=1000, now=now)
    supervisor.cycle_started()
    state = supervisor.cycle_completed(actual_storage_bytes=1234)
    assert state.state == RunState.DRAINING
    state = supervisor.tick(now + timedelta(seconds=1))
    assert state.state == RunState.FINALIZING

    artifact = store.put_bytes("traces", "trace-1", b"trace", "application/json")
    manifest = supervisor.finalize({"traces": Path(artifact.uri).parent})
    assert manifest.state == RunState.COMPLETED
    assert manifest.entries
    assert supervisor.load_required().terminal_manifest_sha256

    notifier = EmailNotifier(tmp_path / "outbox")
    first = notifier.send(
        notification_type="run.completed",
        run_id="run-1",
        subject="FORGE run completed",
        body=f"Manifest: {manifest.manifest_sha256}",
        dedup_scope="terminal",
        dry_run=True,
    )
    second = notifier.send(
        notification_type="run.completed",
        run_id="run-1",
        subject="FORGE run completed",
        body="duplicate",
        dedup_scope="terminal",
        dry_run=True,
    )
    assert first == second
    assert first.read_text().count("Message-ID") == 1
