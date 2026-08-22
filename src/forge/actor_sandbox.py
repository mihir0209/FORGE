"""Synthetic actor sandbox — red team executes tools as a user in the world."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from forge.contracts.contracts import (
    ActionPlan,
    ActorKind,
    ArtifactProvenance,
    FidelityReport,
    GroundTruth,
    LifecycleStage,
    MediaJobRequest,
    MediaObservation,
    SyntheticTrace,
    ToolAction,
    ToolKind,
    TraceEvent,
    WorldSeed,
)
from forge.media import FFmpegFixtureAdapter

if TYPE_CHECKING:
    from forge.artifacts import ArtifactStore


@dataclass
class SandboxResult:
    trace: SyntheticTrace
    provenance: list[ArtifactProvenance] = field(default_factory=list[ArtifactProvenance])
    media_observations: list[MediaObservation] = field(default_factory=list[MediaObservation])


class ActorSandbox:
    """Runs one typed ActionPlan against a non-routable synthetic world."""

    def __init__(self, store: ArtifactStore) -> None:
        self.store = store
        self.media = FFmpegFixtureAdapter(store)

    def execute(self, plan: ActionPlan, seed: WorldSeed, *, cycle_id: str) -> SandboxResult:
        start = datetime(2026, 8, 23, 8, tzinfo=UTC) + timedelta(minutes=seed.master_seed % 360)
        events: list[TraceEvent] = []
        provenance: list[ArtifactProvenance] = []
        observations: list[MediaObservation] = []
        outputs: dict[str, list[str]] = {}
        seq = 0

        def emit(
            kind: str,
            payload: dict[str, object],
            *,
            private: dict[str, object] | None = None,
            actor_kind: ActorKind = ActorKind.ATTACKER,
            stage: LifecycleStage | None = None,
            seconds: int = 0,
        ) -> TraceEvent:
            nonlocal seq
            seq += 1
            event = TraceEvent(
                event_id=f"mm{seq:05d}",
                ts=start + timedelta(seconds=seconds + seq),
                actor_kind=actor_kind,
                actor_id=plan.actor_id,
                kind=kind,
                payload=payload,
                private_payload=private or {},
                is_attack_step=True,
                attack_stage=stage,
            )
            events.append(event)
            return event

        active_call_id: str | None = None
        call_started: TraceEvent | None = None
        latest_video_id: str | None = None

        for index, action in enumerate(plan.actions):
            self._validate_dependencies(action, outputs)
            second = index * 12
            if action.tool in {
                ToolKind.IMAGE_GENERATE,
                ToolKind.AUDIO_GENERATE,
                ToolKind.VIDEO_GENERATE,
                ToolKind.MEDIA_INSPECT,
            }:
                inputs = [ref for dependency in action.depends_on for ref in outputs[dependency]]
                request = MediaJobRequest(
                    job_id=action.action_id,
                    cycle_id=cycle_id,
                    operation=action.tool,
                    input_artifact_ids=inputs,
                    parameters=action.parameters,
                    seed=seed.master_seed + index,
                )
                result, receipts = self.media.execute(request)
                provenance.extend(receipts)
                observations.extend(result.observations)
                outputs[action.action_id] = [a.artifact_id for a in result.output_artifacts]
                for observation in result.observations:
                    latest_video_id = (
                        observation.artifact.artifact_id
                        if observation.artifact.media_type.startswith("video/")
                        else latest_video_id
                    )
                    emit(
                        "media.inspected"
                        if action.tool == ToolKind.MEDIA_INSPECT
                        else "media.generated",
                        {
                            "artifact_id": observation.artifact.artifact_id,
                            "media_type": observation.artifact.media_type,
                            "role": observation.role,
                            "container": observation.container,
                            "codecs": observation.codecs,
                            "duration_seconds": observation.duration_seconds,
                            "width": observation.width,
                            "height": observation.height,
                            "frame_rate": observation.frame_rate,
                            "decode_warnings": observation.decode_warnings,
                        },
                        private={
                            "generated_by": self.media.adapter_name,
                            "seed": request.seed,
                            "intent": "synthetic_deepfake_fixture",
                        },
                        stage=LifecycleStage.AUTHENTICATION,
                        seconds=second,
                    )
                continue

            if action.tool == ToolKind.CALL_START:
                active_call_id = str(action.parameters.get("call_id", f"call-{cycle_id}"))
                call_started = emit(
                    "call.started",
                    {
                        "session_id": f"session-{cycle_id}",
                        "call_id": active_call_id,
                        "direction": "outbound",
                        "peer_ref": "synthetic-victim-1",
                        "media_kinds": ["audio", "video"],
                    },
                    private={"actor_role": "red", "peer_is_synthetic": True},
                    stage=LifecycleStage.AUTHENTICATION,
                    seconds=second,
                )
                emit(
                    "network.observed",
                    {
                        "session_id": f"session-{cycle_id}",
                        "call_id": active_call_id,
                        "network_address_token": "net-unknown-42",
                        "network_asn": 64542,
                        "network_as_org": "Synthetic Hosting Lab",
                        "network_country_iso": "ZZ",
                        "history_ip_seen_count": 0,
                        "history_asn_seen_count": 0,
                        "history_device_seen_count": 0,
                        "is_hosting_provider": True,
                    },
                    private={"true_peer": "attacker-node", "injected_novelty": True},
                    stage=LifecycleStage.AUTHENTICATION,
                    seconds=second + 1,
                )
                continue

            if action.tool == ToolKind.CALL_SAMPLE:
                if active_call_id is None:
                    raise ValueError("call.sample requires an active call")
                emit(
                    "webrtc.transport_stats",
                    {
                        "session_id": f"session-{cycle_id}",
                        "call_id": active_call_id,
                        "ice_state": "connected",
                        "ice_remote_type": "relay",
                        "ice_current_rtt_s": 0.182,
                        "ice_bytes_sent": 820_000,
                        "ice_bytes_received": 610_000,
                        "network_peer_token": "net-unknown-42",
                    },
                    stage=LifecycleStage.AUTHENTICATION,
                    seconds=second,
                )
                emit(
                    "webrtc.rtp_stats",
                    {
                        "session_id": f"session-{cycle_id}",
                        "call_id": active_call_id,
                        "kind": "video",
                        "codec": "h264",
                        "packets_received": 790,
                        "packets_lost": 17,
                        "jitter_s": 0.039,
                        "frames_per_second": 24.0,
                        "frames_dropped": 8,
                        "media_artifact_id": latest_video_id,
                        "liveness_anomaly_score": 0.91,
                        "detector_version": "fixture-liveness-v1",
                    },
                    private={"media_generated": True},
                    stage=LifecycleStage.AUTHENTICATION,
                    seconds=second + 1,
                )
                continue

            if action.tool == ToolKind.PAYMENT_INITIATE:
                if active_call_id is None or call_started is None:
                    raise ValueError("payment must occur during an active communication session")
                payment = emit(
                    "payment.initiated",
                    {
                        "payment_id": f"pay-{cycle_id}",
                        "amount_minor": int(action.parameters.get("amount_minor", 75_000)),
                        "currency": str(action.parameters.get("currency", "INR")),
                        "method_token": "synthetic-token-1",
                        "state": "initiated",
                        "channel": "upi",
                        "device_id": "victim-device-1",
                        "session_id": f"session-{cycle_id}",
                        "call_id": active_call_id,
                        "ref_event_ids": [call_started.event_id],
                    },
                    private={"coerced_by_synthetic_media": True},
                    actor_kind=ActorKind.VICTIM,
                    stage=LifecycleStage.PAYMENT,
                    seconds=second,
                )
                emit(
                    "payment.authorized",
                    {
                        **payment.payload,
                        "state": "authorized",
                        "ref_event_ids": [payment.event_id, call_started.event_id],
                    },
                    private={"fraud_ground_truth": True},
                    actor_kind=ActorKind.SYSTEM,
                    stage=LifecycleStage.PAYMENT,
                    seconds=second + 2,
                )
                continue

            if action.tool == ToolKind.CALL_END:
                if active_call_id is None:
                    raise ValueError("call.end requires an active call")
                emit(
                    "call.ended",
                    {
                        "session_id": f"session-{cycle_id}",
                        "call_id": active_call_id,
                        "termination_reason": "normal",
                    },
                    stage=LifecycleStage.CASH_OUT,
                    seconds=second,
                )
                active_call_id = None
                continue

            raise ValueError(f"unsupported actor tool: {action.tool}")

        trace_id = (
            "tr_mm_"
            + hashlib.sha256(f"{plan.plan_id}:{seed.master_seed}".encode()).hexdigest()[:12]
        )
        attack_ids = [e.event_id for e in events]
        trace = SyntheticTrace(
            trace_id=trace_id,
            seed=seed,
            events=sorted(events, key=lambda event: event.ts),
            ground_truth=GroundTruth(
                strategy_id=plan.strategy_id,
                fingerprint=hashlib.sha256(plan.model_dump_json().encode()).hexdigest()[:16],
                attack_event_ids=attack_ids,
            ),
            fidelity=FidelityReport(
                psi_amount=0.0,
                ks_timestamp_gap=0.0,
                graph_density_delta=0.0,
                temporal_autocorr=0.0,
                reachability_ok=active_call_id is None and bool(attack_ids),
                notes=["multimodal deterministic actor-sandbox fixture"],
            ),
        )
        return SandboxResult(trace=trace, provenance=provenance, media_observations=observations)

    def _validate_dependencies(self, action: ToolAction, outputs: dict[str, list[str]]) -> None:
        missing = [dependency for dependency in action.depends_on if dependency not in outputs]
        if missing:
            raise ValueError(f"action {action.action_id} missing dependencies: {missing}")


def deepfake_payment_plan(strategy_id: str, cycle_id: str) -> ActionPlan:
    """Known-good smoke plan. A live red agent emits the same ActionPlan schema."""
    return ActionPlan(
        plan_id=f"plan-{cycle_id}",
        strategy_id=strategy_id,
        actor_id="synthetic-attacker-1",
        actions=[
            ToolAction(action_id="portrait", tool=ToolKind.IMAGE_GENERATE),
            ToolAction(action_id="voice", tool=ToolKind.AUDIO_GENERATE),
            ToolAction(
                action_id="video",
                tool=ToolKind.VIDEO_GENERATE,
                depends_on=["portrait", "voice"],
            ),
            ToolAction(
                action_id="inspect",
                tool=ToolKind.MEDIA_INSPECT,
                depends_on=["video"],
                parameters={"role": "presented_video"},
            ),
            ToolAction(
                action_id="call-start",
                tool=ToolKind.CALL_START,
                parameters={"call_id": f"call-{cycle_id}"},
            ),
            ToolAction(action_id="call-stats", tool=ToolKind.CALL_SAMPLE),
            ToolAction(
                action_id="payment",
                tool=ToolKind.PAYMENT_INITIATE,
                parameters={"amount_minor": 75_000, "currency": "INR"},
            ),
            ToolAction(action_id="call-end", tool=ToolKind.CALL_END),
        ],
    )
