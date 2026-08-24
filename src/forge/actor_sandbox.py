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
    EvidenceScope,
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
            scope: EvidenceScope = EvidenceScope.DEFENDER,
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
                evidence_scope=scope,
                private_payload=private or {},
                is_attack_step=True,
                attack_stage=stage,
            )
            events.append(event)
            return event

        app_session_id: str | None = None
        payee_id: str | None = None

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
                        scope=EvidenceScope.INTERNAL,
                    )
                continue

            if action.tool == ToolKind.APP_SESSION_START:
                app_session_id = f"bank-session-{cycle_id}"
                emit(
                    "app.session.started",
                    {
                        "session_id": app_session_id,
                        "device_id": "customer-device-1",
                        "platform": "ios",
                        "app_version": "forge-bank-1",
                        "device_seen_count": 42,
                    },
                    private={"customer_is_simulated": True},
                    actor_kind=ActorKind.CUSTOMER,
                    stage=LifecycleStage.AUTHENTICATION,
                    seconds=second,
                )
                continue

            if action.tool == ToolKind.DEVICE_ATTEST:
                if app_session_id is None:
                    raise ValueError("device.attest requires an app session")
                emit(
                    "device.attested",
                    {
                        "session_id": app_session_id,
                        "provider": "app-attest",
                        "app_integrity": "recognized",
                        "device_integrity": "genuine",
                        "overlay_risk": False,
                    },
                    actor_kind=ActorKind.DEVICE,
                    stage=LifecycleStage.AUTHENTICATION,
                    seconds=second,
                )
                continue

            if action.tool == ToolKind.CALL_STATE_OBSERVE:
                if app_session_id is None:
                    raise ValueError("call_state.observe requires an app session")
                emit(
                    "device.call_state.observed",
                    {
                        "session_id": app_session_id,
                        "source": "ios_callkit",
                        "state_available": True,
                        "active": True,
                        "direction": "incoming",
                        "caller_identity_available": False,
                        "provider_identity_available": False,
                        "media_available": False,
                    },
                    actor_kind=ActorKind.DEVICE,
                    stage=LifecycleStage.AUTHENTICATION,
                    seconds=second,
                )
                continue

            if action.tool == ToolKind.PAYEE_ADD:
                if app_session_id is None:
                    raise ValueError("payee.add requires an app session")
                payee_id = f"payee-{cycle_id}"
                emit(
                    "payee.added",
                    {
                        "session_id": app_session_id,
                        "payee_id": payee_id,
                        "first_time_payee": True,
                        "entry_method": "clipboard_paste",
                    },
                    private={"payee_is_mule": True},
                    actor_kind=ActorKind.CUSTOMER,
                    stage=LifecycleStage.PAYMENT,
                    seconds=second,
                )
                continue

            if action.tool == ToolKind.PAYEE_VERIFY:
                if payee_id is None:
                    raise ValueError("payee.verify requires a payee")
                emit(
                    "payee.verification.completed",
                    {
                        "session_id": app_session_id,
                        "payee_id": payee_id,
                        "result": "close_match",
                        "entered_name_token": "name-entered-1",
                        "matched_name_token": "name-held-1",
                    },
                    actor_kind=ActorKind.SYSTEM,
                    stage=LifecycleStage.PAYMENT,
                    seconds=second,
                )
                continue

            if action.tool == ToolKind.BEHAVIOR_SAMPLE:
                if app_session_id is None or payee_id is None:
                    raise ValueError("behavior.sample requires an app session and payee")
                emit(
                    "app.behavior.sampled",
                    {
                        "session_id": app_session_id,
                        "payee_field_pasted": True,
                        "confirmation_dwell_seconds": 31.0,
                        "field_correction_count": 4,
                        "navigation_directness": 0.96,
                        "behavioral_distance": 0.82,
                    },
                    actor_kind=ActorKind.CUSTOMER,
                    stage=LifecycleStage.PAYMENT,
                    seconds=second,
                )
                continue

            if action.tool == ToolKind.BENEFICIARY_RISK_QUERY:
                if payee_id is None:
                    raise ValueError("beneficiary.risk.query requires a payee")
                emit(
                    "beneficiary.risk.assessed",
                    {
                        "payee_id": payee_id,
                        "account_age_days": 6,
                        "unique_senders_1h": 8,
                        "rapid_pass_through_ratio": 0.88,
                        "network_risk_score": 0.91,
                        "risk_scope": "consortium",
                    },
                    actor_kind=ActorKind.SYSTEM,
                    stage=LifecycleStage.PAYMENT,
                    seconds=second,
                )
                continue

            if action.tool == ToolKind.SCAM_INTERVENE:
                if app_session_id is None or payee_id is None:
                    raise ValueError("scam.intervene requires an app session and payee")
                emit(
                    "scam.intervention.responded",
                    {
                        "session_id": app_session_id,
                        "intervention_id": "safe-account-warning-v1",
                        "reason": "new_payee_and_recipient_network_risk",
                        "response": "continue",
                        "warning_overridden": True,
                    },
                    private={"customer_was_coached_to_override": True},
                    actor_kind=ActorKind.CUSTOMER,
                    stage=LifecycleStage.PAYMENT,
                    seconds=second,
                )
                continue

            if action.tool == ToolKind.PAYMENT_INITIATE:
                if app_session_id is None or payee_id is None:
                    raise ValueError("payment requires an app session and payee")
                payment = emit(
                    "payment.initiated",
                    {
                        "payment_id": f"pay-{cycle_id}",
                        "amount_minor": int(action.parameters.get("amount_minor", 75_000)),
                        "currency": str(action.parameters.get("currency", "INR")),
                        "method_token": "customer-account-token-1",
                        "state": "initiated",
                        "channel": "upi",
                        "device_id": "customer-device-1",
                        "session_id": app_session_id,
                        "payee_id": payee_id,
                        "available_balance_minor": 90_000,
                    },
                    private={"coerced_by_ai_impersonation": True},
                    actor_kind=ActorKind.CUSTOMER,
                    stage=LifecycleStage.PAYMENT,
                    seconds=second,
                )
                emit(
                    "payment.held",
                    {
                        **payment.payload,
                        "state": "held",
                        "hold_reason": "scam_risk_review",
                        "ref_event_ids": [payment.event_id],
                    },
                    private={"fraud_ground_truth": True, "loss_prevented": True},
                    actor_kind=ActorKind.SYSTEM,
                    stage=LifecycleStage.PAYMENT,
                    seconds=second + 2,
                )
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
                reachability_ok=app_session_id is not None and bool(attack_ids),
                notes=["AI-assisted APP scam with realistic payment-time evidence boundaries"],
            ),
        )
        return SandboxResult(trace=trace, provenance=provenance, media_observations=observations)

    def _validate_dependencies(self, action: ToolAction, outputs: dict[str, list[str]]) -> None:
        missing = [dependency for dependency in action.depends_on if dependency not in outputs]
        if missing:
            raise ValueError(f"action {action.action_id} missing dependencies: {missing}")


def ai_assisted_app_scam_plan(strategy_id: str, cycle_id: str) -> ActionPlan:
    """Prepare impersonation off-site, then exercise only realistic bank-visible signals."""
    return ActionPlan(
        plan_id=f"plan-{cycle_id}",
        strategy_id=strategy_id,
        actor_id="simulated-customer-1",
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
                parameters={"role": "offsite_impersonation_asset"},
            ),
            ToolAction(action_id="app-session", tool=ToolKind.APP_SESSION_START),
            ToolAction(action_id="attest", tool=ToolKind.DEVICE_ATTEST),
            ToolAction(action_id="call-state", tool=ToolKind.CALL_STATE_OBSERVE),
            ToolAction(action_id="payee", tool=ToolKind.PAYEE_ADD),
            ToolAction(action_id="payee-check", tool=ToolKind.PAYEE_VERIFY),
            ToolAction(action_id="behavior", tool=ToolKind.BEHAVIOR_SAMPLE),
            ToolAction(action_id="recipient-risk", tool=ToolKind.BENEFICIARY_RISK_QUERY),
            ToolAction(action_id="intervention", tool=ToolKind.SCAM_INTERVENE),
            ToolAction(
                action_id="payment",
                tool=ToolKind.PAYMENT_INITIATE,
                parameters={"amount_minor": 75_000, "currency": "INR"},
            ),
        ],
    )
