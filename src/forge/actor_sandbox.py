"""Synthetic actor sandbox — red team executes tools as a user in the world."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, TypedDict, cast

from forge.contracts.contracts import (
    ActionPlan,
    ActorKind,
    ArtifactProvenance,
    BeneficiaryGraphAssessment,
    EvidenceScope,
    FidelityReport,
    GraphScope,
    GroundTruth,
    LifecycleStage,
    MediaJobRequest,
    MediaObservation,
    ScenarioPurpose,
    SyntheticTrace,
    ToolAction,
    ToolKind,
    TraceEvent,
    WorldSeed,
)
from forge.graph_store import GraphEventStore, graph_store_from_env
from forge.media import FFmpegFixtureAdapter
from forge.risk_graph import graph_for_motif

if TYPE_CHECKING:
    from forge.artifacts import ArtifactStore


@dataclass
class SandboxResult:
    trace: SyntheticTrace
    provenance: list[ArtifactProvenance] = field(default_factory=list[ArtifactProvenance])
    media_observations: list[MediaObservation] = field(default_factory=list[MediaObservation])
    graph_assessments: list[BeneficiaryGraphAssessment] = field(
        default_factory=list[BeneficiaryGraphAssessment]
    )


class _AppScamProfile(TypedDict):
    call_active: bool
    verification: str
    behavioral_distance: float
    network_risk: float
    warning_overridden: bool
    amount_minor: int
    balance_minor: int


class ActorSandbox:
    """Runs one typed ActionPlan against a non-routable synthetic world."""

    def __init__(self, store: ArtifactStore, graph_store: GraphEventStore | None = None) -> None:
        self.store = store
        self.media = FFmpegFixtureAdapter(store)
        self.graph_store = graph_store or graph_store_from_env()

    def execute(
        self,
        plan: ActionPlan,
        seed: WorldSeed,
        *,
        cycle_id: str,
        purpose: ScenarioPurpose = ScenarioPurpose.ATTACK,
    ) -> SandboxResult:
        start = datetime(2026, 8, 23, 8, tzinfo=UTC) + timedelta(minutes=seed.master_seed % 360)
        events: list[TraceEvent] = []
        provenance: list[ArtifactProvenance] = []
        observations: list[MediaObservation] = []
        graph_assessments: list[BeneficiaryGraphAssessment] = []
        outputs: dict[str, list[str]] = {}
        seq = 0

        fraudulent = purpose in {ScenarioPurpose.ATTACK, ScenarioPurpose.LOW_SIGNAL_ATTACK}

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
                is_attack_step=fraudulent,
                attack_stage=stage if fraudulent else None,
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
                        "source": str(action.parameters.get("source", "ios_callkit")),
                        "state_available": bool(action.parameters.get("state_available", True)),
                        "active": bool(action.parameters.get("active", True)),
                        "direction": str(action.parameters.get("direction", "incoming")),
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
                        "first_time_payee": bool(
                            action.parameters.get("first_time_payee", True)
                        ),
                        "entry_method": str(
                            action.parameters.get("entry_method", "clipboard_paste")
                        ),
                    },
                    private={"payee_is_mule": fraudulent},
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
                        "result": str(action.parameters.get("result", "close_match")),
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
                        "payee_field_pasted": bool(action.parameters.get("pasted", True)),
                        "confirmation_dwell_seconds": float(
                            action.parameters.get("dwell_seconds", 31.0)
                        ),
                        "field_correction_count": int(action.parameters.get("corrections", 4)),
                        "navigation_directness": float(
                            action.parameters.get("navigation_directness", 0.96)
                        ),
                        "behavioral_distance": float(
                            action.parameters.get("behavioral_distance", 0.82)
                        ),
                    },
                    actor_kind=ActorKind.CUSTOMER,
                    stage=LifecycleStage.PAYMENT,
                    seconds=second,
                )
                continue

            if action.tool == ToolKind.BENEFICIARY_RISK_QUERY:
                if payee_id is None:
                    raise ValueError("beneficiary.risk.query requires a payee")
                raw_scopes = action.parameters.get("scopes", ["local_bank"])
                if not isinstance(raw_scopes, list):
                    raise ValueError("graph scopes must be a list")
                scopes = [GraphScope(str(value)) for value in cast("list[object]", raw_scopes)]
                motif = str(action.parameters.get("graph_motif", "mule_fanin"))
                decision_at = start + timedelta(seconds=second)
                assessment = graph_for_motif(
                    motif, payee_id, decision_at, store=self.graph_store
                ).assess(
                    payee_id,
                    decision_at,
                    scopes,
                    local_institution_id="bank-b",
                )
                graph_assessments.append(assessment)
                emit(
                    "beneficiary.risk.assessed",
                    {**assessment.features, "payee_id": payee_id, "risk_scope": "+".join(s.value for s in scopes), "snapshot_id": assessment.snapshot_id, "graph_evidence_refs": assessment.evidence_event_ids},
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
                        "response": str(action.parameters.get("response", "continue")),
                        "warning_overridden": bool(
                            action.parameters.get("warning_overridden", True)
                        ),
                    },
                    private={"customer_was_coached_to_override": fraudulent},
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
                        "channel": str(action.parameters.get("rail", "upi")),
                        "device_id": "customer-device-1",
                        "session_id": app_session_id,
                        "payee_id": payee_id,
                        "available_balance_minor": int(
                            action.parameters.get("available_balance_minor", 90_000)
                        ),
                    },
                    private={"coerced_by_ai_impersonation": True},
                    actor_kind=ActorKind.CUSTOMER,
                    stage=LifecycleStage.PAYMENT,
                    seconds=second,
                )
                outcome = "held" if fraudulent else "authorized"
                emit(
                    f"payment.{outcome}",
                    {
                        **payment.payload,
                        "state": outcome,
                        **({"hold_reason": "scam_risk_review"} if outcome == "held" else {}),
                        "ref_event_ids": [payment.event_id],
                    },
                    private={
                        "fraud_ground_truth": fraudulent,
                        "loss_prevented": fraudulent and outcome == "held",
                    },
                    actor_kind=ActorKind.SYSTEM,
                    stage=LifecycleStage.PAYMENT,
                    seconds=second + 2,
                )
                continue

            workflow_events = {
                ToolKind.KYC_SUBMIT: "kyc.application.submitted",
                ToolKind.VENDOR_DETAILS_CHANGE: "vendor.payment_details.changed",
                ToolKind.AGENT_CONTENT_INGEST: "agent.untrusted_content.ingested",
                ToolKind.AUTH_CHALLENGE: "authentication.challenge.completed",
                ToolKind.WALLET_TOKEN_PROVISION: "wallet.token.provisioned",
                ToolKind.SUBSCRIPTION_ENROLL: "subscription.enrolled",
                ToolKind.DELEGATION_CREATE: "payment.delegation.created",
                ToolKind.PAYMENT_REQUEST_CREATE: "payment_request.created",
                ToolKind.CONSENT_CREATE: "open_banking.consent.created",
                ToolKind.CRYPTO_TRANSFER: "crypto.transfer.initiated",
                ToolKind.CLAIM_SUBMIT: "claim.submitted",
                ToolKind.PAYROLL_DESTINATION_CHANGE: "payroll.destination.changed",
            }
            if action.tool in workflow_events:
                emit(
                    workflow_events[action.tool],
                    {
                        "session_id": app_session_id,
                        "synthetic_entity_token": f"entity-{cycle_id}",
                        **action.parameters,
                    },
                    private={"research_scenario": True},
                    actor_kind=ActorKind.SYSTEM,
                    stage=LifecycleStage.PAYMENT,
                    seconds=second,
                )
                continue

            raise ValueError(f"unsupported actor tool: {action.tool}")

        trace_id = (
            "tr_mm_"
            + hashlib.sha256(f"{plan.plan_id}:{seed.master_seed}".encode()).hexdigest()[:12]
        )
        attack_ids = [e.event_id for e in events] if fraudulent else []
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
                reachability_ok=app_session_id is not None and bool(events),
                notes=["AI-assisted APP scam with realistic payment-time evidence boundaries"],
            ),
        )
        return SandboxResult(
            trace=trace,
            provenance=provenance,
            media_observations=observations,
            graph_assessments=graph_assessments,
        )

    def _validate_dependencies(self, action: ToolAction, outputs: dict[str, list[str]]) -> None:
        missing = [dependency for dependency in action.depends_on if dependency not in outputs]
        if missing:
            raise ValueError(f"action {action.action_id} missing dependencies: {missing}")


def ai_assisted_app_scam_plan(
    strategy_id: str, cycle_id: str, *, variant: str = "safe_account"
) -> ActionPlan:
    """Prepare impersonation off-site, then exercise only realistic bank-visible signals."""
    profiles: dict[str, _AppScamProfile] = {
        "safe_account": {
            "call_active": True,
            "verification": "close_match",
            "behavioral_distance": 0.82,
            "network_risk": 0.91,
            "warning_overridden": True,
            "amount_minor": 75_000,
            "balance_minor": 90_000,
        },
        "family_emergency": {
            "call_active": True,
            "verification": "match",
            "behavioral_distance": 0.76,
            "network_risk": 0.73,
            "warning_overridden": True,
            "amount_minor": 35_000,
            "balance_minor": 80_000,
        },
        "investment_coaching": {
            "call_active": False,
            "verification": "match",
            "behavioral_distance": 0.88,
            "network_risk": 0.86,
            "warning_overridden": True,
            "amount_minor": 60_000,
            "balance_minor": 100_000,
        },
    }
    profile = profiles.get(variant)
    if profile is None:
        raise ValueError(f"unknown APP scam variant: {variant}")
    jitter = int(hashlib.sha256(cycle_id.encode()).hexdigest()[:8], 16) / 0xFFFFFFFF
    behavioral_distance = min(0.99, profile["behavioral_distance"] + 0.08 * (jitter - 0.5))
    network_risk = min(0.99, profile["network_risk"] + 0.10 * (0.5 - jitter))
    amount_minor = int(profile["amount_minor"] * (0.9 + 0.2 * jitter))
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
            ToolAction(
                action_id="call-state",
                tool=ToolKind.CALL_STATE_OBSERVE,
                parameters={"active": profile["call_active"]},
            ),
            ToolAction(action_id="payee", tool=ToolKind.PAYEE_ADD),
            ToolAction(
                action_id="payee-check",
                tool=ToolKind.PAYEE_VERIFY,
                parameters={"result": profile["verification"]},
            ),
            ToolAction(
                action_id="behavior",
                tool=ToolKind.BEHAVIOR_SAMPLE,
                parameters={"behavioral_distance": behavioral_distance},
            ),
            ToolAction(
                action_id="recipient-risk",
                tool=ToolKind.BENEFICIARY_RISK_QUERY,
                parameters={"network_risk_score": network_risk},
            ),
            ToolAction(
                action_id="intervention",
                tool=ToolKind.SCAM_INTERVENE,
                parameters={"warning_overridden": profile["warning_overridden"]},
            ),
            ToolAction(
                action_id="payment",
                tool=ToolKind.PAYMENT_INITIATE,
                parameters={
                    "amount_minor": amount_minor,
                    "available_balance_minor": profile["balance_minor"],
                    "currency": "INR",
                    "fraudulent": True,
                    "outcome": "held",
                },
            ),
        ],
    )


def legitimate_app_payment_plan(
    strategy_id: str,
    cycle_id: str,
    *,
    active_call: bool,
    first_time_payee: bool = False,
) -> ActionPlan:
    """Legitimate control using the same observable APP evidence contract."""
    return ActionPlan(
        plan_id=f"plan-{cycle_id}",
        strategy_id=strategy_id,
        actor_id="simulated-customer-control",
        actions=[
            ToolAction(action_id="app-session", tool=ToolKind.APP_SESSION_START),
            ToolAction(action_id="attest", tool=ToolKind.DEVICE_ATTEST),
            ToolAction(
                action_id="call-state",
                tool=ToolKind.CALL_STATE_OBSERVE,
                parameters={"active": active_call},
            ),
            ToolAction(
                action_id="payee",
                tool=ToolKind.PAYEE_ADD,
                parameters={
                    "first_time_payee": first_time_payee,
                    "entry_method": "manual_entry" if first_time_payee else "saved_payee",
                },
            ),
            ToolAction(
                action_id="payee-check",
                tool=ToolKind.PAYEE_VERIFY,
                parameters={"result": "match"},
            ),
            ToolAction(
                action_id="behavior",
                tool=ToolKind.BEHAVIOR_SAMPLE,
                parameters={
                    "pasted": False,
                    "dwell_seconds": 4.0,
                    "corrections": 0,
                    "behavioral_distance": 0.12,
                },
            ),
            ToolAction(
                action_id="recipient-risk",
                tool=ToolKind.BENEFICIARY_RISK_QUERY,
                parameters={
                    "graph_motif": "established_account",
                    "scopes": ["local_bank"],
                },
            ),
            ToolAction(
                action_id="intervention",
                tool=ToolKind.SCAM_INTERVENE,
                parameters={"response": "acknowledged", "warning_overridden": False},
            ),
            ToolAction(
                action_id="payment",
                tool=ToolKind.PAYMENT_INITIATE,
                parameters={
                    "amount_minor": 8_000,
                    "available_balance_minor": 100_000,
                    "currency": "INR",
                    "fraudulent": False,
                    "outcome": "authorized",
                },
            ),
        ],
    )
