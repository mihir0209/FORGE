"""Immutable, evidence-supported fraud families and reviewed scenario templates."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from forge.contracts.contracts import (
    ActionPlan,
    DetectionTrack,
    EvidenceCapability,
    F3Mapping,
    FamilyEvidenceStatus,
    FraudFamilyDefinition,
    ToolAction,
    ToolKind,
)
from forge.payment_rails import rail_profile
from forge.research_snapshots import ResearchSnapshotStore

if TYPE_CHECKING:
    from forge.kb import Registry

_SCENARIO_KEYS = {
    "call_active",
    "verification",
    "behavioral_distance",
    "warning_overridden",
    "amount_minor",
    "balance_minor",
    "graph_motif",
    "entry_method",
    "first_time_payee",
    "dwell_seconds",
    "corrections",
    "workflow_template",
}

_APP = ToolKind.APP_SESSION_START
_BANK_TOOLS = (
    _APP, ToolKind.DEVICE_ATTEST, ToolKind.CALL_STATE_OBSERVE, ToolKind.PAYEE_ADD,
    ToolKind.PAYEE_VERIFY, ToolKind.BEHAVIOR_SAMPLE, ToolKind.BENEFICIARY_RISK_QUERY,
    ToolKind.SCAM_INTERVENE, ToolKind.PAYMENT_INITIATE,
)
_TEMPLATE_TOOLS: dict[str, tuple[ToolKind, ...]] = {
    "voice_call": (ToolKind.AUDIO_GENERATE, ToolKind.MEDIA_INSPECT),
    "video_call": (
        ToolKind.IMAGE_GENERATE,
        ToolKind.AUDIO_GENERATE,
        ToolKind.VIDEO_GENERATE,
        ToolKind.MEDIA_INSPECT,
    ),
    "document_lure": (ToolKind.IMAGE_GENERATE, ToolKind.MEDIA_INSPECT),
    "async_coaching": (),
    "synthetic_kyc": (ToolKind.IMAGE_GENERATE, ToolKind.MEDIA_INSPECT, ToolKind.KYC_SUBMIT),
    "corporate_bec": (
        ToolKind.AUDIO_GENERATE,
        ToolKind.MEDIA_INSPECT,
        ToolKind.VENDOR_DETAILS_CHANGE,
    ),
    "agent_hijack": (ToolKind.AGENT_CONTENT_INGEST,),
    "auth_bypass": (ToolKind.AUDIO_GENERATE, ToolKind.AUTH_CHALLENGE),
    "wallet_provisioning": (ToolKind.AUTH_CHALLENGE, ToolKind.WALLET_TOKEN_PROVISION),
    "recurring_billing": (ToolKind.IMAGE_GENERATE, ToolKind.SUBSCRIPTION_ENROLL),
    "delegated_payment": (ToolKind.DELEGATION_CREATE,),
    "request_to_pay": (ToolKind.PAYMENT_REQUEST_CREATE,),
    "consent_abuse": (ToolKind.CONSENT_CREATE,),
    "crypto_offramp": (ToolKind.CRYPTO_TRANSFER,),
    "reimbursement_claim": (ToolKind.IMAGE_GENERATE, ToolKind.CLAIM_SUBMIT),
    "payroll_diversion": (ToolKind.PAYROLL_DESTINATION_CHANGE,),
}
_PRIMARY_REFS = {
    "ic3": "https://www.ic3.gov/AnnualReport/Reports/2024_IC3Report.pdf",
    "ftc": "https://www.ftc.gov/system/files/ftc_gov/pdf/CSN-Annual-Data-Book-2024.pdf",
    "ukf": "https://www.ukfinance.org.uk/system/files/2024-05/Annual%20Fraud%20Report%202024.pdf",
    "europol": "https://www.europol.europa.eu/cms/sites/default/files/documents/Internet_Organised_Crime_Threat_Assessment_IOCTA_2023.pdf",
    "fincen": "https://www.fincen.gov/sites/default/files/shared/FinCEN_Advisory_FIN-2024-A002.pdf",
}


def define_family(**values: Any) -> FraudFamilyDefinition:
    draft = FraudFamilyDefinition.model_validate({**values, "definition_sha256": "pending"})
    unsigned = draft.model_dump(mode="json", exclude={"definition_sha256"})
    digest = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return draft.model_copy(update={"definition_sha256": digest})


def _family(
    slug: str, title: str, description: str, template: str, *,
    status: FamilyEvidenceStatus = FamilyEvidenceStatus.DEMONSTRATED,
    rail: str = "upi", amount: int = 50_000, call: bool = False,
    verification: str = "match", motif: str = "young_account",
    refs: tuple[str, ...] = ("ic3",),
) -> FraudFamilyDefinition:
    media = _TEMPLATE_TOOLS[template]
    return define_family(
        slug=slug, version="1.0.0", title=title, description=description,
        detection_track=DetectionTrack.AI_ASSISTED_APP,
        f3=F3Mapping(tactic="monetization", techniques=["F1010"]), rail=rail,
        channel="mobile_banking", genai_leverage="generative personalization and adaptive social engineering",
        evasion_hypothesis="genuine customer authentication obscures manipulated intent",
        evidence_status=status, scenario_template=template,
        allowed_tools=[*media, *_BANK_TOOLS],
        required_capabilities=[EvidenceCapability.APP_BEHAVIOR, EvidenceCapability.BENEFICIARY_NETWORK],
        scenario_defaults={
            "call_active": call, "verification": verification, "behavioral_distance": 0.78,
            "warning_overridden": True, "amount_minor": amount,
            "balance_minor": max(amount + 20_000, int(amount * 1.25)), "graph_motif": motif,
            "entry_method": "clipboard_paste", "first_time_payee": True,
            "dwell_seconds": 26.0, "corrections": 3,
            "workflow_template": template,
        },
        research_refs=[_PRIMARY_REFS[key] for key in refs],
    )


BUILTIN_FAMILIES: tuple[FraudFamilyDefinition, ...] = (
    _family("ai_bank_impersonation", "AI bank impersonation", "AI impersonation coaches a safe-account transfer.", "video_call", call=True, amount=75_000, verification="close_match", motif="mule_fanin"),
    _family("ai_family_emergency", "AI family emergency", "Cloned family voice creates emergency-payment urgency.", "voice_call", call=True, amount=35_000),
    _family("ai_investment_coaching", "AI investment coaching", "A persistent AI persona coaches an investment transfer.", "async_coaching", amount=60_000, motif="rapid_passthrough"),
    _family("synthetic_kyc_account_factory", "Synthetic KYC account factory", "Generated documents and liveness media establish mule accounts.", "synthetic_kyc", amount=20_000, refs=("fincen", "ic3")),
    _family("deepfake_executive_bec", "Deepfake executive BEC", "Synthetic executive approval redirects a corporate invoice.", "corporate_bec", amount=180_000, verification="close_match", refs=("fincen", "ic3")),
    _family("agent_prompt_injection_payment_hijack", "Payment-agent prompt injection", "Untrusted content diverts an AI payment agent.", "agent_hijack", amount=65_000, refs=("ic3",)),
    _family("ai_task_job_deposit_scam", "AI task-job deposit scam", "Synthetic recruiter and task ledger demand escalating deposits.", "async_coaching", rail="stablecoin_offramp", amount=30_000, refs=("ftc", "ic3")),
    _family("ai_romance_remittance", "AI romance remittance", "Persistent synthetic romantic identity requests remittances.", "video_call", amount=45_000, refs=("ftc", "ic3")),
    _family("deepfake_sextortion", "Deepfake sextortion", "Synthetic explicit media coerces prepaid or crypto payment.", "video_call", rail="stablecoin_offramp", amount=25_000, refs=("fincen", "ic3")),
    _family("genai_otp_auth_bypass", "GenAI OTP authentication bypass", "AI interaction captures an OTP and provisions account access.", "auth_bypass", amount=70_000, refs=("ic3",)),
    _family("wallet_token_provisioning_fraud", "Wallet token provisioning", "Stolen authentication provisions a card token to a new wallet.", "wallet_provisioning", rail="card", amount=55_000, refs=("ic3",)),
    _family("deepfake_voice_auth_bypass", "Deepfake voice authentication bypass", "Cloned voice passes contact-center verification.", "auth_bypass", call=True, amount=90_000, refs=("ic3",)),
    _family("agentic_checkout_farming", "Agentic checkout farming", "Autonomous browser agents coordinate account creation and checkout.", "agent_hijack", rail="card", amount=40_000, refs=("ic3",)),
    _family("dating_verification_subscription", "Dating verification subscription trap", "Synthetic dating persona enrolls recurring card billing.", "recurring_billing", rail="card", amount=5_000, refs=("ic3",)),
    _family("synthetic_media_market_manipulation", "Synthetic media market manipulation", "Generated endorsements funnel purchases into a manipulated asset.", "crypto_offramp", rail="stablecoin_offramp", amount=85_000, refs=("ic3",)),
    _family("synthetic_kyc_bnpl_bustout", "Synthetic KYC BNPL bust-out", "Synthetic identities season and exhaust BNPL facilities.", "synthetic_kyc", status=FamilyEvidenceStatus.EXPERIMENTAL, rail="card", amount=100_000, refs=("fincen",)),
    _family("request_for_payment_deception", "Request-for-payment deception", "Synthetic creditor sends an in-channel payment request.", "request_to_pay", status=FamilyEvidenceStatus.EXPERIMENTAL, rail="fednow", amount=60_000, refs=("ic3",)),
    _family("delegated_payment_mandate_abuse", "Delegated payment mandate abuse", "AI persona obtains delegated payment authority.", "delegated_payment", status=FamilyEvidenceStatus.EXPERIMENTAL, rail="upi_circle", amount=15_000, refs=("ic3",)),
    _family("open_banking_consent_abuse", "Open-banking consent abuse", "Synthetic financial assistant obtains excessive payment consent.", "consent_abuse", status=FamilyEvidenceStatus.EXPERIMENTAL, rail="open_banking", amount=75_000, refs=("ic3",)),
    _family("merchant_qr_substitution", "Merchant QR substitution", "Generated merchant material redirects QR acceptance credentials.", "document_lure", status=FamilyEvidenceStatus.EXPERIMENTAL, amount=12_000, refs=("ic3",)),
    _family("synthetic_expense_reimbursement", "Synthetic expense reimbursement", "Generated receipts support a false reimbursement claim.", "reimbursement_claim", status=FamilyEvidenceStatus.EXPERIMENTAL, amount=28_000, refs=("fincen",)),
    _family("synthetic_remote_worker_payroll", "Synthetic remote-worker payroll", "Synthetic applicant diverts payroll to a controlled account.", "payroll_diversion", status=FamilyEvidenceStatus.EXPERIMENTAL, amount=95_000, refs=("fincen",)),
    _family("agentic_stablecoin_offramp", "Agentic stablecoin offramp", "Agent orchestrates scam-proceeds consolidation and fiat withdrawal.", "crypto_offramp", status=FamilyEvidenceStatus.EXPERIMENTAL, rail="stablecoin_offramp", amount=110_000, motif="rapid_passthrough", refs=("ic3",)),
)


class FamilyRegistry:
    def __init__(
        self,
        root: Path | None = None,
        *,
        require_approval: bool = False,
        registry: Registry | None = None,
    ) -> None:
        self.root = root
        self.require_approval = require_approval
        self.registry = registry
        self._families = {(f.slug, f.version): f for f in BUILTIN_FAMILIES}
        if root and root.exists():
            for path in sorted(root.glob("*.json")):
                family = FraudFamilyDefinition.model_validate_json(path.read_text())
                self._register(family, persist=False, persist_database=False)
        if registry is not None:
            for family in registry.families():
                self._register(family, persist=False, persist_database=False)

    def register(self, family: FraudFamilyDefinition) -> None:
        self._register(family, persist=True, persist_database=True)

    def _register(
        self,
        family: FraudFamilyDefinition,
        *,
        persist: bool,
        persist_database: bool,
    ) -> None:
        if not family.allowed_tools or not set(family.scenario_defaults) <= _SCENARIO_KEYS:
            raise ValueError("family uses unsupported tools or scenario parameters")
        rail_profile(family.rail)
        expected = define_family(**family.model_dump(mode="json", exclude={"definition_sha256"})).definition_sha256
        if expected != family.definition_sha256:
            raise ValueError("family definition checksum mismatch")
        key = (family.slug, family.version)
        current = self._families.get(key)
        if current and current.definition_sha256 != family.definition_sha256:
            raise ValueError("family version is immutable")
        if self.require_approval and family not in BUILTIN_FAMILIES:
            if self.root is None:
                raise ValueError("external family approval store is unavailable")
            approval = self.root.parent / "research" / f"approval-{family.slug}-{family.version}.json"
            if not approval.exists():
                raise ValueError("external family requires an approval receipt")
            from forge.contracts.contracts import FamilyApprovalReceipt

            receipt = FamilyApprovalReceipt.model_validate_json(approval.read_text())
            if (
                not receipt.approved
                or receipt.family_slug != family.slug
                or receipt.family_version != family.version
                or receipt.definition_sha256 != family.definition_sha256
            ):
                raise ValueError("external family approval receipt is invalid")
            snapshot_store = ResearchSnapshotStore(self.root.parent / "research")
            snapshots = [snapshot_store.load(snapshot_id) for snapshot_id in receipt.research_snapshot_ids]
            if not set(family.research_refs) <= {snapshot.source_url for snapshot in snapshots}:
                raise ValueError("external family approval sources are incomplete")
        if self.root and persist:
            self.root.mkdir(parents=True, exist_ok=True)
            target = self.root / f"{family.slug}-{family.version}.json"
            payload = family.model_dump_json(indent=2) + "\n"
            if target.exists():
                stored = FraudFamilyDefinition.model_validate_json(target.read_text())
                if stored.definition_sha256 != family.definition_sha256:
                    raise ValueError("family version is immutable")
            else:
                fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=self.root)
                try:
                    with os.fdopen(fd, "w") as stream:
                        stream.write(payload)
                        stream.flush()
                        os.fsync(stream.fileno())
                    try:
                        os.link(temporary, target)
                    except FileExistsError:
                        stored = FraudFamilyDefinition.model_validate_json(target.read_text())
                        if stored.definition_sha256 != family.definition_sha256:
                            raise ValueError("family version is immutable") from None
                finally:
                    if os.path.exists(temporary):
                        os.unlink(temporary)
        if self.registry is not None and persist_database:
            self.registry.record_family(family)
        self._families[key] = family

    def get(self, slug: str, version: str = "1.0.0") -> FraudFamilyDefinition:
        try:
            return self._families[(slug, version)]
        except KeyError as exc:
            raise ValueError(f"unknown fraud family {slug}@{version}") from exc

    def list(self) -> list[FraudFamilyDefinition]:
        return sorted(self._families.values(), key=lambda f: (f.slug, f.version))


def family_registry_from_env() -> FamilyRegistry:
    from forge.kb import registry_from_env

    root = Path(os.environ.get("FORGE_DATA_DIR", "data")) / "families"
    return FamilyRegistry(root, require_approval=True, registry=registry_from_env())


def build_app_plan(
    family: FraudFamilyDefinition,
    cycle_id: str,
    seed: int = 0,
    *,
    purpose: str = "attack",
) -> ActionPlan:
    p = dict(family.scenario_defaults)
    digest = hashlib.sha256(f"{seed}:{family.definition_sha256}".encode()).digest()
    unit = int.from_bytes(digest[:8], "big") / ((1 << 64) - 1)
    p["amount_minor"] = int(int(p["amount_minor"]) * (0.9 + 0.2 * unit))
    p["behavioral_distance"] = max(0.0, min(1.0, float(p["behavioral_distance"]) + 0.08 * (unit - 0.5)))
    p["dwell_seconds"] = max(5.0, float(p["dwell_seconds"]) + 10.0 * (unit - 0.5))
    if purpose == "hard_negative":
        p["behavioral_distance"] = max(0.78, float(p["behavioral_distance"]))
        p["graph_motif"] = "mule_fanin"
    elif purpose == "low_signal_attack":
        p.update(
            behavioral_distance=0.2,
            warning_overridden=False,
            graph_motif="established_account",
            call_active=False,
        )
    elif purpose not in {"attack", "matched_control"}:
        raise ValueError(f"unknown scenario purpose: {purpose}")
    actions: list[ToolAction] = []
    if family.scenario_template == "voice_call":
        actions += [ToolAction(action_id="voice", tool=ToolKind.AUDIO_GENERATE), ToolAction(action_id="inspect", tool=ToolKind.MEDIA_INSPECT, depends_on=["voice"], parameters={"role": "offsite_voice_lure"})]
    elif family.scenario_template == "video_call":
        actions += [
            ToolAction(action_id="portrait", tool=ToolKind.IMAGE_GENERATE),
            ToolAction(action_id="voice", tool=ToolKind.AUDIO_GENERATE),
            ToolAction(action_id="video", tool=ToolKind.VIDEO_GENERATE, depends_on=["portrait", "voice"]),
            ToolAction(action_id="inspect", tool=ToolKind.MEDIA_INSPECT, depends_on=["video"], parameters={"role": "offsite_video_lure"}),
        ]
    elif family.scenario_template == "document_lure":
        actions += [ToolAction(action_id="document", tool=ToolKind.IMAGE_GENERATE), ToolAction(action_id="inspect", tool=ToolKind.MEDIA_INSPECT, depends_on=["document"], parameters={"role": "offsite_document_lure"})]
    elif family.scenario_template in {
        "synthetic_kyc", "corporate_bec", "agent_hijack", "auth_bypass",
        "wallet_provisioning", "recurring_billing", "delegated_payment",
        "request_to_pay", "consent_abuse", "crypto_offramp",
        "reimbursement_claim", "payroll_diversion",
    }:
        actions += _workflow_actions(family.scenario_template)
    elif family.scenario_template != "async_coaching":
        raise ValueError(f"unknown reviewed scenario template: {family.scenario_template}")
    actions += [
        ToolAction(action_id="app-session", tool=ToolKind.APP_SESSION_START),
        ToolAction(action_id="attest", tool=ToolKind.DEVICE_ATTEST),
        ToolAction(action_id="call-state", tool=ToolKind.CALL_STATE_OBSERVE, parameters={"active": p["call_active"]}),
        ToolAction(action_id="payee", tool=ToolKind.PAYEE_ADD, parameters={"first_time_payee": p["first_time_payee"], "entry_method": p["entry_method"]}),
        ToolAction(action_id="payee-check", tool=ToolKind.PAYEE_VERIFY, parameters={"result": p["verification"]}),
        ToolAction(action_id="behavior", tool=ToolKind.BEHAVIOR_SAMPLE, parameters={"behavioral_distance": p["behavioral_distance"], "dwell_seconds": p["dwell_seconds"], "corrections": p["corrections"]}),
        ToolAction(action_id="recipient-risk", tool=ToolKind.BENEFICIARY_RISK_QUERY, parameters={"scopes": ["local_bank", "consortium"], "graph_motif": p["graph_motif"]}),
        ToolAction(action_id="intervention", tool=ToolKind.SCAM_INTERVENE, parameters={"warning_overridden": p["warning_overridden"]}),
        ToolAction(
            action_id="payment",
            tool=ToolKind.PAYMENT_INITIATE,
            parameters={
                "amount_minor": p["amount_minor"],
                "available_balance_minor": p["balance_minor"],
                "currency": "INR",
                "rail": family.rail,
            },
        ),
    ]
    if not {a.tool for a in actions} <= set(family.allowed_tools):
        raise ValueError("plan exceeds family tool policy")
    return ActionPlan(plan_id=f"plan-{cycle_id}", strategy_id=f"strategy-{family.slug}-{cycle_id}", actor_id="simulated-customer-1", actions=actions)


def _workflow_actions(template: str) -> list[ToolAction]:
    if template == "synthetic_kyc":
        return [
            ToolAction(action_id="identity-document", tool=ToolKind.IMAGE_GENERATE),
            ToolAction(action_id="identity-inspect", tool=ToolKind.MEDIA_INSPECT, depends_on=["identity-document"]),
            ToolAction(action_id="kyc-submit", tool=ToolKind.KYC_SUBMIT),
        ]
    if template == "corporate_bec":
        return [
            ToolAction(action_id="executive-voice", tool=ToolKind.AUDIO_GENERATE),
            ToolAction(action_id="voice-inspect", tool=ToolKind.MEDIA_INSPECT, depends_on=["executive-voice"]),
            ToolAction(action_id="vendor-change", tool=ToolKind.VENDOR_DETAILS_CHANGE),
        ]
    return [
        ToolAction(action_id=f"workflow-{index}", tool=tool)
        for index, tool in enumerate(_TEMPLATE_TOOLS[template])
    ]
