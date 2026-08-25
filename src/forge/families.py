"""Immutable fraud-family registry and generic APP plan construction."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from forge.contracts.contracts import (
    ActionPlan,
    DetectionTrack,
    EvidenceCapability,
    F3Mapping,
    FraudFamilyDefinition,
    ToolAction,
    ToolKind,
)
from forge.payment_rails import rail_profile

_SCENARIO_KEYS = {
    "call_active",
    "verification",
    "behavioral_distance",
    "warning_overridden",
    "amount_minor",
    "balance_minor",
    "graph_motif",
}


def define_family(**values: Any) -> FraudFamilyDefinition:
    draft = FraudFamilyDefinition.model_validate({**values, "definition_sha256": "pending"})
    unsigned = draft.model_dump(mode="json", exclude={"definition_sha256"})
    digest = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return draft.model_copy(update={"definition_sha256": digest})


BUILTIN_FAMILIES: tuple[FraudFamilyDefinition, ...] = (
    define_family(
        slug="ai_bank_impersonation", version="1.0.0", title="AI bank impersonation",
        description="AI impersonation coaches a safe-account transfer.",
        detection_track=DetectionTrack.AI_ASSISTED_APP,
        f3=F3Mapping(tactic="monetization", techniques=["F1010"]), rail="upi", channel="mobile_banking",
        genai_leverage="voice/video impersonation and adaptive coaching",
        evasion_hypothesis="genuine customer authentication hides coerced intent",
        allowed_tools=list(ToolKind),
        required_capabilities=[EvidenceCapability.APP_BEHAVIOR, EvidenceCapability.BENEFICIARY_NETWORK],
        scenario_defaults={"call_active": True, "verification": "close_match", "behavioral_distance": 0.82, "warning_overridden": True, "amount_minor": 75000, "balance_minor": 90000, "graph_motif": "mule_fanin"},
        research_refs=["FBI-IC3-2024", "Mastercard-CFR"],
    ),
    define_family(
        slug="ai_family_emergency", version="1.0.0", title="AI family emergency",
        description="Cloned family voice creates emergency-payment urgency.",
        detection_track=DetectionTrack.AI_ASSISTED_APP,
        f3=F3Mapping(tactic="monetization", techniques=["F1010"]), rail="upi", channel="mobile_banking",
        genai_leverage="zero-shot voice cloning", evasion_hypothesis="plausible payee and lower value",
        allowed_tools=list(ToolKind), required_capabilities=[EvidenceCapability.APP_BEHAVIOR],
        scenario_defaults={"call_active": True, "verification": "match", "behavioral_distance": 0.76, "warning_overridden": True, "amount_minor": 35000, "balance_minor": 80000, "graph_motif": "young_account"},
        research_refs=["FBI-IC3-2024"],
    ),
    define_family(
        slug="ai_investment_coaching", version="1.0.0", title="AI investment coaching",
        description="AI persona asynchronously coaches an investment transfer.",
        detection_track=DetectionTrack.AI_ASSISTED_APP,
        f3=F3Mapping(tactic="monetization", techniques=["F1010"]), rail="upi", channel="mobile_banking",
        genai_leverage="persistent multilingual investment persona", evasion_hypothesis="asynchronous coaching removes call evidence",
        allowed_tools=list(ToolKind), required_capabilities=[EvidenceCapability.BENEFICIARY_NETWORK],
        scenario_defaults={"call_active": False, "verification": "match", "behavioral_distance": 0.88, "warning_overridden": True, "amount_minor": 60000, "balance_minor": 100000, "graph_motif": "rapid_passthrough"},
        research_refs=["FBI-IC3-2024", "Visa-A2A-Protect"],
    ),
)


class FamilyRegistry:
    def __init__(self, root: Path | None = None) -> None:
        self.root = root
        self._families = {(f.slug, f.version): f for f in BUILTIN_FAMILIES}
        if root and root.exists():
            for path in sorted(root.glob("*.json")):
                family = FraudFamilyDefinition.model_validate_json(path.read_text())
                self.register(family)

    def register(self, family: FraudFamilyDefinition) -> None:
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
        self._families[key] = family
        if self.root:
            self.root.mkdir(parents=True, exist_ok=True)
            (self.root / f"{family.slug}-{family.version}.json").write_text(family.model_dump_json(indent=2))

    def get(self, slug: str, version: str = "1.0.0") -> FraudFamilyDefinition:
        try:
            return self._families[(slug, version)]
        except KeyError as exc:
            raise ValueError(f"unknown fraud family {slug}@{version}") from exc

    def list(self) -> list[FraudFamilyDefinition]:
        return sorted(self._families.values(), key=lambda f: (f.slug, f.version))


def family_registry_from_env() -> FamilyRegistry:
    root = Path(os.environ.get("FORGE_DATA_DIR", "data")) / "families"
    return FamilyRegistry(root)


def build_app_plan(family: FraudFamilyDefinition, cycle_id: str) -> ActionPlan:
    p = family.scenario_defaults
    actions = [
        ToolAction(action_id="portrait", tool=ToolKind.IMAGE_GENERATE),
        ToolAction(action_id="voice", tool=ToolKind.AUDIO_GENERATE),
        ToolAction(action_id="video", tool=ToolKind.VIDEO_GENERATE, depends_on=["portrait", "voice"]),
        ToolAction(action_id="app-session", tool=ToolKind.APP_SESSION_START),
        ToolAction(action_id="attest", tool=ToolKind.DEVICE_ATTEST),
        ToolAction(action_id="call-state", tool=ToolKind.CALL_STATE_OBSERVE, parameters={"active": p["call_active"]}),
        ToolAction(action_id="payee", tool=ToolKind.PAYEE_ADD),
        ToolAction(action_id="payee-check", tool=ToolKind.PAYEE_VERIFY, parameters={"result": p["verification"]}),
        ToolAction(action_id="behavior", tool=ToolKind.BEHAVIOR_SAMPLE, parameters={"behavioral_distance": p["behavioral_distance"]}),
        ToolAction(action_id="recipient-risk", tool=ToolKind.BENEFICIARY_RISK_QUERY, parameters={"scopes": ["local_bank", "consortium"], "graph_motif": p["graph_motif"]}),
        ToolAction(action_id="intervention", tool=ToolKind.SCAM_INTERVENE, parameters={"warning_overridden": p["warning_overridden"]}),
        ToolAction(action_id="payment", tool=ToolKind.PAYMENT_INITIATE, parameters={"amount_minor": p["amount_minor"], "available_balance_minor": p["balance_minor"], "currency": "INR"}),
    ]
    if not {a.tool for a in actions} <= set(family.allowed_tools):
        raise ValueError("plan exceeds family tool policy")
    return ActionPlan(plan_id=f"plan-{cycle_id}", strategy_id=f"strategy-{family.slug}-{cycle_id}", actor_id="simulated-customer-1", actions=actions)
