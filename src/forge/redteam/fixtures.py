"""Offline-mode fixture drafts: family diversity without LLM keys.

Real LLM composition (forge.reasoning adapters) replaces this once keys are
provisioned; compose() consumes both identically.
"""

from __future__ import annotations

from typing import Any

from forge.contracts.contracts import DraftStrategy, LifecycleStage
from forge.kb import f3_matrix

_REFUND_ABUSE = dict(
    fraud_objective=(
        "extract value via refund abuse: small test payments to a new payee, "
        "then mass disputes and off-hour cash-out"
    ),
    attack_family="refund_abuse",
    rail="upi",
    channel="web",
    lifecycle_stages=[
        LifecycleStage.AUTHENTICATION,
        LifecycleStage.PAYMENT,
        LifecycleStage.REFUND,
        LifecycleStage.CASH_OUT,
    ],
    behavioral_sequence=[
        "new device login at night",
        "small test payment to new payee",
        "burst of rapid payments",
        "request refund for each payment",
        "off-hour cash-out attempts",
    ],
    entities={"mule_accounts": 1},
    genai_leverage="synthetic complaint narratives to justify disputes",
    evasion_hypothesis="mimic grocery rhythm; keep tickets small; act at night",
    expected_signals=["velocity_burst", "refund_chain"],
    novelty_rationale="first refund-abuse combination under monetization",
)

_ACCOUNT_TAKEOVER = dict(
    fraud_objective=(
        "take over dormant accounts via credential stuffing, then drain stored "
        "value through rapid card payments and off-hour cash-out"
    ),
    attack_family="account_takeover",
    rail="card",
    channel="mobile",
    lifecycle_stages=[
        LifecycleStage.AUTHENTICATION,
        LifecycleStage.PAYMENT,
        LifecycleStage.CASH_OUT,
    ],
    behavioral_sequence=[
        "credential stuffing login attempts at night",
        "new device login and password change session",
        "burst of rapid payments to fresh payees",
        "off-hour cash-out attempts",
    ],
    entities={"breached_credentials": 5000},
    genai_leverage="lure copy tailored from breached-credential patterns",
    evasion_hypothesis="mimic card-rail rhythm; act in the quiet 0-5h band",
    expected_signals=["velocity_burst", "new_device_payment"],
    novelty_rationale="first ATO combination under initial access",
)


def default_draft() -> DraftStrategy:
    """Refund-abuse reference strategy under Monetization."""
    slug = "monetization"
    matrix = f3_matrix()
    if matrix.tactic_by_slug(slug) is None:
        slug = matrix.tactics[0].slug
    techs = [t.technique_id for t in matrix.techniques_of(slug)[:2]]

    return DraftStrategy(
        fraud_objective=_REFUND_ABUSE["fraud_objective"],  # type: ignore[arg-type]
        attack_family=_REFUND_ABUSE["attack_family"],  # type: ignore[arg-type]
        f3_tactic=slug,
        f3_techniques=techs,
        rail=_REFUND_ABUSE["rail"],  # type: ignore[arg-type]
        channel=_REFUND_ABUSE["channel"],  # type: ignore[arg-type]
        lifecycle_stages=_REFUND_ABUSE["lifecycle_stages"],  # type: ignore[arg-type]
        behavioral_sequence=_REFUND_ABUSE["behavioral_sequence"],  # type: ignore[arg-type]
        entities=_REFUND_ABUSE["entities"],  # type: ignore[arg-type]
        genai_leverage=_REFUND_ABUSE["genai_leverage"],  # type: ignore[arg-type]
        evasion_hypothesis=_REFUND_ABUSE["evasion_hypothesis"],  # type: ignore[arg-type]
        expected_signals=_REFUND_ABUSE["expected_signals"],  # type: ignore[arg-type]
        novelty_rationale=_REFUND_ABUSE["novelty_rationale"],  # type: ignore[arg-type]
    )


def _tactic_draft(slug: str, overrides: dict[str, Any]) -> DraftStrategy:
    matrix = f3_matrix()
    techs = [t.technique_id for t in matrix.techniques_of(slug)[:2]]
    updates: dict[str, Any] = {"f3_tactic": slug, "f3_techniques": techs}
    updates.update(overrides)
    return default_draft().model_copy(update=updates)


def draft_for_tactic(tactic_slug: str) -> DraftStrategy:
    """Each tactic slug yields a distinct fingerprint."""
    special = {
        "initial-access": _ACCOUNT_TAKEOVER,
        "stealth": {
            **_ACCOUNT_TAKEOVER,
            "attack_family": "stealthy_account_takeover",
            "evasion_hypothesis": (
                "strictly 0-4h activity window; ticket sizes mimic utilities; "
                "session counts kept low"
            ),
        },
    }
    if tactic_slug in special:
        return _tactic_draft(tactic_slug, special[tactic_slug])
    # Generic: keep refund_abuse template but stamp it to the target tactic
    # so fingerprint (which hashes family+f3+rail+channel+stages+sequence)
    # varies per tactic even without hand-curated families.
    return _tactic_draft(
        tactic_slug,
        {
            "attack_family": tactic_slug.replace("-", "_") + "_abuse",
            "fraud_objective": f"abuse {tactic_slug.replace('-', ' ')} for value extraction",
        },
    )
