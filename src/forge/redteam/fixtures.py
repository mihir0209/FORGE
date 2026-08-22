"""Offline-mode fixtures: a deterministic DraftStrategy that passes validation."""

from __future__ import annotations

from forge.contracts.contracts import DraftStrategy, LifecycleStage
from forge.kb import f3_matrix


def default_draft() -> DraftStrategy:
    """Refund-abuse reference strategy; tactic picked from the live matrix."""
    matrix = f3_matrix()
    slug = "monetization"
    if matrix.tactic_by_slug(slug) is None:
        slug = matrix.tactics[0].slug
    techs = matrix.techniques_of(slug)
    technique_ids = [t.technique_id for t in techs[:2]]

    return DraftStrategy(
        fraud_objective=(
            "extract value via refund abuse: small test payments to a new payee, "
            "then mass disputes and off-hour cash-out"
        ),
        attack_family="refund_abuse",
        f3_tactic=slug,
        f3_techniques=technique_ids,
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
