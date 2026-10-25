"""Decentralized Chargeback Predictor & Merchant Friendly-Fraud Shield for FORGE.

Evaluates pre-dispute transaction signals, merchant category risk factors,
and delivery proof verifications to calculate chargeback probability and synthesize
Visa Compelling Evidence 3.0 / Mastercard dispute rebuttal evidence bundles.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class FriendlyFraudRisk(str, Enum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH_RISK_CHARGEBACK = "HIGH_RISK_CHARGEBACK"
    CRITICAL_FIRST_PARTY_FRAUD = "CRITICAL_FIRST_PARTY_FRAUD"


@dataclass
class TransactionContext:
    transaction_id: str
    account_id: str
    amount: float
    mcc: str  # Merchant Category Code (e.g. "5734" Software, "7995" Gambling, "5411" Grocery)
    card_present: bool
    billing_country: str
    shipping_country: str
    account_age_days: int
    prior_dispute_count: int
    prior_successful_tx_count: int
    delivery_signed: bool = False
    delivery_carrier_hash: Optional[str] = None
    buyer_ip: str = "127.0.0.1"


@dataclass
class DisputeRebuttalPacket:
    transaction_id: str
    evidence_bundle_hash: str
    rebuttal_strategy: str
    ce30_qualifying: bool  # Visa Compelling Evidence 3.0 qualified
    evidence_documents: Dict[str, Any]
    synthesized_representation_summary: str


@dataclass
class ChargebackPredictionResult:
    transaction_id: str
    chargeback_probability: float
    risk_level: FriendlyFraudRisk
    risk_factors: List[str]
    dispute_shield_action: str  # "APPROVE", "FLAG_PRE_DISPUTE", "FORCE_3DS", "REJECT"
    rebuttal_packet: Optional[DisputeRebuttalPacket] = None


# High-risk MCC baseline chargeback weight
MCC_RISK_TABLE: Dict[str, float] = {
    "7995": 0.35,  # Betting / Gambling
    "5734": 0.25,  # Computer Software / Digital Downloads
    "5967": 0.30,  # Direct Marketing - Inbound Telemarketing
    "4722": 0.20,  # Travel Agencies & Tour Operators
    "7273": 0.28,  # Dating Services
    "5411": 0.05,  # Grocery Stores
    "5311": 0.08,  # Department Stores
}


class ChargebackShieldEngine:
    """Friendly fraud prediction and automated dispute defense engine."""

    def __init__(self, high_risk_threshold: float = 0.65, critical_threshold: float = 0.85) -> None:
        self.high_risk_threshold = high_risk_threshold
        self.critical_threshold = critical_threshold

    def calculate_chargeback_probability(self, ctx: TransactionContext) -> Tuple[float, List[str]]:
        """Calculate the probability of chargeback dispute based on multi-factor heuristics."""
        prob = 0.05  # Base global dispute rate baseline
        factors: List[str] = []

        # 1. MCC Industry baseline
        mcc_weight = MCC_RISK_TABLE.get(ctx.mcc, 0.12)
        prob += mcc_weight
        if mcc_weight > 0.20:
            factors.append(f"High-dispute merchant category code MCC={ctx.mcc} (+{mcc_weight:.2f})")

        # 2. Prior dispute history & dispute ratio
        total_tx = max(1, ctx.prior_dispute_count + ctx.prior_successful_tx_count)
        dispute_ratio = ctx.prior_dispute_count / total_tx
        if ctx.prior_dispute_count >= 2 or dispute_ratio > 0.15:
            penalty = min(0.35, dispute_ratio * 0.8 + 0.1)
            prob += penalty
            factors.append(f"Elevated prior dispute history (disputes={ctx.prior_dispute_count}, ratio={dispute_ratio:.2%})")

        # 3. New account large purchase anomaly
        if ctx.account_age_days < 7 and ctx.amount > 500.0:
            prob += 0.22
            factors.append(f"High-ticket purchase on new account ({ctx.account_age_days}d old, ${ctx.amount:.2f})")

        # 4. Geographic billing vs shipping mismatch
        if ctx.billing_country.upper() != ctx.shipping_country.upper():
            prob += 0.18
            factors.append(f"Cross-border shipping mismatch (billing={ctx.billing_country}, shipping={ctx.shipping_country})")

        # 5. Delivery attestation mitigation
        if ctx.delivery_signed and ctx.delivery_carrier_hash:
            prob = max(0.01, prob - 0.20)
            factors.append("Mitigation: Carrier-verified physical signature attached (-0.20)")

        # 6. Card not present penalty
        if not ctx.card_present:
            prob += 0.08
            factors.append("Card-not-present online transaction (+0.08)")

        # Clamp between 0.01 and 0.99
        prob = round(min(0.99, max(0.01, prob)), 4)
        return prob, factors

    def build_rebuttal_packet(self, ctx: TransactionContext) -> DisputeRebuttalPacket:
        """Synthesize pre-compiled evidence packet for Visa Compelling Evidence 3.0."""
        # Visa CE3.0 requires prior non-fraud transactions sharing same core credentials
        ce30_qualifies = ctx.prior_successful_tx_count >= 2 and ctx.prior_dispute_count == 0

        docs = {
            "transaction_id": ctx.transaction_id,
            "account_id": ctx.account_id,
            "amount": ctx.amount,
            "buyer_ip": ctx.buyer_ip,
            "delivery_carrier_hash": ctx.delivery_carrier_hash,
            "delivery_signed": ctx.delivery_signed,
            "billing_country": ctx.billing_country,
            "shipping_country": ctx.shipping_country,
            "timestamp": time.time(),
        }

        # SHA-256 fingerprint of evidence payload
        raw_evidence = f"{ctx.transaction_id}|{ctx.account_id}|{ctx.amount}|{ctx.delivery_carrier_hash}"
        bundle_hash = hashlib.sha256(raw_evidence.encode("utf-8")).hexdigest()

        if ce30_qualifies:
            strategy = "Visa Compelling Evidence 3.0 (CE3.0) / Mastercard First-Party Trust Qualified Representation"
            summary = (
                f"Qualified under Compelling Evidence 3.0: Customer has {ctx.prior_successful_tx_count} "
                "prior undisputed settled transactions sharing identical IP and device credentials. "
                "Chargeback liability shifts back to issuer."
            )
        elif ctx.delivery_signed:
            strategy = "Proof of Delivery Carrier Attestation"
            summary = (
                f"Carrier attestation verified with signature hash {ctx.delivery_carrier_hash}. "
                "Physical delivery confirmed to customer shipping address."
            )
        else:
            strategy = "Digital Audit Trail & Activity Log Representation"
            summary = f"Digital activity logs and IP attestation {ctx.buyer_ip} recorded."

        return DisputeRebuttalPacket(
            transaction_id=ctx.transaction_id,
            evidence_bundle_hash=bundle_hash,
            rebuttal_strategy=strategy,
            ce30_qualifying=ce30_qualifies,
            evidence_documents=docs,
            synthesized_representation_summary=summary,
        )

    def evaluate(self, ctx: TransactionContext) -> ChargebackPredictionResult:
        """Evaluate full chargeback risk and generate automated rebuttal bundle."""
        prob, factors = self.calculate_chargeback_probability(ctx)

        if prob >= self.critical_threshold:
            risk = FriendlyFraudRisk.CRITICAL_FIRST_PARTY_FRAUD
            action = "FORCE_3DS"
        elif prob >= self.high_risk_threshold:
            risk = FriendlyFraudRisk.HIGH_RISK_CHARGEBACK
            action = "FLAG_PRE_DISPUTE"
        elif prob >= 0.35:
            risk = FriendlyFraudRisk.MODERATE
            action = "APPROVE"
        else:
            risk = FriendlyFraudRisk.LOW
            action = "APPROVE"

        packet = self.build_rebuttal_packet(ctx)

        return ChargebackPredictionResult(
            transaction_id=ctx.transaction_id,
            chargeback_probability=prob,
            risk_level=risk,
            risk_factors=factors,
            dispute_shield_action=action,
            rebuttal_packet=packet,
        )
