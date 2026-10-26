"""Promo / Referral Abuse & Multi-Account Voucher Exploitation Engine.

Normalizes account aliases, detects synthetic account farms claiming first-time
sign-up credits, and mitigates referral velocity attacks.
"""

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple


@dataclass
class PromoRedemption:
    redemption_id: str
    user_id: str
    email: str
    phone_number: str
    card_fingerprint: str
    promo_code: str
    timestamp_epoch: float


@dataclass
class PromoAbuseVerdict:
    redemption_id: str
    user_id: str
    is_abusive: bool
    abuse_type: str  # NONE, EMAIL_ALIASING, REUSED_PAYMENT_METHOD, PHONE_CLUSTER, VELOCITY_BURST
    canonical_email: str
    associated_user_count: int
    risk_score: float  # 0.0 to 1.0


def canonicalize_email(email: str) -> str:
    """Normalizes email addresses to strip dots and plus-addressing for Gmail/common domains."""
    email = email.lower().strip()
    if "@" not in email:
        return email

    local_part, domain = email.split("@", 1)

    # For gmail and googlemail, strip dots and drop everything after plus
    if domain in ("gmail.com", "googlemail.com"):
        local_part = local_part.replace(".", "")
        local_part = local_part.split("+")[0]
        domain = "gmail.com"
    else:
        # Standard plus-addressing stripping
        local_part = local_part.split("+")[0]

    return f"{local_part}@{domain}"


class PromoAbuseEngine:
    def __init__(self, max_allowed_per_canonical_email: int = 1, max_allowed_per_card: int = 1):
        self.max_allowed_per_canonical_email = max_allowed_per_canonical_email
        self.max_allowed_per_card = max_allowed_per_card

        # Canonical email -> Set of user_ids
        self.email_to_users: Dict[str, Set[str]] = defaultdict(set)
        # Card fingerprint -> Set of user_ids
        self.card_to_users: Dict[str, Set[str]] = defaultdict(set)
        # Phone prefix (first 7 digits) -> List of redemptions
        self.phone_cluster: Dict[str, List[PromoRedemption]] = defaultdict(list)

    def evaluate_redemption(self, redemption: PromoRedemption) -> PromoAbuseVerdict:
        canonical_email = canonicalize_email(redemption.email)
        abuse_reasons = []
        score = 0.0

        # Check Email Aliasing Abuse
        existing_email_users = self.email_to_users[canonical_email]
        if existing_email_users and redemption.user_id not in existing_email_users:
            score += 0.65
            abuse_reasons.append("EMAIL_ALIASING")

        # Check Payment Method Multi-Account Reuse
        existing_card_users = self.card_to_users[redemption.card_fingerprint]
        if existing_card_users and redemption.user_id not in existing_card_users:
            score += 0.50
            abuse_reasons.append("REUSED_PAYMENT_METHOD")

        # Check Phone VoIP range cluster
        clean_phone = re.sub(r"\D", "", redemption.phone_number)
        phone_prefix = clean_phone[:7] if len(clean_phone) >= 7 else clean_phone
        cluster_history = self.phone_cluster[phone_prefix]
        recent_cluster_count = sum(1 for r in cluster_history if (redemption.timestamp_epoch - r.timestamp_epoch) <= 300.0)
        if recent_cluster_count >= 3:
            score += 0.40
            abuse_reasons.append("PHONE_CLUSTER")

        is_abusive = score >= 0.50
        primary_abuse = abuse_reasons[0] if abuse_reasons else "NONE"

        # Record redemption
        self.email_to_users[canonical_email].add(redemption.user_id)
        self.card_to_users[redemption.card_fingerprint].add(redemption.user_id)
        self.phone_cluster[phone_prefix].append(redemption)

        total_associated_users = len(self.email_to_users[canonical_email] | self.card_to_users[redemption.card_fingerprint])

        return PromoAbuseVerdict(
            redemption_id=redemption.redemption_id,
            user_id=redemption.user_id,
            is_abusive=is_abusive,
            abuse_type=primary_abuse,
            canonical_email=canonical_email,
            associated_user_count=total_associated_users,
            risk_score=min(1.0, round(score, 2)),
        )
