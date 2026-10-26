"""Synthetic Identity & Deepfake Profile Cluster Detector.

Detects synthetic identity fraud (blended real/fabricated PII, thin-file
piggybacking, and shared entity clusters across disparate applicants).
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple


@dataclass
class SyntheticIdentityResult:
    application_id: str
    risk_score: float  # 0.0 to 1.0
    is_synthetic: bool
    cluster_size: int
    reasons: List[str]


class SyntheticIdentityDetector:
    def __init__(self, risk_threshold: float = 0.65):
        self.risk_threshold = risk_threshold
        # PII to application mapping for graph cluster analysis
        self._phone_to_apps: Dict[str, Set[str]] = {}
        self._address_to_apps: Dict[str, Set[str]] = {}
        self._ssn_to_names: Dict[str, Set[str]] = {}

    def assess_applicant(
        self,
        application_id: str,
        name: str,
        ssn_fragment: str,
        phone: str,
        address: str,
        credit_line_age_months: int,
        authorized_user_count: int,
    ) -> SyntheticIdentityResult:
        reasons: List[str] = []
        score = 0.0

        # Normalize strings
        norm_phone = "".join(filter(str.isdigit, phone))
        norm_address = address.strip().lower()
        norm_name = name.strip().lower()

        # 1. Update identity graph
        if norm_phone not in self._phone_to_apps:
            self._phone_to_apps[norm_phone] = set()
        self._phone_to_apps[norm_phone].add(application_id)

        if norm_address not in self._address_to_apps:
            self._address_to_apps[norm_address] = set()
        self._address_to_apps[norm_address].add(application_id)

        if ssn_fragment not in self._ssn_to_names:
            self._ssn_to_names[ssn_fragment] = set()
        self._ssn_to_names[ssn_fragment].add(norm_name)

        # 2. SSN collision with multiple names (high confidence synthetic marker)
        if len(self._ssn_to_names[ssn_fragment]) > 1:
            score += 0.45
            reasons.append(
                f"SSN fragment {ssn_fragment} associated with {len(self._ssn_to_names[ssn_fragment])} distinct applicant names"
            )

        # 3. PII Cluster density (phone or address shared across multiple applications)
        phone_cluster = len(self._phone_to_apps[norm_phone])
        addr_cluster = len(self._address_to_apps[norm_address])
        max_cluster = max(phone_cluster, addr_cluster)

        if max_cluster >= 3:
            cluster_penalty = min(0.35, (max_cluster - 1) * 0.1)
            score += cluster_penalty
            reasons.append(
                f"Applicant PII linked to dense entity cluster of {max_cluster} applications"
            )

        # 4. Authorized User Piggybacking & Thin Credit File Anomaly
        # Synthetic identities often artificially age their credit by purchasing tradelines
        # where primary age is < 6 months but they have 2+ authorized user accounts
        if credit_line_age_months <= 6 and authorized_user_count >= 2:
            score += 0.35
            reasons.append(
                f"High-risk tradeline piggybacking: age {credit_line_age_months}mo with {authorized_user_count} authorized user lines"
            )

        # 5. Thin file zero history baseline check
        if credit_line_age_months == 0 and authorized_user_count == 0:
            score += 0.10
            reasons.append("Zero credit history baseline file")

        risk_score = min(1.0, round(score, 3))
        is_synthetic = risk_score >= self.risk_threshold

        return SyntheticIdentityResult(
            application_id=application_id,
            risk_score=risk_score,
            is_synthetic=is_synthetic,
            cluster_size=max_cluster,
            reasons=reasons,
        )
