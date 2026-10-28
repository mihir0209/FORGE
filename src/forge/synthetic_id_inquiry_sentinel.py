from dataclasses import dataclass
from typing import Dict, List, Set

@dataclass
class SyntheticInquiryCluster:
    is_synthetic_ring: bool
    shared_attribute_count: int
    cluster_size: int
    risk_level: str

class SyntheticIdInquirySentinel:
    def check_application_attribute_sharing(
        self,
        applicant_id: str,
        phone_hash: str,
        address_hash: str,
        recent_applications: List[Dict[str, str]] # [{'id': str, 'phone': str, 'addr': str}]
    ) -> SyntheticInquiryCluster:
        matched_apps = set()
        for app in recent_applications:
            if app["id"] == applicant_id:
                continue
            if app["phone"] == phone_hash or app["addr"] == address_hash:
                matched_apps.add(app["id"])

        cluster_size = len(matched_apps) + 1
        is_ring = cluster_size >= 4
        risk = "CRITICAL_SYNTHETIC_FARM" if cluster_size >= 5 else ("HIGH_COLLUSION" if is_ring else "NORMAL")

        return SyntheticInquiryCluster(
            is_synthetic_ring=is_ring,
            shared_attribute_count=len(matched_apps),
            cluster_size=cluster_size,
            risk_level=risk
        )
