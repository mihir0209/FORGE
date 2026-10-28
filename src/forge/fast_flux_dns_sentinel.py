from dataclasses import dataclass
from typing import Dict, List, Set

@dataclass
class FastFluxAlert:
    is_fast_flux: bool
    unique_ip_count: int
    min_observed_ttl: int
    threat_classification: str

class FastFluxDnsSentinel:
    def __init__(self, max_ip_churn: int = 4, min_ttl_threshold_sec: int = 120):
        self.max_ip_churn = max_ip_churn
        self.min_ttl_threshold_sec = min_ttl_threshold_sec

    def evaluate_dns_resolutions(
        self,
        resolved_ips: List[str],
        observed_ttls_sec: List[int]
    ) -> FastFluxAlert:
        unique_ips = set(resolved_ips)
        min_ttl = min(observed_ttls_sec) if observed_ttls_sec else 300

        # Fast-flux botnets rapidly rotate IP addresses across low TTL windows (<120s)
        is_flux = len(unique_ips) >= self.max_ip_churn and min_ttl <= self.min_ttl_threshold_sec
        threat = "FAST_FLUX_BOTNET_C2" if is_flux else "STANDARD_DNS_LOAD_BALANCING"

        return FastFluxAlert(
            is_fast_flux=is_flux,
            unique_ip_count=len(unique_ips),
            min_observed_ttl=min_ttl,
            threat_classification=threat
        )
