from dataclasses import dataclass
from typing import List
import math

@dataclass
class DohTunnelAlert:
    is_tunneling: bool
    query_entropy: float
    packet_size_ratio: float
    threat_tier: str

class DohTunnelingSentinel:
    def evaluate_doh_traffic_pattern(
        self,
        subdomain_label: str,
        upstream_bytes: int,
        downstream_bytes: int
    ) -> DohTunnelAlert:
        # Calculate entropy of subdomain label
        entropy = 0.0
        if subdomain_label:
            freq = {}
            for c in subdomain_label:
                freq[c] = freq.get(c, 0) + 1
            for count in freq.values():
                p = count / len(subdomain_label)
                entropy -= p * math.log2(p)

        ratio = upstream_bytes / max(1.0, downstream_bytes)
        # DNS exfiltration signature: long high-entropy subdomain label (>30 chars, H >= 3.8) or massive upstream ratio
        is_tunnel = (len(subdomain_label) >= 30 and entropy >= 3.8) or ratio >= 8.0
        tier = "CRITICAL_DOH_DATA_EXFILTRATION" if is_tunnel else "STANDARD_DOH_RESOLVER"

        return DohTunnelAlert(
            is_tunneling=is_tunnel,
            query_entropy=round(entropy, 2),
            packet_size_ratio=round(ratio, 2),
            threat_tier=tier
        )
