from dataclasses import dataclass
from typing import List

@dataclass
class BgpBlackholeAlert:
    is_unauthorized_blackholing: bool
    detected_community: str
    severity: str

class BgpBlackholeCommunitySentinel:
    RFC7999_BLACKHOLE_COMMUNITY = "65535:666"

    def audit_communities(
        self,
        prefix: str,
        origin_as: int,
        communities: List[str],
        is_prefix_under_active_ddos: bool = False
    ) -> BgpBlackholeAlert:
        has_blackhole = self.RFC7999_BLACKHOLE_COMMUNITY in communities
        # Unauthorized blackholing: an external AS tags prefix with 65535:666 when no DDoS is signaled
        is_unauthorized = has_blackhole and not is_prefix_under_active_ddos

        tier = "CRITICAL_UNAUTHORIZED_ROUTE_DROPPING_HIJACK" if is_unauthorized else ("AUTHORIZED_DDOS_BLACKHOLE" if has_blackhole else "NORMAL")

        return BgpBlackholeAlert(
            is_unauthorized_blackholing=is_unauthorized,
            detected_community=self.RFC7999_BLACKHOLE_COMMUNITY if has_blackhole else "NONE",
            severity=tier
        )
