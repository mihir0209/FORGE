from dataclasses import dataclass
from typing import List, Dict

@dataclass
class EclipseAttackAlert:
    is_eclipse_attack_detected: bool
    peer_diversity_score: float
    isolated_peer_count: int
    mitigation_action: str

class ValidatorEclipseAttackDetector:
    def evaluate_peer_mesh(
        self,
        connected_peer_ips: List[str],
        connected_peer_asns: List[int],
        min_distinct_asns: int = 4
    ) -> EclipseAttackAlert:
        distinct_asns = len(set(connected_peer_asns))
        distinct_ips = len(set(connected_peer_ips))

        # Eclipse attack signature: node is surrounded by peers belonging to 1 or 2 ASNs (lack of diversity)
        is_eclipsed = distinct_asns < min_distinct_asns and distinct_ips >= 8
        div_score = round(distinct_asns / max(1, len(connected_peer_asns)), 2)

        action = "DISCONNECT_MONOPOLIZED_SUBNET_AND_DISCOVER_OUTBOUND_PEERS" if is_eclipsed else "MESH_DIVERSE_HEALTHY"

        return EclipseAttackAlert(
            is_eclipse_attack_detected=is_eclipsed,
            peer_diversity_score=div_score,
            isolated_peer_count=distinct_ips,
            mitigation_action=action
        )
