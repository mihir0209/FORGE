from dataclasses import dataclass
from typing import List, Set

@dataclass
class PeerDasSamplingAlert:
    is_custody_subnet_eclipsed: bool
    sampled_subnets_count: int
    data_availability_verified: bool
    action: str

class Eip7594PeerDasEclipseGuard:
    def evaluate_custody_sampling(
        self,
        assigned_custody_subnets: List[int],
        active_peer_subnets: List[int],
        total_subnets: int = 128
    ) -> PeerDasSamplingAlert:
        # In PeerDAS (EIP-7594), a validator must sample across its assigned custody subnets
        # If peers fail to cover assigned custody subnets, node is eclipsed or data is withheld
        covered = set(assigned_custody_subnets).intersection(set(active_peer_subnets))
        coverage_ratio = len(covered) / max(1, len(assigned_custody_subnets))

        is_eclipsed = coverage_ratio < 0.75
        action = "DISCOVER_PEERDAS_CUSTODY_PEERS" if is_eclipsed else "DATA_COLUMN_AVAILABLE"

        return PeerDasSamplingAlert(
            is_custody_subnet_eclipsed=is_eclipsed,
            sampled_subnets_count=len(covered),
            data_availability_verified=not is_eclipsed,
            action=action
        )
