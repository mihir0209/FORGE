from dataclasses import dataclass
from typing import Dict, List, Optional

@dataclass
class StorageCollisionAlert:
    has_collision: bool
    colliding_slots: List[int]
    risk_level: str

class EvmStorageCollisionAnalyzer:
    def check_proxy_implementation_layout(
        self,
        proxy_state_variables: Dict[str, int],      # {"_admin": 0, "_implementation": 1}
        implementation_variables: Dict[str, int]   # {"owner": 0, "balance": 1}
    ) -> StorageCollisionAlert:
        # Standard EIP-1967 reserved slots are:
        # implementation: bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
        # admin: bytes32(uint256(keccak256('eip1967.proxy.admin')) - 1)
        # If proxy defines variables directly at low slots [0..10] that overlap with implementation, collision occurs.
        colliding = []
        for var_name, slot in proxy_state_variables.items():
            # If implementation uses the exact same slot index
            for imp_name, imp_slot in implementation_variables.items():
                if slot == imp_slot and slot < 1000:
                    colliding.append(slot)

        has_col = len(colliding) > 0
        return StorageCollisionAlert(
            has_collision=has_col,
            colliding_slots=colliding,
            risk_level="CRITICAL_STORAGE_OVERWRITE_COLLISION" if has_col else "EIP1967_COMPLIANT_CLEAN"
        )
