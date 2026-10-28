from dataclasses import dataclass
from typing import Dict, List, Set

@dataclass
class StorageManipulationAlert:
    is_storage_collision: bool
    implementation_slot_mutated: bool
    affected_slots: List[str]
    action: str

class StorageSlotManipulationSentinel:
    IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" # EIP-1967

    def inspect_state_diff(
        self,
        slot_writes: Dict[str, str], # slot_hex -> new_val_hex
        expected_layout_slots: Set[str]
    ) -> StorageManipulationAlert:
        mutated_impl = False
        suspicious_slots = []

        for slot in slot_writes.keys():
            s_lower = slot.lower()
            if s_lower == self.IMPLEMENTATION_SLOT.lower():
                mutated_impl = True
                suspicious_slots.append(slot)
            elif s_lower not in {s.lower() for s in expected_layout_slots}:
                suspicious_slots.append(slot)

        is_attack = mutated_impl or len(suspicious_slots) > 0
        action = "TRIGGER_CIRCUIT_BREAKER_UPGRADE_ATTACK" if mutated_impl else ("ISOLATE_SLOT_COLLISION" if is_attack else "ALLOW")

        return StorageManipulationAlert(
            is_storage_collision=is_attack,
            implementation_slot_mutated=mutated_impl,
            affected_slots=suspicious_slots,
            action=action
        )
