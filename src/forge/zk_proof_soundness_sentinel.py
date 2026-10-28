from dataclasses import dataclass
from typing import List, Dict, Set

@dataclass
class ZkSoundnessFinding:
    is_sound: bool
    underconstrained_signals: List[str]
    has_remainder_bypass: bool
    risk_level: str

class ZkProofSoundnessSentinel:
    def audit_circuit_constraints(
        self,
        signal_names: List[str],
        constrained_signals: Set[str],
        division_remainder_check_enforced: bool
    ) -> ZkSoundnessFinding:
        underconstrained = [s for s in signal_names if s not in constrained_signals]
        has_bypass = not division_remainder_check_enforced

        is_sound = len(underconstrained) == 0 and division_remainder_check_enforced
        risk = "CRITICAL_SOUNDNESS_HOLE" if (underconstrained or has_bypass) else "VERIFIED_SOUND"

        return ZkSoundnessFinding(
            is_sound=is_sound,
            underconstrained_signals=underconstrained,
            has_remainder_bypass=has_bypass,
            risk_level=risk
        )
