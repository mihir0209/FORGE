from dataclasses import dataclass

@dataclass
class ReflectionDdosAlert:
    is_reflection_attack: bool
    amplification_factor: float
    action: str

class DdosSynAckReflectionWatchdog:
    def inspect_amplification_traffic(
        self,
        request_bytes: int,
        response_bytes: int,
        syn_ratio: float
    ) -> ReflectionDdosAlert:
        af = response_bytes / max(1.0, request_bytes)
        # Reflection amplification attacks exhibit AF >= 15x combined with spoofed SYN/ACK floods
        is_attack = af >= 15.0 and syn_ratio >= 0.70
        action = "DROP_AND_BLACKHOLE_REFLECTOR_IP" if is_attack else "PASS_TRAFFIC"

        return ReflectionDdosAlert(
            is_reflection_attack=is_attack,
            amplification_factor=round(af, 2),
            action=action
        )
