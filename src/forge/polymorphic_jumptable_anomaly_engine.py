from dataclasses import dataclass
from typing import List

@dataclass
class JumpTableAnomalyResult:
    is_shellcode_detected: bool
    indirect_jump_density: float
    threat_tier: str

class PolymorphicJumpTableAnomalyEngine:
    def inspect_disassembly_instructions(
        self,
        opcodes: List[str]
    ) -> JumpTableAnomalyResult:
        if not opcodes:
            return JumpTableAnomalyResult(False, 0.0, "CLEAN")

        # Count indirect jumps: "jmp rax", "jmp [rdi+rcx*8]", "call rdx"
        indirect_jumps = sum(1 for op in opcodes if any(pattern in op.lower() for pattern in ("jmp r", "call r", "jmp [", "call [", "ret")))
        density = indirect_jumps / len(opcodes)

        # Polymorphic shellcode decryption stub exhibits high indirect jump/call density (> 25%)
        is_shellcode = density >= 0.25 and len(opcodes) >= 8
        tier = "CRITICAL_POLYMORPHIC_SHELLCODE_JUMPTABLE" if is_shellcode else "STANDARD_COMPILER_OUTPUT"

        return JumpTableAnomalyResult(
            is_shellcode_detected=is_shellcode,
            indirect_jump_density=round(density, 3),
            threat_tier=tier
        )
