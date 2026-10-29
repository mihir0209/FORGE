from dataclasses import dataclass

@dataclass
class MemoryGasGriefingAlert:
    is_memory_griefing: bool
    memory_expansion_gas_cost: int
    requested_memory_bytes: int
    verdict: str

class EvmMemoryExpansionGasGriefingAuditor:
    def calculate_memory_gas(self, memory_bytes: int) -> MemoryGasGriefingAlert:
        # EVM quadratic memory cost:
        # words = ceil(memory_bytes / 32)
        # cost = 3 * words + floor(words^2 / 512)
        words = (memory_bytes + 31) // 32
        cost = (3 * words) + ((words * words) // 512)

        # Standard EVM block gas limit is 30,000,000.
        # If single memory expansion consumes > 15,000,000 gas (> ~3 MB memory allocated) -> griefing
        is_grief = cost >= 15_000_000

        return MemoryGasGriefingAlert(
            is_memory_griefing=is_grief,
            memory_expansion_gas_cost=cost,
            requested_memory_bytes=memory_bytes,
            verdict="REVERT_MEMORY_EXPANSION_GAS_GRIEFING" if is_grief else "WITHIN_BLOCK_GAS_LIMIT"
        )
