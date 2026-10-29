from dataclasses import dataclass

@dataclass
class JitLiquidityAlert:
    is_jit_frontrunning_detected: bool
    extracted_fee_usd: float
    mempool_position: str
    mitigation: str

class ConcentratedLiquidityJitWatchdog:
    def detect_jit_sandwich(
        self,
        mint_tx_index: int,
        target_swap_tx_index: int,
        burn_tx_index: int,
        mint_volume_usd: float,
        target_swap_volume_usd: float
    ) -> JitLiquidityAlert:
        # JIT Sandwich signature: Mint at index N, Target swap at N+1, Burn at N+2 within the exact same block
        is_consecutive = (target_swap_tx_index == mint_tx_index + 1) and (burn_tx_index == target_swap_tx_index + 1)
        # JIT liquidity mint volume is massive relative to swap volume (> 3x)
        is_massive = mint_volume_usd >= (target_swap_volume_usd * 2.0)

        is_jit = is_consecutive and is_massive
        # Estimated captured fee: 30 bps of swap volume
        captured_fee = round((target_swap_volume_usd * 0.0030), 2) if is_jit else 0.0

        return JitLiquidityAlert(
            is_jit_frontrunning_detected=is_jit,
            extracted_fee_usd=captured_fee,
            mempool_position=f"MINT:{mint_tx_index}_SWAP:{target_swap_tx_index}_BURN:{burn_tx_index}",
            mitigation="ENFORCE_MINIMUM_LIQUIDITY_LOCK_BLOCKS" if is_jit else "BENIGN_LP_POSITION"
        )
