from dataclasses import dataclass

@dataclass
class AmmRoundingFinding:
    is_drain_vulnerable: bool
    initial_k: int
    final_k: int
    k_invariant_decay_bps: float

class AmmKInvariantRoundingAuditor:
    def audit_swap_rounding(
        self,
        reserve_x: int,
        reserve_y: int,
        amount_in_x: int,
        amount_out_y: int,
        fee_bps: int = 30
    ) -> AmmRoundingFinding:
        initial_k = reserve_x * reserve_y

        # After swap: new_x = reserve_x + amount_in_x, new_y = reserve_y - amount_out_y
        new_x = reserve_x + amount_in_x
        new_y = reserve_y - amount_out_y
        final_k = new_x * new_y

        # Constant product invariant: k_final must be >= k_initial (taking into account fees)
        # If final_k < initial_k due to truncation/rounding in favor of the trader -> vulnerability
        is_decay = final_k < initial_k
        decay_bps = ((initial_k - final_k) / initial_k * 10000.0) if is_decay else 0.0

        return AmmRoundingFinding(
            is_drain_vulnerable=is_decay,
            initial_k=initial_k,
            final_k=final_k,
            k_invariant_decay_bps=round(decay_bps, 4)
        )
