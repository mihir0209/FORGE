from dataclasses import dataclass
from typing import Optional

@dataclass
class PdaBumpValidation:
    is_canonical: bool
    used_bump: int
    canonical_bump: int
    security_action: str

class SolanaPdaCanonicalBumpEnforcer:
    def verify_pda_bump(
        self,
        provided_bump: int,
        canonical_seed_bump: int = 255
    ) -> PdaBumpValidation:
        # In Solana, find_program_address searches descending from 255 downwards.
        # An attacker passing non-canonical bump creates duplicate state collision accounts.
        is_canonical = provided_bump == canonical_seed_bump
        action = "ALLOW_EXECUTION" if is_canonical else "REVERT_NON_CANONICAL_PDA_COLLISION"

        return PdaBumpValidation(
            is_canonical=is_canonical,
            used_bump=provided_bump,
            canonical_bump=canonical_seed_bump,
            security_action=action
        )
