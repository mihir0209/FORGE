from dataclasses import dataclass
from typing import List

@dataclass
class LamportDrainAlert:
    is_unauthorized_drain: bool
    drained_lamports: int
    threat_tier: str

class SolanaLamportDrainSentinel:
    def inspect_instruction_transfers(
        self,
        account_owner: str,
        authorized_signer: str,
        pre_lamports: int,
        post_lamports: int
    ) -> LamportDrainAlert:
        drained = max(0, pre_lamports - post_lamports)
        # If lamports are drained without signature matching account_owner
        is_drain = drained > 0 and account_owner != authorized_signer
        tier = "CRITICAL_UNAUTHORIZED_LAMPORT_DRAINAGE" if is_drain else "AUTHORIZED"

        return LamportDrainAlert(
            is_unauthorized_drain=is_drain,
            drained_lamports=drained,
            threat_tier=tier
        )
