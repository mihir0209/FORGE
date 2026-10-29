from dataclasses import dataclass
from typing import Dict, List

@dataclass
class MultisigNonceAlert:
    is_nonce_desynced: bool
    expected_onchain_nonce: int
    offchain_signature_nonce: int
    action: str

class MultisigNonceDesyncWatchdog:
    def verify_proposal_nonce(
        self,
        onchain_current_nonce: int,
        proposal_payload_nonce: int
    ) -> MultisigNonceAlert:
        is_desync = proposal_payload_nonce != onchain_current_nonce
        action = "REJECT_INVALID_PROPOSAL_NONCE_REPLAY" if is_desync else "PROCEED_TO_THRESHOLD_CHECK"

        return MultisigNonceAlert(
            is_nonce_desynced=is_desync,
            expected_onchain_nonce=onchain_current_nonce,
            offchain_signature_nonce=proposal_payload_nonce,
            action=action
        )
