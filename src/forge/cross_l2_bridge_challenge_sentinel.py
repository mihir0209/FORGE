from dataclasses import dataclass

@dataclass
class L2BridgeDisputeStatus:
    is_dispute_challenge_triggered: bool
    claimed_withdrawal_root: str
    challenge_bond_slashed_eth: float
    dispute_verdict: str

class CrossL2BridgeChallengeSentinel:
    def verify_optimistic_withdrawal_assertion(
        self,
        assertion_id: str,
        claimed_withdrawal_root: str,
        verified_onchain_withdrawal_root: str,
        dispute_window_blocks_remaining: int,
        staked_bond_eth: float = 10.0
    ) -> L2BridgeDisputeStatus:
        is_fraud = claimed_withdrawal_root.lower() != verified_onchain_withdrawal_root.lower()
        # Challenge can only be mounted while within dispute challenge window (> 0 blocks)
        can_challenge = is_fraud and dispute_window_blocks_remaining > 0

        slashed_amount = staked_bond_eth if can_challenge else 0.0
        verdict = "SLASH_DISHONEST_PROPOSER_AND_HALT_BRIDGE" if can_challenge else ("CLEAN_DISPUTE_PASSED" if not is_fraud else "DISPUTE_WINDOW_EXPIRED")

        return L2BridgeDisputeStatus(
            is_dispute_challenge_triggered=can_challenge,
            claimed_withdrawal_root=claimed_withdrawal_root,
            challenge_bond_slashed_eth=slashed_amount,
            dispute_verdict=verdict
        )
