"""
FORGE Flash Loan Governance Hijack & Liquidity Snapshot Arbitrage Sentinel
Detects atomic and intra-epoch flash borrowing attacks aimed at hijacking
DAO governance proposals, draining treasury funds, or manipulating snapshot checkpoints.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import numpy as np


@dataclass
class ProposalVoteEvent:
    proposal_id: str
    voter_address: str
    vote_weight: float
    support: bool
    block_number: int
    tx_hash: str
    pre_vote_balance: float
    post_vote_balance: float
    borrowed_amount: float = 0.0
    lender_protocol: Optional[str] = None
    repaid_same_block: bool = False


@dataclass
class GovernanceRiskAssessment:
    is_flash_loan_hijack: bool
    hijack_probability: float
    risk_severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    anomaly_flags: List[str]
    mitigation_action: str  # "QUARANTINE_VOTE", "FREEZE_PROPOSAL", "FLAG_FOR_TIMELOCK", "ALLOW"
    voter_address: str
    proposal_id: str
    confidence_score: float


class FlashLoanGovernanceSentinel:
    """
    Real-time analyzer evaluating transaction traces and balance deltas
    to intercept governance attacks executed via uncollateralized flash liquidity.
    """

    KNOWN_FLASH_LENDERS = {
        "AAVE_V2", "AAVE_V3", "BALANCER_VAULT", "UNISWAP_V3_POOL", "MAKER_FLASH_MINT", "DYDX"
    }

    def __init__(
        self,
        critical_borrow_ratio: float = 0.70,
        flash_loan_prob_threshold: float = 0.85,
        min_voting_weight_threshold: float = 10_000.0,
    ):
        self.critical_borrow_ratio = critical_borrow_ratio
        self.flash_loan_prob_threshold = flash_loan_prob_threshold
        self.min_voting_weight_threshold = min_voting_weight_threshold

    def evaluate_vote_event(self, event: ProposalVoteEvent) -> GovernanceRiskAssessment:
        anomaly_flags = []
        prob_accum = 0.0

        if event.vote_weight <= 0:
            return GovernanceRiskAssessment(
                is_flash_loan_hijack=False,
                hijack_probability=0.0,
                risk_severity="LOW",
                anomaly_flags=["ZERO_OR_NEGATIVE_WEIGHT"],
                mitigation_action="ALLOW",
                voter_address=event.voter_address,
                proposal_id=event.proposal_id,
                confidence_score=1.0,
            )

        # 1. Borrowed vs Total Voting Weight Ratio
        borrow_ratio = event.borrowed_amount / event.vote_weight if event.vote_weight > 0 else 0.0
        if borrow_ratio >= self.critical_borrow_ratio:
            anomaly_flags.append(f"EXCESSIVE_BORROW_RATIO_{borrow_ratio:.2f}")
            prob_accum += 0.45
        elif borrow_ratio > 0.30:
            anomaly_flags.append(f"MODERATE_BORROW_RATIO_{borrow_ratio:.2f}")
            prob_accum += 0.20

        # 2. Intra-block Repayment (Flash Loan Signature)
        if event.repaid_same_block:
            anomaly_flags.append("ATOMIC_SAME_BLOCK_REPAYMENT")
            prob_accum += 0.40

        # 3. Known Flash Lender Protocol Trace
        if event.lender_protocol and event.lender_protocol.upper() in self.KNOWN_FLASH_LENDERS:
            anomaly_flags.append(f"KNOWN_FLASH_LENDER_{event.lender_protocol.upper()}")
            prob_accum += 0.25

        # 4. Liquidity Snapshot Divergence (Pre vs Post Vote Balance Discrepancy)
        balance_drop = event.pre_vote_balance - event.post_vote_balance
        if balance_drop > 0 and event.pre_vote_balance > 0:
            drop_ratio = balance_drop / event.pre_vote_balance
            if drop_ratio >= 0.80 and event.repaid_same_block:
                anomaly_flags.append(f"MASSIVE_POST_VOTE_DRAIN_{drop_ratio:.2f}")
                prob_accum += 0.25

        # Cap probability at 0.999
        hijack_prob = min(prob_accum, 0.999)
        is_hijack = hijack_prob >= self.flash_loan_prob_threshold or (
            event.repaid_same_block and borrow_ratio >= self.critical_borrow_ratio
        )

        # Determine severity and mitigation
        if is_hijack and event.vote_weight >= self.min_voting_weight_threshold:
            severity = "CRITICAL"
            action = "QUARANTINE_VOTE"
        elif is_hijack:
            severity = "HIGH"
            action = "FLAG_FOR_TIMELOCK"
        elif hijack_prob > 0.50:
            severity = "MEDIUM"
            action = "FLAG_FOR_TIMELOCK"
        else:
            severity = "LOW"
            action = "ALLOW"

        return GovernanceRiskAssessment(
            is_flash_loan_hijack=is_hijack,
            hijack_probability=round(hijack_prob, 3),
            risk_severity=severity,
            anomaly_flags=anomaly_flags,
            mitigation_action=action,
            voter_address=event.voter_address,
            proposal_id=event.proposal_id,
            confidence_score=round(min(1.0, 0.70 + (0.30 * len(anomaly_flags) / 4.0)), 2),
        )

    def batch_audit_proposal(self, events: List[ProposalVoteEvent]) -> Dict[str, Any]:
        """
        Aggregate audit across all votes in a proposal to detect coordinated flash cartels.
        """
        assessments = [self.evaluate_vote_event(e) for e in events]
        hijacks = [a for a in assessments if a.is_flash_loan_hijack]
        total_compromised_weight = sum(
            e.vote_weight for e, a in zip(events, assessments) if a.is_flash_loan_hijack
        )
        total_weight = sum(e.vote_weight for e in events)

        cartel_share = total_compromised_weight / total_weight if total_weight > 0 else 0.0

        proposal_status = "SAFE"
        if cartel_share >= 0.50:
            proposal_status = "HIJACKED_FREEZE_REQUIRED"
        elif len(hijacks) > 0:
            proposal_status = "CONTAMINATED_QUARANTINE_VOTES"

        return {
            "total_votes_audited": len(events),
            "flagged_flash_votes": len(hijacks),
            "total_compromised_weight": total_compromised_weight,
            "compromised_voting_share": round(cartel_share, 4),
            "proposal_status": proposal_status,
            "assessments": assessments,
        }
