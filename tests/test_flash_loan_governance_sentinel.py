"""
Unit, integration, and regression test suite for Flash Loan Governance Hijack Sentinel.
"""

import pytest
from forge.flash_loan_governance_sentinel import (
    FlashLoanGovernanceSentinel,
    ProposalVoteEvent,
    GovernanceRiskAssessment,
)


class TestFlashLoanGovernanceSentinel:
    @pytest.fixture
    def sentinel(self):
        return FlashLoanGovernanceSentinel(
            critical_borrow_ratio=0.70,
            flash_loan_prob_threshold=0.85,
            min_voting_weight_threshold=10_000.0,
        )

    # 1. Unit Tests
    def test_benign_organic_vote(self, sentinel):
        """A normal long-term token holder casting a legitimate vote."""
        event = ProposalVoteEvent(
            proposal_id="PROP-DAO-2026-88",
            voter_address="0xLongTermStaker1111",
            vote_weight=50_000.0,
            support=True,
            block_number=19800100,
            tx_hash="0xabc123legit",
            pre_vote_balance=50_000.0,
            post_vote_balance=50_000.0,
            borrowed_amount=0.0,
            lender_protocol=None,
            repaid_same_block=False,
        )
        assessment = sentinel.evaluate_vote_event(event)

        assert not assessment.is_flash_loan_hijack
        assert assessment.risk_severity == "LOW"
        assert assessment.mitigation_action == "ALLOW"
        assert assessment.hijack_probability == 0.0
        assert len(assessment.anomaly_flags) == 0

    def test_zero_or_negative_vote_weight(self, sentinel):
        """Zero weight vote should be immediately handled safely."""
        event = ProposalVoteEvent(
            proposal_id="PROP-DAO-2026-88",
            voter_address="0xEmptyVoter",
            vote_weight=0.0,
            support=False,
            block_number=19800100,
            tx_hash="0xzeroweight",
            pre_vote_balance=0.0,
            post_vote_balance=0.0,
        )
        assessment = sentinel.evaluate_vote_event(event)
        assert not assessment.is_flash_loan_hijack
        assert "ZERO_OR_NEGATIVE_WEIGHT" in assessment.anomaly_flags

    # 2. Integration Tests: Atomic Flash Loan Detection
    def test_classic_aave_flash_loan_governance_hijack(self, sentinel):
        """
        Adversary borrows 2,000,000 DAO tokens from Aave V3, votes YES to drain treasury,
        and repays in the exact same block.
        """
        event = ProposalVoteEvent(
            proposal_id="PROP-DRAIN-TREASURY-01",
            voter_address="0xAttackerFlashHijacker9999",
            vote_weight=2_000_000.0,
            support=True,
            block_number=19800250,
            tx_hash="0xexploitblocktxhash99",
            pre_vote_balance=2_000_000.0,
            post_vote_balance=0.0,
            borrowed_amount=2_000_000.0,  # 100% borrowed!
            lender_protocol="AAVE_V3",
            repaid_same_block=True,
        )
        assessment = sentinel.evaluate_vote_event(event)

        assert assessment.is_flash_loan_hijack
        assert assessment.risk_severity == "CRITICAL"
        assert assessment.mitigation_action == "QUARANTINE_VOTE"
        assert assessment.hijack_probability >= 0.85
        assert "ATOMIC_SAME_BLOCK_REPAYMENT" in assessment.anomaly_flags
        assert "KNOWN_FLASH_LENDER_AAVE_V3" in assessment.anomaly_flags
        assert any("EXCESSIVE_BORROW_RATIO" in f for f in assessment.anomaly_flags)

    # 3. Regression Tests: Partial Borrows vs Full Flash Attacks
    def test_partial_borrow_below_threshold(self, sentinel):
        """Participant with 80,000 native tokens borrows 20,000 (20% ratio) without same-block repayment."""
        event = ProposalVoteEvent(
            proposal_id="PROP-DAO-2026-90",
            voter_address="0xInstitutionalHolder2222",
            vote_weight=100_000.0,
            support=True,
            block_number=19800300,
            tx_hash="0xpartialborrow123",
            pre_vote_balance=100_000.0,
            post_vote_balance=100_000.0,
            borrowed_amount=20_000.0,  # 20%
            lender_protocol="DYDX",
            repaid_same_block=False,
        )
        assessment = sentinel.evaluate_vote_event(event)

        assert not assessment.is_flash_loan_hijack
        assert assessment.risk_severity in ("LOW", "MEDIUM")
        assert assessment.mitigation_action != "QUARANTINE_VOTE"

    # 4. Batch Proposal Audit: Cartel Hijack Detection
    def test_batch_proposal_cartel_freeze(self, sentinel):
        """Proposal where a flash cartel commands > 50% voting weight must trigger freeze."""
        legit_vote = ProposalVoteEvent(
            proposal_id="PROP-DAO-VITAL-SECURITY",
            voter_address="0xHonestDelegator",
            vote_weight=100_000.0,
            support=False,
            block_number=19800400,
            tx_hash="0xlegit1",
            pre_vote_balance=100_000.0,
            post_vote_balance=100_000.0,
        )

        flash_vote = ProposalVoteEvent(
            proposal_id="PROP-DAO-VITAL-SECURITY",
            voter_address="0xSybilFlashCartel",
            vote_weight=300_000.0,
            support=True,
            block_number=19800400,
            tx_hash="0xflashcartel1",
            pre_vote_balance=300_000.0,
            post_vote_balance=0.0,
            borrowed_amount=300_000.0,
            lender_protocol="BALANCER_VAULT",
            repaid_same_block=True,
        )

        batch_result = sentinel.batch_audit_proposal([legit_vote, flash_vote])

        assert batch_result["total_votes_audited"] == 2
        assert batch_result["flagged_flash_votes"] == 1
        assert batch_result["total_compromised_weight"] == 300_000.0
        assert batch_result["compromised_voting_share"] == 0.75  # 300k / 400k = 75%
        assert batch_result["proposal_status"] == "HIJACKED_FREEZE_REQUIRED"
