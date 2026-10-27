import pytest
from forge.sybil_louvain_sentinel import SybilLouvainSentinel
from forge.remittance_smurfing_sentinel import RemittanceSmurfingSentinel
from forge.synthetic_id_entropy_sentinel import SyntheticIdSentinel
from forge.rugpull_detector_sentinel import RugpullDetectorSentinel
from forge.sandwich_predation_blocker import SandwichPredationBlocker

def test_sybil_louvain_detects_clique():
    s = SybilLouvainSentinel(min_cluster_size=3, density_threshold=0.6)
    adj = {
        "A": {"B", "C"},
        "B": {"A", "C"},
        "C": {"A", "B"},
        "D": set(),
    }
    findings = s.analyze_graph(adj)
    assert len(findings) == 1
    assert findings[0].is_sybil_cluster is True

def test_remittance_smurfing_alert():
    s = RemittanceSmurfingSentinel(threshold=10000.0)
    res = s.analyze_transactions("0xSmurfer", [9500.0, 9200.0, 9800.0])
    assert res.is_smurfing is True
    assert res.transaction_count == 3

def test_synthetic_id_flagging():
    s = SyntheticIdSentinel()
    res = s.evaluate_identity("John Doe", "ssn_hash_1", credit_age_days=10, inquiry_count_30d=8)
    assert res.is_synthetic is True

def test_rugpull_detector_catches_deployer_drain():
    s = RugpullDetectorSentinel()
    alert = s.check_liquidity_removal("0xPool1", 10000.0, 8000.0, is_deployer=True)
    assert alert.is_rugpull is True
    assert alert.removed_lp_pct == 80.0

def test_sandwich_predation_blocker_recommends_private_mempool():
    s = SandwichPredationBlocker()
    res = s.evaluate_swap_safety(amount_usd=50000.0, pool_tvl_usd=1000000.0, max_user_slippage_pct=5.0)
    assert res.needs_private_mempool is True
    assert res.recommended_slippage_bps == 50
