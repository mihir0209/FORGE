import pytest
from forge.sybil_slowroll_neutralizer import SybilSlowRollNeutralizer

def test_sybil_neutralizer_clean_transactions():
    neutralizer = SybilSlowRollNeutralizer()
    clean_txs = [
        {"ip": f"192.168.{i}.{i+5}", "timestamp": 1000.0 + (i * 37.3) + (i % 3 * 12.0), "amount": 10.0 + (i * 2.5)}
        for i in range(15)
    ]
    res = neutralizer.evaluate_cluster(clean_txs)
    assert not res["is_sybil_botnet"]
    assert res["action"] == "ALLOW"
    assert res["risk_score"] < 0.70

def test_sybil_neutralizer_detects_slowroll_botnet():
    neutralizer = SybilSlowRollNeutralizer(entropy_threshold=2.0)
    # Synthetic bot: fixed timing (cadence = 10.0s), identical amounts (.00), clustered subnets
    bot_txs = [
        {"ip": f"10.0.1.{i % 4}", "timestamp": 5000.0 + (i * 10.0), "amount": 1.00}
        for i in range(25)
    ]
    res = neutralizer.evaluate_cluster(bot_txs)
    assert res["is_sybil_botnet"]
    assert res["action"] == "QUARANTINE_CLUSTER"
    assert res["risk_score"] >= 0.70
    assert res["cadence_variance"] < 1.0

def test_sybil_neutralizer_small_cluster():
    neutralizer = SybilSlowRollNeutralizer()
    res = neutralizer.evaluate_cluster([{"ip": "1.1.1.1", "timestamp": 100, "amount": 10}])
    assert not res["is_sybil_botnet"]
    assert "Insufficient" in res["reason"]
