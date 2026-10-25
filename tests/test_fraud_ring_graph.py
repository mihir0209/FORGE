"""Tests for Graph-Based Fraud Ring & Entity Resolution Engine."""

import pytest
from forge.fraud_ring_graph import (
    AccountNode,
    TransactionFlow,
    FraudRingGraphEngine,
    FraudRingCluster,
    EntityResolutionReport,
)


def test_entity_resolution_clusters_shared_phone_and_ip():
    engine = FraudRingGraphEngine(risk_threshold=0.3)

    # 3 accounts sharing the same phone and IP subnet
    acc1 = AccountNode(account_id="ACC-01", phone="+1-555-0199", ip_address="198.51.100.12")
    acc2 = AccountNode(account_id="ACC-02", phone="555-0199", ip_address="198.51.100.45")
    acc3 = AccountNode(account_id="ACC-03", phone="(555) 0199", ip_address="198.51.100.99")
    acc4 = AccountNode(account_id="ACC-ISOLATED", phone="+1-555-9999", ip_address="203.0.113.1")

    engine.register_account(acc1)
    engine.register_account(acc2)
    engine.register_account(acc3)
    engine.register_account(acc4)

    clusters = engine.find_connected_clusters()
    assert len(clusters) == 1
    assert clusters[0] == {"ACC-01", "ACC-02", "ACC-03"}


def test_cyclic_layering_detection_in_mule_syndicate():
    engine = FraudRingGraphEngine(cycle_max_hops=4)

    nodes = [
        AccountNode(account_id=f"MULE-{i}", device_hash="shared_device_botnet")
        for i in range(1, 5)
    ]
    for n in nodes:
        engine.register_account(n)

    # Create a 4-node circular transaction ring: 1 -> 2 -> 3 -> 4 -> 1
    engine.add_transaction(TransactionFlow("MULE-1", "MULE-2", 5000.0, 100.0))
    engine.add_transaction(TransactionFlow("MULE-2", "MULE-3", 4900.0, 101.0))
    engine.add_transaction(TransactionFlow("MULE-3", "MULE-4", 4800.0, 102.0))
    engine.add_transaction(TransactionFlow("MULE-4", "MULE-1", 4700.0, 103.0))

    report = engine.analyze()
    assert report.total_accounts == 4
    assert report.resolved_clusters_count == 1
    assert report.global_cycle_count >= 1

    cluster = report.high_risk_clusters[0] if report.high_risk_clusters else engine.compute_cluster_metrics(set(engine.nodes.keys()), 1)
    assert len(cluster.detected_cycles) >= 1
    assert cluster.total_flow_amount == 19400.0
    assert cluster.risk_score > 0.5


def test_disconnected_components_and_empty_graph():
    engine = FraudRingGraphEngine()
    empty_report = engine.analyze()
    assert empty_report.total_accounts == 0
    assert empty_report.resolved_clusters_count == 0
    assert empty_report.global_cycle_count == 0

    # Two separate clusters
    engine.register_account(AccountNode("A1", ssn_hash="ssn_A"))
    engine.register_account(AccountNode("A2", ssn_hash="ssn_A"))
    engine.register_account(AccountNode("B1", postal_code="90210", email="b1@syndicate.ru"))
    engine.register_account(AccountNode("B2", postal_code="90210", email="b2@syndicate.ru"))

    report = engine.analyze()
    assert report.total_accounts == 4
    assert report.resolved_clusters_count == 2
