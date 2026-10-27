import pytest
from forge.wash_trade_annihilator import (
    TransactionFlow,
    WashCycleReport,
    WashTradeAnnihilator,
)


class TestWashTradeAnnihilator:
    # 1. Unit Tests
    def test_empty_transaction_stream(self):
        annihilator = WashTradeAnnihilator()
        reports = annihilator.analyze_transactions([])
        assert reports == []

    def test_linear_flow_no_cycle(self):
        annihilator = WashTradeAnnihilator()
        flows = [
            TransactionFlow("tx1", "alice", "bob", 100.0, 1000.0),
            TransactionFlow("tx2", "bob", "charlie", 100.0, 1010.0),
            TransactionFlow("tx3", "charlie", "dave", 100.0, 1020.0),
        ]
        reports = annihilator.analyze_transactions(flows)
        assert len(reports) == 0

    # 2. Integration Tests
    def test_three_node_circular_wash_trade(self):
        annihilator = WashTradeAnnihilator(time_window_seconds=300.0, min_conservation_ratio=0.95)
        flows = [
            TransactionFlow("tx1", "alice", "bob", 1000.0, 1000.0),
            TransactionFlow("tx2", "bob", "charlie", 995.0, 1050.0),
            TransactionFlow("tx3", "charlie", "alice", 990.0, 1100.0),
        ]
        reports = annihilator.analyze_transactions(flows)
        assert len(reports) == 1
        rep = reports[0]
        assert rep.is_wash_trade is True
        assert set(rep.cycle_nodes) == {"alice", "bob", "charlie"}
        assert rep.volume_conservation_ratio >= 0.95
        assert rep.duration_seconds == 100.0
        assert len(rep.flow_ids) == 3

    # 3. Regression & Boundary Tests
    def test_decayed_cycle_fails_conservation_threshold(self):
        annihilator = WashTradeAnnihilator(min_conservation_ratio=0.90)
        flows = [
            TransactionFlow("tx1", "alice", "bob", 1000.0, 1000.0),
            TransactionFlow("tx2", "bob", "charlie", 800.0, 1050.0),  # 20% loss
            TransactionFlow("tx3", "charlie", "alice", 750.0, 1100.0),
        ]
        reports = annihilator.analyze_transactions(flows)
        assert len(reports) == 1
        assert reports[0].is_wash_trade is False
        assert reports[0].volume_conservation_ratio == 0.75

    def test_cycle_exceeding_time_window_quarantined(self):
        annihilator = WashTradeAnnihilator(time_window_seconds=600.0)
        flows = [
            TransactionFlow("tx1", "alice", "bob", 1000.0, 1000.0),
            TransactionFlow("tx2", "bob", "charlie", 1000.0, 1500.0),
            TransactionFlow("tx3", "charlie", "alice", 1000.0, 2000.0),  # 1000s duration > 600s
        ]
        reports = annihilator.analyze_transactions(flows)
        assert len(reports) == 0
