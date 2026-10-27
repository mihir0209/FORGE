import pytest
from forge.vampire_attack_sentinel import (
    VampireAttackSentinel,
    LpMigrationEvent,
    VampireAttackAlert,
)


@pytest.fixture
def sentinel():
    s = VampireAttackSentinel(
        pool_total_lp={"pool-eco-eth": 100000.0},
        pool_total_usd={"pool-eco-eth": 5000000.0},
        drain_threshold_pct=20.0,
        window_seconds=600.0,
    )
    s.register_vampire_sink("0xPredatoryVampireRouter00000000000001")
    return s


def test_benign_small_lp_withdrawal_passes(sentinel):
    ev = LpMigrationEvent(
        pool_id="pool-eco-eth",
        tx_hash="0xbenign_tx",
        block_number=19000000,
        timestamp_sec=1000.0,
        user_address="0xUserNormal",
        destination_contract="0xStandardWallet",
        lp_tokens_unstaked=500.0,  # 0.5%
        underlying_usd_value=25000.0,
    )
    alert = sentinel.process_event(ev)
    assert alert is None


def test_detects_mass_vampire_drain_threshold(sentinel):
    # Multiple coordinated accounts unstake 30,000 LP tokens (30% of pool) within 5 minutes
    sink = "0xUnknownRivalYieldFarm"
    ev1 = LpMigrationEvent("pool-eco-eth", "0xtx1", 19000001, 1000.0, "0xWhale1", sink, 15000.0, 750000.0)
    ev2 = LpMigrationEvent("pool-eco-eth", "0xtx2", 19000002, 1050.0, "0xWhale2", sink, 15000.0, 750000.0)

    sentinel.process_event(ev1)
    alert = sentinel.process_event(ev2)

    assert alert is not None
    assert alert.is_vampire_attack
    assert alert.drain_percentage == 30.0
    assert alert.total_usd_drained == 1500000.0
    assert alert.mitigation_action == "SURGE_LP_REWARDS"


def test_detects_known_vampire_sink_critical_alert(sentinel):
    # Migration specifically to registered predatory router
    vampire_sink = "0xPredatoryVampireRouter00000000000001"
    ev = LpMigrationEvent(
        pool_id="pool-eco-eth",
        tx_hash="0xvampire_tx",
        block_number=19000003,
        timestamp_sec=2000.0,
        user_address="0xMercenaryCapital",
        destination_contract=vampire_sink,
        lp_tokens_unstaked=18000.0,  # 18%
        underlying_usd_value=900000.0,
    )
    alert = sentinel.process_event(ev)
    assert alert is not None
    assert alert.is_vampire_attack
    assert alert.severity == "CRITICAL"
    assert alert.destination_contract == vampire_sink


def test_batch_processing_correctly_aggregates(sentinel):
    events = [
        LpMigrationEvent("pool-eco-eth", "0x1", 19000000, 3000.0, "0xA", "0xRouterA", 1000.0, 50000.0),
        LpMigrationEvent("pool-eco-eth", "0x2", 19000001, 3050.0, "0xB", "0xRouterA", 25000.0, 1250000.0),
    ]
    alerts = sentinel.analyze_batch(events)
    assert len(alerts) >= 1
    assert alerts[-1].drain_percentage >= 25.0
