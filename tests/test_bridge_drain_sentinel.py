import pytest
from forge.bridge_drain_sentinel import (
    BridgeDrainSentinel,
    BridgeTransferEvent,
    BridgeDrainAlert,
)


@pytest.fixture
def sentinel():
    # Bridge with 100,000 USDC reserve
    return BridgeDrainSentinel(
        pool_reserves={"bridge-eth-polygon": 100000.0},
        window_seconds=300.0,
        max_depletion_threshold=0.20,
        velocity_spike_threshold=5000.0,
    )


def test_normal_orderly_bridge_transfers_no_alert(sentinel):
    transfers = [
        BridgeTransferEvent(
            tx_hash="0x1",
            bridge_id="bridge-eth-polygon",
            source_chain="Ethereum",
            target_chain="Polygon",
            token_symbol="USDC",
            amount=500.0,
            sender_address="0xUserA",
            recipient_address="0xUserA",
            timestamp_sec=1000.0,
            proof_nonce=101,
        ),
        BridgeTransferEvent(
            tx_hash="0x2",
            bridge_id="bridge-eth-polygon",
            source_chain="Ethereum",
            target_chain="Polygon",
            token_symbol="USDC",
            amount=1200.0,
            sender_address="0xUserB",
            recipient_address="0xUserB",
            timestamp_sec=1050.0,
            proof_nonce=102,
        ),
    ]

    alerts = sentinel.analyze_batch(transfers)
    assert len(alerts) == 0


def test_rapid_liquidity_drain_burst_alert(sentinel):
    # Attacker triggers 3 back-to-back large withdrawals totaling 30,000 USDC (30% of 100k reserve)
    attacker = "0xBlackhatBridgeSiphoner00000000000001"
    transfers = [
        BridgeTransferEvent("0xa1", "bridge-eth-polygon", "Eth", "Poly", "USDC", 10000.0, attacker, attacker, 1000.0, 201),
        BridgeTransferEvent("0xa2", "bridge-eth-polygon", "Eth", "Poly", "USDC", 10000.0, attacker, attacker, 1020.0, 202),
        BridgeTransferEvent("0xa3", "bridge-eth-polygon", "Eth", "Poly", "USDC", 10000.0, attacker, attacker, 1040.0, 203),
    ]

    alerts = sentinel.analyze_batch(transfers)
    assert len(alerts) > 0
    latest = alerts[-1]
    assert latest.is_drain_attack
    assert latest.attack_vector == "RAPID_DRAIN_BURST"
    assert latest.suspect_address == attacker
    assert latest.total_drained_amount == 30000.0
    assert latest.depletion_ratio == 0.30


def test_proof_replay_double_spend_detection(sentinel):
    # Exploiter attempts to replay the same valid proof nonce 305 with different tx_hash
    exploiter = "0xProofReplayAttacker00000000000000002"
    ev1 = BridgeTransferEvent("0xorig", "bridge-eth-polygon", "Eth", "Poly", "USDC", 5000.0, exploiter, exploiter, 1000.0, 305)
    ev2_replay = BridgeTransferEvent("0xforged_replay", "bridge-eth-polygon", "Eth", "Poly", "USDC", 5000.0, exploiter, exploiter, 1010.0, 305)

    alert1 = sentinel.process_transfer(ev1)
    assert alert1 is None

    alert2 = sentinel.process_transfer(ev2_replay)
    assert alert2 is not None
    assert alert2.is_drain_attack
    assert alert2.attack_vector == "PROOF_REPLAY_DOUBLE_SPEND"
    assert alert2.circuit_breaker_triggered is True
    assert alert2.risk_severity == "CRITICAL"
    assert "0xorig" in alert2.tx_hashes
    assert "0xforged_replay" in alert2.tx_hashes


def test_unbacked_synthetic_mint_catastrophic_alert(sentinel):
    # Bridge reserve is 100k, attacker attempts synthetic mint of 150k unbacked tokens
    attacker = "0xFakeBridgeValidator0000000000000003"
    ev = BridgeTransferEvent(
        tx_hash="0xmint_unbacked",
        bridge_id="bridge-eth-polygon",
        source_chain="Arbitrum",
        target_chain="Ethereum",
        token_symbol="USDC",
        amount=150000.0,
        sender_address="0xBridgeRelayer",
        recipient_address=attacker,
        timestamp_sec=2000.0,
        proof_nonce=501,
        is_synthetic_mint=True,
    )

    alert = sentinel.process_transfer(ev)
    assert alert is not None
    assert alert.attack_vector == "UNBACKED_SYNTHETIC_MINT"
    assert alert.circuit_breaker_triggered is True
    assert alert.risk_severity == "CRITICAL"
    assert alert.suspect_address == attacker


def test_sliding_window_expiration_prevents_false_positive(sentinel):
    # Two transfers totaling 25k, but separated by 400 seconds (> 300s window)
    t1 = BridgeTransferEvent("0x1", "bridge-eth-polygon", "Eth", "Poly", "USDC", 12000.0, "0xU1", "0xU1", 1000.0, 601)
    t2 = BridgeTransferEvent("0x2", "bridge-eth-polygon", "Eth", "Poly", "USDC", 13000.0, "0xU2", "0xU2", 1450.0, 602)

    a1 = sentinel.process_transfer(t1)
    assert a1 is None

    a2 = sentinel.process_transfer(t2)
    # At t2 (1450s), t1 (1000s) has expired from 300s window -> only 13k in window (13% < 20%)
    assert a2 is None
