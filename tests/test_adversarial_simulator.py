# pyright: reportMissingTypeStubs=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownParameterType=false, reportMissingTypeArgument=false, reportArgumentType=false
"""Adversarial QA test suite: Attack generator fuzzing, 10,000-transaction stress testing, schema & feature invariants."""

import math
from collections import Counter
from datetime import UTC, datetime

import pytest

from forge.adversarial_simulator import (
    AdversarialAttackGenerator,
    AdversarialTransaction,
    AttackMode,
)
from forge.contracts.contracts import (
    GraphEvent,
    LifecycleStage,
    TraceEvent,
)
from forge.feature_schema import FEATURE_NAMES
from forge.mule_ring import MuleRingDetector, MuleRingGraph

NOW = datetime(2026, 8, 25, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# 1. 10,000 Synthetic Adversarial Transactions: Fuzzing & Schema Validity
# ---------------------------------------------------------------------------


def test_10000_synthetic_adversarial_transactions_across_burst_spoof_structuring() -> None:
    """Generate 10,000 synthetic adversarial transactions across burst, spoof, and structuring modes.

    Assert strict schema validity and valid 15-feature representations on every single transaction.
    """
    generator = AdversarialAttackGenerator(seed=2026)
    count = 10_000

    transactions = generator.generate_batch(
        count=count,
        modes=[AttackMode.BURST, AttackMode.SPOOF, AttackMode.STRUCTURING],
    )

    # 1. Volume and Distribution Invariants
    assert len(transactions) == count
    mode_counts = Counter(tx.attack_mode for tx in transactions)
    assert mode_counts[AttackMode.BURST] > 2800
    assert mode_counts[AttackMode.SPOOF] > 2800
    assert mode_counts[AttackMode.STRUCTURING] > 2800

    seen_tx_ids: set[str] = set()

    burst_features_burst: list[float] = []
    burst_features_volume: list[float] = []

    spoof_features_new_device: list[float] = []
    spoof_features_network: list[float] = []
    spoof_features_liveness: list[float] = []

    structuring_amounts: list[float] = []
    structuring_depletion: list[float] = []
    structuring_cashout: list[float] = []

    for tx in transactions:
        # Schema Invariants
        assert isinstance(tx, AdversarialTransaction)
        assert tx.transaction_id.startswith("tx_adv_")
        assert tx.transaction_id not in seen_tx_ids
        seen_tx_ids.add(tx.transaction_id)

        assert tx.amount > 0.0
        assert tx.amount_minor > 0
        assert tx.amount_minor == round(tx.amount * 100)
        assert tx.currency == "USD"
        assert tx.is_fraud is True
        assert tx.timestamp.tzinfo is not None
        assert tx.source_account.startswith("acc_src_")
        assert tx.destination_account.startswith("acc_dst_")
        assert tx.device_id.startswith("dev_")
        assert tx.ip_address.startswith("198.51.100.")

        # Feature Representation Invariants
        feat = tx.to_feature_dict()
        assert set(feat.keys()) == set(FEATURE_NAMES)
        assert len(feat) == 15

        for feat_name, feat_val in feat.items():
            assert isinstance(feat_val, float), f"{feat_name} is not float"
            assert math.isfinite(feat_val), f"{feat_name} is infinite or NaN: {feat_val}"
            assert feat_val >= 0.0, f"{feat_name} is negative: {feat_val}"
            assert feat_val <= 1.0, f"{feat_name} exceeds 1.0: {feat_val}"

        # Mode-specific collection for distribution assertions
        if tx.attack_mode == AttackMode.BURST:
            assert "burst_batch_id" in tx.attributes
            assert tx.attributes["velocity_tps"] == 25.0
            burst_features_burst.append(feat["burst"])
            burst_features_volume.append(feat["volume"])

        elif tx.attack_mode == AttackMode.SPOOF:
            assert tx.attributes["spoofed_device"] is True
            assert tx.attributes["proxy_detected"] is True
            spoof_features_new_device.append(feat["new_device"])
            spoof_features_network.append(feat["unknown_peer_network"])
            spoof_features_liveness.append(feat["media_liveness_anomaly"])

        elif tx.attack_mode == AttackMode.STRUCTURING:
            # Structuring / smurfing is intentionally under the $10,000 threshold
            assert 5000.0 <= tx.amount < 10000.0
            assert tx.attributes["threshold_evasion_target"] == 10000.0
            assert tx.attributes["delta_to_threshold"] > 0.0
            assert tx.attributes["delta_to_threshold"] == pytest.approx(10000.0 - tx.amount, abs=0.01)
            structuring_amounts.append(tx.amount)
            structuring_depletion.append(feat["balance_depletion"])
            structuring_cashout.append(feat["cashout_pressure"])

    # 2. Assert Valid Feature Distributions Across Modes
    # Burst mode exhibits high velocity burst and elevated volume
    assert (sum(burst_features_burst) / len(burst_features_burst)) >= 0.70
    assert (sum(burst_features_volume) / len(burst_features_volume)) >= 0.70

    # Spoof mode has 100% new_device and elevated network & liveness anomaly
    assert all(nd == 1.0 for nd in spoof_features_new_device)
    assert (sum(spoof_features_network) / len(spoof_features_network)) >= 0.70
    assert (sum(spoof_features_liveness) / len(spoof_features_liveness)) >= 0.70

    # Structuring mode has average amount ~9,500 and high depletion/cashout features
    assert 9000.0 < (sum(structuring_amounts) / len(structuring_amounts)) < 10000.0
    assert (sum(structuring_depletion) / len(structuring_depletion)) >= 0.70
    assert (sum(structuring_cashout) / len(structuring_cashout)) >= 0.70


# ---------------------------------------------------------------------------
# 2. Attack Generator Fuzzing: Noise, Jitter, and Boundary Resilience
# ---------------------------------------------------------------------------


def test_fuzzed_transactions_remain_strictly_valid() -> None:
    """Stress test with feature jitter, timestamp jitter, and amount mutations."""
    generator = AdversarialAttackGenerator(seed=999)
    fuzzed = generator.fuzz_transactions(count=1500, noise_scale=0.10)

    assert len(fuzzed) == 1500
    for tx in fuzzed:
        assert isinstance(tx, AdversarialTransaction)
        assert tx.amount > 0.0
        assert tx.amount_minor > 0
        assert tx.amount_minor == round(tx.amount * 100)

        feat = tx.to_feature_dict()
        for _k, v in feat.items():
            assert math.isfinite(v)
            assert 0.0 <= v <= 1.0


@pytest.mark.parametrize("seed", [0, 1, 42, 1337, 999999, 2147483647])
def test_generator_deterministic_across_varied_seeds(seed: int) -> None:
    """Determinism check: same seed produces identical transactions; different seeds differ."""
    gen1 = AdversarialAttackGenerator(seed=seed)
    gen2 = AdversarialAttackGenerator(seed=seed)
    gen_other = AdversarialAttackGenerator(seed=seed + 1)

    batch1 = gen1.generate_batch(50)
    batch2 = gen2.generate_batch(50)
    batch_other = gen_other.generate_batch(50)

    # Exact equality across runs with same seed
    assert [tx.transaction_id for tx in batch1] == [tx.transaction_id for tx in batch2]
    assert [tx.amount for tx in batch1] == [tx.amount for tx in batch2]
    assert [tx.to_feature_dict() for tx in batch1] == [tx.to_feature_dict() for tx in batch2]

    # Divergence across different seeds
    assert [tx.amount for tx in batch1] != [tx.amount for tx in batch_other]


def test_single_transaction_generation_with_custom_overrides() -> None:
    """Verify single transaction creation across all three modes with explicit overrides."""
    generator = AdversarialAttackGenerator(seed=777)

    # Burst with specific amount
    tx_burst = generator.generate_transaction(
        AttackMode.BURST,
        amount=123.45,
        source_account="cust_special",
        destination_account="merchant_fast",
    )
    assert tx_burst.amount == 123.45
    assert tx_burst.amount_minor == 12345
    assert tx_burst.source_account == "cust_special"
    assert tx_burst.destination_account == "merchant_fast"
    assert tx_burst.attack_mode == AttackMode.BURST
    assert tx_burst.to_feature_dict()["burst"] >= 0.70

    # Spoof with specific location and channel
    tx_spoof = generator.generate_transaction(
        AttackMode.SPOOF,
        location="US-CA",
        channel="web_portal",
    )
    assert tx_spoof.location == "US-CA"
    assert tx_spoof.channel == "web_portal"
    assert tx_spoof.attributes["spoofed_device"] is True
    assert tx_spoof.to_feature_dict()["new_device"] == 1.0

    # Structuring with explicit threshold evasion amount
    tx_struct = generator.generate_transaction(
        AttackMode.STRUCTURING,
        amount=9980.00,
    )
    assert tx_struct.amount == 9980.00
    assert tx_struct.amount_minor == 998000
    assert tx_struct.attributes["delta_to_threshold"] == pytest.approx(20.00)
    assert tx_struct.to_feature_dict()["balance_depletion"] >= 0.70


# ---------------------------------------------------------------------------
# 3. Interoperability & Contract Conversions
# ---------------------------------------------------------------------------


def test_adversarial_transaction_converts_to_graph_event() -> None:
    """Verify conversion to forge.contracts.contracts.GraphEvent."""
    generator = AdversarialAttackGenerator(seed=303)
    tx = generator.generate_transaction(AttackMode.STRUCTURING, amount=9500.0)

    ge = tx.to_graph_event(institution_id="bank-consortium")
    assert isinstance(ge, GraphEvent)
    assert ge.event_id == tx.transaction_id
    assert ge.institution_id == "bank-consortium"
    assert ge.source_account_ref == tx.source_account
    assert ge.destination_account_ref == tx.destination_account
    assert ge.amount_minor == 950000
    assert ge.attributes["attack_mode"] == "structuring"
    assert ge.attributes["is_fraud"] is True


def test_adversarial_transaction_converts_to_trace_event() -> None:
    """Verify conversion to forge.contracts.contracts.TraceEvent."""
    generator = AdversarialAttackGenerator(seed=404)
    tx = generator.generate_transaction(AttackMode.BURST, amount=50.0)

    te = tx.to_trace_event(stage=LifecycleStage.PAYMENT)
    assert isinstance(te, TraceEvent)
    assert te.event_id == tx.transaction_id
    assert te.is_attack_step is True
    assert te.attack_stage == LifecycleStage.PAYMENT
    assert te.payload["customer"] == tx.source_account
    assert te.payload["merchant"] == tx.destination_account
    assert te.payload["amount"] == 50.0
    assert te.payload["attack_mode"] == "burst"


# ---------------------------------------------------------------------------
# 4. Integration: Structured Circular Mule Ring Detection
# ---------------------------------------------------------------------------


def test_adversarial_structured_mule_ring_detected_in_graph() -> None:
    """Generate structured transactions that form a circular laundering ring; assert mule ring detector catches it."""
    generator = AdversarialAttackGenerator(seed=808)
    ring_accounts = ["smurf_node_1", "smurf_node_2", "smurf_node_3", "smurf_node_4"]
    ring_txs: list[AdversarialTransaction] = []

    for i in range(4):
        src = ring_accounts[i]
        dst = ring_accounts[(i + 1) % 4]
        tx = generator.generate_transaction(
            AttackMode.STRUCTURING,
            source_account=src,
            destination_account=dst,
            amount=9800.0 - i * 50.0,
        )
        ring_txs.append(tx)

    # Ingest into MuleRingGraph
    graph = MuleRingGraph()
    for tx in ring_txs:
        graph.add_transaction(
            source=tx.source_account,
            destination=tx.destination_account,
            amount=tx.amount,
            timestamp=tx.timestamp,
            edge_id=tx.transaction_id,
        )

    # Detect rings
    detector = MuleRingDetector(min_ring_size=3, max_ring_size=6)
    result = detector.detect_rings(graph)

    assert result.cycle_count == 1
    ring = result.rings[0]
    assert ring.length == 4
    assert set(ring.nodes) == set(ring_accounts)
    assert ring.confidence_score >= 0.75
    assert ring.total_volume == pytest.approx(sum(tx.amount for tx in ring_txs))
