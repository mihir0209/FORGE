import pytest
from forge.eip7594_peerdas_eclipse_guard import Eip7594PeerDasEclipseGuard
from forge.multiprover_rollup_dispute_sentinel import MultiProverRollupDisputeSentinel
from forge.solana_cross_cpi_reentrancy_watchdog import SolanaCrossCpiReentrancyWatchdog
from forge.bgp_asset_deprecation_sentinel import BgpAsSetDeprecationSentinel
from forge.concentrated_liquidity_jit_watchdog import ConcentratedLiquidityJitWatchdog

def test_achievement_1_peerdas_eclipse():
    guard = Eip7594PeerDasEclipseGuard()
    assigned = [1, 5, 9, 13]
    # Peers only cover subnet 1 (25% < 75%) -> Eclipsed
    alert_eclipsed = guard.evaluate_custody_sampling(assigned, [1, 2, 3])
    assert alert_eclipsed.is_custody_subnet_eclipsed is True
    assert alert_eclipsed.data_availability_verified is False

    # Peers cover [1, 5, 9] (75%) -> Healthy
    alert_ok = guard.evaluate_custody_sampling(assigned, [1, 5, 9, 20])
    assert alert_ok.is_custody_subnet_eclipsed is False
    assert alert_ok.data_availability_verified is True

def test_achievement_2_multiprover_dispute():
    sentinel = MultiProverRollupDisputeSentinel()
    # 2 out of 3 provers agree on 0xRootA (66.7% >= 66%) -> Quorum achieved
    provers_agree = {
        "sgx": "0xRootA",
        "risc0": "0xRootA",
        "sp1": "0xRootB"
    }
    res_agree = sentinel.arbitrate_multi_prover_roots(provers_agree, min_quorum_ratio=0.66)
    assert res_agree.is_dispute_triggered is False
    assert res_agree.consensus_state_root == "0xRootA"

    # Split dispute: 1 SGX says RootA, 1 Risc0 says RootB, 1 SP1 says RootC
    provers_split = {"sgx": "0xRootA", "risc0": "0xRootB", "sp1": "0xRootC"}
    res_split = sentinel.arbitrate_multi_prover_roots(provers_split, min_quorum_ratio=0.66)
    assert res_split.is_dispute_triggered is True
    assert "BISECTION_GAME" in res_split.arbitration_action

def test_achievement_3_solana_cross_cpi():
    watchdog = SolanaCrossCpiReentrancyWatchdog()
    # Call stack: Program A -> Program B -> Program A (Reentrant!)
    stack_bad = ["Program_A", "Program_B", "Program_A"]
    alert_bad = watchdog.inspect_cpi_stack("Program_A", stack_bad)
    assert alert_bad.is_cpi_reentrancy_detected is True
    assert alert_bad.security_action == "ABORT_TRANSACTION_CPI_REENTRANCY_TRAP"

    # Normal stack: Program A -> Program B -> Program C
    stack_good = ["Program_A", "Program_B", "Program_C"]
    assert watchdog.inspect_cpi_stack("Program_A", stack_good).is_cpi_reentrancy_detected is False

def test_achievement_4_bgp_asset_deprecation():
    sentinel = BgpAsSetDeprecationSentinel()
    # Route containing deprecated AS_SET
    bad_path = [{"type": "AS_SEQUENCE", "values": [15169]}, {"type": "AS_SET", "values": [65001, 65002]}]
    res_bad = sentinel.inspect_as_path(bad_path)
    assert res_bad.has_deprecated_as_set is True
    assert res_bad.severity == "HIGH_DEPRECATED_AS_SET_ROUTE_FILTERED"

    # Clean standard AS_SEQUENCE
    good_path = [{"type": "AS_SEQUENCE", "values": [15169, 701]}]
    assert sentinel.inspect_as_path(good_path).has_deprecated_as_set is False

def test_achievement_5_concentrated_liquidity_jit():
    watchdog = ConcentratedLiquidityJitWatchdog()
    # JIT sandwich: Mint at idx 10, Victim swap $100k at idx 11, Burn at idx 12
    alert = watchdog.detect_jit_sandwich(
        mint_tx_index=10,
        target_swap_tx_index=11,
        burn_tx_index=12,
        mint_volume_usd=500_000.0,
        target_swap_volume_usd=100_000.0
    )
    assert alert.is_jit_frontrunning_detected is True
    assert alert.extracted_fee_usd == 300.0
    assert "MINT:10_SWAP:11_BURN:12" in alert.mempool_position
