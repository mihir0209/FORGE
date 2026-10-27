import pytest
from forge.marathon30_forge_part1 import *
from forge.marathon30_forge_part2 import *
from forge.marathon30_forge_part3 import *

def test_achievement_1_sim_swap():
    assert detect_sim_swap(12.0) is True
    assert detect_sim_swap(48.0) is False

def test_achievement_2_bin_attack():
    assert detect_bin_attack(150) is True

def test_achievement_3_mule_account():
    assert detect_mule_account(10, 8, 0.9) is True

def test_achievement_4_wash_trade_cycle():
    assert detect_wash_trade_cycle(["A", "B", "C", "A"]) is True

def test_achievement_5_gas_griefing():
    assert detect_gas_griefing(95.0, 0.0) is True

def test_achievement_6_governance_flash_loan():
    assert detect_governance_flash_loan(150000, 1000000) is True

def test_achievement_7_btc_dusting():
    assert detect_btc_dusting(546, 100) is True

def test_achievement_8_sanctions_filter():
    assert check_sanctions_hit("0xOFAC", {"0xofac"}) is True

def test_achievement_9_dns_tunneling():
    assert detect_dns_tunneling(4.5, 40) is True

def test_achievement_10_credential_leak():
    assert detect_credential_leak_match("hash123", {"hash123", "hash456"}) is True

def test_achievement_11_synthetic_pii():
    assert detect_synthetic_pii_sharing(5) is True

def test_achievement_12_atm_cashout():
    assert detect_atm_impossible_cashout(1000.0, 30.0) is True

def test_achievement_13_merchant_collusion():
    assert detect_merchant_collusion(35.0, 50.0) is True

def test_achievement_14_chargeback_arbitration():
    assert score_chargeback_arbitration_risk(3, False) >= 0.8

def test_achievement_15_session_fingerprint():
    assert detect_session_fingerprint_divergence("fp1", "fp2") is True

def test_achievement_16_promo_voucher():
    assert detect_promo_voucher_cluster("dev1", 4) is True

def test_achievement_17_bridge_root_drift():
    assert detect_bridge_root_drift("rootA", "rootB") is True

def test_achievement_18_credential_stuffing():
    assert detect_credential_stuffing(15) is True

def test_achievement_19_punycode_phishing():
    assert detect_phishing_punycode("xn--pple-43d.com") is True

def test_achievement_20_stealth_wallet_sweeper():
    assert detect_stealth_wallet_sweeper(0.8) is True

def test_achievement_21_reentrancy_drain():
    assert detect_reentrancy_drain(2, True) is True

def test_achievement_22_oracle_staleness():
    assert detect_oracle_staleness(5000, 1000, 3600) is True

def test_achievement_23_rbf_frontrunning():
    assert detect_rbf_frontrunning(50.0, 100.0) is True

def test_achievement_24_cross_border_velocity():
    assert detect_cross_border_velocity_limit(60000.0, 50000.0) is True

def test_achievement_25_dex_pool_skew():
    assert detect_dex_pool_skew(100.0, 120.0, 5.0) is True

def test_achievement_26_micro_deposit_bruteforce():
    assert detect_micro_deposit_bruteforce(4) is True

def test_achievement_27_apk_signature_tamper():
    assert detect_apk_signature_tamper("shaA", "shaB") is True

def test_achievement_28_tor_wire_transfer():
    assert detect_tor_wire_transfer(True, 25000.0) is True

def test_achievement_29_synthetic_credit_burst():
    assert detect_synthetic_credit_burst(12) is True

def test_achievement_30_zk_nullifier_replay():
    assert detect_zk_nullifier_replay("null1", {"null1", "null2"}) is True
