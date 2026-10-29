import pytest
from forge.erc7702_delegated_account_watchdog import Erc7702DelegatedAccountWatchdog
from forge.l2_rollup_state_fraud_sentinel import L2RollupStateFraudSentinel
from forge.zk_groth16_malleability_trap import ZkGroth16MalleabilityTrap
from forge.validator_eclipse_attack_detector import ValidatorEclipseAttackDetector
from forge.evm_memory_expansion_gas_griefing_auditor import EvmMemoryExpansionGasGriefingAuditor

def test_achievement_1_erc7702_delegation():
    watchdog = Erc7702DelegatedAccountWatchdog()
    # Malicious delegation target with SELFDESTRUCT opcode (0xff)
    malicious_bytecode = b"\x60\x00\x60\x00\xff" # PUSH 0 PUSH 0 SELFDESTRUCT
    alert = watchdog.audit_delegation_authorization("0xBadActorContractAddress111111111111111111", malicious_bytecode)
    assert alert.is_malicious_delegation is True
    assert alert.threat_tier == "CRITICAL_ERC7702_ACCOUNT_DRAINER_DELEGATION"

    # Clean smart account logic
    clean_bytecode = b"\x60\x80\x60\x40\x52\x34\x80\x15" * 10
    assert watchdog.audit_delegation_authorization("0xSafeSmartAccountLogic", clean_bytecode).is_malicious_delegation is False

def test_achievement_2_l2_rollup_fraud_proof():
    sentinel = L2RollupStateFraudSentinel()
    pre_root = "0x1111111111111111111111111111111111111111111111111111111111111111"
    txs = "0x2222222222222222222222222222222222222222222222222222222222222222"
    # False claimed root submitted by dishonest sequencer
    fraudulent_claim = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    res = sentinel.verify_state_transition(pre_root, fraudulent_claim, txs)
    assert res.is_state_transition_invalid is True
    assert "EMIT_FRAUD_PROOF_CHALLENGE" in res.action

    # Valid computed post-state root matches
    valid_res = sentinel.verify_state_transition(pre_root, res.computed_post_state_root, txs)
    assert valid_res.is_state_transition_invalid is False

def test_achievement_3_zk_groth16_malleability():
    trap = ZkGroth16MalleabilityTrap()
    p = trap.BN254_PRIME_P
    # Point with y > p // 2 (malleable high-y representation)
    pt_a_malleable = (100, p - 10)
    pt_b = ((1, 2), (3, 4))
    pt_c = (5, 6)
    check = trap.inspect_proof_points(pt_a_malleable, pt_b, pt_c)
    assert check.is_malleable_proof is True
    assert "REJECT_MALLEABLE" in check.security_verdict

    # Canonical lower-y point
    pt_a_canonical = (100, 100)
    assert trap.inspect_proof_points(pt_a_canonical, pt_b, pt_c).is_malleable_proof is False

def test_achievement_4_validator_eclipse():
    detector = ValidatorEclipseAttackDetector()
    # 10 peers all from AS65001 (attacker ASN monopoly)
    ips = [f"192.168.1.{i}" for i in range(10)]
    asns = [65001] * 10
    alert = detector.evaluate_peer_mesh(ips, asns, min_distinct_asns=4)
    assert alert.is_eclipse_attack_detected is True
    assert "DISCONNECT_MONOPOLIZED_SUBNET" in alert.mitigation_action

    # Diverse peers across 5 different ASNs
    diverse_asns = [13335, 15169, 701, 2914, 3356, 13335, 15169, 701, 2914, 3356]
    assert detector.evaluate_peer_mesh(ips, diverse_asns, min_distinct_asns=4).is_eclipse_attack_detected is False

def test_achievement_5_evm_memory_griefing():
    auditor = EvmMemoryExpansionGasGriefingAuditor()
    # Normal memory allocation (64 KB = 65,536 bytes) -> cost ~ 14,000 gas
    normal = auditor.calculate_memory_gas(65536)
    assert normal.is_memory_griefing is False
    assert normal.memory_expansion_gas_cost < 100_000

    # Malicious 4 MB allocation -> quadratic explosion > 15,000,000 gas
    huge = auditor.calculate_memory_gas(4 * 1024 * 1024)
    assert huge.is_memory_griefing is True
    assert huge.verdict == "REVERT_MEMORY_EXPANSION_GAS_GRIEFING"
