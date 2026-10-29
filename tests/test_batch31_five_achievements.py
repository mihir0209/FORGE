import pytest
from forge.eip4844_blob_gas_sentinel import Eip4844BlobGasSentinel
from forge.multisig_nonce_desync_watchdog import MultisigNonceDesyncWatchdog
from forge.bgp_blackhole_community_sentinel import BgpBlackholeCommunitySentinel
from forge.amm_k_invariant_rounding_auditor import AmmKInvariantRoundingAuditor
from forge.polymorphic_jumptable_anomaly_engine import PolymorphicJumpTableAnomalyEngine

def test_achievement_1_eip4844_blob_gas():
    sentinel = Eip4844BlobGasSentinel()
    # Underpriced blob (offered 5 gwei < 10 gwei base) -> DROP
    under = sentinel.evaluate_blob_mempool_priority(5.0, 10.0, 2)
    assert under.is_blob_underpriced_frontrun is True
    assert under.mempool_action == "DROP_UNDERPRICED_BLOB"

    # Frontrun aggressive blob (offered 35 gwei vs 10 gwei base)
    front = sentinel.evaluate_blob_mempool_priority(35.0, 10.0, 2)
    assert front.is_blob_underpriced_frontrun is True
    assert front.mempool_action == "EIP4844_PRIORITY_BLOB_SUBMISSION"

def test_achievement_2_multisig_nonce_desync():
    watchdog = MultisigNonceDesyncWatchdog()
    # On-chain nonce is 5, but attacker submits proposal with old nonce 4 -> replay reject
    bad = watchdog.verify_proposal_nonce(onchain_current_nonce=5, proposal_payload_nonce=4)
    assert bad.is_nonce_desynced is True
    assert "REJECT" in bad.action

    # Aligned nonce
    good = watchdog.verify_proposal_nonce(onchain_current_nonce=5, proposal_payload_nonce=5)
    assert good.is_nonce_desynced is False

def test_achievement_3_bgp_blackhole_sentinel():
    sentinel = BgpBlackholeCommunitySentinel()
    # Malicious route tagged with 65535:666 without active DDoS
    hijack = sentinel.audit_communities("198.51.100.0/24", 65001, ["65535:666", "13335:100"], is_prefix_under_active_ddos=False)
    assert hijack.is_unauthorized_blackholing is True
    assert hijack.severity == "CRITICAL_UNAUTHORIZED_ROUTE_DROPPING_HIJACK"

    # Legitimate operator blackholing during verified DDoS
    legit = sentinel.audit_communities("198.51.100.0/24", 65001, ["65535:666"], is_prefix_under_active_ddos=True)
    assert legit.is_unauthorized_blackholing is False
    assert legit.severity == "AUTHORIZED_DDOS_BLACKHOLE"

def test_achievement_4_amm_k_invariant_rounding():
    auditor = AmmKInvariantRoundingAuditor()
    # Flawed swap implementation: 1000 * 1000 = 1,000,000. In: 10, Out: 11 -> (1010) * (989) = 998,890 < 1,000,000
    vulnerable = auditor.audit_swap_rounding(1000, 1000, 10, 11)
    assert vulnerable.is_drain_vulnerable is True
    assert vulnerable.final_k < vulnerable.initial_k
    assert vulnerable.k_invariant_decay_bps > 0

    # Proper swap: 1000 * 1000. In: 10, Out: 9 -> (1010) * (991) = 1,000,910 >= 1,000,000
    secure = auditor.audit_swap_rounding(1000, 1000, 10, 9)
    assert secure.is_drain_vulnerable is False

def test_achievement_5_polymorphic_jumptable():
    engine = PolymorphicJumpTableAnomalyEngine()
    # Normal function prologue and epilogue
    normal_code = ["push rbp", "mov rbp, rsp", "mov eax, [rbp-4]", "add eax, 1", "pop rbp", "ret"]
    assert engine.inspect_disassembly_instructions(normal_code).is_shellcode_detected is False

    # Polymorphic shellcode decryption loop with heavy indirect register jumps
    shellcode = [
        "xor eax, eax", "jmp rax", "call rbx", "mov [rdi], cl", "jmp rcx",
        "call rdx", "jmp [rbx+8]", "ret"
    ]
    res_shell = engine.inspect_disassembly_instructions(shellcode)
    assert res_shell.is_shellcode_detected is True
    assert res_shell.threat_tier == "CRITICAL_POLYMORPHIC_SHELLCODE_JUMPTABLE"
