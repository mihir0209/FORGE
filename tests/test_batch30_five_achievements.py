import pytest
from forge.solana_lamport_drain_sentinel import SolanaLamportDrainSentinel
from forge.cpi_recursion_depth_classifier import CpiRecursionDepthClassifier
from forge.erc4626_vault_inflation_watchdog import Erc4626VaultInflationWatchdog
from forge.adversarial_fgsm_perturbation_sentinel import AdversarialFgsmPerturbationSentinel
from forge.ddos_synack_reflection_watchdog import DdosSynAckReflectionWatchdog

def test_achievement_1_solana_lamport_drain():
    sentinel = SolanaLamportDrainSentinel()
    # Drained 10 SOL without owner signature
    alert = sentinel.inspect_instruction_transfers(
        account_owner="VictimPubKey1111111111111111111111",
        authorized_signer="AttackerPubKey22222222222222222222",
        pre_lamports=10_000_000_000,
        post_lamports=0
    )
    assert alert.is_unauthorized_drain is True
    assert alert.drained_lamports == 10_000_000_000
    assert alert.threat_tier == "CRITICAL_UNAUTHORIZED_LAMPORT_DRAINAGE"

    # Authorized withdrawal
    safe = sentinel.inspect_instruction_transfers(
        account_owner="OwnerPubKey1111111111111111111111",
        authorized_signer="OwnerPubKey1111111111111111111111",
        pre_lamports=10_000_000_000,
        post_lamports=5_000_000_000
    )
    assert safe.is_unauthorized_drain is False

def test_achievement_2_cpi_depth_limit():
    classifier = CpiRecursionDepthClassifier()
    # Depth 4 is permitted (Solana max)
    assert classifier.check_call_chain_depth(4).is_cpi_limit_exceeded is False

    # Depth 5 exceeds limit and traps
    exceeded = classifier.check_call_chain_depth(5)
    assert exceeded.is_cpi_limit_exceeded is True
    assert "TRAP" in exceeded.action

def test_achievement_3_erc4626_inflation():
    dog = Erc4626VaultInflationWatchdog()
    # Attacker donates 100,000,000 units while holding only 1 share
    attack = dog.inspect_share_ratio(100_000_000, 1)
    assert attack.is_inflation_attack_suspected is True
    assert attack.threat_level == "CRITICAL_ERC4626_SHARE_INFLATION_ATTACK"

    # Healthy vault: 1,000,000 assets for 1,000,000 shares
    healthy = dog.inspect_share_ratio(1_000_000, 1_000_000)
    assert healthy.is_inflation_attack_suspected is False

def test_achievement_4_adversarial_fgsm():
    sentinel = AdversarialFgsmPerturbationSentinel()
    clean = [0.2, 0.4, 0.6, 0.8]
    # Subtle uniform perturbation delta = 0.03
    adv = [0.23, 0.43, 0.63, 0.83]
    alert = sentinel.detect_perturbation(clean, adv, epsilon_threshold=0.05)
    assert alert.is_adversarial_evasion is True
    assert alert.confidence_drop > 0.20

def test_achievement_5_ddos_synack_reflection():
    watchdog = DdosSynAckReflectionWatchdog()
    # Amplification factor 50x with 90% SYN flood
    alert = watchdog.inspect_amplification_traffic(request_bytes=1000, response_bytes=50000, syn_ratio=0.90)
    assert alert.is_reflection_attack is True
    assert alert.amplification_factor == 50.0
    assert "DROP_AND_BLACKHOLE" in alert.action
