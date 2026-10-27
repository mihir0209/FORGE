from typing import List, Dict, Set

def detect_synthetic_pii_sharing(ssn_to_address_count: int) -> bool:
    return ssn_to_address_count >= 4

def detect_atm_impossible_cashout(km_distance: float, minutes_apart: float) -> bool:
    if minutes_apart <= 0: return True
    speed = (km_distance / minutes_apart) * 60.0
    return speed >= 800.0

def detect_merchant_collusion(refund_rate_pct: float, repeat_card_pct: float) -> bool:
    return refund_rate_pct >= 30.0 and repeat_card_pct >= 40.0

def score_chargeback_arbitration_risk(dispute_count_90d: int, delivery_signature_present: bool) -> float:
    risk = dispute_count_90d * 0.25
    if not delivery_signature_present: risk += 0.4
    return min(1.0, round(risk, 2))

def detect_session_fingerprint_divergence(initial_fp: str, current_fp: str) -> bool:
    return initial_fp != current_fp

def detect_promo_voucher_cluster(device_id: str, claimed_accounts: int) -> bool:
    return claimed_accounts >= 3

def detect_bridge_root_drift(l1_root: str, l2_root: str) -> bool:
    return l1_root != l2_root

def detect_credential_stuffing(failed_attempts_5m: int, threshold: int = 10) -> bool:
    return failed_attempts_5m >= threshold

def detect_phishing_punycode(domain: str) -> bool:
    return domain.startswith("xn--") or any(ord(c) > 127 for c in domain)

def detect_stealth_wallet_sweeper(time_to_sweep_seconds: float) -> bool:
    return time_to_sweep_seconds <= 2.0
