from typing import List

def detect_reentrancy_drain(call_depth: int, balance_depleted_before_ret: bool) -> bool:
    return call_depth >= 2 and balance_depleted_before_ret

def detect_oracle_staleness(now_epoch: float, last_update_epoch: float, max_heartbeat: float = 3600.0) -> bool:
    return (now_epoch - last_update_epoch) > max_heartbeat

def detect_rbf_frontrunning(original_gas_price: float, replacement_gas_price: float) -> bool:
    return replacement_gas_price >= (original_gas_price * 1.5)

def detect_cross_border_velocity_limit(transfers_24h_total_usd: float, statutory_limit: float = 50000.0) -> bool:
    return transfers_24h_total_usd >= statutory_limit

def detect_dex_pool_skew(k_initial: float, k_observed: float, tolerance_pct: float = 5.0) -> bool:
    delta = abs(k_observed - k_initial) / max(1.0, k_initial) * 100.0
    return delta > tolerance_pct

def detect_micro_deposit_bruteforce(attempt_count: int, max_allowed: int = 3) -> bool:
    return attempt_count > max_allowed

def detect_apk_signature_tamper(stored_cert_sha256: str, reported_cert_sha256: str) -> bool:
    return stored_cert_sha256.lower() != reported_cert_sha256.lower()

def detect_tor_wire_transfer(is_tor_exit_node: bool, transfer_amount_usd: float) -> bool:
    return is_tor_exit_node and transfer_amount_usd >= 10000.0

def detect_synthetic_credit_burst(inquiries_48h: int) -> bool:
    return inquiries_48h >= 10

def detect_zk_nullifier_replay(nullifier: str, spent_nullifiers: set) -> bool:
    return nullifier in spent_nullifiers
