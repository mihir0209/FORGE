from dataclasses import dataclass
from typing import List, Set, Dict

def detect_sim_swap(last_carrier_change_hours: float, hours_before_reset: float = 24.0) -> bool:
    return last_carrier_change_hours <= hours_before_reset

def detect_bin_attack(attempts_per_minute: int, threshold: int = 100) -> bool:
    return attempts_per_minute >= threshold

def detect_mule_account(inflow_count: int, outflow_count: int, velocity_ratio: float) -> bool:
    return inflow_count >= 5 and outflow_count >= 5 and velocity_ratio >= 0.85

def detect_wash_trade_cycle(cycle_nodes: List[str]) -> bool:
    return len(cycle_nodes) >= 3 and cycle_nodes[0] == cycle_nodes[-1]

def detect_gas_griefing(gas_limit_used_pct: float, value_transferred_eth: float) -> bool:
    return gas_limit_used_pct >= 90.0 and value_transferred_eth == 0.0

def detect_governance_flash_loan(borrowed_tokens: float, total_voting_supply: float) -> bool:
    return (borrowed_tokens / max(1.0, total_voting_supply)) >= 0.10

def detect_btc_dusting(satoshis: int, recipient_count: int) -> bool:
    return satoshis <= 1000 and recipient_count >= 50

def check_sanctions_hit(address: str, sanctioned_list: Set[str]) -> bool:
    return address.lower() in {s.lower() for s in sanctioned_list}

def detect_dns_tunneling(query_entropy: float, subdomain_length: int) -> bool:
    return query_entropy >= 4.2 and subdomain_length >= 35

def detect_credential_leak_match(user_pwd_hash: str, breach_db_hashes: Set[str]) -> bool:
    return user_pwd_hash in breach_db_hashes
