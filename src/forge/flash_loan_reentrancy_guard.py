from dataclasses import dataclass
from typing import List, Dict, Set

@dataclass
class ReentrancyCheckResult:
    is_reentrancy_attack: bool
    reentered_pool: str
    call_depth: int
    threat_severity: str

class FlashLoanReentrancyGuard:
    def __init__(self, max_allowed_depth: int = 1):
        self.max_allowed_depth = max_allowed_depth
        self._in_flight_calls: Dict[str, int] = {}

    def enter_pool_callback(self, pool_address: str) -> ReentrancyCheckResult:
        addr = pool_address.lower()
        self._in_flight_calls[addr] = self._in_flight_calls.get(addr, 0) + 1
        depth = self._in_flight_calls[addr]

        is_attack = depth > self.max_allowed_depth
        severity = "CRITICAL" if is_attack else "SAFE"
        return ReentrancyCheckResult(
            is_reentrancy_attack=is_attack,
            reentered_pool=addr,
            call_depth=depth,
            threat_severity=severity
        )

    def exit_pool_callback(self, pool_address: str) -> None:
        addr = pool_address.lower()
        if addr in self._in_flight_calls:
            self._in_flight_calls[addr] = max(0, self._in_flight_calls[addr] - 1)
