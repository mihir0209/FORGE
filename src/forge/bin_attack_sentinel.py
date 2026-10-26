"""Card-Testing (BIN Attack) High-Frequency Velocity Sentinel.

Detects automated card-testing botnets probing stolen credit card numbers,
CVV permutations, and expiry dates across specific Bank Identification Numbers (BINs).
"""

from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Set, Tuple


@dataclass
class AuthAttempt:
    bin_number: str
    merchant_id: str
    card_hash: str
    approved: bool
    timestamp_epoch: float


@dataclass
class BINAttackAlert:
    bin_number: str
    merchant_id: str
    is_attack_detected: bool
    total_attempts_in_window: int
    failure_rate: float
    unique_cards: int
    recommended_mitigation: str  # NONE, CAPTCHA, THROTTLE, BLOCK_BIN


class BINAttackSentinel:
    def __init__(self, window_seconds: float = 60.0):
        self.window_seconds = window_seconds
        # Key: (bin_number, merchant_id) -> Deque of AuthAttempt
        self._history: Dict[Tuple[str, str], Deque[AuthAttempt]] = {}

    def record_auth_attempt(
        self,
        bin_number: str,
        merchant_id: str,
        card_hash: str,
        approved: bool,
        timestamp_epoch: float,
    ) -> BINAttackAlert:
        key = (bin_number, merchant_id)
        if key not in self._history:
            self._history[key] = deque()

        queue = self._history[key]
        queue.append(
            AuthAttempt(
                bin_number=bin_number,
                merchant_id=merchant_id,
                card_hash=card_hash,
                approved=approved,
                timestamp_epoch=timestamp_epoch,
            )
        )

        # Prune older than window_seconds
        cutoff = timestamp_epoch - self.window_seconds
        while queue and queue[0].timestamp_epoch < cutoff:
            queue.popleft()

        total = len(queue)
        failures = sum(1 for a in queue if not a.approved)
        failure_rate = (failures / total) if total > 0 else 0.0
        unique_cards = len(set(a.card_hash for a in queue))

        # Card-testing bot heuristic:
        # High volume of distinct cards with high failure rate indicates automated credential/PAN harvesting
        is_attack = False
        mitigation = "NONE"

        if total >= 5 and unique_cards >= 3 and failure_rate >= 0.40:
            is_attack = True
            if total >= 15 or failure_rate >= 0.70:
                mitigation = "BLOCK_BIN"
            elif total >= 8:
                mitigation = "THROTTLE"
            else:
                mitigation = "CAPTCHA"

        return BINAttackAlert(
            bin_number=bin_number,
            merchant_id=merchant_id,
            is_attack_detected=is_attack,
            total_attempts_in_window=total,
            failure_rate=round(failure_rate, 3),
            unique_cards=unique_cards,
            recommended_mitigation=mitigation,
        )
