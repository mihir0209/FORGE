"""Distributed Velocity Rate Limiter & Token Bucket Registry.

Implements thread-safe sliding window transaction logs, multi-tier account policies,
channel risk weighting, and token bucket replenishment algorithms.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class AccountTier(str, Enum):
    NEW = "NEW"
    TRUSTED = "TRUSTED"
    HIGH_RISK = "HIGH_RISK"


class PaymentChannel(str, Enum):
    CARD = "CARD"
    P2P = "P2P"
    CRYPTO = "CRYPTO"
    WIRE = "WIRE"


@dataclass
class TierPolicy:
    max_tx_per_minute: int
    max_amount_per_minute: float
    max_tx_per_hour: int
    max_amount_per_hour: float
    token_capacity: float
    token_refill_per_sec: float


TIER_POLICIES: Dict[AccountTier, TierPolicy] = {
    AccountTier.NEW: TierPolicy(
        max_tx_per_minute=3,
        max_amount_per_minute=500.0,
        max_tx_per_hour=10,
        max_amount_per_hour=2000.0,
        token_capacity=5.0,
        token_refill_per_sec=0.10,  # 1 token every 10 seconds
    ),
    AccountTier.TRUSTED: TierPolicy(
        max_tx_per_minute=20,
        max_amount_per_minute=10000.0,
        max_tx_per_hour=100,
        max_amount_per_hour=100000.0,
        token_capacity=30.0,
        token_refill_per_sec=1.0,  # 1 token per second
    ),
    AccountTier.HIGH_RISK: TierPolicy(
        max_tx_per_minute=1,
        max_amount_per_minute=100.0,
        max_tx_per_hour=2,
        max_amount_per_hour=300.0,
        token_capacity=2.0,
        token_refill_per_sec=0.02,  # 1 token every 50 seconds
    ),
}

CHANNEL_WEIGHTS: Dict[PaymentChannel, float] = {
    PaymentChannel.CARD: 1.0,
    PaymentChannel.P2P: 1.0,
    PaymentChannel.CRYPTO: 1.5,
    PaymentChannel.WIRE: 2.0,
}


@dataclass
class RateLimitResult:
    allowed: bool
    reason: Optional[str] = None
    tokens_remaining: float = 0.0
    retry_after_seconds: float = 0.0
    account_tier: AccountTier = AccountTier.NEW


class VelocityRateLimiter:
    """Thread-safe velocity limiter combining sliding window logs and token buckets."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # account_id -> list of (timestamp, amount)
        self._tx_history: Dict[str, List[Tuple[float, float]]] = {}
        # account_id -> (tokens, last_refill_time)
        self._token_buckets: Dict[str, Tuple[float, float]] = {}
        # account_id -> tier
        self._account_tiers: Dict[str, AccountTier] = {}

    def set_account_tier(self, account_id: str, tier: AccountTier) -> None:
        with self._lock:
            self._account_tiers[account_id] = tier

    def check_and_consume(
        self,
        account_id: str,
        amount: float,
        channel: PaymentChannel = PaymentChannel.CARD,
        timestamp: Optional[float] = None,
    ) -> RateLimitResult:
        """Atomically checks sliding window limits and consumes rate tokens."""
        now = timestamp if timestamp is not None else time.time()

        with self._lock:
            tier = self._account_tiers.get(account_id, AccountTier.NEW)
            policy = TIER_POLICIES[tier]
            channel_weight = CHANNEL_WEIGHTS.get(channel, 1.0)
            token_cost = channel_weight

            # 1. Update Token Bucket
            if account_id not in self._token_buckets:
                current_tokens = policy.token_capacity
                last_refill = now
            else:
                tokens, last_refill = self._token_buckets[account_id]
                elapsed = max(0.0, now - last_refill)
                current_tokens = min(policy.token_capacity, tokens + elapsed * policy.token_refill_per_sec)

            if current_tokens < token_cost:
                deficit = token_cost - current_tokens
                retry_after = deficit / policy.token_refill_per_sec
                self._token_buckets[account_id] = (current_tokens, now)
                return RateLimitResult(
                    allowed=False,
                    reason=f"TOKEN_BUCKET_EXHAUSTED: required {token_cost}, available {current_tokens:.2f}",
                    tokens_remaining=current_tokens,
                    retry_after_seconds=retry_after,
                    account_tier=tier,
                )

            # 2. Check Sliding Windows (60s and 3600s)
            if account_id not in self._tx_history:
                self._tx_history[account_id] = []

            # Prune events older than 1 hour
            cutoff_1h = now - 3600.0
            self._tx_history[account_id] = [
                (ts, amt) for ts, amt in self._tx_history[account_id] if ts >= cutoff_1h
            ]

            # 1-minute window
            cutoff_1m = now - 60.0
            tx_1m = [(ts, amt) for ts, amt in self._tx_history[account_id] if ts >= cutoff_1m]
            count_1m = len(tx_1m)
            amount_1m = sum(amt for _, amt in tx_1m)

            if count_1m >= policy.max_tx_per_minute:
                return RateLimitResult(
                    allowed=False,
                    reason=f"RATE_LIMIT_TX_PER_MINUTE_EXCEEDED: {count_1m}/{policy.max_tx_per_minute}",
                    tokens_remaining=current_tokens,
                    retry_after_seconds=max(1.0, 60.0 - (now - tx_1m[0][0])),
                    account_tier=tier,
                )

            if amount_1m + amount > policy.max_amount_per_minute:
                return RateLimitResult(
                    allowed=False,
                    reason=f"RATE_LIMIT_VOLUME_PER_MINUTE_EXCEEDED: {amount_1m + amount:.2f}/{policy.max_amount_per_minute}",
                    tokens_remaining=current_tokens,
                    retry_after_seconds=30.0,
                    account_tier=tier,
                )

            # 1-hour window
            count_1h = len(self._tx_history[account_id])
            amount_1h = sum(amt for _, amt in self._tx_history[account_id])

            if count_1h >= policy.max_tx_per_hour:
                return RateLimitResult(
                    allowed=False,
                    reason=f"RATE_LIMIT_TX_PER_HOUR_EXCEEDED: {count_1h}/{policy.max_tx_per_hour}",
                    tokens_remaining=current_tokens,
                    retry_after_seconds=120.0,
                    account_tier=tier,
                )

            if amount_1h + amount > policy.max_amount_per_hour:
                return RateLimitResult(
                    allowed=False,
                    reason=f"RATE_LIMIT_VOLUME_PER_HOUR_EXCEEDED: {amount_1h + amount:.2f}/{policy.max_amount_per_hour}",
                    tokens_remaining=current_tokens,
                    retry_after_seconds=300.0,
                    account_tier=tier,
                )

            # 3. Successful consumption
            current_tokens -= token_cost
            self._token_buckets[account_id] = (current_tokens, now)
            self._tx_history[account_id].append((now, amount))

            return RateLimitResult(
                allowed=True,
                tokens_remaining=current_tokens,
                retry_after_seconds=0.0,
                account_tier=tier,
            )
