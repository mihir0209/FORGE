"""Unit & Adversarial Tests for Distributed Velocity Rate Limiter."""

import concurrent.futures
import pytest
import time
from forge.velocity_limiter import (
    VelocityRateLimiter,
    AccountTier,
    PaymentChannel,
)


def test_new_account_transaction_rate_limit():
    limiter = VelocityRateLimiter()
    acc = "acc_new_01"
    now = time.time()

    # 3 allowed txs within 1 minute
    res1 = limiter.check_and_consume(acc, 50.0, timestamp=now)
    assert res1.allowed
    res2 = limiter.check_and_consume(acc, 50.0, timestamp=now + 5)
    assert res2.allowed
    res3 = limiter.check_and_consume(acc, 50.0, timestamp=now + 10)
    assert res3.allowed

    # 4th transaction within same minute is rejected
    res4 = limiter.check_and_consume(acc, 50.0, timestamp=now + 15)
    assert not res4.allowed
    assert "RATE_LIMIT_TX_PER_MINUTE_EXCEEDED" in str(res4.reason)

    # After 65 seconds, 1 minute window has rolled forward
    res5 = limiter.check_and_consume(acc, 50.0, timestamp=now + 65)
    assert res5.allowed


def test_volume_velocity_limit():
    limiter = VelocityRateLimiter()
    acc = "acc_vol_02"
    now = time.time()

    # $450 allowed ($500 cap)
    res1 = limiter.check_and_consume(acc, 450.0, timestamp=now)
    assert res1.allowed

    # Next $60 brings total to $510 -> rejected
    res2 = limiter.check_and_consume(acc, 60.0, timestamp=now + 5)
    assert not res2.allowed
    assert "RATE_LIMIT_VOLUME_PER_MINUTE_EXCEEDED" in str(res2.reason)


def test_tier_differentiation():
    limiter = VelocityRateLimiter()
    trusted_acc = "acc_trusted_03"
    high_risk_acc = "acc_high_risk_04"

    limiter.set_account_tier(trusted_acc, AccountTier.TRUSTED)
    limiter.set_account_tier(high_risk_acc, AccountTier.HIGH_RISK)

    now = time.time()

    # Trusted account easily handles $5,000 transaction
    res_trusted = limiter.check_and_consume(trusted_acc, 5000.0, timestamp=now)
    assert res_trusted.allowed

    # High-risk account rejects > $100 transaction
    res_hr_fail = limiter.check_and_consume(high_risk_acc, 150.0, timestamp=now)
    assert not res_hr_fail.allowed

    # High-risk account allows $50 transaction
    res_hr_ok = limiter.check_and_consume(high_risk_acc, 50.0, timestamp=now)
    assert res_hr_ok.allowed


def test_token_bucket_replenishment():
    limiter = VelocityRateLimiter()
    acc = "acc_token_05"
    now = time.time()

    # Wire channel costs 2.0 tokens (capacity is 5.0 tokens)
    res1 = limiter.check_and_consume(acc, 10.0, channel=PaymentChannel.WIRE, timestamp=now)
    assert res1.allowed
    assert res1.tokens_remaining == 3.0

    res2 = limiter.check_and_consume(acc, 10.0, channel=PaymentChannel.WIRE, timestamp=now)
    assert res2.allowed
    assert res2.tokens_remaining == 1.0

    # 3rd wire requires 2.0 tokens, only 1.0 available -> bucket exhausted
    res3 = limiter.check_and_consume(acc, 10.0, channel=PaymentChannel.WIRE, timestamp=now)
    assert not res3.allowed
    assert "TOKEN_BUCKET_EXHAUSTED" in str(res3.reason)

    # After 15 seconds, tokens refill (0.1 token/sec * 15s = +1.5 tokens -> total 2.5)
    res4 = limiter.check_and_consume(acc, 10.0, channel=PaymentChannel.WIRE, timestamp=now + 15)
    assert res4.allowed


def test_multithreaded_concurrency_race_safety():
    limiter = VelocityRateLimiter()
    acc = "acc_concurrent_06"
    limiter.set_account_tier(acc, AccountTier.TRUSTED)
    # Trusted capacity: 20 tx/min, 30 tokens

    success_count = 0
    failure_count = 0

    def worker():
        nonlocal success_count, failure_count
        res = limiter.check_and_consume(acc, 100.0)
        if res.allowed:
            success_count += 1
        else:
            failure_count += 1

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(worker) for _ in range(30)]
        concurrent.futures.wait(futures)

    # At most 20 transactions can succeed within 1 minute
    assert success_count <= 20
    assert success_count + failure_count == 30
