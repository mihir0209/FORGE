from dataclasses import dataclass
from typing import Dict, List

@dataclass
class LoginVelocityResult:
    is_credential_stuffing: bool
    failed_count: int
    lockout_seconds: int
    risk_score: float

class AtoLoginVelocitySentinel:
    def __init__(self, failure_threshold: int = 5, base_lockout_sec: int = 30):
        self.failure_threshold = failure_threshold
        self.base_lockout_sec = base_lockout_sec

    def evaluate_account_attempts(self, failed_attempts_window: int, unique_ip_count: int) -> LoginVelocityResult:
        is_attack = failed_attempts_window >= self.failure_threshold
        # Exponential backoff lockout based on severity
        lockout = (self.base_lockout_sec * (2 ** min(5, failed_attempts_window - self.failure_threshold))) if is_attack else 0
        risk = min(1.0, (failed_attempts_window / self.failure_threshold) * 0.5 + (unique_ip_count * 0.1))

        return LoginVelocityResult(
            is_credential_stuffing=is_attack or unique_ip_count >= 4,
            failed_count=failed_attempts_window,
            lockout_seconds=lockout,
            risk_score=round(risk, 2)
        )
