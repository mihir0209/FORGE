from dataclasses import dataclass

@dataclass
class BinAttackGovernorAlert:
    quarantine_bin_prefix: bool
    bin_prefix: str
    failure_rate_pct: float
    action: str

class BinAttackQuarantineGovernor:
    def __init__(self, velocity_threshold: int = 20, max_failure_rate_pct: float = 70.0):
        self.velocity_threshold = velocity_threshold
        self.max_failure_rate_pct = max_failure_rate_pct

    def evaluate_bin_stream(
        self,
        bin_prefix: str, # First 6 or 8 digits
        total_attempts_60s: int,
        failed_attempts_60s: int
    ) -> BinAttackGovernorAlert:
        if total_attempts_60s < self.velocity_threshold:
            return BinAttackGovernorAlert(False, bin_prefix, 0.0, "ALLOW")

        fail_pct = (failed_attempts_60s / total_attempts_60s) * 100.0
        is_attack = fail_pct >= self.max_failure_rate_pct

        return BinAttackGovernorAlert(
            quarantine_bin_prefix=is_attack,
            bin_prefix=bin_prefix,
            failure_rate_pct=round(fail_pct, 1),
            action="QUARANTINE_BIN_RANGE_60M" if is_attack else "ALLOW"
        )
