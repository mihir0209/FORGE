from dataclasses import dataclass

@dataclass
class CardTestingGovernorResult:
    quarantine_terminal: bool
    decline_rate_pct: float
    action: str

class CardTestingVelocityGovernor:
    def evaluate_terminal_attempts(
        self,
        total_attempts: int,
        declined_attempts: int
    ) -> CardTestingGovernorResult:
        if total_attempts < 10:
            return CardTestingGovernorResult(False, 0.0, "ALLOW")

        decline_rate = (declined_attempts / total_attempts) * 100.0
        quarantine = total_attempts >= 20 and decline_rate >= 60.0
        return CardTestingGovernorResult(
            quarantine_terminal=quarantine,
            decline_rate_pct=round(decline_rate, 2),
            action="TRIP_TERMINAL_QUARANTINE" if quarantine else "ALLOW"
        )
