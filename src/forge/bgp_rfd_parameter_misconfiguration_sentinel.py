from dataclasses import dataclass

@dataclass
class RfdParameterAlert:
    is_flapping_route_suppressed: bool
    accumulated_penalty: float
    current_status: str

class BgpRfdParameterSentinel:
    def evaluate_route_flaps(
        self,
        flap_count: int,
        suppress_threshold: float = 2000.0,
        reuse_threshold: float = 750.0,
        half_life_minutes: float = 15.0
    ) -> RfdParameterAlert:
        # RFC 2439: Each flap adds 1000 penalty points
        penalty = flap_count * 1000.0
        is_suppressed = penalty >= suppress_threshold
        status = "ROUTE_SUPPRESSED_FLAP_DAMPED" if is_suppressed else "ACTIVE_STABLE"

        return RfdParameterAlert(
            is_flapping_route_suppressed=is_suppressed,
            accumulated_penalty=round(penalty, 1),
            current_status=status
        )
