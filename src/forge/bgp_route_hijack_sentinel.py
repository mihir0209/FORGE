from dataclasses import dataclass
from typing import List

@dataclass
class BgpHijackAlert:
    is_hijack_suspected: bool
    anomaly_reason: str
    severity: str

class BgpRouteHijackSentinel:
    def evaluate_route_announcement(
        self,
        prefix: str,
        prefix_len: int,
        origin_as: int,
        authorized_origin_as: int,
        as_path: List[int]
    ) -> BgpHijackAlert:
        # Check MOAS / unauthorized origin
        if origin_as != authorized_origin_as:
            return BgpHijackAlert(
                is_hijack_suspected=True,
                anomaly_reason=f"UNAUTHORIZED_ORIGIN_AS_{origin_as}_EXPECTED_{authorized_origin_as}",
                severity="CRITICAL"
            )

        # Check sub-prefix hijacking (> /24)
        if prefix_len > 24:
            return BgpHijackAlert(
                is_hijack_suspected=True,
                anomaly_reason=f"INVALID_PREFIX_LENGTH_EXCEEDS_24_{prefix_len}",
                severity="HIGH"
            )

        return BgpHijackAlert(
            is_hijack_suspected=False,
            anomaly_reason="VALID_RPKI_ALIGNED",
            severity="NORMAL"
        )
