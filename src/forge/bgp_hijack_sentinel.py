"""
FORGE Automated BGP Hijack Countermeasure & Subnet Route Poisoning Sentinel.

Detects unauthorized AS-origin divergence (RPKI/ROA validation), more-specific
prefix deaggregation attacks, AS-path poisoning loops, and synthesizes automated
mitigation rules (null routing, route flap damping, upstream filter withdrawal).
"""

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class RoaEntry:
    prefix: str
    max_length: int
    authorized_as: int


@dataclass
class BgpRouteAnnouncement:
    prefix: str
    origin_as: int
    as_path: List[int]
    peer_ip: str
    timestamp_sec: float
    is_withdrawal: bool = False
    community_tags: List[str] = field(default_factory=list)


@dataclass
class BgpHijackAlert:
    is_hijack_alert: bool
    attack_type: str  # "RPKI_ORIGIN_MISMATCH", "MORE_SPECIFIC_SUBPREFIX_HIJACK", "AS_PATH_FORGERY_LOOP", "RAPID_FLAP_POISONING"
    prefix: str
    culprit_as: int
    legitimate_as: Optional[int]
    severity: str  # "CRITICAL", "HIGH", "MEDIUM"
    mitigation_action: str  # "NULL_ROUTE", "FILTER_AS_PATH", "ENABLE_ROUTE_FLAP_DAMPING"
    confidence_score: float
    description: str


class BgpHijackSentinel:
    """
    Analyzes live BGP announcements against validated cryptographic ROA records,
    known prefix registries, and sliding-window flap frequencies.
    """

    def __init__(
        self,
        roa_database: Optional[Dict[str, RoaEntry]] = None,
        flap_window_sec: float = 60.0,
        max_flap_threshold: int = 5,
    ):
        self.roa_db: Dict[str, RoaEntry] = roa_database.copy() if roa_database else {}
        self.flap_window_sec = flap_window_sec
        self.max_flap_threshold = max_flap_threshold

        # Flap history tracking: { prefix: List[float timestamp] }
        self._flap_history: Dict[str, List[float]] = {}
        # Active registered routing state: { prefix: BgpRouteAnnouncement }
        self._active_routes: Dict[str, BgpRouteAnnouncement] = {}

    def add_roa(self, roa: RoaEntry) -> None:
        self.roa_db[roa.prefix] = roa

    def validate_roa(self, announcement: BgpRouteAnnouncement) -> Tuple[bool, Optional[RoaEntry]]:
        """
        Validates announcement prefix and origin AS against ROA cache.
        Returns (is_valid, matching_roa).
        """
        ann_net = ipaddress.ip_network(announcement.prefix)

        for roa_net_str, roa in self.roa_db.items():
            roa_net = ipaddress.ip_network(roa_net_str)
            if ann_net.subnet_of(roa_net):
                # Subnet matches; check max length and origin AS
                length_ok = ann_net.prefixlen <= roa.max_length
                origin_ok = announcement.origin_as == roa.authorized_as
                if length_ok and origin_ok:
                    return True, roa
                else:
                    return False, roa

        # Unknown / No ROA found
        return True, None

    def process_announcement(self, ann: BgpRouteAnnouncement) -> Optional[BgpHijackAlert]:
        p = ann.prefix
        ts = ann.timestamp_sec

        # 1. Track Flapping Frequency (Route Poisoning / Flap Attack)
        if p not in self._flap_history:
            self._flap_history[p] = []
        self._flap_history[p].append(ts)
        cutoff = ts - self.flap_window_sec
        self._flap_history[p] = [t for t in self._flap_history[p] if t >= cutoff]

        if len(self._flap_history[p]) >= self.max_flap_threshold:
            return BgpHijackAlert(
                is_hijack_alert=True,
                attack_type="RAPID_FLAP_POISONING",
                prefix=p,
                culprit_as=ann.origin_as,
                legitimate_as=None,
                severity="HIGH",
                mitigation_action="ENABLE_ROUTE_FLAP_DAMPING",
                confidence_score=0.95,
                description=f"Prefix {p} flapped {len(self._flap_history[p])} times in {self.flap_window_sec}s",
            )

        if ann.is_withdrawal:
            self._active_routes.pop(p, None)
            return None

        # 2. Check AS-Path Loop / Forgery
        if len(ann.as_path) != len(set(ann.as_path)):
            # Loop detected in AS-path
            return BgpHijackAlert(
                is_hijack_alert=True,
                attack_type="AS_PATH_FORGERY_LOOP",
                prefix=p,
                culprit_as=ann.origin_as,
                legitimate_as=None,
                severity="MEDIUM",
                mitigation_action="FILTER_AS_PATH",
                confidence_score=0.90,
                description=f"Cyclic AS-path detected in announcement for {p}: {ann.as_path}",
            )

        # 3. Check ROA / RPKI Validation
        is_valid, matching_roa = self.validate_roa(ann)
        if not is_valid and matching_roa is not None:
            ann_net = ipaddress.ip_network(p)
            roa_net = ipaddress.ip_network(matching_roa.prefix)

            if ann.origin_as != matching_roa.authorized_as:
                # Direct origin hijacking
                return BgpHijackAlert(
                    is_hijack_alert=True,
                    attack_type="RPKI_ORIGIN_MISMATCH",
                    prefix=p,
                    culprit_as=ann.origin_as,
                    legitimate_as=matching_roa.authorized_as,
                    severity="CRITICAL",
                    mitigation_action="NULL_ROUTE",
                    confidence_score=0.99,
                    description=(
                        f"Unauthorized AS{ann.origin_as} announced {p} covering ROA {matching_roa.prefix} (authorized: AS{matching_roa.authorized_as})"
                    ),
                )
            elif ann_net.prefixlen > matching_roa.max_length:
                # Sub-prefix deaggregation beyond allowed max_length
                return BgpHijackAlert(
                    is_hijack_alert=True,
                    attack_type="MORE_SPECIFIC_SUBPREFIX_HIJACK",
                    prefix=p,
                    culprit_as=ann.origin_as,
                    legitimate_as=matching_roa.authorized_as,
                    severity="CRITICAL",
                    mitigation_action="NULL_ROUTE",
                    confidence_score=0.96,
                    description=(
                        f"Illegal subprefix deaggregation: {p} exceeds ROA max length /{matching_roa.max_length}"
                    ),
                )

        # 4. Check Deaggregation against currently active broader routes
        ann_net = ipaddress.ip_network(p)
        for active_p, active_route in self._active_routes.items():
            active_net = ipaddress.ip_network(active_p)
            if ann_net.subnet_of(active_net) and ann_net != active_net:
                if ann.origin_as != active_route.origin_as:
                    return BgpHijackAlert(
                        is_hijack_alert=True,
                        attack_type="MORE_SPECIFIC_SUBPREFIX_HIJACK",
                        prefix=p,
                        culprit_as=ann.origin_as,
                        legitimate_as=active_route.origin_as,
                        severity="CRITICAL",
                        mitigation_action="NULL_ROUTE",
                        confidence_score=0.98,
                        description=(
                            f"Hostile deaggregation: AS{ann.origin_as} announced /{ann_net.prefixlen} under active {active_p} owned by AS{active_route.origin_as}"
                        ),
                    )

        self._active_routes[p] = ann
        return None

    def analyze_stream(self, announcements: List[BgpRouteAnnouncement]) -> List[BgpHijackAlert]:
        alerts = []
        for a in announcements:
            alert = self.process_announcement(a)
            if alert:
                alerts.append(alert)
        return alerts
