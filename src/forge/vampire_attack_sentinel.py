"""
FORGE Vampire Attack & Liquidity Siphon Anomaly Sentinel.

Detects predatory protocol liquidity siphoning, mass LP token migration drains,
and predatory emission staking sinks to safeguard decentralized AMM reserves.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class LpMigrationEvent:
    pool_id: str
    tx_hash: str
    block_number: int
    timestamp_sec: float
    user_address: str
    destination_contract: str
    lp_tokens_unstaked: float
    underlying_usd_value: float


@dataclass
class VampireAttackAlert:
    is_vampire_attack: bool
    pool_id: str
    destination_contract: str
    total_lp_drained: float
    total_usd_drained: float
    drain_percentage: float
    severity: str  # "CRITICAL", "HIGH", "MEDIUM"
    mitigation_action: str  # "ACTIVATE_MIGRATION_TIMELOCK", "SURGE_LP_REWARDS", "ALERT_DAO"
    confidence_score: float
    description: str


class VampireAttackSentinel:
    """
    Monitors LP token flows across pools to detect coordinated vampire drains.
    """

    def __init__(
        self,
        pool_total_lp: Optional[Dict[str, float]] = None,
        pool_total_usd: Optional[Dict[str, float]] = None,
        drain_threshold_pct: float = 20.0,
        window_seconds: float = 600.0,
    ):
        self.pool_total_lp = pool_total_lp.copy() if pool_total_lp else {}
        self.pool_total_usd = pool_total_usd.copy() if pool_total_usd else {}
        self.drain_threshold_pct = drain_threshold_pct
        self.window_seconds = window_seconds

        # Sliding window history: { pool_id: List[LpMigrationEvent] }
        self._history: Dict[str, List[LpMigrationEvent]] = {}
        # Known vampire contracts flagged by security research
        self.known_vampire_sinks: Set[str] = set()

    def register_vampire_sink(self, address: str) -> None:
        self.known_vampire_sinks.add(address.lower())

    def process_event(self, event: LpMigrationEvent) -> Optional[VampireAttackAlert]:
        p = event.pool_id
        if p not in self._history:
            self._history[p] = []
        self._history[p].append(event)

        cutoff = event.timestamp_sec - self.window_seconds
        self._history[p] = [e for e in self._history[p] if e.timestamp_sec >= cutoff]

        window_events = self._history[p]
        total_lp_drained = sum(e.lp_tokens_unstaked for e in window_events)
        total_usd_drained = sum(e.underlying_usd_value for e in window_events)

        total_lp_pool = self.pool_total_lp.get(p, max(1.0, total_lp_drained * 2))
        total_usd_pool = self.pool_total_usd.get(p, max(1.0, total_usd_drained * 2))

        drain_pct = (total_lp_drained / total_lp_pool) * 100.0
        drain_pct = round(drain_pct, 2)

        is_known_sink = event.destination_contract.lower() in self.known_vampire_sinks
        is_drain_exceeded = drain_pct >= self.drain_threshold_pct

        if is_drain_exceeded or is_known_sink:
            is_critical = drain_pct >= 40.0 or (is_known_sink and drain_pct >= 15.0)
            severity = "CRITICAL" if is_critical else "HIGH"
            confidence = 0.98 if is_known_sink else 0.88
            mitigation = "ACTIVATE_MIGRATION_TIMELOCK" if is_critical else "SURGE_LP_REWARDS"

            dest = event.destination_contract
            desc = (
                f"Coordinated liquidity vampire drain on pool {p}: {drain_pct}% LP supply "
                f"(${total_usd_drained:,.2f}) diverted to {dest}"
            )

            return VampireAttackAlert(
                is_vampire_attack=True,
                pool_id=p,
                destination_contract=dest,
                total_lp_drained=total_lp_drained,
                total_usd_drained=total_usd_drained,
                drain_percentage=drain_pct,
                severity=severity,
                mitigation_action=mitigation,
                confidence_score=confidence,
                description=desc,
            )

        return None

    def analyze_batch(self, events: List[LpMigrationEvent]) -> List[VampireAttackAlert]:
        alerts = []
        for ev in events:
            alert = self.process_event(ev)
            if alert:
                alerts.append(alert)
        return alerts
