"""
FORGE Cross-Chain Bridge Liquidity Drain & Reentrancy Siphon Sentinel
Detects anomalous cross-chain liquidity drains, unbacked synthetic token minting,
proof replay double-spends, and generates automated circuit-breaker trip signals.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class BridgeTransferEvent:
    tx_hash: str
    bridge_id: str
    source_chain: str
    target_chain: str
    token_symbol: str
    amount: float
    sender_address: str
    recipient_address: str
    timestamp_sec: float
    proof_nonce: int
    is_synthetic_mint: bool = False


@dataclass
class BridgeDrainAlert:
    is_drain_attack: bool
    bridge_id: str
    suspect_address: str
    total_drained_amount: float
    depletion_ratio: float
    drain_velocity_per_min: float
    attack_vector: str  # "RAPID_DRAIN_BURST", "PROOF_REPLAY_DOUBLE_SPEND", "UNBACKED_SYNTHETIC_MINT", "ASYMMETRIC_SOLVENCY_COLLAPSE"
    circuit_breaker_triggered: bool
    risk_severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    tx_hashes: List[str]


class BridgeDrainSentinel:
    """
    Monitors cross-chain bridge events in real-time to defend against
    liquidity vacuuming, reentrancy drain loops, and proof replay exploits.
    """

    def __init__(
        self,
        pool_reserves: Optional[Dict[str, float]] = None,
        window_seconds: float = 300.0,
        max_depletion_threshold: float = 0.20,  # 20% drain within window triggers alert
        velocity_spike_threshold: float = 5000.0,  # tokens per minute
    ):
        self.pool_reserves: Dict[str, float] = pool_reserves.copy() if pool_reserves else {}
        self.initial_reserves: Dict[str, float] = self.pool_reserves.copy()
        self.window_seconds: float = window_seconds
        self.max_depletion_threshold: float = max_depletion_threshold
        self.velocity_spike_threshold: float = velocity_spike_threshold

        self._history: Dict[str, List[BridgeTransferEvent]] = {}
        self._seen_nonces: Dict[Tuple[str, int], str] = {}
        self._synthetic_minted: Dict[str, float] = {}

    def set_reserve(self, bridge_id: str, reserve: float) -> None:
        self.pool_reserves[bridge_id] = reserve
        if bridge_id not in self.initial_reserves:
            self.initial_reserves[bridge_id] = reserve

    def process_transfer(self, transfer: BridgeTransferEvent) -> Optional[BridgeDrainAlert]:
        """
        Process a single transfer event and check for immediate exploit patterns.
        """
        b_id = transfer.bridge_id
        current_res = self.pool_reserves.get(b_id, 0.0)

        # 1. Check for Proof Replay / Nonce Double Spend
        nonce_key = (b_id, transfer.proof_nonce)
        if nonce_key in self._seen_nonces and self._seen_nonces[nonce_key] != transfer.tx_hash:
            return BridgeDrainAlert(
                is_drain_attack=True,
                bridge_id=b_id,
                suspect_address=transfer.recipient_address or transfer.sender_address,
                total_drained_amount=transfer.amount,
                depletion_ratio=transfer.amount / max(1.0, current_res),
                drain_velocity_per_min=0.0,
                attack_vector="PROOF_REPLAY_DOUBLE_SPEND",
                circuit_breaker_triggered=True,
                risk_severity="CRITICAL",
                tx_hashes=[self._seen_nonces[nonce_key], transfer.tx_hash],
            )
        self._seen_nonces[nonce_key] = transfer.tx_hash

        # 2. Check for Unbacked Synthetic Mint
        if transfer.is_synthetic_mint:
            self._synthetic_minted[b_id] = self._synthetic_minted.get(b_id, 0.0) + transfer.amount
            if self._synthetic_minted[b_id] > current_res:
                return BridgeDrainAlert(
                    is_drain_attack=True,
                    bridge_id=b_id,
                    suspect_address=transfer.recipient_address,
                    total_drained_amount=transfer.amount,
                    depletion_ratio=transfer.amount / max(1.0, current_res),
                    drain_velocity_per_min=0.0,
                    attack_vector="UNBACKED_SYNTHETIC_MINT",
                    circuit_breaker_triggered=True,
                    risk_severity="CRITICAL",
                    tx_hashes=[transfer.tx_hash],
                )

        # Add to window history
        if b_id not in self._history:
            self._history[b_id] = []
        self._history[b_id].append(transfer)

        # Prune events outside sliding window
        cutoff = transfer.timestamp_sec - self.window_seconds
        self._history[b_id] = [ev for ev in self._history[b_id] if ev.timestamp_sec >= cutoff]

        # 3. Check for Rapid Drain Burst across window
        window_events = self._history[b_id]
        total_drained = sum(ev.amount for ev in window_events)
        init_res = self.initial_reserves.get(b_id, max(1.0, current_res))
        depletion_ratio = total_drained / max(1.0, init_res)

        if len(window_events) >= 2:
            time_span = max(1.0, window_events[-1].timestamp_sec - window_events[0].timestamp_sec)
            velocity_per_min = (total_drained / time_span) * 60.0
        else:
            time_span = self.window_seconds
            velocity_per_min = (total_drained / self.window_seconds) * 60.0

        is_depleted = depletion_ratio >= self.max_depletion_threshold
        is_velocity_spike = (
            len(window_events) >= 2
            and velocity_per_min >= self.velocity_spike_threshold
            and depletion_ratio >= 0.10
        )

        if is_depleted or is_velocity_spike:
            address_vol: Dict[str, float] = {}
            for ev in window_events:
                addr = ev.recipient_address or ev.sender_address
                address_vol[addr] = address_vol.get(addr, 0.0) + ev.amount
            suspect = max(address_vol, key=address_vol.get) if address_vol else transfer.sender_address

            is_critical = depletion_ratio >= 0.40 or velocity_per_min >= (self.velocity_spike_threshold * 2)

            return BridgeDrainAlert(
                is_drain_attack=True,
                bridge_id=b_id,
                suspect_address=suspect,
                total_drained_amount=total_drained,
                depletion_ratio=round(depletion_ratio, 4),
                drain_velocity_per_min=round(velocity_per_min, 2),
                attack_vector="RAPID_DRAIN_BURST",
                circuit_breaker_triggered=is_critical,
                risk_severity="CRITICAL" if is_critical else "HIGH",
                tx_hashes=[ev.tx_hash for ev in window_events],
            )

        return None

    def analyze_batch(self, transfers: List[BridgeTransferEvent]) -> List[BridgeDrainAlert]:
        alerts = []
        for t in transfers:
            alert = self.process_transfer(t)
            if alert:
                alerts.append(alert)
        return alerts
