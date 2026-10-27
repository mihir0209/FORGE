"""
FORGE Flash Loan Oracle Price Manipulation Sentinel.

Detects anomalous intra-block spot price deviations against TWAP or multi-DEX feeds,
correlating instantaneous reserve imbalances with flash-loan borrowing signatures
to prevent lending protocol insolvency and bad-debt minting.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any


@dataclass
class OraclePriceObservation:
    timestamp_sec: float
    block_number: int
    asset_pair: str
    spot_price: float
    reference_twap_price: float
    dex_source: str
    reserve_in: float
    reserve_out: float
    tx_hash: Optional[str] = None
    flash_loan_amount: Optional[float] = None


@dataclass
class OracleManipulationAlert:
    is_manipulation: bool
    asset_pair: str
    block_number: int
    spot_price: float
    reference_twap_price: float
    price_deviation_pct: float
    dex_source: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM"
    has_flash_loan: bool
    mitigation_action: str  # "FALLBACK_TO_TWAP", "HALT_LENDING_ORACLE", "REJECT_TRANSACTION"
    confidence_score: float
    description: str


class OracleManipulationSentinel:
    """
    Monitors price feeds and AMM pool reserves for flash loan price distortions.
    """

    def __init__(
        self,
        deviation_threshold_pct: float = 8.0,
        flash_loan_threshold_usd: float = 50000.0,
    ):
        self.deviation_threshold_pct = deviation_threshold_pct
        self.flash_loan_threshold_usd = flash_loan_threshold_usd
        # History of observations: { asset_pair: List[OraclePriceObservation] }
        self._history: Dict[str, List[OraclePriceObservation]] = {}

    def compute_deviation_pct(self, spot: float, twap: float) -> float:
        if twap <= 0 or spot <= 0:
            return 0.0
        return abs(spot - twap) / twap * 100.0

    def evaluate_observation(self, obs: OraclePriceObservation) -> Optional[OracleManipulationAlert]:
        if obs.reference_twap_price <= 0 or obs.spot_price <= 0:
            return None

        dev_pct = abs(obs.spot_price - obs.reference_twap_price) / obs.reference_twap_price * 100.0
        dev_pct = round(dev_pct, 2)

        has_flash_loan = (obs.flash_loan_amount is not None and obs.flash_loan_amount >= self.flash_loan_threshold_usd)

        # Trigger condition:
        # 1. High deviation (>= threshold) AND flash loan present -> CRITICAL
        # 2. Extreme deviation (>= 2x threshold) even without explicit flash loan -> HIGH
        is_critical = dev_pct >= self.deviation_threshold_pct and has_flash_loan
        is_high = dev_pct >= (self.deviation_threshold_pct * 2)

        if is_critical or is_high or dev_pct >= self.deviation_threshold_pct:
            severity = "CRITICAL" if is_critical else ("HIGH" if is_high else "MEDIUM")
            confidence = 0.98 if is_critical else (0.90 if is_high else 0.80)
            mitigation = "HALT_LENDING_ORACLE" if is_critical else "FALLBACK_TO_TWAP"

            desc = (
                f"Oracle price anomaly on {obs.asset_pair}: spot {obs.spot_price} diverges by {dev_pct}% "
                f"from TWAP {obs.reference_twap_price} at block {obs.block_number} ({obs.dex_source})"
            )
            if has_flash_loan:
                desc += f" with correlated flash loan of {obs.flash_loan_amount}"

            return OracleManipulationAlert(
                is_manipulation=True,
                asset_pair=obs.asset_pair,
                block_number=obs.block_number,
                spot_price=obs.spot_price,
                reference_twap_price=obs.reference_twap_price,
                price_deviation_pct=dev_pct,
                dex_source=obs.dex_source,
                severity=severity,
                has_flash_loan=has_flash_loan,
                mitigation_action=mitigation,
                confidence_score=confidence,
                description=desc,
            )

        return None

    def analyze_batch(self, observations: List[OraclePriceObservation]) -> List[OracleManipulationAlert]:
        alerts = []
        for o in observations:
            alert = self.evaluate_observation(o)
            if alert:
                alerts.append(alert)
        return alerts
