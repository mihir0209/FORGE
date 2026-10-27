"""
FORGE BGP Anycast & Geolocation Time-of-Flight (ToF) Physical Travel Anomaly Sentinel
Detects impossible physical travel velocities and fiber speed-of-light physical latency
violations between sequential authenticated user sessions across disparate geographic regions.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
import math


@dataclass
class GeoCoordinates:
    latitude: float
    longitude: float
    city: str
    country_code: str
    asn: Optional[int] = None
    ip_address: Optional[str] = None


@dataclass
class SessionAccessEvent:
    session_id: str
    user_id: str
    timestamp_epoch_sec: float
    coords: GeoCoordinates
    reported_rtt_ms: Optional[float] = None
    tls_cipher: Optional[str] = None


@dataclass
class TravelAnomalyAssessment:
    is_impossible_travel: bool
    is_latency_anomaly: bool
    travel_speed_kmh: float
    great_circle_distance_km: float
    time_delta_seconds: float
    risk_level: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    anomaly_reasons: List[str]
    suggested_action: str  # "STEP_UP_MFA", "FORCE_LOGOUT", "NOTIFY_SEC_OPS", "ALLOW"
    confidence_score: float


class ToFTravelSentinel:
    """
    Evaluates successive authentication events for a given identity
    using Haversine geodesic distance and relativistic network bounds.
    """

    EARTH_RADIUS_KM = 6371.0
    MAX_COMMERCIAL_SPEED_KMH = 950.0  # Commercial flight cruising speed + buffers
    MIN_FLIGHT_TRANSIT_GRACE_SEC = 1800.0  # 30-minute minimal airport turnaround grace
    FIBER_PROPAGATION_SPEED_KM_PER_MS = 200.0  # ~ c / 1.52 refractive index of optical silica

    def __init__(self, velocity_threshold_kmh: float = 950.0):
        self.velocity_threshold_kmh = velocity_threshold_kmh

    @staticmethod
    def calculate_haversine_distance(coord1: GeoCoordinates, coord2: GeoCoordinates) -> float:
        """
        Calculates Great-Circle distance between two points on a spherical Earth (in km).
        """
        lat1_rad = math.radians(coord1.latitude)
        lon1_rad = math.radians(coord1.longitude)
        lat2_rad = math.radians(coord2.latitude)
        lon2_rad = math.radians(coord2.longitude)

        dlat = lat2_rad - lat1_rad
        dlon = lon2_rad - lon1_rad

        a = math.sin(dlat / 2.0) ** 2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2.0) ** 2
        c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
        return ToFTravelSentinel.EARTH_RADIUS_KM * c

    def evaluate_travel_velocity(
        self, prev_event: SessionAccessEvent, curr_event: SessionAccessEvent
    ) -> TravelAnomalyAssessment:
        """
        Analyzes pair of chronological session events for velocity and latency anomalies.
        """
        if curr_event.timestamp_epoch_sec < prev_event.timestamp_epoch_sec:
            # Handle out-of-order events by swapping
            prev_event, curr_event = curr_event, prev_event

        time_delta = curr_event.timestamp_epoch_sec - prev_event.timestamp_epoch_sec
        dist_km = self.calculate_haversine_distance(prev_event.coords, curr_event.coords)

        anomaly_reasons: List[str] = []
        is_impossible = False
        is_latency_viol = False
        speed_kmh = 0.0

        if dist_km > 50.0:  # Ignore micro-movements within same metro area
            if time_delta <= 0:
                speed_kmh = float("inf")
                is_impossible = True
                anomaly_reasons.append(
                    f"Simultaneous access from distinct geographies: {dist_km:.1f} km apart with zero elapsed time."
                )
            else:
                speed_kmh = (dist_km / time_delta) * 3600.0
                if speed_kmh > self.velocity_threshold_kmh:
                    is_impossible = True
                    anomaly_reasons.append(
                        f"Calculated travel velocity of {speed_kmh:.1f} km/h exceeds physical commercial limit of {self.velocity_threshold_kmh} km/h ({dist_km:.1f} km in {time_delta:.0f}s)."
                    )

        # Fiber Time-of-Flight validation if RTT reported
        if curr_event.reported_rtt_ms is not None and dist_km > 200.0:
            # Minimum theoretical RTT round-trip is 2 * (dist_km / FIBER_SPEED)
            min_theoretical_rtt = 2.0 * (dist_km / self.FIBER_PROPAGATION_SPEED_KM_PER_MS)
            if curr_event.reported_rtt_ms < min_theoretical_rtt * 0.7:  # Allow 30% margin for direct links
                is_latency_viol = True
                anomaly_reasons.append(
                    f"Reported RTT ({curr_event.reported_rtt_ms} ms) physically violates optical light propagation lower bound ({min_theoretical_rtt:.1f} ms for {dist_km:.1f} km)."
                )

        # Determine risk level and suggested action
        if is_impossible and is_latency_viol:
            risk_level = "CRITICAL"
            suggested_action = "FORCE_LOGOUT"
            confidence = 0.98
        elif is_impossible:
            risk_level = "HIGH" if speed_kmh > 2000.0 else "MEDIUM"
            suggested_action = "STEP_UP_MFA"
            confidence = min(0.95, 0.70 + (speed_kmh / 5000.0) * 0.25)
        elif is_latency_viol:
            risk_level = "HIGH"
            suggested_action = "STEP_UP_MFA"
            confidence = 0.90
        else:
            risk_level = "LOW"
            suggested_action = "ALLOW"
            confidence = 0.95

        return TravelAnomalyAssessment(
            is_impossible_travel=is_impossible,
            is_latency_anomaly=is_latency_viol,
            travel_speed_kmh=speed_kmh,
            great_circle_distance_km=dist_km,
            time_delta_seconds=time_delta,
            risk_level=risk_level,
            anomaly_reasons=anomaly_reasons,
            suggested_action=suggested_action,
            confidence_score=confidence,
        )
