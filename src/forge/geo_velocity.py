"""Real-Time Geo-Velocity & Impossible Travel Anomaly Engine for FORGE."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

EARTH_RADIUS_KM = 6371.0
MAX_COMMERCIAL_FLIGHT_SPEED_KMH = 1050.0  # Cruising speed + taxi/acceleration tolerance
PROXY_HOPPING_THRESHOLD_KM = 2500.0  # Suspicious sudden jump indicating VPN switch


@dataclass
class GeoLocation:
    latitude: float
    longitude: float
    ip: str = ""
    city: str = ""
    country: str = ""


@dataclass
class GeoEvent:
    event_id: str
    user_id: str
    location: GeoLocation
    timestamp: datetime


@dataclass
class TravelAuditResult:
    is_impossible: bool
    risk_score: float  # 0.0 to 1.0
    distance_km: float
    time_delta_hours: float
    velocity_kmh: float
    reason: str
    previous_event_id: str | None = None
    current_event_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_impossible": self.is_impossible,
            "risk_score": round(self.risk_score, 4),
            "distance_km": round(self.distance_km, 2),
            "time_delta_hours": round(self.time_delta_hours, 4),
            "velocity_kmh": round(self.velocity_kmh, 2),
            "reason": self.reason,
            "previous_event_id": self.previous_event_id,
            "current_event_id": self.current_event_id,
        }


def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculates great-circle distance between two geographic coordinates in kilometers."""
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (
        math.sin(delta_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * (math.sin(delta_lambda / 2.0) ** 2)
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return EARTH_RADIUS_KM * c


class GeoVelocityDetector:
    """Tracks sequential user events and detects physically impossible travel anomalies."""

    def __init__(self, max_speed_kmh: float = MAX_COMMERCIAL_FLIGHT_SPEED_KMH) -> None:
        self.max_speed_kmh = max_speed_kmh
        self.user_history: dict[str, GeoEvent] = {}

    def evaluate_travel(self, current: GeoEvent) -> TravelAuditResult:
        prev = self.user_history.get(current.user_id)
        if prev is None:
            self.user_history[current.user_id] = current
            return TravelAuditResult(
                is_impossible=False,
                risk_score=0.0,
                distance_km=0.0,
                time_delta_hours=0.0,
                velocity_kmh=0.0,
                reason="First recorded event for user; baseline established.",
                current_event_id=current.event_id,
            )

        # Calculate time delta in hours
        t1 = prev.timestamp if prev.timestamp.tzinfo else prev.timestamp.replace(tzinfo=timezone.utc)
        t2 = current.timestamp if current.timestamp.tzinfo else current.timestamp.replace(tzinfo=timezone.utc)
        delta_seconds = (t2 - t1).total_seconds()

        # Handle out of order or simultaneous timestamps
        if delta_seconds < 0:
            return TravelAuditResult(
                is_impossible=True,
                risk_score=1.0,
                distance_km=0.0,
                time_delta_hours=0.0,
                velocity_kmh=0.0,
                reason="Clock skew / Out-of-order event sequence detected.",
                previous_event_id=prev.event_id,
                current_event_id=current.event_id,
            )

        dist_km = haversine_distance(
            prev.location.latitude,
            prev.location.longitude,
            current.location.latitude,
            current.location.longitude,
        )

        # Simultaneous events from distinct locations (> 20 km apart within 30 seconds)
        if delta_seconds <= 30.0 and dist_km > 20.0:
            self.user_history[current.user_id] = current
            return TravelAuditResult(
                is_impossible=True,
                risk_score=1.0,
                distance_km=dist_km,
                time_delta_hours=delta_seconds / 3600.0,
                velocity_kmh=float("inf"),
                reason=f"Concurrent actions from locations {dist_km:.1f} km apart within {delta_seconds:.0f}s (impossible physical concurrency).",
                previous_event_id=prev.event_id,
                current_event_id=current.event_id,
            )

        time_hours = max(delta_seconds / 3600.0, 1.0 / 3600.0)  # Min 1 second denominator
        velocity = dist_km / time_hours

        # Update last known location
        self.user_history[current.user_id] = current

        # Impossible flight velocity
        if velocity > self.max_speed_kmh:
            # Risk scales with excess velocity
            excess_ratio = min((velocity / self.max_speed_kmh), 10.0)
            risk = min(0.7 + (excess_ratio / 10.0) * 0.3, 1.0)
            return TravelAuditResult(
                is_impossible=True,
                risk_score=risk,
                distance_km=dist_km,
                time_delta_hours=time_hours,
                velocity_kmh=velocity,
                reason=f"Impossible travel speed: {velocity:.1f} km/h over {dist_km:.1f} km in {time_hours * 60:.1f} mins exceeds max physical limit {self.max_speed_kmh} km/h.",
                previous_event_id=prev.event_id,
                current_event_id=current.event_id,
            )

        # Proxy hopping warning (> 2500 km in under 15 minutes)
        if dist_km > PROXY_HOPPING_THRESHOLD_KM and time_hours < 0.25:
            return TravelAuditResult(
                is_impossible=True,
                risk_score=0.9,
                distance_km=dist_km,
                time_delta_hours=time_hours,
                velocity_kmh=velocity,
                reason=f"Rapid high-distance IP relocation ({dist_km:.1f} km in {time_hours * 60:.1f} mins) indicating proxy/VPN switching.",
                previous_event_id=prev.event_id,
                current_event_id=current.event_id,
            )

        # Normal, feasible travel
        risk = min((velocity / self.max_speed_kmh) * 0.2, 0.2)
        return TravelAuditResult(
            is_impossible=False,
            risk_score=risk,
            distance_km=dist_km,
            time_delta_hours=time_hours,
            velocity_kmh=velocity,
            reason="Travel speed is within plausible physical transport boundaries.",
            previous_event_id=prev.event_id,
            current_event_id=current.event_id,
        )
