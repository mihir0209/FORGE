"""Account Takeover (ATO) Session Hijacking & Device Fingerprint Drift Sentinel.

Monitors active authenticated sessions for behavioral and cryptographic drifts in
TLS fingerprints, canvas hashes, subnet ASNs, and physical travel velocity.
"""

import math
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass
class SessionFingerprint:
    session_id: str
    user_id: str
    ja3_hash: str
    canvas_hash: str
    user_agent: str
    ip_address: str
    asn: int
    latitude: float
    longitude: float
    timestamp_epoch: float


@dataclass
class ATORiskAssessment:
    session_id: str
    user_id: str
    risk_score: float  # 0.0 (benign) to 1.0 (critical hijacking)
    action: str  # ALLOW, STEP_UP_MFA, REVOKE_SESSION
    reasons: Tuple[str, ...]
    drift_detected: bool


def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculates great-circle distance between two GPS coordinates in kilometers."""
    r = 6371.0  # Earth radius in km
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = math.sin(delta_phi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * (math.sin(delta_lambda / 2.0) ** 2)
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return r * c


class ATOSessionSentinel:
    def __init__(self, max_travel_velocity_kmh: float = 850.0):
        self.max_travel_velocity_kmh = max_travel_velocity_kmh
        # Key: session_id -> SessionFingerprint
        self.active_sessions: Dict[str, SessionFingerprint] = {}

    def register_initial_session(self, fp: SessionFingerprint) -> None:
        self.active_sessions[fp.session_id] = fp

    def evaluate_session_activity(self, current: SessionFingerprint) -> ATORiskAssessment:
        baseline = self.active_sessions.get(current.session_id)
        if not baseline:
            self.active_sessions[current.session_id] = current
            return ATORiskAssessment(
                session_id=current.session_id,
                user_id=current.user_id,
                risk_score=0.0,
                action="ALLOW",
                reasons=("Initial session registration",),
                drift_detected=False,
            )

        score = 0.0
        reasons = []

        # 1. TLS JA3 Fingerprint Drift
        if current.ja3_hash != baseline.ja3_hash:
            score += 0.35
            reasons.append("TLS JA3 client fingerprint mismatch (possible proxy/curl hijack)")

        # 2. Canvas Entropy Hash Drift
        if current.canvas_hash != baseline.canvas_hash:
            score += 0.25
            reasons.append("Browser canvas rendering hash mutated mid-session")

        # 3. User-Agent Drift
        if current.user_agent != baseline.user_agent:
            score += 0.30
            reasons.append("User-Agent header abruptly altered within active cookie session")

        # 4. Autonomous System Number (ASN) Drift
        if current.asn != baseline.asn:
            score += 0.15
            reasons.append(f"Network ASN changed from {baseline.asn} to {current.asn}")

        # 5. Impossible Travel Velocity (Geographical Anomaly)
        time_diff_hours = (current.timestamp_epoch - baseline.timestamp_epoch) / 3600.0
        if time_diff_hours > 0:
            dist_km = haversine_distance_km(baseline.latitude, baseline.longitude, current.latitude, current.longitude)
            velocity = dist_km / time_diff_hours
            if velocity > self.max_travel_velocity_kmh and dist_km > 50.0:
                score += 0.45
                reasons.append(f"Impossible travel velocity: {velocity:.1f} km/h across {dist_km:.1f} km in {time_diff_hours * 60:.1f} min")

        score = min(1.0, score)
        drift_detected = score >= 0.20

        if score >= 0.70:
            action = "REVOKE_SESSION"
        elif score >= 0.30:
            action = "STEP_UP_MFA"
        else:
            action = "ALLOW"

        # Update baseline timestamp and IP for ongoing evaluation
        if action != "REVOKE_SESSION":
            self.active_sessions[current.session_id] = current

        return ATORiskAssessment(
            session_id=current.session_id,
            user_id=current.user_id,
            risk_score=round(score, 2),
            action=action,
            reasons=tuple(reasons) if reasons else ("Session parameters consistent",),
            drift_detected=drift_detected,
        )
