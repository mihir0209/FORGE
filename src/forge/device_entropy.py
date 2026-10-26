"""Device Fingerprint Entropy & Anti-Detect Browser Sentinel.

Evaluates multi-dimensional hardware, canvas, WebGL, and audio context telemetry to detect
automated bot suites, stealth scrapers (Puppeteer-stealth, Playwright), and anti-detect browser
profiles (Multilogin, GoLogin, Dolphin{anty}) spoofing client identity.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DeviceProfile:
    device_id: str
    user_agent: str
    platform: str
    hardware_concurrency: int
    device_memory_gb: Optional[float]
    webgl_vendor: str
    webgl_renderer: str
    canvas_hash: str
    audio_jitter_ms: float  # microscopic variance in audio buffer processing


@dataclass
class DeviceEntropyReport:
    device_id: str
    spoofing_detected: bool
    entropy_score: float  # 0.0 (synthetic/spoofed) to 1.0 (authentic)
    anomalies: List[str]
    risk_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"


class DeviceEntropyClassifier:
    """Classifies client device profiles for fingerprint spoofing and emulation markers."""

    # Known dummy / generic canvas hashes produced by naive headless stealth scripts
    SUSPICIOUS_CANVAS_HASHES = {
        "0000000000000000",
        "deadbeefdeadbeef",
        "c4ca4238a0b92382",
        "canvas_blocked",
        "",
    }

    def evaluate_profile(self, profile: DeviceProfile) -> DeviceEntropyReport:
        anomalies: List[str] = []

        # 1. Platform vs User-Agent Consistency Check
        ua_lower = profile.user_agent.lower()
        plat_lower = profile.platform.lower()

        if "windows" in ua_lower and "win" not in plat_lower:
            anomalies.append(f"OS mismatch: User-Agent claims Windows but platform is '{profile.platform}'")
        elif "macintosh" in ua_lower and "mac" not in plat_lower:
            anomalies.append(f"OS mismatch: User-Agent claims Mac but platform is '{profile.platform}'")
        elif "linux" in ua_lower and "android" not in ua_lower and "linux" not in plat_lower:
            anomalies.append(f"OS mismatch: User-Agent claims Linux but platform is '{profile.platform}'")

        # 2. WebGL Renderer vs Platform Consistency
        renderer_lower = profile.webgl_renderer.lower()
        if "apple" in renderer_lower and "mac" not in plat_lower and "iphone" not in plat_lower:
            anomalies.append(f"WebGL mismatch: Apple GPU renderer on non-Apple platform '{profile.platform}'")
        if "mali" in renderer_lower and "android" not in ua_lower and "linux arm" not in plat_lower:
            anomalies.append(f"WebGL mismatch: Mobile ARM Mali GPU renderer on desktop User-Agent")

        # 3. Hardware Concurrency Sanity
        if profile.hardware_concurrency <= 0 or profile.hardware_concurrency > 64:
            anomalies.append(f"Unrealistic hardware concurrency: {profile.hardware_concurrency} cores")

        # 4. Canvas Hash Check
        if profile.canvas_hash.lower() in self.SUSPICIOUS_CANVAS_HASHES or len(profile.canvas_hash) < 8:
            anomalies.append(f"Synthetic or blocked canvas fingerprint hash: '{profile.canvas_hash}'")

        # 5. Audio Context Jitter (OfflineAudioContext Mocking Check)
        # Synthetic anti-detect browsers often mock audio by returning a flat constant 0.0ms jitter
        if profile.audio_jitter_ms == 0.0:
            anomalies.append("Zero audio oscillator jitter: characteristic of synthetic audio context mocking")

        # Scoring
        # Start at 1.0, penalize for each anomaly
        penalty = len(anomalies) * 0.25
        entropy_score = max(0.0, min(1.0, 1.0 - penalty))
        spoofing_detected = len(anomalies) >= 2 or ("OS mismatch" in str(anomalies) and len(anomalies) >= 1)

        if entropy_score >= 0.8:
            risk_level = "LOW"
        elif entropy_score >= 0.5:
            risk_level = "MEDIUM"
        elif entropy_score >= 0.25:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        return DeviceEntropyReport(
            device_id=profile.device_id,
            spoofing_detected=spoofing_detected,
            entropy_score=round(entropy_score, 2),
            anomalies=anomalies,
            risk_level=risk_level,
        )
