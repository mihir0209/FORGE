"""Device Fingerprinting, Session Hijack & Browser Botnet Defense Engine.

Provides deep browser/client fingerprinting, headless botnet detection,
session cookie replay/hijack defense, and device clustering analytics.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class DeviceFingerprint:
    user_agent: str
    accept_language: str
    screen_resolution: str  # e.g., "1920x1080"
    timezone_offset: int  # minutes, e.g. -300
    canvas_hash: str
    webgl_vendor: str
    webgl_renderer: str
    ip_address: str
    asn: Optional[int] = None
    ja3_fingerprint: Optional[str] = None
    is_headless: Optional[bool] = None


@dataclass
class BotAnalysisResult:
    is_bot: bool
    risk_score: float  # 0.0 to 1.0
    flags: List[str]


@dataclass
class SessionDriftResult:
    is_hijacked: bool
    risk_score: float
    reasons: List[str]
    is_benign_ip_shift: bool


@dataclass
class DeviceVelocityResult:
    is_suspicious: bool
    associated_accounts_count: int
    rapid_device_switches_count: int
    risk_score: float
    flags: List[str]


class DeviceFingerprintEngine:
    """Evaluates client fingerprints for botnets, spoofing, and session hijacking."""

    def __init__(self) -> None:
        # device_hash -> list of (account_id, timestamp)
        self._device_account_history: Dict[str, List[Tuple[str, float]]] = {}
        # account_id -> list of (device_hash, timestamp)
        self._account_device_history: Dict[str, List[Tuple[str, float]]] = {}

    @staticmethod
    def compute_device_hash(fp: DeviceFingerprint) -> str:
        """Computes a deterministic SHA-256 hash across hardware-bound traits."""
        core_elements = [
            fp.user_agent.strip().lower(),
            fp.accept_language.strip().lower(),
            fp.screen_resolution.strip(),
            str(fp.timezone_offset),
            fp.canvas_hash.strip(),
            fp.webgl_vendor.strip().lower(),
            fp.webgl_renderer.strip().lower(),
        ]
        raw_signature = "|".join(core_elements)
        return hashlib.sha256(raw_signature.encode("utf-8")).hexdigest()

    @staticmethod
    def detect_headless_browser(fp: DeviceFingerprint) -> BotAnalysisResult:
        """Inspects fingerprint traits for signs of headless automated browsers."""
        flags: List[str] = []
        ua_lower = fp.user_agent.lower()
        renderer_lower = fp.webgl_renderer.lower()
        vendor_lower = fp.webgl_vendor.lower()

        # User-agent headless checks
        known_bots = [
            "headlesschrome",
            "phantomjs",
            "puppeteer",
            "playwright",
            "selenium",
            "webdriver",
            "cypress",
        ]
        for bot in known_bots:
            if bot in ua_lower:
                flags.append(f"HEADLESS_UA_{bot.upper()}")

        # WebGL software emulation / swiftshader
        if "swiftshader" in renderer_lower or "llvmpipe" in renderer_lower:
            flags.append("WEBGL_SOFTWARE_EMULATION")
        if "brian paul" in vendor_lower or "mesa offscreen" in renderer_lower:
            flags.append("WEBGL_MESA_OFFSCREEN")
        if "google inc. (google)" in vendor_lower and "google swiftshader" in renderer_lower:
            flags.append("HEADLESS_CHROME_SWIFTSHADER")

        # Zero or unnatural resolutions common in headless CLI runs
        if fp.screen_resolution in ["0x0", "800x600", "1x1"]:
            flags.append("ANOMALOUS_HEADLESS_RESOLUTION")

        # Explicit flag
        if fp.is_headless is True:
            flags.append("EXPLICIT_HEADLESS_FLAG")

        risk_score = 0.0
        if flags:
            risk_score = min(1.0, 0.40 * len(flags))
            # Critical bot indicators immediately elevate risk
            if any("HEADLESS" in f or "WEBGL" in f for f in flags):
                risk_score = max(risk_score, 0.85)

        return BotAnalysisResult(
            is_bot=len(flags) > 0,
            risk_score=risk_score,
            flags=flags,
        )

    def assess_session_drift(
        self,
        baseline_fp: DeviceFingerprint,
        current_fp: DeviceFingerprint,
    ) -> SessionDriftResult:
        """Evaluates whether session cookie has been replayed from a foreign device."""
        baseline_hash = self.compute_device_hash(baseline_fp)
        current_hash = self.compute_device_hash(current_fp)

        reasons: List[str] = []
        is_hijacked = False
        risk_score = 0.0
        is_benign_ip_shift = False

        hardware_match = baseline_hash == current_hash
        ip_match = baseline_fp.ip_address == current_fp.ip_address
        asn_match = baseline_fp.asn == current_fp.asn if (baseline_fp.asn and current_fp.asn) else True

        if hardware_match and not ip_match:
            # Benign roaming (e.g. mobile LTE switching to home Wi-Fi)
            is_benign_ip_shift = True
            risk_score = 0.10
            reasons.append("BENIGN_IP_ROAMING_IDENTICAL_HARDWARE")
        elif not hardware_match and ip_match:
            # Different hardware signature sharing same IP (NAT/Proxy or credential replay)
            is_hijacked = True
            risk_score = 0.85
            reasons.append("SESSION_REPLAY_HARDWARE_MISMATCH_SAME_IP")
        elif not hardware_match and not ip_match:
            # Total mismatch across hardware, IP, and ASN -> clear session hijacking
            is_hijacked = True
            risk_score = 0.98
            reasons.append("CRITICAL_SESSION_HIJACK_DISPARATE_DEVICE_AND_IP")
            if not asn_match:
                reasons.append("DISPARATE_ASN_TRANSIT")
        else:
            # Hardware match and IP match
            risk_score = 0.0

        return SessionDriftResult(
            is_hijacked=is_hijacked,
            risk_score=risk_score,
            reasons=reasons,
            is_benign_ip_shift=is_benign_ip_shift,
        )

    def track_device_velocity(
        self,
        device_hash: str,
        account_id: str,
        timestamp: Optional[float] = None,
        window_seconds: float = 600.0,  # 10 minutes
    ) -> DeviceVelocityResult:
        """Detects botnet device clustering (1 device -> N accounts) and distributed takeover."""
        now = timestamp if timestamp is not None else time.time()
        flags: List[str] = []

        # Update device -> account history
        if device_hash not in self._device_account_history:
            self._device_account_history[device_hash] = []
        self._device_account_history[device_hash].append((account_id, now))

        # Update account -> device history
        if account_id not in self._account_device_history:
            self._account_device_history[account_id] = []
        self._account_device_history[account_id].append((device_hash, now))

        # Filter within window
        cutoff = now - window_seconds
        recent_accounts: Set[str] = {
            acc for acc, ts in self._device_account_history[device_hash] if ts >= cutoff
        }
        recent_devices: Set[str] = {
            dev for dev, ts in self._account_device_history[account_id] if ts >= cutoff
        }

        risk_score = 0.0
        # Cluster check: 1 device signing into multiple distinct accounts
        if len(recent_accounts) >= 3:
            flags.append(f"DEVICE_CLUSTERING_{len(recent_accounts)}_ACCOUNTS")
            risk_score = max(risk_score, 0.90)

        # Account takeover check: single account hit by multiple distinct devices
        if len(recent_devices) >= 3:
            flags.append(f"DISTRIBUTED_TAKEOVER_{len(recent_devices)}_DEVICES")
            risk_score = max(risk_score, 0.85)

        is_suspicious = len(flags) > 0
        return DeviceVelocityResult(
            is_suspicious=is_suspicious,
            associated_accounts_count=len(recent_accounts),
            rapid_device_switches_count=len(recent_devices),
            risk_score=risk_score,
            flags=flags,
        )
