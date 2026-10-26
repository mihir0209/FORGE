"""FORGE — Fraud Offense-defense Research and Generation Engine."""

from forge.adversarial_simulator import (
    AdversarialAttackGenerator,
    AdversarialTransaction,
    AttackMode,
)
from forge.mule_ring import (
    MuleRing,
    MuleRingDetectionResult,
    MuleRingDetector,
    MuleRingGraph,
    TransactionEdge,
    canonicalize_cycle,
)
from forge.streaming_scorer import (
    RiskAssessment,
    RiskDecision,
    StreamingRiskEngine,
    StreamingTransaction,
)
from forge.rule_engine import AdaptiveRuleEngine, Condition, Rule, RuleAction
from forge.behavioral_engine import (
    BehavioralProfiler,
    UserBehavioralProfile,
    AnomalyScoreResult,
)
from forge.device_fingerprint import (
    DeviceFingerprint,
    DeviceFingerprintEngine,
    BotAnalysisResult,
    SessionDriftResult,
    DeviceVelocityResult,
)
from forge.velocity_limiter import (
    VelocityRateLimiter,
    AccountTier,
    PaymentChannel,
    RateLimitResult,
)
from forge.synthetic_identity import (
    SyntheticIdentityProfile,
    BustOutFeatureVector,
    SyntheticIdentityResult,
    BustOutPredictionResult,
    SyntheticIdentityEngine,
)
from forge.fraud_ring_graph import (
    AccountNode,
    TransactionFlow,
    FraudRingCluster,
    EntityResolutionReport,
    FraudRingGraphEngine,
)
from forge.concept_drift import (
    DriftSeverity,
    PageHinkleyConfig,
    DriftMetricReport,
    PageHinkleyDetector,
    compute_two_sample_ks,
    ConceptDriftEngine,
)
from forge.chargeback_shield import (
    FriendlyFraudRisk,
    TransactionContext,
    DisputeRebuttalPacket,
    ChargebackPredictionResult,
    ChargebackShieldEngine,
)
from forge.geo_velocity import (
    GeoLocation,
    GeoEvent,
    TravelAuditResult,
    GeoVelocityDetector,
    haversine_distance,
)
from forge.behavioral_biometrics import (
    KeyEvent,
    BiometricProfileResult,
    KeystrokeDynamicsClassifier,
)
from forge.merchant_collusion import (
    MerchantTransaction,
    MerchantRiskReport,
    MerchantCollusionSentinel,
)
from forge.smurfing_detector import (
    TransactionRecord,
    SmurfingAlert,
    SmurfingDetector,
)
from forge.device_entropy import (
    DeviceProfile,
    DeviceEntropyReport,
    DeviceEntropyClassifier,
)
from forge.adaptive_velocity_governor import (
    VelocityEvent,
    VelocityMetrics,
    AdaptiveVelocityGovernor,
)

__version__ = "0.1.0"

__all__ = [
    "AdaptiveRuleEngine",
    "Rule",
    "Condition",
    "RuleAction",
    "AdversarialAttackGenerator",
    "AdversarialTransaction",
    "AttackMode",
    "MuleRing",
    "MuleRingDetectionResult",
    "MuleRingDetector",
    "MuleRingGraph",
    "RiskAssessment",
    "RiskDecision",
    "StreamingRiskEngine",
    "StreamingTransaction",
    "TransactionEdge",
    "canonicalize_cycle",
    "BehavioralProfiler",
    "UserBehavioralProfile",
    "AnomalyScoreResult",
    "DeviceFingerprint",
    "DeviceFingerprintEngine",
    "BotAnalysisResult",
    "SessionDriftResult",
    "DeviceVelocityResult",
    "VelocityRateLimiter",
    "AccountTier",
    "PaymentChannel",
    "RateLimitResult",
    "SyntheticIdentityProfile",
    "BustOutFeatureVector",
    "SyntheticIdentityResult",
    "BustOutPredictionResult",
    "SyntheticIdentityEngine",
    "AccountNode",
    "TransactionFlow",
    "FraudRingCluster",
    "EntityResolutionReport",
    "FraudRingGraphEngine",
    "DriftSeverity",
    "PageHinkleyConfig",
    "DriftMetricReport",
    "PageHinkleyDetector",
    "compute_two_sample_ks",
    "ConceptDriftEngine",
    "FriendlyFraudRisk",
    "TransactionContext",
    "DisputeRebuttalPacket",
    "ChargebackPredictionResult",
    "ChargebackShieldEngine",
    "GeoLocation",
    "GeoEvent",
    "TravelAuditResult",
    "GeoVelocityDetector",
    "haversine_distance",
    "KeyEvent",
    "BiometricProfileResult",
    "KeystrokeDynamicsClassifier",
    "MerchantTransaction",
    "MerchantRiskReport",
    "MerchantCollusionSentinel",
    "TransactionRecord",
    "SmurfingAlert",
    "SmurfingDetector",
    "DeviceProfile",
    "DeviceEntropyReport",
    "DeviceEntropyClassifier",
    "VelocityEvent",
    "VelocityMetrics",
    "AdaptiveVelocityGovernor",
]
