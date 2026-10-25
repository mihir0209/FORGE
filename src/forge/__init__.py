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
]
from .rule_engine import AdaptiveRuleEngine, Condition, Rule, RuleAction
