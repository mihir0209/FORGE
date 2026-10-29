from dataclasses import dataclass
import math

@dataclass
class TemporalEdgeScore:
    decayed_weight: float
    is_active_fraud_risk: bool
    recency_score: float

class TemporalEdgeDecayFraudClassifier:
    def __init__(self, half_life_hours: float = 24.0):
        # lambda = ln(2) / half_life
        self.decay_lambda = math.log(2.0) / max(1.0, half_life_hours)

    def evaluate_transaction_edge(
        self,
        initial_fraud_weight: float,
        elapsed_hours: float
    ) -> TemporalEdgeScore:
        # w(t) = w0 * exp(-lambda * delta_t)
        decayed = initial_fraud_weight * math.exp(-self.decay_lambda * max(0.0, elapsed_hours))
        decayed_rounded = round(decayed, 3)

        # High fraud risk if weight remains >= 0.50
        is_risk = decayed_rounded >= 0.50
        recency = round(math.exp(-0.05 * max(0.0, elapsed_hours)), 3)

        return TemporalEdgeScore(
            decayed_weight=decayed_rounded,
            is_active_fraud_risk=is_risk,
            recency_score=recency
        )
