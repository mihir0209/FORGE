from dataclasses import dataclass
from typing import Dict, Set

@dataclass
class DidSybilAssessment:
    sybil_resistance_score: float # [0.0, 100.0]
    trust_tier: str

class DecentralizedIdentitySybilScore:
    def compute_trust_score(
        self,
        attestation_count: int,
        unique_verifiers: int,
        age_in_days: int
    ) -> DidSybilAssessment:
        score = min(50.0, attestation_count * 5.0) + min(30.0, unique_verifiers * 6.0) + min(20.0, age_in_days * 0.1)
        score = round(score, 1)

        if score >= 75.0:
            tier = "VERIFIED_HUMAN"
        elif score >= 40.0:
            tier = "PROBATIONARY"
        else:
            tier = "HIGH_SYBIL_RISK"

        return DidSybilAssessment(sybil_resistance_score=score, trust_tier=tier)
