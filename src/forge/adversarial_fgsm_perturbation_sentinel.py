from dataclasses import dataclass
from typing import List

@dataclass
class AdversarialPerturbationAlert:
    is_adversarial_evasion: bool
    l_infinity_norm: float
    confidence_drop: float

class AdversarialFgsmPerturbationSentinel:
    def detect_perturbation(
        self,
        clean_features: List[float],
        incoming_features: List[float],
        epsilon_threshold: float = 0.05
    ) -> AdversarialPerturbationAlert:
        if len(clean_features) != len(incoming_features) or not clean_features:
            return AdversarialPerturbationAlert(False, 0.0, 0.0)

        diffs = [abs(a - b) for a, b in zip(clean_features, incoming_features)]
        l_inf = max(diffs)

        # If perturbation is bounded closely near epsilon with systematic signs -> adversarial FGSM
        is_adversarial = 0.01 <= l_inf <= epsilon_threshold * 2.0 and all(d > 0.005 for d in diffs)
        conf_drop = min(1.0, l_inf * 10.0)

        return AdversarialPerturbationAlert(
            is_adversarial_evasion=is_adversarial,
            l_infinity_norm=round(l_inf, 4),
            confidence_drop=round(conf_drop, 2)
        )
