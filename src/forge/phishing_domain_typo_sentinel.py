from dataclasses import dataclass
from typing import List, Set

@dataclass
class TypoSquatFinding:
    is_impersonation: bool
    target_brand: str
    observed_domain: str
    edit_distance: int
    risk_level: str

def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    d = {}
    len1 = len(s1)
    len2 = len(s2)
    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,        # deletion
                d[(i, j - 1)] + 1,        # insertion
                d[(i - 1, j - 1)] + cost  # substitution
            )
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1) # transposition

    return d[(len1 - 1, len2 - 1)]

class PhishingDomainTypoSentinel:
    def __init__(self, protected_brands: Set[str], max_distance_threshold: int = 2):
        self.protected_brands = {b.lower() for b in protected_brands}
        self.max_distance_threshold = max_distance_threshold

    def evaluate_domain(self, domain_name: str) -> TypoSquatFinding:
        clean_name = domain_name.lower().split(".")[0] # Check second-level domain name
        for brand in self.protected_brands:
            if clean_name == brand:
                return TypoSquatFinding(False, brand, domain_name, 0, "OFFICIAL_DOMAIN")
            dist = damerau_levenshtein_distance(clean_name, brand)
            if 1 <= dist <= self.max_distance_threshold:
                risk = "CRITICAL_TYPOSQUAT" if dist == 1 else "HIGH_RISK_SIMILARITY"
                return TypoSquatFinding(True, brand, domain_name, dist, risk)

        return TypoSquatFinding(False, "none", domain_name, 999, "BENIGN")
