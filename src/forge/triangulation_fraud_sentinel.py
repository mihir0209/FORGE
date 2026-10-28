from dataclasses import dataclass
from typing import Dict, List, Optional

@dataclass
class TriangulationAlert:
    is_triangulation_fraud: bool
    buyer_card_hash: str
    shipping_address_hash: str
    secondary_listing_id: Optional[str]
    confidence_score: float

class TriangulationFraudSentinel:
    def evaluate_order(
        self,
        buyer_card_hash: str,
        shipping_address_hash: str,
        matched_marketplace_listing: Optional[str],
        cardholder_name: str,
        shipping_recipient_name: str,
        order_to_listing_delta_seconds: float
    ) -> TriangulationAlert:
        name_mismatch = cardholder_name.lower().strip() != shipping_recipient_name.lower().strip()
        has_marketplace_match = matched_marketplace_listing is not None
        rapid_drop = order_to_listing_delta_seconds <= 3600.0 # Under 1 hour

        is_fraud = has_marketplace_match and name_mismatch and rapid_drop
        confidence = 0.95 if is_fraud else (0.60 if (has_marketplace_match and name_mismatch) else 0.10)

        return TriangulationAlert(
            is_triangulation_fraud=is_fraud,
            buyer_card_hash=buyer_card_hash,
            shipping_address_hash=shipping_address_hash,
            secondary_listing_id=matched_marketplace_listing,
            confidence_score=confidence
        )
