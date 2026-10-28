from dataclasses import dataclass
from typing import List, Dict, Optional

@dataclass
class MevBundleClassification:
    is_private_builder_bundle: bool
    builder_pubkey: Optional[str]
    frontrun_backrun_spread_gwei: float
    classification: str

class MevBundleArbitrageTracer:
    def evaluate_block_transaction_group(
        self,
        tx_hashes: List[str],
        gas_price_spread_gwei: float,
        is_routed_via_flashbots_or_builder: bool
    ) -> MevBundleClassification:
        # Transactions arriving atomically with identical nonces or bundled through builders
        is_bundle = is_routed_via_flashbots_or_builder or (len(tx_hashes) >= 2 and gas_price_spread_gwei >= 50.0)
        category = "MEV_BOOST_ATOMIC_BUNDLE" if is_bundle else "PUBLIC_P2P_MEMPOOL"

        return MevBundleClassification(
            is_private_builder_bundle=is_bundle,
            builder_pubkey="0xBuilderRelay1" if is_bundle else None,
            frontrun_backrun_spread_gwei=round(gas_price_spread_gwei, 1),
            classification=category
        )
