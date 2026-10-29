from dataclasses import dataclass
from typing import List, Set

@dataclass
class MevCensorshipAlert:
    is_censorship_detected: bool
    inclusion_delay_blocks: int
    censoring_relays: List[str]
    threat_tier: str

class PbsMevboostCensorshipSentinel:
    def __init__(self, sanctioned_addresses: Set[str] = None):
        self.sanctioned_addresses = sanctioned_addresses or {
            "0x1111111111111111111111111111111111111111", # E.g. Tornado Cash or sanctioned OFAC router
        }

    def audit_block_bids(
        self,
        relay_name: str,
        mempool_pending_tx_senders: List[str],
        block_included_tx_senders: List[str],
        consecutive_blocks_omitted: int
    ) -> MevCensorshipAlert:
        # Check if high-priority transaction from a sanctioned address is systematically omitted
        omitted_sanctioned = [s for s in mempool_pending_tx_senders if s in self.sanctioned_addresses and s not in block_included_tx_senders]

        is_censored = len(omitted_sanctioned) > 0 and consecutive_blocks_omitted >= 4
        tier = "CRITICAL_PROPOSER_BUILDER_OFAC_CENSORSHIP" if is_censored else "COMPLIANT_NEUTRAL_RELAY"

        return MevCensorshipAlert(
            is_censorship_detected=is_censored,
            inclusion_delay_blocks=consecutive_blocks_omitted,
            censoring_relays=[relay_name] if is_censored else [],
            threat_tier=tier
        )
