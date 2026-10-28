from dataclasses import dataclass
from typing import Dict, Set

@dataclass
class RelayNonceCheck:
    is_replay_attack: bool
    source_chain_id: int
    target_chain_id: int
    nonce: int
    action: str

class CrossChainNonceSentinel:
    def __init__(self):
        # (src_chain, target_chain) -> Set of consumed nonces
        self._consumed_nonces: Dict[tuple, Set[int]] = {}

    def process_message_delivery(
        self,
        src_chain: int,
        target_chain: int,
        nonce: int
    ) -> RelayNonceCheck:
        key = (src_chain, target_chain)
        if key not in self._consumed_nonces:
            self._consumed_nonces[key] = set()

        if nonce in self._consumed_nonces[key]:
            return RelayNonceCheck(
                is_replay_attack=True,
                source_chain_id=src_chain,
                target_chain_id=target_chain,
                nonce=nonce,
                action="DROP_REPLAY_MESSAGE"
            )

        self._consumed_nonces[key].add(nonce)
        return RelayNonceCheck(
            is_replay_attack=False,
            source_chain_id=src_chain,
            target_chain_id=target_chain,
            nonce=nonce,
            action="EXECUTE_RELAY_PAYLOAD"
        )
