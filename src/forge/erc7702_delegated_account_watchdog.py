from dataclasses import dataclass
from typing import List

@dataclass
class Erc7702DelegationAlert:
    is_malicious_delegation: bool
    delegated_contract_address: str
    threat_tier: str

class Erc7702DelegatedAccountWatchdog:
    def audit_delegation_authorization(
        self,
        delegated_target_address: str,
        target_bytecode: bytes,
        is_revocation: bool = False
    ) -> Erc7702DelegationAlert:
        if is_revocation or delegated_target_address == "0x0000000000000000000000000000000000000000":
            return Erc7702DelegationAlert(False, delegated_target_address, "SAFE_REVOCATION")

        # Flag delegation targets that contain SELFDESTRUCT (0xff) or DELEGATECALL in unprotected proxy
        has_selfdestruct = b"\xff" in target_bytecode
        has_delegatecall = b"\xf4" in target_bytecode

        is_suspicious = has_selfdestruct or (has_delegatecall and len(target_bytecode) < 64)
        tier = "CRITICAL_ERC7702_ACCOUNT_DRAINER_DELEGATION" if is_suspicious else "VERIFIED_SMART_ACCOUNT_LOGIC"

        return Erc7702DelegationAlert(
            is_malicious_delegation=is_suspicious,
            delegated_contract_address=delegated_target_address,
            threat_tier=tier
        )
