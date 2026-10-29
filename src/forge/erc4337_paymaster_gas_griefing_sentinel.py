from dataclasses import dataclass

@dataclass
class PaymasterGasValidationResult:
    is_gas_griefing_risk: bool
    verification_gas_limit: int
    postop_gas_limit: int
    action: str

class Erc4337PaymasterGasGriefingSentinel:
    def audit_paymaster_user_op(
        self,
        verification_gas_limit: int,
        call_gas_limit: int,
        postop_gas_limit: int,
        max_allowed_verification_gas: int = 150_000
    ) -> PaymasterGasValidationResult:
        # Paymaster gas griefing occurs when verificationGasLimit is inflated to burn relayer funds,
        # or postOp simulates execution revert to drain sponsor deposits
        is_grief = verification_gas_limit > max_allowed_verification_gas or postop_gas_limit > 100_000
        action = "REJECT_EXCESSIVE_PAYMASTER_GAS_LIMIT" if is_grief else "PERMIT_USER_OP_SPONSORSHIP"

        return PaymasterGasValidationResult(
            is_gas_griefing_risk=is_grief,
            verification_gas_limit=verification_gas_limit,
            postop_gas_limit=postop_gas_limit,
            action=action
        )
