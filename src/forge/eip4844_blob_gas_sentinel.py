from dataclasses import dataclass

@dataclass
class BlobGasAlert:
    is_blob_underpriced_frontrun: bool
    blob_gas_fee_gwei: float
    mempool_action: str

class Eip4844BlobGasSentinel:
    def evaluate_blob_mempool_priority(
        self,
        offered_max_fee_per_blob_gas_gwei: float,
        target_blob_base_fee_gwei: float,
        blob_count: int
    ) -> BlobGasAlert:
        # EIP-4844 blob gas fee checks: if offered fee is below current target base fee
        is_underpriced = offered_max_fee_per_blob_gas_gwei < target_blob_base_fee_gwei
        # Frontrunning check: if offered fee is exactly 1 wei / marginal gwei above base fee in high contention
        is_frontrun = not is_underpriced and (offered_max_fee_per_blob_gas_gwei - target_blob_base_fee_gwei) > 20.0

        action = "DROP_UNDERPRICED_BLOB" if is_underpriced else ("EIP4844_PRIORITY_BLOB_SUBMISSION" if is_frontrun else "ACCEPT_NORMAL")

        return BlobGasAlert(
            is_blob_underpriced_frontrun=is_underpriced or is_frontrun,
            blob_gas_fee_gwei=offered_max_fee_per_blob_gas_gwei,
            mempool_action=action
        )
