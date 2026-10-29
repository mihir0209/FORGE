from dataclasses import dataclass
from typing import List, Dict

@dataclass
class MultiProverDisputeResult:
    is_dispute_triggered: bool
    consensus_state_root: str
    dissenting_provers_count: int
    arbitration_action: str

class MultiProverRollupDisputeSentinel:
    def arbitrate_multi_prover_roots(
        self,
        prover_claims: Dict[str, str], # {"sgx_prover": "0xRootA", "risc0_zk": "0xRootA", "sp1_zk": "0xRootB"}
        min_quorum_ratio: float = 0.66
    ) -> MultiProverDisputeResult:
        if not prover_claims:
            return MultiProverDisputeResult(True, "", 0, "NO_PROVERS_AVAILABLE")

        counts = {}
        for prover, root in prover_claims.items():
            counts[root] = counts.get(root, 0) + 1

        total = len(prover_claims)
        # Find majority root
        best_root, best_count = max(counts.items(), key=lambda x: x[1])
        has_quorum = (best_count / total) >= min_quorum_ratio

        dissenters = total - best_count
        action = "FINALIZE_ROLLUP_BLOCK" if has_quorum else "ESCALATE_TO_ONCHAIN_INTERACTIVE_BISECTION_GAME"

        return MultiProverDisputeResult(
            is_dispute_triggered=not has_quorum,
            consensus_state_root=best_root if has_quorum else "DISPUTED",
            dissenting_provers_count=dissenters,
            arbitration_action=action
        )
