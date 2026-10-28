from dataclasses import dataclass

@dataclass
class EcdsaMalleabilityResult:
    is_malleable: bool
    normalized_s: str
    remediation_required: bool

class EcdsaSignatureMalleabilitySentinel:
    # secp256k1 curve order n
    SECP256K1_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
    HALF_N = SECP256K1_N // 2

    def check_and_normalize_s(self, s_hex: str) -> EcdsaMalleabilityResult:
        s_val = int(s_hex.strip().lstrip("0x"), 16)
        # BIP-62 / BIP-146 lower-S requirement: s <= n / 2
        is_malleable = s_val > self.HALF_N
        normalized_val = (self.SECP256K1_N - s_val) if is_malleable else s_val

        return EcdsaMalleabilityResult(
            is_malleable=is_malleable,
            normalized_s=hex(normalized_val),
            remediation_required=is_malleable
        )
