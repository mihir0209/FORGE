from dataclasses import dataclass

@dataclass
class RpkiValidationResult:
    rpki_status: str # "VALID", "INVALID", "NOT_FOUND"
    is_route_leak_dropped: bool
    origin_asn: int
    authorized_asn: int

class BgpOriginValidationFailureSentinel:
    def validate_rpki_route(
        self,
        prefix: str,
        prefix_len: int,
        origin_asn: int,
        roa_authorized_asn: int,
        roa_max_length: int
    ) -> RpkiValidationResult:
        # RFC 6811 BGP Origin Validation
        if origin_asn != roa_authorized_asn or prefix_len > roa_max_length:
            status = "INVALID"
            drop = True
        elif origin_asn == roa_authorized_asn and prefix_len <= roa_max_length:
            status = "VALID"
            drop = False
        else:
            status = "NOT_FOUND"
            drop = False

        return RpkiValidationResult(
            rpki_status=status,
            is_route_leak_dropped=drop,
            origin_asn=origin_asn,
            authorized_asn=roa_authorized_asn
        )
