from dataclasses import dataclass
from typing import List

@dataclass
class AsSetDeprecationAlert:
    has_deprecated_as_set: bool
    as_path_segment_types: List[str]
    severity: str

class BgpAsSetDeprecationSentinel:
    def inspect_as_path(self, as_path_segments: List[dict]) -> AsSetDeprecationAlert:
        # RFC 9234 & RFC 6472: AS_SET in AS_PATH is deprecated due to route hijacking ambiguities
        # segments: [{"type": "AS_SEQUENCE", "values": [15169, 701]}, {"type": "AS_SET", "values": [65001, 65002]}]
        has_set = False
        types = []

        for seg in as_path_segments:
            s_type = seg.get("type", "AS_SEQUENCE")
            types.append(s_type)
            if s_type == "AS_SET":
                has_set = True

        tier = "HIGH_DEPRECATED_AS_SET_ROUTE_FILTERED" if has_set else "COMPLIANT_AS_SEQUENCE"

        return AsSetDeprecationAlert(
            has_deprecated_as_set=has_set,
            as_path_segment_types=types,
            severity=tier
        )
