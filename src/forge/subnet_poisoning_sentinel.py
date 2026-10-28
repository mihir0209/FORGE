from dataclasses import dataclass
from typing import Dict, List, Set
import ipaddress

@dataclass
class SubnetPoisoningAlert:
    is_poisoned: bool
    subnet_cidr: str
    unique_asns_seen: int
    rapid_ip_churn_count: int
    risk_level: str

class SubnetPoisoningSentinel:
    def __init__(self, max_asns_per_subnet: int = 3, churn_threshold: int = 5):
        self.max_asns_per_subnet = max_asns_per_subnet
        self.churn_threshold = churn_threshold
        # subnet -> set of ASNs
        self._subnet_asns: Dict[str, Set[int]] = {}
        # subnet -> count of distinct IPs seen
        self._subnet_ips: Dict[str, Set[str]] = {}

    def register_connection(self, ip_str: str, asn: int) -> SubnetPoisoningAlert:
        ip = ipaddress.ip_address(ip_str)
        # Group by /24 for IPv4 or /48 for IPv6
        if ip.version == 4:
            net = ipaddress.ip_network(f"{ip_str}/24", strict=False)
        else:
            net = ipaddress.ip_network(f"{ip_str}/48", strict=False)
        net_str = str(net)

        if net_str not in self._subnet_asns:
            self._subnet_asns[net_str] = set()
            self._subnet_ips[net_str] = set()

        self._subnet_asns[net_str].add(asn)
        self._subnet_ips[net_str].add(ip_str)

        asns_count = len(self._subnet_asns[net_str])
        ips_count = len(self._subnet_ips[net_str])

        is_poisoned = asns_count > self.max_asns_per_subnet or ips_count >= self.churn_threshold
        risk = "CRITICAL" if (asns_count > self.max_asns_per_subnet and ips_count >= self.churn_threshold) else (
            "HIGH" if is_poisoned else "LOW"
        )

        return SubnetPoisoningAlert(
            is_poisoned=is_poisoned,
            subnet_cidr=net_str,
            unique_asns_seen=asns_count,
            rapid_ip_churn_count=ips_count,
            risk_level=risk
        )
