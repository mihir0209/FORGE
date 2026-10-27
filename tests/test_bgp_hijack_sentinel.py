import pytest
from forge.bgp_hijack_sentinel import (
    BgpHijackSentinel,
    RoaEntry,
    BgpRouteAnnouncement,
    BgpHijackAlert,
)


@pytest.fixture
def sentinel():
    s = BgpHijackSentinel(flap_window_sec=60.0, max_flap_threshold=4)
    s.add_roa(RoaEntry(prefix="198.51.100.0/22", max_length=22, authorized_as=13335))
    return s


def test_benign_authorized_announcement_passes(sentinel):
    ann = BgpRouteAnnouncement(
        prefix="198.51.100.0/22",
        origin_as=13335,
        as_path=[174, 3356, 13335],
        peer_ip="192.0.2.1",
        timestamp_sec=1000.0,
    )
    alert = sentinel.process_announcement(ann)
    assert alert is None


def test_detects_rpki_origin_hijack(sentinel):
    rogue_ann = BgpRouteAnnouncement(
        prefix="198.51.100.0/22",
        origin_as=64496,
        as_path=[701, 1239, 64496],
        peer_ip="192.0.2.2",
        timestamp_sec=1010.0,
    )
    alert = sentinel.process_announcement(rogue_ann)
    assert alert is not None
    assert alert.is_hijack_alert
    assert alert.attack_type == "RPKI_ORIGIN_MISMATCH"
    assert alert.culprit_as == 64496
    assert alert.legitimate_as == 13335
    assert alert.severity == "CRITICAL"
    assert alert.mitigation_action == "NULL_ROUTE"


def test_detects_more_specific_subprefix_deaggregation_hijack(sentinel):
    deagg_ann = BgpRouteAnnouncement(
        prefix="198.51.100.0/24",
        origin_as=64496,
        as_path=[1299, 64496],
        peer_ip="192.0.2.3",
        timestamp_sec=1020.0,
    )
    alert = sentinel.process_announcement(deagg_ann)
    assert alert is not None
    assert alert.is_hijack_alert
    assert alert.attack_type in ("MORE_SPECIFIC_SUBPREFIX_HIJACK", "RPKI_ORIGIN_MISMATCH")
    assert alert.culprit_as == 64496
    assert alert.severity == "CRITICAL"


def test_detects_as_path_cyclic_loop_poisoning(sentinel):
    cyclic_ann = BgpRouteAnnouncement(
        prefix="203.0.113.0/24",
        origin_as=65000,
        as_path=[174, 3356, 174, 65000],
        peer_ip="192.0.2.4",
        timestamp_sec=1030.0,
    )
    alert = sentinel.process_announcement(cyclic_ann)
    assert alert is not None
    assert alert.attack_type == "AS_PATH_FORGERY_LOOP"
    assert alert.mitigation_action == "FILTER_AS_PATH"


def test_detects_rapid_route_flap_poisoning(sentinel):
    prefix = "192.0.2.0/24"
    for i in range(5):
        ann = BgpRouteAnnouncement(
            prefix=prefix,
            origin_as=65001,
            as_path=[3356, 65001],
            peer_ip="192.0.2.5",
            timestamp_sec=1000.0 + (i * 3),
            is_withdrawal=(i % 2 == 1),
        )
        alert = sentinel.process_announcement(ann)
        if i == 4:
            assert alert is not None
            assert alert.attack_type == "RAPID_FLAP_POISONING"
            assert alert.mitigation_action == "ENABLE_ROUTE_FLAP_DAMPING"
