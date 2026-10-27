import pytest
from forge.tof_travel_sentinel import (
    ToFTravelSentinel,
    GeoCoordinates,
    SessionAccessEvent,
    TravelAnomalyAssessment,
)


@pytest.fixture
def sentinel():
    return ToFTravelSentinel()


def test_normal_intra_city_movement(sentinel):
    coord_sf = GeoCoordinates(37.7749, -122.4194, "San Francisco", "US")
    coord_oakland = GeoCoordinates(37.8044, -122.2712, "Oakland", "US")

    ev1 = SessionAccessEvent("s1", "user1", 1700000000, coord_sf)
    ev2 = SessionAccessEvent("s2", "user1", 1700003600, coord_oakland)  # 1 hour later

    res = sentinel.evaluate_travel_velocity(ev1, ev2)
    assert not res.is_impossible_travel
    assert not res.is_latency_anomaly
    assert res.risk_level == "LOW"
    assert res.suggested_action == "ALLOW"


def test_reasonable_transcontinental_flight(sentinel):
    # NYC to LA (~3940 km) in 6 hours = ~656 km/h
    coord_nyc = GeoCoordinates(40.7128, -74.0060, "New York", "US")
    coord_la = GeoCoordinates(34.0522, -118.2437, "Los Angeles", "US")

    ev1 = SessionAccessEvent("s1", "user1", 1700000000, coord_nyc)
    ev2 = SessionAccessEvent("s2", "user1", 1700000000 + 21600, coord_la)  # 6 hrs = 21600s

    res = sentinel.evaluate_travel_velocity(ev1, ev2)
    assert not res.is_impossible_travel
    assert res.travel_speed_kmh < 950.0
    assert res.risk_level == "LOW"
    assert res.suggested_action == "ALLOW"


def test_impossible_supersonic_travel(sentinel):
    # London to Tokyo (~9560 km) in 15 minutes (900s) = ~38,240 km/h
    coord_london = GeoCoordinates(51.5074, -0.1278, "London", "GB")
    coord_tokyo = GeoCoordinates(35.6762, 139.6503, "Tokyo", "JP")

    ev1 = SessionAccessEvent("s1", "user_victim", 1700000000, coord_london)
    ev2 = SessionAccessEvent("s2", "user_victim", 1700000900, coord_tokyo)

    res = sentinel.evaluate_travel_velocity(ev1, ev2)
    assert res.is_impossible_travel
    assert res.travel_speed_kmh > 10000.0
    assert res.risk_level == "HIGH"
    assert res.suggested_action == "STEP_UP_MFA"
    assert any("exceeds physical commercial limit" in reason for reason in res.anomaly_reasons)


def test_simultaneous_concurrent_access_from_distinct_geographies(sentinel):
    # NYC and SF simultaneously (time_delta = 0)
    coord_nyc = GeoCoordinates(40.7128, -74.0060, "New York", "US")
    coord_sf = GeoCoordinates(37.7749, -122.4194, "San Francisco", "US")

    ev1 = SessionAccessEvent("s1", "user_admin", 1700000000, coord_nyc)
    ev2 = SessionAccessEvent("s2", "user_admin", 1700000000, coord_sf)

    res = sentinel.evaluate_travel_velocity(ev1, ev2)
    assert res.is_impossible_travel
    assert res.travel_speed_kmh == float("inf")
    assert any("Simultaneous access" in reason for reason in res.anomaly_reasons)


def test_fiber_speed_of_light_latency_violation(sentinel):
    # 9500 km distance cannot have 5ms RTT (minimum optical RTT is ~95ms)
    coord_london = GeoCoordinates(51.5074, -0.1278, "London", "GB")
    coord_tokyo = GeoCoordinates(35.6762, 139.6503, "Tokyo", "JP")

    ev1 = SessionAccessEvent("s1", "user2", 1700000000, coord_london)
    # Even with 24 hours between logins, an impossible RTT indicates VPN proxy spoofing / MITM
    ev2 = SessionAccessEvent("s2", "user2", 1700000000 + 86400, coord_tokyo, reported_rtt_ms=5.0)

    res = sentinel.evaluate_travel_velocity(ev1, ev2)
    assert res.is_latency_anomaly
    assert any("physically violates optical light propagation" in reason for reason in res.anomaly_reasons)
