"""Unit and regression tests for Geo-Velocity & Impossible Travel Detector."""

from datetime import datetime, timedelta, timezone
import pytest
from forge.geo_velocity import (
    GeoEvent,
    GeoLocation,
    GeoVelocityDetector,
    haversine_distance,
)


def test_haversine_distance_accuracy():
    # London (51.5074, -0.1278) to Paris (48.8566, 2.3522) ≈ 344 km
    dist = haversine_distance(51.5074, -0.1278, 48.8566, 2.3522)
    assert 340.0 <= dist <= 350.0

    # Same coordinate distance should be zero
    zero_dist = haversine_distance(40.7128, -74.0060, 40.7128, -74.0060)
    assert zero_dist == 0.0


def test_feasible_travel_passes():
    detector = GeoVelocityDetector()
    now = datetime.now(timezone.utc)

    # Event 1: New York (40.7128, -74.0060)
    ev1 = GeoEvent(
        event_id="ev-1",
        user_id="user-123",
        location=GeoLocation(40.7128, -74.0060, city="New York"),
        timestamp=now,
    )
    res1 = detector.evaluate_travel(ev1)
    assert res1.is_impossible is False
    assert res1.risk_score == 0.0

    # Event 2: Philadelphia (39.9526, -75.1652) 2 hours later (~150 km)
    ev2 = GeoEvent(
        event_id="ev-2",
        user_id="user-123",
        location=GeoLocation(39.9526, -75.1652, city="Philadelphia"),
        timestamp=now + timedelta(hours=2),
    )
    res2 = detector.evaluate_travel(ev2)
    assert res2.is_impossible is False
    assert res2.velocity_kmh < 150.0
    assert res2.risk_score < 0.2


def test_impossible_travel_triggers_alert():
    detector = GeoVelocityDetector()
    now = datetime.now(timezone.utc)

    # Event 1: London (51.5074, -0.1278)
    ev1 = GeoEvent(
        event_id="ev-ldn",
        user_id="user-victim",
        location=GeoLocation(51.5074, -0.1278, city="London"),
        timestamp=now,
    )
    detector.evaluate_travel(ev1)

    # Event 2: Tokyo (35.6762, 139.6503) 30 minutes later (9,560 km in 0.5h = 19,120 km/h)
    ev2 = GeoEvent(
        event_id="ev-tyo",
        user_id="user-victim",
        location=GeoLocation(35.6762, 139.6503, city="Tokyo"),
        timestamp=now + timedelta(minutes=30),
    )
    res2 = detector.evaluate_travel(ev2)
    assert res2.is_impossible is True
    assert res2.velocity_kmh > 10000.0
    assert res2.risk_score > 0.8
    assert "Impossible travel speed" in res2.reason


def test_simultaneous_concurrent_actions_blocked():
    detector = GeoVelocityDetector()
    now = datetime.now(timezone.utc)

    ev1 = GeoEvent(
        event_id="ev-ny",
        user_id="user-hacked",
        location=GeoLocation(40.7128, -74.0060, city="New York"),
        timestamp=now,
    )
    detector.evaluate_travel(ev1)

    # Simultaneous event 5 seconds later from Los Angeles (34.0522, -118.2437)
    ev2 = GeoEvent(
        event_id="ev-la",
        user_id="user-hacked",
        location=GeoLocation(34.0522, -118.2437, city="Los Angeles"),
        timestamp=now + timedelta(seconds=5),
    )
    res2 = detector.evaluate_travel(ev2)
    assert res2.is_impossible is True
    assert res2.risk_score == 1.0
    assert "Concurrent actions" in res2.reason
