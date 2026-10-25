
from app.safety_engine import ThreatDetector


def test_detects_repeated_failed_logins():
    detector = ThreatDetector(threshold=5, window_minutes=10)

    result = None
    for _ in range(5):
        result = detector.record_failed_login(
            asset_id="test-device-01",
            source_ip="192.0.2.10",
        )

    assert result["detected"] is True
    assert result["severity"] == "high"
    assert result["attempts"] == 5
    assert result["simulated"] is True


def test_does_not_alert_before_threshold():
    detector = ThreatDetector(threshold=5, window_minutes=10)

    for _ in range(4):
        result = detector.record_failed_login(
            asset_id="test-device-02",
            source_ip="192.0.2.20",
        )

    assert result["detected"] is False
    assert result["attempts"] == 4
