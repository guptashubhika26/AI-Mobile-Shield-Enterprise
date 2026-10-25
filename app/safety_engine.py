
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone


class ThreatDetector:
    """Detect repeated failed-login attempts."""

    def __init__(self, threshold=5, window_minutes=10):
        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)
        self.failed_attempts = defaultdict(deque)

    def record_failed_login(self, asset_id, source_ip=None):
        now = datetime.now(timezone.utc)
        key = (asset_id, source_ip)
        attempts = self.failed_attempts[key]

        cutoff = now - self.window

        while attempts and attempts[0] < cutoff:
            attempts.popleft()

        attempts.append(now)

        if len(attempts) >= self.threshold:
            return {
                "detected": True,
                "severity": "high",
                "event_type": "repeated_failed_login",
                "asset_id": asset_id,
                "source_ip": source_ip,
                "attempts": len(attempts),
                "window_minutes": int(
                    self.window.total_seconds() / 60
                ),
                "simulated": True,
                "message": "Repeated failed logins detected.",
            }

        return {
            "detected": False,
            "attempts": len(attempts),
            "simulated": True,
        }


threat_detector = ThreatDetector()
