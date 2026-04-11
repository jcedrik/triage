"""Group alerts into incidents by host + time window."""

from __future__ import annotations

from datetime import timedelta

from .models import Incident


class Correlator:
    def __init__(self, window_minutes: int = 30):
        self.window = timedelta(minutes=window_minutes)

    def correlate(self, alerts: list) -> list:
        by_host = {}
        for a in alerts:
            by_host.setdefault(a.source_host, []).append(a)

        incidents = []
        seq = 1
        for host, host_alerts in sorted(by_host.items()):
            host_alerts.sort(key=lambda a: a.timestamp)
            current = []
            last_ts = None
            for a in host_alerts:
                if last_ts is not None and a.timestamp - last_ts > self.window:
                    incidents.append(self._make(seq, host, current))
                    seq += 1
                    current = []
                current.append(a)
                last_ts = a.timestamp
            if current:
                incidents.append(self._make(seq, host, current))
                seq += 1
        return incidents

    def _make(self, seq, host, alerts):
        return Incident(
            incident_id=f"INC-{seq:04d}",
            host=host,
            alerts=list(alerts),
        )
