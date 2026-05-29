"""Correlation engine: turn a stream of alerts into a handful of incidents.

The strategy is host-plus-time-window correlation, which is the workhorse of
real SOC tooling: alerts on the same asset that happen close together in time
are almost always part of the same activity, so we group them. Within a host,
a new incident starts when the gap since the last alert exceeds the window.

This collapses alert volume dramatically (the whole reason correlation exists)
and, because we also collect the MITRE techniques per incident, each resulting
incident shows how many stages of the kill chain it spans, which is a strong
prioritization signal on its own.
"""

from __future__ import annotations

from datetime import timedelta

from .models import Alert, Incident
from . import mitre


class Correlator:
    def __init__(self, window_minutes: int = 30):
        # Alerts on one host within this gap belong to the same incident.
        self.window = timedelta(minutes=window_minutes)

    def correlate(self, alerts: list[Alert]) -> list[Incident]:
        # Group by host first, then split each host's timeline into incidents
        # wherever there is a quiet gap longer than the window.
        by_host: dict[str, list[Alert]] = {}
        for a in alerts:
            by_host.setdefault(a.source_host, []).append(a)

        incidents: list[Incident] = []
        seq = 1
        for host, host_alerts in sorted(by_host.items()):
            host_alerts.sort(key=lambda a: a.timestamp)
            current: list[Alert] = []
            last_ts = None

            for a in host_alerts:
                if last_ts is not None and a.timestamp - last_ts > self.window:
                    incidents.append(self._make_incident(seq, host, current))
                    seq += 1
                    current = []
                current.append(a)
                last_ts = a.timestamp

            if current:
                incidents.append(self._make_incident(seq, host, current))
                seq += 1

        return incidents

    def _make_incident(self, seq: int, host: str,
                       alerts: list[Alert]) -> Incident:
        inc = Incident(
            incident_id=f"INC-{seq:04d}",
            host=host,
            alerts=list(alerts),
        )
        # Roll up techniques and tactics seen in this incident.
        for a in alerts:
            if a.technique_id:
                inc.techniques.add(a.technique_id)
                inc.tactics.add(mitre.tactic_for(a.technique_id))
        return inc
