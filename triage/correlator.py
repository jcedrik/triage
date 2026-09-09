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

import ipaddress
from datetime import timedelta

from . import mitre
from .models import Alert, Incident

_INTERNAL = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
              "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128")
]


def _is_private(ip: str) -> bool:
    """RFC 1918 / loopback / link-local only. Deliberately not
    ipaddress.is_private, which also flags documentation ranges such as
    203.0.113.0/24 that show up in lab data and samples."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparsable: treat as internal, never pivot on it
    return any(addr in n for n in _INTERNAL)


class Correlator:
    def __init__(self, window_minutes: int = 30, pivot_src_ip: bool = False):
        # Alerts on one host within this gap belong to the same incident.
        self.window = timedelta(minutes=window_minutes)
        # Second pass: merge incidents on different hosts that share an
        # external source IP and overlap in time. That is what lateral
        # movement and a scanner sweeping a subnet look like.
        self.pivot_src_ip = pivot_src_ip

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

        if self.pivot_src_ip:
            incidents = self._merge_by_src_ip(incidents)
        return incidents

    def _merge_by_src_ip(self, incidents: list[Incident]) -> list[Incident]:
        """Union-find over incidents: two incidents join if they share a
        non-empty src_ip and their time spans are within one window of each
        other. Internal/private sources are not pivoted on, otherwise a
        proxy or a jump host would glue everything together."""
        parent = list(range(len(incidents)))

        def find(i: int) -> int:
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        def union(a: int, b: int) -> None:
            parent[find(a)] = find(b)

        ips = [
            {a.src_ip for a in inc.alerts if a.src_ip and not _is_private(a.src_ip)}
            for inc in incidents
        ]
        for i in range(len(incidents)):
            for j in range(i + 1, len(incidents)):
                if not (ips[i] & ips[j]):
                    continue
                gap = max(incidents[i].first_seen(), incidents[j].first_seen()) - min(
                    incidents[i].last_seen(), incidents[j].last_seen()
                )
                if gap <= self.window:
                    union(i, j)

        groups: dict[int, list[Incident]] = {}
        for i, inc in enumerate(incidents):
            groups.setdefault(find(i), []).append(inc)

        merged: list[Incident] = []
        for seq, members in enumerate(groups.values(), start=1):
            if len(members) == 1:
                inc = members[0]
                inc.incident_id = f"INC-{seq:04d}"
                merged.append(inc)
                continue
            alerts = [a for m in members for a in m.alerts]
            hosts = sorted({m.host for m in members})
            inc = self._make_incident(seq, ",".join(hosts), alerts)
            inc.hosts = hosts
            merged.append(inc)
        return merged

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
