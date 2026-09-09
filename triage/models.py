"""Core data model for the SOC correlation engine.

The pipeline is: raw Alerts come in, get grouped into Incidents, each Incident
is scored and mapped to MITRE ATT&CK tactics. Keeping these types in one place
means the parsers, the correlator, the scorer, and the reporters all agree on
the shape of the data.
"""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from datetime import datetime


class Severity(enum.IntEnum):
    """Ordered so incidents can be ranked and the worst surfaced first."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, s: str) -> "Severity":
        return cls[s.strip().upper()]

    def label(self) -> str:
        return self.name.capitalize()


@dataclass
class Alert:
    """One raw detection, from an IDS, an endpoint agent, a log pipeline, etc.

    We normalize every input source into this shape so the rest of the engine
    is source-agnostic.
    """

    timestamp: datetime
    source_host: str          # which asset the alert concerns
    signature: str            # short rule name / detection name
    severity: Severity
    technique_id: str = ""    # MITRE technique, e.g. "T1059" (may be empty)
    category: str = ""        # e.g. "malware", "recon"
    src_ip: str = ""
    dst_ip: str = ""
    raw: str = ""             # original message, for reference

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        d["severity"] = self.severity.label()
        return d


@dataclass
class Incident:
    """A group of related alerts that together tell one story.

    Correlation collapses many alerts (often noisy and repetitive) into a small
    number of incidents an analyst can actually triage. That reduction is the
    whole point of a SOC correlation layer.
    """

    incident_id: str
    host: str
    alerts: list[Alert] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)  # >1 when merged by src_ip pivot
    tactics: set[str] = field(default_factory=set)   # MITRE tactic names
    techniques: set[str] = field(default_factory=set)  # MITRE technique ids
    risk_score: int = 0
    severity: Severity = Severity.INFO

    def first_seen(self) -> datetime:
        return min(a.timestamp for a in self.alerts)

    def last_seen(self) -> datetime:
        return max(a.timestamp for a in self.alerts)

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "host": self.host,
            "hosts": self.hosts or [self.host],
            "src_ips": sorted({a.src_ip for a in self.alerts if a.src_ip}),
            "severity": self.severity.label(),
            "risk_score": self.risk_score,
            "first_seen": self.first_seen().isoformat(),
            "last_seen": self.last_seen().isoformat(),
            "alert_count": len(self.alerts),
            "tactics": sorted(self.tactics),
            "techniques": sorted(self.techniques),
            "alerts": [a.to_dict() for a in self.alerts],
        }
