"""Data model. Alerts come in, get grouped into incidents."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime


class Severity(enum.IntEnum):
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
    timestamp: datetime
    source_host: str
    signature: str
    severity: Severity
    technique_id: str = ""
    category: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    raw: str = ""


@dataclass
class Incident:
    incident_id: str
    host: str
    alerts: list = field(default_factory=list)
    tactics: set = field(default_factory=set)
    techniques: set = field(default_factory=set)
    risk_score: int = 0
    severity: Severity = Severity.INFO

    def first_seen(self):
        return min(a.timestamp for a in self.alerts)

    def last_seen(self):
        return max(a.timestamp for a in self.alerts)
