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


@dataclass
class Incident:
    incident_id: str
    host: str
    alerts: list = field(default_factory=list)
    risk_score: int = 0
