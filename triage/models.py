"""Data model."""

from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import datetime


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Alert:
    timestamp: datetime
    source_host: str
    signature: str
    severity: Severity
    technique_id: str = ""
