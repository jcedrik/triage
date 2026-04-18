"""Risk scoring for incidents. 0-100."""

from __future__ import annotations

from .models import Incident, Severity

_SEVERITY_BASE = {
    Severity.INFO: 5,
    Severity.LOW: 15,
    Severity.MEDIUM: 35,
    Severity.HIGH: 60,
    Severity.CRITICAL: 80,
}

_TACTIC_BONUS = 8


def score_incident(inc: Incident) -> None:
    if not inc.alerts:
        inc.risk_score = 0
        inc.severity = Severity.INFO
        return

    worst = max(a.severity for a in inc.alerts)
    score = _SEVERITY_BASE[worst]

    distinct = len(inc.tactics)
    if distinct > 1:
        score += (distinct - 1) * _TACTIC_BONUS

    inc.risk_score = min(score, 100)
    inc.severity = worst


def score_all(incidents: list) -> None:
    for inc in incidents:
        score_incident(inc)
