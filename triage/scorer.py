"""Risk scoring for correlated incidents.

An analyst can't chase every incident equally. The scorer produces a single
0-100 risk number so incidents can be ranked, and derives an overall severity
from it. The score combines signals that genuinely change how urgent an
incident is:

  - the worst single alert severity (a critical detection dominates)
  - how many distinct kill-chain tactics are present (an incident spanning
    execution -> credential access -> exfiltration is far worse than three
    recon hits)
  - alert volume (sustained activity is more suspicious than a one-off)

The weights are deliberately simple and documented so the number is
explainable, which matters: a black-box score an analyst can't reason about
gets ignored.
"""

from __future__ import annotations

from .models import Incident, Severity

# Base points contributed by the worst alert severity in the incident.
_SEVERITY_BASE = {
    Severity.INFO: 5,
    Severity.LOW: 15,
    Severity.MEDIUM: 35,
    Severity.HIGH: 60,
    Severity.CRITICAL: 80,
}

# Each distinct tactic beyond the first adds points: multi-stage attacks are
# the ones that matter most.
_TACTIC_BONUS = 8

# Small bonus for sustained volume, capped so noise alone can't max the score.
_VOLUME_BONUS_PER_ALERT = 2
_VOLUME_BONUS_CAP = 16

# Ceiling for an incident made of one signature in one tactic (see below).
_SINGLE_STAGE_CAP = 59


def score_incident(inc: Incident) -> None:
    """Compute and set inc.risk_score (0-100) and inc.severity in place."""
    if not inc.alerts:
        inc.risk_score = 0
        inc.severity = Severity.INFO
        return

    worst = max(a.severity for a in inc.alerts)
    score = _SEVERITY_BASE[worst]

    # Multi-tactic escalation.
    distinct_tactics = len(inc.tactics)
    if distinct_tactics > 1:
        score += (distinct_tactics - 1) * _TACTIC_BONUS

    # Volume, capped.
    volume_bonus = min(len(inc.alerts) * _VOLUME_BONUS_PER_ALERT,
                       _VOLUME_BONUS_CAP)
    score += volume_bonus

    # Single-stage dampening. A lone HIGH alert with no second tactic and no
    # second signature is, on the labelled benchmark, a backup job or a
    # scanner far more often than an intrusion. Cap it just below HIGH so it
    # is still visible but does not page anyone. A lone CRITICAL still does.
    distinct_sigs = len({a.signature for a in inc.alerts})
    if worst < Severity.CRITICAL and distinct_tactics <= 1 and distinct_sigs == 1:
        score = min(score, _SINGLE_STAGE_CAP)

    inc.risk_score = min(score, 100)
    inc.severity = _severity_from_score(inc.risk_score)


def _severity_from_score(score: int) -> Severity:
    if score >= 80:
        return Severity.CRITICAL
    if score >= 60:
        return Severity.HIGH
    if score >= 35:
        return Severity.MEDIUM
    if score >= 15:
        return Severity.LOW
    return Severity.INFO


def score_all(incidents: list[Incident]) -> None:
    for inc in incidents:
        score_incident(inc)
