"""Tests for correlation and scoring."""

from datetime import datetime

from triage.models import Alert, Severity
from triage.correlator import Correlator
from triage.scorer import score_incident


def _alert(host, minute, sev, tech=""):
    return Alert(
        timestamp=datetime(2026, 6, 13, 2, minute, 0),
        source_host=host,
        signature=f"sig-{minute}",
        severity=sev,
        technique_id=tech,
    )


def test_correlation_groups_same_host_window():
    alerts = [
        _alert("h1", 0, Severity.LOW),
        _alert("h1", 5, Severity.HIGH),
        _alert("h1", 10, Severity.MEDIUM),
    ]
    incs = Correlator(window_minutes=30).correlate(alerts)
    assert len(incs) == 1
    assert len(incs[0].alerts) == 3


def test_correlation_splits_on_time_gap():
    alerts = [
        _alert("h1", 0, Severity.LOW),
        _alert("h1", 5, Severity.LOW),
        _alert("h1", 50, Severity.LOW),
    ]
    incs = Correlator(window_minutes=30).correlate(alerts)
    assert len(incs) == 2


def test_correlation_separates_hosts():
    alerts = [
        _alert("h1", 0, Severity.LOW),
        _alert("h2", 1, Severity.LOW),
    ]
    incs = Correlator(window_minutes=30).correlate(alerts)
    assert len(incs) == 2


def test_critical_alert_drives_severity():
    inc = Correlator().correlate([_alert("a", 0, Severity.CRITICAL, "T1003")])[0]
    score_incident(inc)
    assert inc.severity == Severity.CRITICAL
