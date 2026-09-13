"""Tests for triage: parsing, correlation, scoring, MITRE mapping.

Positive and negative cases both matter. We check that correlation actually
groups and splits correctly (the core value), that scoring reflects
multi-stage escalation, and that parsers reject bad input loudly.
"""

import os
import tempfile
from datetime import datetime

from triage import mitre
from triage.correlator import Correlator
from triage.models import Alert, Severity
from triage.parsers import parse_csv, parse_json
from triage.scorer import score_all, score_incident


def _alert(host, minute, sev, tech=""):
    return Alert(
        timestamp=datetime(2026, 6, 13, 2, minute, 0),
        source_host=host,
        signature=f"sig-{minute}",
        severity=sev,
        technique_id=tech,
    )


# ---- correlation ----

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
        _alert("h1", 50, Severity.LOW),  # 45 min gap > 30 min window
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
    hosts = {i.host for i in incs}
    assert hosts == {"h1", "h2"}


def test_correlation_rolls_up_techniques():
    alerts = [
        _alert("h1", 0, Severity.HIGH, "T1190"),   # Initial Access
        _alert("h1", 2, Severity.HIGH, "T1059"),   # Execution
        _alert("h1", 4, Severity.CRITICAL, "T1041"),  # Exfiltration
    ]
    incs = Correlator(window_minutes=30).correlate(alerts)
    assert len(incs) == 1
    assert incs[0].techniques == {"T1190", "T1059", "T1041"}
    assert "Initial Access" in incs[0].tactics
    assert "Exfiltration" in incs[0].tactics


# ---- scoring ----

def test_multistage_scores_higher_than_single():
    single = Correlator().correlate([_alert("a", 0, Severity.HIGH, "T1190")])[0]
    multi = Correlator().correlate([
        _alert("b", 0, Severity.HIGH, "T1190"),
        _alert("b", 2, Severity.HIGH, "T1059"),
        _alert("b", 4, Severity.HIGH, "T1041"),
    ])[0]
    score_incident(single)
    score_incident(multi)
    assert multi.risk_score > single.risk_score


def test_critical_alert_drives_severity():
    inc = Correlator().correlate([_alert("a", 0, Severity.CRITICAL, "T1003")])[0]
    score_incident(inc)
    assert inc.risk_score >= 80
    assert inc.severity == Severity.CRITICAL


def test_score_capped_at_100():
    alerts = [_alert("a", m, Severity.CRITICAL, tid)
              for m, tid in enumerate(
                  ["T1190", "T1059", "T1003", "T1041", "T1486", "T1046"])]
    inc = Correlator().correlate(alerts)[0]
    score_incident(inc)
    assert inc.risk_score == 100


# ---- mitre ----

def test_mitre_tactic_lookup():
    assert mitre.tactic_for("T1041") == "Exfiltration"
    assert mitre.tactic_for("T9999") == "Unknown"


def test_mitre_sorts_along_killchain():
    tactics = ["Exfiltration", "Initial Access", "Execution"]
    ordered = mitre.sort_tactics(tactics)
    assert ordered == ["Initial Access", "Execution", "Exfiltration"]


# ---- parsers ----

def test_parse_json_roundtrip():
    data = ('[{"timestamp":"2026-06-13T02:00:00","host":"h1",'
            '"signature":"test","severity":"high","technique_id":"T1059"}]')
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write(data)
        path = f.name
    try:
        alerts = parse_json(path)
        assert len(alerts) == 1
        assert alerts[0].source_host == "h1"
        assert alerts[0].severity == Severity.HIGH
    finally:
        os.unlink(path)


def test_parse_json_bad_severity_raises():
    data = ('[{"timestamp":"2026-06-13T02:00:00","host":"h1",'
            '"signature":"t","severity":"bogus"}]')
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write(data)
        path = f.name
    try:
        raised = False
        try:
            parse_json(path)
        except ValueError:
            raised = True
        assert raised
    finally:
        os.unlink(path)


def test_parse_csv_missing_column_raises():
    data = "timestamp,host,signature\n2026-06-13T02:00:00,h1,test\n"
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
        f.write(data)
        path = f.name
    try:
        raised = False
        try:
            parse_csv(path)
        except ValueError:
            raised = True
        assert raised
    finally:
        os.unlink(path)


# ---- v0.2: Suricata EVE, src_ip pivot, dampening, KQL ----
import json

from triage import report
from triage.parsers import load, parse_suricata_eve


def test_suricata_eve_parser_filters_and_maps(tmp_path):
    alerts = parse_suricata_eve("samples/eve.json")
    assert len(alerts) == 5  # the flow record is skipped
    assert alerts[0].technique_id == "T1046"
    assert alerts[1].severity == Severity.CRITICAL  # suricata severity 1
    assert alerts[2].technique_id == "T1505"  # sub-technique rolled up
    assert alerts[3].technique_id == "T1041"  # pulled from the signature text
    assert alerts[0].source_host == "10.0.0.5"


def test_load_autodetects_suricata():
    assert len(load("samples/eve.json")) == 5
    assert len(load("samples/alerts.json")) == 8


def _a(ts, host, sig, sev, tech="", src=""):
    return Alert(datetime.fromisoformat(ts), host, sig, Severity.from_str(sev), tech, "", src)


def test_pivot_merges_lateral_movement_across_hosts():
    alerts = [
        _a("2026-06-13T02:00:00", "web-01", "SQLi", "high", "T1190", "203.0.113.9"),
        _a("2026-06-13T02:05:00", "web-01", "Web shell", "critical", "T1059", "203.0.113.9"),
        _a("2026-06-13T02:12:00", "db-01", "SMB lateral", "high", "T1021", "203.0.113.9"),
    ]
    assert len(Correlator().correlate(alerts)) == 2
    merged = Correlator(pivot_src_ip=True).correlate(alerts)
    assert len(merged) == 1
    assert merged[0].hosts == ["db-01", "web-01"]


def test_pivot_never_joins_on_internal_ip():
    alerts = [
        _a("2026-06-13T02:00:00", "ws-001", "Brute force", "medium", "T1110", "10.0.5.4"),
        _a("2026-06-13T02:01:00", "ws-002", "Brute force", "medium", "T1110", "10.0.5.4"),
    ]
    assert len(Correlator(pivot_src_ip=True).correlate(alerts)) == 2


def test_single_stage_high_is_capped_below_high():
    inc = Correlator().correlate([_a("2026-06-13T02:00:00", "db-01", "Large outbound transfer", "high", "T1041")])
    score_all(inc)
    assert inc[0].severity == Severity.MEDIUM
    assert inc[0].risk_score == 59


def test_single_critical_is_not_capped():
    inc = Correlator().correlate([_a("2026-06-13T02:00:00", "db-01", "Ransomware burst", "critical", "T1486")])
    score_all(inc)
    assert inc[0].severity == Severity.CRITICAL


def test_kql_has_one_query_per_incident():
    alerts = load("samples/alerts.json")
    incidents = Correlator().correlate(alerts)
    score_all(incidents)
    kql = report.render_kql(incidents)
    assert kql.count("SecurityAlert\n") == len(incidents)
    assert 'CompromisedEntity =~ "web-01"' in kql
    assert 'Techniques has "T1190"' in kql


def test_json_report_carries_hosts_and_src_ips():
    alerts = load("samples/alerts.json")
    incidents = Correlator().correlate(alerts)
    score_all(incidents)
    data = json.loads(report.render_json(incidents, len(alerts)))
    top = max(data["incidents"], key=lambda i: i["risk_score"])
    assert "203.0.113.9" in top["src_ips"]
