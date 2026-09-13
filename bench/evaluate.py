#!/usr/bin/env python3
"""Measure triage against a labelled dataset.

Metrics (all computed from the ground-truth labels triage never sees):

  reduction          alerts in / incidents out
  campaign recall    fraction of attack campaigns that end up in an incident
                     scored HIGH or CRITICAL (an analyst would open it)
  false-positive rate fraction of benign-only incidents scored HIGH or
                     CRITICAL (an analyst would waste time on it)
  purity             fraction of incidents that are all-attack or all-benign
                     (a mixed incident means correlation glued noise onto a
                     real attack, or split one)
  precision@k        of the k top-ranked incidents, how many contain an attack

Run with and without --pivot-src-ip to see what cross-host correlation buys.

Usage:
    python bench/evaluate.py bench/data/week.json [--window 30] [--pivot-src-ip]
"""

from __future__ import annotations

import argparse
import json
from collections import Counter

from triage.correlator import Correlator
from triage.models import Severity
from triage.parsers import parse_json
from triage.scorer import score_all


def evaluate(path: str, window: int, pivot: bool, k: int = 10) -> dict:
    raw = json.load(open(path))
    label_by_key = {}
    for a in raw:
        label_by_key[(a["timestamp"], a["host"], a["signature"], a.get("src_ip", ""))] = (a["label"], a.get("campaign", ""))

    alerts = parse_json(path)
    incidents = Correlator(window_minutes=window, pivot_src_ip=pivot).correlate(alerts)
    score_all(incidents)
    ranked = sorted(incidents, key=lambda i: i.risk_score, reverse=True)

    campaigns_total = {c for (_, c) in label_by_key.values() if c.startswith("ATK")}
    campaigns_hit = set()
    benign_only = attack_any = mixed = 0
    benign_high = 0
    topk_hits = 0

    for rank, inc in enumerate(ranked):
        labels = Counter()
        camps = set()
        for a in inc.alerts:
            lab, camp = label_by_key[(a.timestamp.strftime("%Y-%m-%dT%H:%M:%S"), a.source_host, a.signature, a.src_ip)]
            labels[lab] += 1
            if camp.startswith("ATK"):
                camps.add(camp)
        actionable = inc.severity >= Severity.HIGH
        if labels["attack"] and labels["benign"]:
            mixed += 1
        if labels["attack"]:
            attack_any += 1
            if actionable:
                campaigns_hit |= camps
            if rank < k:
                topk_hits += 1
        else:
            benign_only += 1
            if actionable:
                benign_high += 1

    return {
        "alerts": len(alerts),
        "incidents": len(incidents),
        "reduction": round(len(alerts) / max(len(incidents), 1), 1),
        "campaigns": len(campaigns_total),
        "campaign_recall": round(len(campaigns_hit) / max(len(campaigns_total), 1), 3),
        "benign_incidents": benign_only,
        "benign_scored_high_or_critical": benign_high,
        "false_positive_rate": round(benign_high / max(benign_only, 1), 3),
        "mixed_incidents": mixed,
        "purity": round(1 - mixed / max(len(incidents), 1), 3),
        f"precision_at_{k}": round(topk_hits / min(k, len(ranked)), 3) if ranked else 0,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("--window", type=int, default=30)
    ap.add_argument("--pivot-src-ip", action="store_true")
    ap.add_argument("--json", action="store_true", help="print JSON only")
    a = ap.parse_args()
    res = evaluate(a.dataset, a.window, a.pivot_src_ip)
    if a.json:
        print(json.dumps(res))
        return
    for k, v in res.items():
        print(f"{k:32} {v}")


if __name__ == "__main__":
    main()
