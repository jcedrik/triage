"""MITRE ATT&CK technique -> tactic mapping (subset)."""

from __future__ import annotations

TECHNIQUES = {
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1003": ("OS Credential Dumping", "Credential Access"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1566": ("Phishing", "Initial Access"),
}


def technique_name(tid: str) -> str:
    entry = TECHNIQUES.get(tid)
    return entry[0] if entry else "Unknown Technique"


def tactic_for(tid: str) -> str:
    entry = TECHNIQUES.get(tid)
    return entry[1] if entry else "Unknown"
