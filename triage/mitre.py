"""A compact MITRE ATT&CK technique -> tactic mapping.

The real ATT&CK matrix has hundreds of techniques. For a correlation engine we
need enough coverage to map common detections onto the kill chain and show
which stages of an attack are present. This is a curated subset of the most
frequently seen enterprise techniques, enough to make the tactic view
meaningful without vendoring the entire framework.

Each technique id maps to (technique_name, tactic). Tactics follow the ATT&CK
enterprise tactic ordering, which we preserve so a report can show progression
along the kill chain.
"""

from __future__ import annotations

# Canonical tactic order along the attack lifecycle. Used to sort the tactics
# present in an incident so the report reads like a kill chain.
TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# technique_id -> (name, tactic)
TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1590": ("Gather Victim Network Information", "Reconnaissance"),
    "T1189": ("Drive-by Compromise", "Initial Access"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1133": ("External Remote Services", "Initial Access"),
    "T1566": ("Phishing", "Initial Access"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1203": ("Exploitation for Client Execution", "Execution"),
    "T1053": ("Scheduled Task/Job", "Execution"),
    "T1547": ("Boot or Logon Autostart Execution", "Persistence"),
    "T1543": ("Create or Modify System Process", "Persistence"),
    "T1136": ("Create Account", "Persistence"),
    "T1068": ("Exploitation for Privilege Escalation", "Privilege Escalation"),
    "T1548": ("Abuse Elevation Control Mechanism", "Privilege Escalation"),
    "T1055": ("Process Injection", "Defense Evasion"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1070": ("Indicator Removal", "Defense Evasion"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1003": ("OS Credential Dumping", "Credential Access"),
    "T1552": ("Unsecured Credentials", "Credential Access"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1570": ("Lateral Tool Transfer", "Lateral Movement"),
    "T1005": ("Data from Local System", "Collection"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1572": ("Protocol Tunneling", "Command and Control"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration"),
    "T1567": ("Exfiltration Over Web Service", "Exfiltration"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1490": ("Inhibit System Recovery", "Impact"),
    # Added in 0.2 after running against Suricata ET Open metadata and the
    # labelled benchmark, which both surfaced these as frequent.
    "T1078": ("Valid Accounts", "Persistence"),
    "T1505": ("Server Software Component", "Persistence"),  # web shells
    "T1098": ("Account Manipulation", "Persistence"),
    "T1562": ("Impair Defenses", "Defense Evasion"),
    "T1036": ("Masquerading", "Defense Evasion"),
    "T1557": ("Adversary-in-the-Middle", "Credential Access"),
    "T1087": ("Account Discovery", "Discovery"),
    "T1018": ("Remote System Discovery", "Discovery"),
    "T1039": ("Data from Network Shared Drive", "Collection"),
    "T1560": ("Archive Collected Data", "Collection"),
    "T1573": ("Encrypted Channel", "Command and Control"),
    "T1219": ("Remote Access Software", "Command and Control"),
    "T1489": ("Service Stop", "Impact"),
    "T1498": ("Network Denial of Service", "Impact"),
    "T1195": ("Supply Chain Compromise", "Initial Access"),
    "T1204": ("User Execution", "Execution"),
    "T1047": ("Windows Management Instrumentation", "Execution"),
    "T1499": ("Endpoint Denial of Service", "Impact"),
}


def technique_name(tid: str) -> str:
    entry = TECHNIQUES.get(tid)
    return entry[0] if entry else "Unknown Technique"


def tactic_for(tid: str) -> str:
    entry = TECHNIQUES.get(tid)
    return entry[1] if entry else "Unknown"


def sort_tactics(tactics) -> list[str]:
    """Return tactics ordered along the kill chain, unknowns last."""
    def key(t: str) -> int:
        try:
            return TACTIC_ORDER.index(t)
        except ValueError:
            return len(TACTIC_ORDER)
    return sorted(tactics, key=key)
