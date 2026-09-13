# MITRE ATT&CK coverage

Techniques triage knows how to place on the kill chain, grouped by tactic in ATT&CK order. Alerts with any other technique id are still correlated and scored; they just do not contribute a tactic. Sub-techniques (T1059.001) roll up to their parent.

**51 techniques across 13 tactics.**


## Reconnaissance

| Technique | Name |
|---|---|
| [T1590](https://attack.mitre.org/techniques/T1590/) | Gather Victim Network Information |
| [T1595](https://attack.mitre.org/techniques/T1595/) | Active Scanning |

## Initial Access

| Technique | Name |
|---|---|
| [T1133](https://attack.mitre.org/techniques/T1133/) | External Remote Services |
| [T1189](https://attack.mitre.org/techniques/T1189/) | Drive-by Compromise |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| [T1195](https://attack.mitre.org/techniques/T1195/) | Supply Chain Compromise |
| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing |

## Execution

| Technique | Name |
|---|---|
| [T1047](https://attack.mitre.org/techniques/T1047/) | Windows Management Instrumentation |
| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |
| [T1203](https://attack.mitre.org/techniques/T1203/) | Exploitation for Client Execution |
| [T1204](https://attack.mitre.org/techniques/T1204/) | User Execution |

## Persistence

| Technique | Name |
|---|---|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation |
| [T1136](https://attack.mitre.org/techniques/T1136/) | Create Account |
| [T1505](https://attack.mitre.org/techniques/T1505/) | Server Software Component |
| [T1543](https://attack.mitre.org/techniques/T1543/) | Create or Modify System Process |
| [T1547](https://attack.mitre.org/techniques/T1547/) | Boot or Logon Autostart Execution |

## Privilege Escalation

| Technique | Name |
|---|---|
| [T1068](https://attack.mitre.org/techniques/T1068/) | Exploitation for Privilege Escalation |
| [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism |

## Defense Evasion

| Technique | Name |
|---|---|
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information |
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading |
| [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection |
| [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal |
| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses |

## Credential Access

| Technique | Name |
|---|---|
| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping |
| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force |
| [T1552](https://attack.mitre.org/techniques/T1552/) | Unsecured Credentials |
| [T1557](https://attack.mitre.org/techniques/T1557/) | Adversary-in-the-Middle |

## Discovery

| Technique | Name |
|---|---|
| [T1018](https://attack.mitre.org/techniques/T1018/) | Remote System Discovery |
| [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery |
| [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery |
| [T1083](https://attack.mitre.org/techniques/T1083/) | File and Directory Discovery |
| [T1087](https://attack.mitre.org/techniques/T1087/) | Account Discovery |

## Lateral Movement

| Technique | Name |
|---|---|
| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services |
| [T1570](https://attack.mitre.org/techniques/T1570/) | Lateral Tool Transfer |

## Collection

| Technique | Name |
|---|---|
| [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| [T1039](https://attack.mitre.org/techniques/T1039/) | Data from Network Shared Drive |
| [T1560](https://attack.mitre.org/techniques/T1560/) | Archive Collected Data |

## Command and Control

| Technique | Name |
|---|---|
| [T1071](https://attack.mitre.org/techniques/T1071/) | Application Layer Protocol |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer |
| [T1219](https://attack.mitre.org/techniques/T1219/) | Remote Access Software |
| [T1572](https://attack.mitre.org/techniques/T1572/) | Protocol Tunneling |
| [T1573](https://attack.mitre.org/techniques/T1573/) | Encrypted Channel |

## Exfiltration

| Technique | Name |
|---|---|
| [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |
| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol |
| [T1567](https://attack.mitre.org/techniques/T1567/) | Exfiltration Over Web Service |

## Impact

| Technique | Name |
|---|---|
| [T1486](https://attack.mitre.org/techniques/T1486/) | Data Encrypted for Impact |
| [T1489](https://attack.mitre.org/techniques/T1489/) | Service Stop |
| [T1490](https://attack.mitre.org/techniques/T1490/) | Inhibit System Recovery |
| [T1498](https://attack.mitre.org/techniques/T1498/) | Network Denial of Service |

## How the tactic count feeds the score

Each distinct tactic beyond the first adds 8 points (`_TACTIC_BONUS` in `scorer.py`). An incident spanning Initial Access, Execution, Credential Access and Exfiltration therefore gets +24 on top of its worst alert's base score, which is what pushes a real intrusion to the top of the list ahead of a scanner that only ever hits Discovery.
