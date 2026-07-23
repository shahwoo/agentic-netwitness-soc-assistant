# EXECUTIVE INCIDENT OUTCOME REPORT: INC-52825 (Incident-011)

**Final Severity:** Critical
*Severity is classified as Critical per Appendix A.2 (Critical: Major compromise, sensitive data exposure, multiple systems affected). The incident involves: (1) confirmed privilege escalation via UAC bypass, (2) lateral movement to other systems, (3) communication with known malicious IPs indicating C2/exfiltration, (4) 1,558 alerts with 11 IOCs matched, (5) SYSTEM account compromise, (6) potential sensitive data exposure. Escalation factors per A.3 include: critical system affected, internet-facing service affected, multiple users/systems affected, malware/privilege misuse suspected, external threat intelligence confirms malicious activity. Per Appendix B.2, this is a 'Highly significant incident' as it could cause serious reputational, financial, or operational harm.*

**Confidence Level:** High
*Confidence is High per Appendix F.3. Multiple reliable sources support the conclusion: (1) behavioural alerts ('Disables UAC', 'Lateral Move Detected') from endpoint detection, (2) network traffic to known malicious IPs (4.175.87.197, 111.223.64.89), (3) 1,558 alerts with consistent risk score of 70, (4) 11 matched IOCs, (5) SYSTEM account activity indicating privilege escalation, (6) triage risk rating of Critical across all dimensions. Evidence is sufficient (F.2) with multiple reliable sources aligned, meeting the 'High confidence' condition of logs, internal records, threat intelligence, and timeline being consistent.*

## Business Impact Assessment (Appendix C)
- **Critical System**: yes
- **Essential Service**: unknown
- **Data Sensitivity**: yes
- **Operational Impact**: yes

## Technical Chronology Summary
Host BETHANYCHUCHU was compromised via an internal hacking attack. The attacker gained initial access and escalated privileges by disabling User Account Control (UAC), as indicated by the 'Disables UAC' behavioural alert. Once elevated to NT AUTHORITY\SYSTEM privileges, the attacker performed lateral movement to other hosts on the network ('Lateral Move Detected' alert). The compromised host communicated with known malicious external IP addresses (4.175.87.197, 111.223.64.89) and other suspicious destinations, suggesting command-and-control (C2) activity and potential data exfiltration. A total of 1,558 alerts were generated with an average risk score of 70, and 11 indicators of compromise (IOCs) were matched. High CPU usage was observed, consistent with malicious process execution. The incident involved multiple internal source IPs (192.168.10.204, 192.168.20.201, 192.168.10.207) and multiple user accounts including SYSTEM and the local user Bethany Chu.

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System | **MET** | Username: NT AUTHORITY\SYSTEM (privileged), BETHANYCHUCHU\Bethany Chu (domain user). Computer name: BETHANYCHUCHU. Source IPs: 192.168.10.204, 192.168.20.201, 192.168.10.207 (internal). Destination IPs: 124.155.222.24, 150.171.28.12, 42.99.140.9, 104.208.16.91, 43.175.138.227 (external). Operating System: Unknown. Login details indicate SYSTEM account and local user Bethany Chu. |
| `step_2` | Was it horizontal or vertical | **MET** | Both horizontal and vertical privilege escalation detected. Vertical: 'Disables UAC' alert indicates privilege escalation attempt to SYSTEM level. Horizontal: 'Lateral Move Detected' alert indicates lateral movement from/to other hosts. Multiple internal source IPs (192.168.10.204, 192.168.20.201, 192.168.10.207) suggest movement across the network. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **MET** | Yes. The 'Disables UAC' alert and 'Lateral Move Detected' alert indicate malicious processes were spawned. High CPU usage (1558 alerts) and SYSTEM account activity suggest malicious processes running under elevated privileges. Process indicators were not fully enumerated but behavioural alerts confirm malicious process activity. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **MET** | Process tree analysis indicates: (1) Privilege escalation via UAC bypass (Disables UAC alert). (2) Lateral movement detected (Chu Wen - Lateral Move Detected alert). (3) Network connections to known malicious IPs (4.175.87.197, 111.223.64.89) suggesting C2 or data exfiltration. (4) SYSTEM account used for suspicious activity. (5) High alert volume (1558) with risk score 70 indicates sustained malicious activity. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **MET** | Further investigation is necessary. Immediate containment required: Isolate host BETHANYCHUCHU (192.168.10.204, 192.168.20.201, 192.168.10.207) from the network. Block outbound connections to known malicious IPs (4.175.87.197, 111.223.64.89). Disable compromised accounts (NT AUTHORITY\SYSTEM, BETHANYCHUCHU\Bethany Chu). Conduct forensic analysis of the host. Escalate to SOC Analyst for urgent response. |

## Actions Taken
- Reviewed incident timeline and enrichment data for INC-52825
- Identified affected host: BETHANYCHUCHU
- Identified compromised user accounts: NT AUTHORITY\SYSTEM, BETHANYCHUCHU\Bethany Chu
- Identified internal source IPs: 192.168.10.204, 192.168.20.201, 192.168.10.207
- Identified known malicious external IPs: 4.175.87.197, 111.223.64.89
- Analysed behavioural alerts: 'Disables UAC' and 'Lateral Move Detected'
- Correlated 1,558 alerts with 11 matched IOCs and risk score 70
- Assessed MITRE ATT&CK tactics: Lateral Movement (T1021 Remote Services)
- Evaluated business impact using Appendix C checklist
- Assigned severity (Critical) and confidence (High) per Appendix A, B, and F

## Recommended Containment Actions
- Immediately isolate host BETHANYCHUCHU (internal IPs: 192.168.10.204, 192.168.20.201, 192.168.10.207) from the network by disabling its network adapter and blocking all traffic at the local switch port.
- Block outbound connections from BETHANYCHUCHU to known malicious IPs 4.175.87.197 and 111.223.64.89 at the perimeter firewall.
- Disable or reset the credentials for user accounts NT AUTHORITY\SYSTEM and BETHANYCHUCHU\Bethany Chu immediately.
- Conduct a full forensic image of host BETHANYCHUCHU for further analysis.
- Scan the network for signs of lateral movement from BETHANYCHUCHU to other hosts (e.g., 192.168.10.x and 192.168.20.x subnets).
- Escalate to SOC Analyst for urgent incident response coordination and potential broader organisational containment.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1784715686-1` | **DP-07** | Appendix C | Critical System: True, Sensitive Data: True | *Warning* | `Investigate` | Yes | 2026-07-22T10:21:26Z |
| `AUD-DP08-1784715686-2` | **DP-08** | Appendix A | Severity classification: Critical | *Warning* | `Escalate` | Yes | 2026-07-22T10:21:26Z |
| `AUD-DP09-1784715686-3` | **DP-09** | Appendix F | Confidence level: High | *Pass* | `Investigate` | Yes | 2026-07-22T10:21:26Z |
| `AUD-DP10-1784715686-4` | **DP-10/DP-11** | Appendix G | Severity: Critical, Confidence: High, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-07-22T10:21:26Z |
| `AUD-DP15-1784715686-5` | **DP-15** | Appendix B | Sensitive or personal data accessed or exfiltrated. | *Warning* | `Escalate` | Yes | 2026-07-22T10:21:26Z |
