# EXECUTIVE INCIDENT OUTCOME REPORT: INC-53018 (Incident-008)

**Final Severity:** High
*Severity is set to High. The incident involves confirmed suspicious activity (unknown processes, odd device behavior) with potential lateral movement (MITRE T1021) between internal hosts. While no sensitive data or critical system is confirmed, the escalation factors include: potential lateral movement/spreading activity, multiple systems potentially affected (192.168.10.204 and 192.168.10.202), and the triage risk rating is High (score 70). Per Appendix A.2, 'Strongly suspected or confirmed cyber attack affecting important assets, users, or systems' and 'Successful unauthorised access, malicious IOC, privilege misuse, server attack, repeated suspicious activity' map to High severity. It does not meet Critical criteria as there is no confirmed ransomware, data exfiltration, or widespread service outage.*

**Confidence Level:** Medium
*Confidence is set to Medium. Per Appendix F.3, Medium confidence means 'Some evidence supports the conclusion, but there are gaps.' The incident has multiple indicators (unknown processes, odd behavior, internal traffic changes, 4 matched IOCs) but lacks critical details such as confirmed process names/paths, confirmed malicious files, confirmed data exfiltration, or endpoint forensic evidence. The evidence is partially sufficient - some evidence exists but there are gaps in the process tree and full scope of compromise. Per Appendix F.2, this is 'Partially sufficient evidence' requiring continued investigation.*

## Business Impact Assessment (Appendix C)
- **Critical System**: unknown
- **Essential Service**: unknown
- **Data Sensitivity**: unknown
- **Operational Impact**: unknown

## Technical Chronology Summary
On 2025-11-18 at 03:18 UTC, NetWitness Endpoint generated high-risk alerts on host KELLYWANG (IP 192.168.10.204). The alerts indicated unknown processes running and odd device behavior. Network telemetry showed traffic from KELLYWANG (192.168.10.204) to another internal host at 192.168.10.202, suggesting possible lateral movement or data exfiltration. The MITRE ATT&CK technique identified was T1021 (Remote Services) under the Lateral Movement tactic. The triage identified 4 matched IOCs including changes in network traffic telemetry, unknown traffic between internal IPs, odd device behavior, and unknown processes running. The overall risk was assessed as High.

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. datetime, 2. Email address of sender/receiver, 3 IP address of sender/receiver and 4. subject of email. | **NOT_MET** | No email-related data is available in the incident. The alert originates from NetWitness Endpoint (host-based detection), not from an email security gateway. No sender/receiver email addresses or email subject lines are present in the incident data. |
| `step_2` | Does phishing attempt contain a URL or attachment? | **NOT_MET** | No phishing email artifacts (URLs or attachments) are present in the incident data. The alert is based on endpoint behavioral detections (unknown processes, odd device behavior, network traffic changes) rather than email-based indicators. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **NOT_MET** | The incident mentions 'unknown processes running' and 'odd device behavior' on host KELLYWANG (192.168.10.204), but no specific process names, paths, or PIDs are provided in the available data to confirm malicious process spawning. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **NOT_MET** | The incident indicates potential lateral movement (MITRE ATT&CK T1021 - Remote Services) with traffic between 192.168.10.204 (KELLYWANG) and 192.168.10.202. However, no detailed process tree data is available for analysis. The triage notes mention 'unknown traffic originating from/terminating on the device' and 'unknown process running' as indicators of compromise. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **NOT_MET** | The phishing playbook is not applicable to this incident. The alert is an endpoint behavioral detection (NetWitness Endpoint) with signs of lateral movement, not a phishing email. Further investigation is required using a different playbook (e.g., Lateral Movement or Compromised Asset playbook). Containment of host KELLYWANG (192.168.10.204) is recommended. |

## Actions Taken
- Reviewed incident details and alert classification from NetWitness Endpoint
- Identified affected host KELLYWANG (192.168.10.204) and target host (192.168.10.202)
- Analyzed MITRE ATT&CK mapping to T1021 Remote Services (Lateral Movement)
- Reviewed triage IOC summary and risk rating (High risk score of 70)
- Determined that the Phishing playbook is not applicable to this endpoint behavioral alert
- Assessed business impact using Appendix C checklist

## Recommended Containment Actions
- Isolate the host KELLYWANG (192.168.10.204) immediately from the network by disabling its network adapter or blocking its IP at the local switch to prevent further lateral movement or data exfiltration.
- Block all outbound traffic from 192.168.10.204 to 192.168.10.202 at the firewall or network segmentation boundary to halt any active lateral movement or data exfiltration sessions.
- Conduct a forensic image of KELLYWANG (192.168.10.204) for further analysis of the unknown processes and odd device behavior.
- Review and revoke any active remote sessions (RDP, WinRM, SSH, etc.) originating from KELLYWANG (192.168.10.204) to other internal hosts.
- Check host 192.168.10.202 for signs of compromise or unauthorized access originating from KELLYWANG.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1784697349-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: False | *Pass* | `Investigate` | Yes | 2026-07-22T05:15:49Z |
| `AUD-DP08-1784697349-2` | **DP-08** | Appendix A | Severity classification: High | *Warning* | `Escalate` | Yes | 2026-07-22T05:15:49Z |
| `AUD-DP09-1784697349-3` | **DP-09** | Appendix F | Confidence level: Medium | *Warning* | `Escalate` | Yes | 2026-07-22T05:15:49Z |
| `AUD-DP10-1784697349-4` | **DP-10/DP-11** | Appendix G | Severity: High, Confidence: Medium, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-07-22T05:15:49Z |
