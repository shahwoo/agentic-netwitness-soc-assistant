# EXECUTIVE INCIDENT OUTCOME REPORT: INC-90419 (Incident-010)

**Final Severity:** High
*Severity is rated as High. The incident involves a confirmed successful unauthorised access (brute-force followed by privileged logon) to a file server (FILESRV-02), which is a critical system supporting important business operations. The account 'svc-backup' was escalated to local Administrators group, indicating privilege misuse. Escalation factors include: critical system affected (file server), sensitive data potentially involved (file server), successful unauthorised access, and privilege escalation. While the incident does not meet the 'Critical' threshold (no evidence of ransomware, data exfiltration, or widespread service outage), it clearly meets the 'High' criteria per Appendix A.2: 'Strongly suspected or confirmed cyber attack affecting important assets, users, or systems' and 'Successful unauthorised access, privilege misuse'.*

**Confidence Level:** High
*Confidence is rated as High. Multiple reliable sources support the conclusion: NetWitness logs captured 47 failed authentication attempts followed by a successful logon from the same source IP, and the account was subsequently added to the local Administrators group. The timeline is clear and consistent, with no conflicting evidence. This meets the 'High' confidence criteria per Appendix F.3: 'Strong evidence from multiple reliable sources supports the conclusion' and 'Logs, internal records, threat intelligence, and timeline are aligned'.*

## Business Impact Assessment (Appendix C)
- **Critical System**: yes
- **Essential Service**: yes
- **Data Sensitivity**: yes
- **Operational Impact**: unknown

## Technical Chronology Summary
On 2026-07-13T03:41:22Z, NetWitness detected 47 failed authentication attempts against the service account 'svc-backup' on host FILESRV-02 (IP: 10.14.20.11) from source IP 10.14.77.203 within a 6-minute window. This was immediately followed by a successful interactive logon from the same source IP using the same account. Immediately after the successful logon, the account 'svc-backup' was added to the local Administrators group on FILESRV-02, indicating privilege escalation.

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. datetime, 2. Email address of sender/receiver, 3 IP address of sender/receiver and 4. subject of email. | **MET** | 1. Datetime: 2026-07-13T03:41:22Z (incident timestamp). 2. Email address of sender/receiver: NOT present in the timeline. The incident is about a brute-force/privileged access attack (not an email/phishing incident), so no email addresses are available. 3. IP address of sender/receiver: Source IP 10.14.77.203, Destination IP 10.14.20.11. 4. Subject of email: Not applicable - no email involved. |
| `step_2` | Does phishing attempt contain a URL or attachment? | **NOT_MET** | No. The incident describes a brute-force authentication pattern (47 failed logons followed by a successful privileged logon) against account svc-backup on host FILESRV-02. There is no URL or attachment mentioned. This is not a phishing attempt. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **NOT_MET** | The timeline indicates a successful interactive logon and immediate addition of the account to the local Administrators group, but does not provide details on whether any malicious process was spawned on the victim's machine (FILESRV-02). No process names, process IDs, or process tree information is available in the timeline. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **NOT_MET** | The timeline lacks process tree information. There is no data on what processes ran after the successful logon, no command-line arguments, no parent-child process relationships, and no indicators of privilege escalation (beyond the group addition), lateral movement, or data exfiltration activities. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **MET** | Further investigation is clearly necessary. The account svc-backup was added to local Administrators group after a brute-force attack from 10.14.77.203. Containment steps would include: isolate FILESRV-02, disable/rotate svc-backup account credentials, block 10.14.77.203 at the firewall, and investigate the source host. |

## Actions Taken
- Reviewed incident timeline and alert details from NetWitness
- Identified source IP (10.14.77.203) and destination host (FILESRV-02 at 10.14.20.11)
- Identified affected user account (svc-backup)
- Confirmed 47 failed logon attempts followed by successful logon and privilege escalation (account added to local Administrators group)
- Executed Phishing Playbook - determined incident is not a phishing attack but a brute-force/privilege escalation attack
- Assessed business impact using Appendix C checklist
- Assigned severity and confidence ratings per Appendix A and F

## Recommended Containment Actions
- Isolate host FILESRV-02 (IP: 10.14.20.11) immediately from the network by disabling its network adapter or blocking its IP at the local switch to prevent lateral movement or further compromise.
- Disable the service account 'svc-backup' immediately and rotate its credentials to prevent further unauthorised access.
- Block source IP 10.14.77.203 at the perimeter firewall and internal network to prevent any further connection attempts from this address.
- Identify and assess all guest operating systems on the same hardware host as FILESRV-02, as well as connected hosts or related virtual machines, for signs of compromise per Appendix I.2.
- Conduct checks on each related guest OS for signs of compromise, including checking for unauthorised account additions, unusual processes, and outbound connections.
- Recommend recovery of FILESRV-02 from the last-known good image after forensic imaging, pending SOC Analyst or Incident Response Team approval.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1784694498-1` | **DP-07** | Appendix C | Critical System: True, Sensitive Data: True | *Warning* | `Investigate` | Yes | 2026-07-22T04:28:18Z |
| `AUD-DP08-1784694498-2` | **DP-08** | Appendix A | Severity classification: High | *Warning* | `Escalate` | Yes | 2026-07-22T04:28:18Z |
| `AUD-DP09-1784694498-3` | **DP-09** | Appendix F | Confidence level: High | *Pass* | `Investigate` | Yes | 2026-07-22T04:28:18Z |
| `AUD-DP10-1784694498-4` | **DP-10/DP-11** | Appendix G | Severity: High, Confidence: High, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-07-22T04:28:18Z |
| `AUD-DP15-1784694498-5` | **DP-15** | Appendix B | Sensitive or personal data accessed or exfiltrated. | *Warning* | `Escalate` | Yes | 2026-07-22T04:28:18Z |
