# SOC Incident Report

## 1. Report Metadata

| Field | Value |
|---|---|
| Incident ID | INC-0001 |
| Alert ID | ALERT-0001 |
| Case Title | Phishing Email with Suspicious Attachment |
| Created At | 2026-06-02T21:10:32+08:00 |
| Report Status | ready_for_analyst_review |
| Validation Status | passed |
| Generation Mode | deterministic_only |
| LLM Used | False |
| LLM Status | disabled |
| LLM Quality Status | not_used |
| LLM Quality Issues | None |
| RAG Used | True |
| RAG Status | success_direct_file_retrieval |

---

## 2. Incident Overview

| Field | Value |
|---|---|
| Alert Name | Suspicious Invoice Attachment |
| Alert Source | RSA NetWitness SIEM |
| Alert Timestamp | 2026-06-02T09:10:00+08:00 |
| Severity | High |
| Severity Reason | Confirmed malicious domain and suspicious endpoint activity. |
| Confidence | High |
| Confidence Reason | Multiple evidence sources support escalation. |
| Classification | True Positive |
| Likely Scenario | Phishing with malicious attachment |
| Scenario Type | phishing |

---

## 3. Executive Summary

This True Positive incident is assessed as High severity with High confidence and is currently framed as Phishing with malicious attachment. The known affected scope is HOST-01 (Invoice processing, Medium criticality, Windows Workstation) and user@example.com (Finance User, Standard User, MFA: Enabled). The case is supported by the following evidence: EVID-001: Suspicious invoice email delivered to user@example.com. EVID-002: WINWORD.EXE spawned powershell.exe with encoded command. Key malicious or suspicious indicators include malicious-domain.com (Domain, Malicious), 203.0.113.45 (IP Address, Suspicious), hxxp://malicious-domain.com/invoice-review (URL, Malicious). Containment is currently Pending Analyst Decision, and analyst approval is Pending Analyst Decision. The report remains review-ready but not finalised because these validation items remain open: High: Confirm whether PowerShell payload completed execution. High: Confirm whether the user clicked the link, opened the attachment, or enabled macros. High: Confirm whether credentials, tokens, mailbox rules, or OAuth grants were abused. Medium: Confirm whether similar phishing emails were delivered to other recipients. Medium: Confirm whether data exfiltration or sensitive mailbox access occurred.

---

## 4. Affected Entities

### Affected Assets

| Hostname | IP Address | Type | Criticality | Owner | Business Function | Isolation Status |
|---|---|---|---|---|---|---|
| HOST-01 | 10.10.20.15 | Windows Workstation | Medium | Finance Department | Invoice processing | No |

### Affected Users

| Username | Email | Role | Privilege | Groups | MFA | Status |
|---|---|---|---|---|---|---|
| user@example.com | user@example.com | Finance User | Standard User | Finance-Users | Enabled | Active |

---

## 5. Indicators of Compromise

| IOC | Type | Reputation | Confidence | Source | Evidence |
|---|---|---|---|---|---|
| `malicious-domain.com` | Domain | Malicious | High | Threat Intelligence | EVID-001 |
| `203.0.113.45` | IP Address | Suspicious | Medium | NetWitness | Not linked |
| `hxxp://malicious-domain.com/invoice-review` | URL | Malicious | High | Investigation | EVID-001 |

---

## 6. Evidence-Backed Findings

| Finding | Status | Confidence | Evidence References | Interpretation |
|---|---|---|---|---|
| The incident classification is True Positive. | Fact | High | EVID-001, EVID-002 | Classification is taken from investigation output first, with triage as fallback. |
| Suspicious phishing email delivery was observed. | Evidence-Backed Finding | High | EVID-001 | Email delivery is supported by existing email/timeline evidence. |
| Suspicious PowerShell or process activity was observed after the phishing event. | Evidence-Backed Finding | Medium | EVID-002 | This supports deeper validation of payload execution, script activity, and created artefacts. |
| 3 malicious or suspicious IOC(s) are present in the reporting context. | Evidence-Backed Finding | Medium | EVID-001 | The Reporting Agent consolidated these IOCs from enrichment and investigation outputs only. |
| An incident timeline was provided by the investigation output. | Fact | Medium | EVID-001, EVID-002 | Timeline entries are rendered as supplied and should be validated by the SOC analyst. |
| Containment/approval status is Pending Analyst Decision. | Fact | High | approval_result.json | Approval data is taken only from approval_result.json and is not decided by the Reporting Agent. |

---

## 7. Timeline

| Time | Event | Source | Evidence |
|---|---|---|---|
| 2026-06-02T09:10:00+08:00 | Suspicious email delivered. | Email Gateway | EVID-001 |
| 2026-06-02T09:14:00+08:00 | Suspicious PowerShell observed. | Endpoint Telemetry | EVID-002 |

---

## 8. Policy and Playbook Context

### 8.1 Policy Application Summary

| Source | Relevant Guidance | Application to This Case |
|---|---|---|
| incident_severity_policy.md | High severity is appropriate when malicious IOCs, suspicious process execution, likely compromise, or business impact are present. | Supports the current severity rating of High based on malicious/suspicious indicators and endpoint activity. |
| containment_approval_policy.md | High or Critical severity containment actions that may disrupt users or systems require SOC analyst approval. | Containment/approval remains Pending Analyst Decision; the report records the decision without executing containment. |
| reporting_timeline_policy.md | High severity incidents require investigation reporting and SOC analyst review as soon as evidence is available. | Supports the current report status: ready_for_analyst_review. |
| report_writing_sop.md | The Reporting Agent must consolidate triage, investigation, IOCs, timeline, containment, and analyst decision data without inventing missing evidence. | The report separates evidence-backed findings, interpretation, and evidence gaps. |
| phishing_response_playbook.md | Phishing reporting should document sender/recipient context, URLs/domains/hashes, user interaction, endpoint activity, and missing validation steps. | The incident is treated as a phishing case and includes phishing-specific evidence gaps for analyst follow-up. |

### 8.2 Knowledge Files Used

- policies/incident_severity_policy.md
- policies/containment_approval_policy.md
- policies/reporting_timeline_policy.md
- procedures/report_writing_sop.md
- procedures/evidence_collection_sop.md
- procedures/investigation_sop.md
- playbooks/phishing_response_playbook.md

### 8.3 Playbooks Excluded in This Version

- malware_response_playbook.md
- ransomware_response_playbook.md

> Raw retrieved RAG snippets are stored in `enriched_reporting_context.json` for traceability, but this report only shows the analyst-friendly policy application summary.

---

## 9. Containment and Approval Status

| Field | Value |
|---|---|
| Containment Status | Pending Analyst Decision |
| Recommended Containment Action | isolate endpoint if execution is confirmed |
| Approval Required | Yes |
| Approval Status | Pending Analyst Decision |
| Analyst Decision | Pending Analyst Decision |
| Approved By | Not Provided |
| Approved Action | Not Provided |
| Analyst Comments | Awaiting SOC analyst decision. |

---

## 10. Impact Assessment

| Impact Area | Assessment |
|---|---|
| Business Impact | Current business impact is limited to HOST-01 (Invoice processing, Medium criticality) and user@example.com (Finance User, Standard User). Because this involves invoice-processing context, containment or credential reset may temporarily affect finance workflow. |
| Security Risk | Security risk is centred on phishing delivery, suspicious attachment interaction, possible PowerShell execution, credential exposure, and possible follow-on access if the payload completed successfully. |
| Not Yet Confirmed | Payload completion, credential submission, mailbox/OAuth abuse, similar recipient exposure, and data exfiltration are not fully confirmed. |

---

## 11. Recommended Actions

| Priority | Action | Owner | Approval Required | Rationale |
|---|---|---|---|---|
| P1 | Block malicious-domain.com and related URL. | Network Security | No | Threat intelligence reputation is malicious. |
| P1 | Review endpoint execution and isolate HOST-01 if compromise is confirmed. | SOC Analyst | Yes | Endpoint shows suspicious process activity. |

---

## 12. Evidence Gaps

| Priority | Gap | Required Data |
|---|---|---|
| High | Confirm whether PowerShell payload completed execution. | Script block logs, process completion status, created files. |
| High | Confirm whether the user clicked the link, opened the attachment, or enabled macros. | Email gateway click logs, endpoint file open events, Office telemetry, macro execution logs. |
| High | Confirm whether credentials, tokens, mailbox rules, or OAuth grants were abused. | Identity provider logs, MFA logs, mailbox audit logs, inbox rule changes, OAuth consent logs. |
| Medium | Confirm whether similar phishing emails were delivered to other recipients. | Email gateway search by sender, subject, URL, attachment hash, and campaign indicators. |
| Medium | Confirm whether data exfiltration or sensitive mailbox access occurred. | Mailbox access logs, cloud storage audit logs, outbound proxy logs, suspicious upload events. |

---

## 13. Analyst Review

This report is generated for SOC analyst review. The Reporting Agent does not close the case, approve containment, or replace analyst judgement.

| Field | Value |
|---|---|
| SOC Review Required | Yes |
| Review Status | Pending |
| Missing Required Fields | None |
| Warnings | None |

---

## 14. Conclusion

The report is suitable for SOC analyst review with status ready_for_analyst_review. Before closure, the analyst should validate payload execution, credential or session exposure, similar recipient exposure, containment approval, and data exposure. Any disruptive action, such as endpoint isolation or credential revocation, should follow the recorded approval workflow.
