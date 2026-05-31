# Escalation Policy

## 1. Purpose

This policy defines when alerts and incidents should be escalated within the Agentic AI Threat Hunting and Autonomous Investigation Assistant.

The purpose is to ensure that high-risk cases, uncertain cases, business-impacting cases, and incidents requiring human judgement are routed to the appropriate SOC analyst or incident response team.

Escalation helps prevent serious incidents from being missed, while also avoiding unnecessary escalation for low-risk alerts.

---

## 2. Scope

This policy applies to alerts and incidents processed by the following components:

- Orchestration Agent
- Triage Agent
- Investigation Agent
- Reporting Agent
- Threat Intelligence module
- Threat Hunting module
- Containment approval workflow

This policy applies to:

- True positive alerts
- False positive alerts
- High and Critical severity incidents
- Low-confidence but high-impact alerts
- Incidents involving containment
- Incidents involving privileged users
- Incidents involving business-critical systems
- Incidents requiring SOC analyst review

---

## 3. Escalation Levels

The system uses four escalation levels:

| Escalation Level | Meaning |
|---|---|
| None | No escalation is needed |
| SOC Review | A SOC analyst should review the case |
| Incident Response | Incident response team involvement is required |
| Management / Stakeholder Notification | Business or management-level awareness may be required |

---

## 4. No Escalation Required

Escalation is not required when the alert is low risk and does not show evidence of compromise.

### Conditions

Set `escalation_required` to `false` when most of the following are true:

- Severity is Low
- Confidence is High or Medium
- Alert is likely benign
- No confirmed malicious IOC
- No suspicious endpoint activity
- No credential compromise
- No lateral movement
- No command-and-control activity
- No data exfiltration
- No business-critical asset involved
- No containment required

### Example Scenarios

- Single failed login attempt
- Benign internal scan
- Clean file hash
- Known authorised admin activity
- Suspicious but unconfirmed URL visit with no payload execution

### Required Output

```json
{
  "escalation_required": false,
  "escalation_level": "none",
  "escalation_reason": "No confirmed malicious activity or business impact detected"
}
```

---

## 5. SOC Review Escalation

SOC analyst review is required when the system needs human validation before making a final decision.

### Conditions

Escalate to SOC Review when one or more of the following are true:

- Severity is High
- Severity is Critical
- Confidence is Low but potential impact is High or Critical
- Classification is uncertain
- Containment is recommended
- SOC analyst approval is pending
- Threat intelligence results are conflicting
- The alert involves a privileged user
- The alert involves a business-critical asset
- The alert has missing but important evidence
- The system detects unusual behaviour that cannot be confidently explained
- Reporting Agent cannot finalise the report due to missing key fields

### Example Scenarios

- High severity malware alert with Medium confidence
- Critical alert requiring containment approval
- Suspicious login from unusual location involving an admin account
- Threat intelligence says an IOC is suspicious, but not clearly malicious
- Report is missing severity, confidence, or classification

### Required Output

```json
{
  "escalation_required": true,
  "escalation_level": "soc_review",
  "escalation_target": "SOC Analyst",
  "escalation_reason": "Human review required due to high severity, uncertain evidence, or pending approval"
}
```

---

## 6. Incident Response Escalation

Escalation to the Incident Response team is required when there is confirmed or highly likely compromise that may affect systems, users, data, or business operations.

### Conditions

Escalate to Incident Response when one or more of the following are true:

- Confirmed malware infection
- Ransomware activity is detected or strongly suspected
- Command-and-control communication is confirmed
- Lateral movement is detected
- Credential compromise is confirmed
- Privileged account abuse is detected
- Data exfiltration is detected or strongly suspected
- Multiple users or hosts are affected
- Business-critical system is compromised
- Containment has been approved or executed
- Threat hunting finds related malicious activity
- The incident may spread if not handled quickly

### Example Scenarios

- Endpoint is confirmed infected with malware
- Host communicates with known C2 infrastructure
- Multiple endpoints show the same malicious IOC
- Admin account is used suspiciously after suspected credential theft
- Ransomware-like file encryption behaviour is detected
- Sensitive data exfiltration is suspected

### Required Output

```json
{
  "escalation_required": true,
  "escalation_level": "incident_response",
  "escalation_target": "Incident Response Team",
  "escalation_reason": "Confirmed or highly likely compromise requiring coordinated response"
}
```

---

## 7. Management or Stakeholder Notification

Management or stakeholder notification may be required when the incident has business, operational, legal, or reputational impact.

### Conditions

Escalate to management or stakeholders when one or more of the following are true:

- Business-critical service is affected
- Multiple systems or departments are affected
- Sensitive data may be exposed
- Ransomware or destructive activity is confirmed
- Incident may cause downtime
- Incident may affect customers, partners, or public-facing services
- Incident requires official reporting or compliance review
- Incident response requires business decision-making

### Example Scenarios

- Database server compromise
- Ransomware affecting shared file servers
- Possible data exfiltration involving personal or sensitive data
- Attack affecting customer-facing systems
- Major operational disruption

### Required Output

```json
{
  "escalation_required": true,
  "escalation_level": "management_notification",
  "escalation_target": "Management or Relevant Stakeholders",
  "escalation_reason": "Incident may cause business, operational, legal, or reputational impact"
}
```

---

## 8. Severity-Based Escalation Rules

| Severity | Escalation Decision |
|---|---|
| Low | Usually no escalation |
| Medium | Escalate only if evidence is unclear, asset is important, or repeated activity is detected |
| High | Escalate to SOC Review |
| Critical | Escalate to SOC Review and likely Incident Response |

---

## 9. Confidence-Based Escalation Rules

Confidence should affect escalation decisions.

| Confidence | Escalation Decision |
|---|---|
| Low | Escalate if severity is High or Critical, or evidence is incomplete |
| Medium | Escalate if severity is High or Critical, or containment is recommended |
| High | Escalate if malicious activity is confirmed or impact is significant |

### Important Rule

A High or Critical severity case with Low confidence should still be escalated for human review because the possible impact is serious.

---

## 10. Asset-Based Escalation Rules

Escalation should be prioritised when important assets or accounts are involved.

| Asset or Account Type | Escalation Decision |
|---|---|
| Normal user workstation | Escalate based on severity and evidence |
| Shared workstation | Escalate if compromise is suspected |
| Server | Escalate to SOC Review or Incident Response |
| Database server | Escalate to Incident Response |
| Domain controller | Escalate to Incident Response |
| Email server | Escalate to Incident Response |
| SIEM or security tool | Escalate to Incident Response |
| Privileged account | Escalate to SOC Review or Incident Response |
| Executive account | Escalate to SOC Review or Incident Response |

---

## 11. Threat Intelligence Escalation Rules

Threat intelligence should influence escalation.

Escalate when:

- IOC is confirmed malicious by multiple sources
- IOC is linked to known malware
- IOC is linked to ransomware
- IOC is linked to phishing infrastructure
- IOC is linked to command-and-control infrastructure
- IOC appears in AlienVault OTX pulses or similar threat reports
- IP address has strong abuse reputation
- File hash has high malicious detections
- Domain or URL is known to deliver payloads
- Threat intelligence results conflict and require analyst review

### Example Output

```json
{
  "escalation_required": true,
  "escalation_level": "soc_review",
  "escalation_reason": "Threat intelligence shows strong malicious reputation and requires analyst validation"
}
```

---

## 12. Threat Hunting Escalation Rules

Threat hunting findings should trigger escalation when they reveal broader compromise.

Escalate when threat hunting finds:

- Same malicious IOC on multiple hosts
- Same suspicious user behaviour across multiple accounts
- Repeated communication to malicious infrastructure
- Historical matches linked to previous incidents
- Signs of lateral movement
- Signs of credential compromise
- Signs of data exfiltration
- Multiple related alerts across the environment

### Example Output

```json
{
  "escalation_required": true,
  "escalation_level": "incident_response",
  "escalation_reason": "Threat hunting found related malicious activity across multiple hosts"
}
```

---

## 13. Containment-Related Escalation

Containment recommendations should usually trigger escalation because containment actions may disrupt business operations.

### Escalate to SOC Review when:

- Containment is recommended
- Containment status is `pending_approval`
- SOC analyst approval status is `pending`
- The recommended action may disrupt a user, host, service, or network connection

### Escalate to Incident Response when:

- Containment is approved for a confirmed compromise
- Multiple containment actions are needed
- Endpoint isolation, account disabling, or network blocking is required for a serious incident

### Example Output

```json
{
  "escalation_required": true,
  "escalation_level": "soc_review",
  "escalation_target": "SOC Analyst",
  "escalation_reason": "Containment approval is required before disruptive action can be taken"
}
```

---

## 14. Missing Information Escalation

Escalation may be required when key fields are missing and the system cannot safely proceed.

Escalate or return to investigation when any of the following are missing:

- Severity
- Confidence
- Classification
- Likely scenario
- Affected host
- Affected user
- Key IOCs
- Containment status
- Approval status
- Evidence summary

### Required Output

```json
{
  "escalation_required": true,
  "escalation_level": "soc_review",
  "escalation_reason": "Required decision fields are missing and the case cannot be finalised safely",
  "recommended_next_step": "Return to Triage Agent or Investigation Agent for missing context"
}
```

---

## 15. Escalation Workflow

The escalation workflow should be:

1. Triage Agent or Investigation Agent evaluates severity, confidence, evidence, and impact.
2. Agent determines whether escalation is required.
3. Orchestration Agent checks the escalation fields.
4. If escalation is not required, workflow continues normally.
5. If SOC Review is required, Orchestration Agent routes to SOC analyst review.
6. If Incident Response is required, Orchestration Agent routes to incident response handling.
7. If Management notification is required, final report should include management summary.
8. Reporting Agent records the escalation reason and final escalation status.

---

## 16. Orchestration Routing Rules

The Orchestration Agent should route based on escalation decision.

| Escalation Condition | Next Agent or Step |
|---|---|
| No escalation required | Continue normal workflow |
| SOC Review required | `soc_review_step` or `approval_step` |
| Containment approval pending | `approval_step` |
| Incident Response required | `incident_response_step` |
| Management notification required | `management_notification_step` or Reporting Agent |
| Missing critical fields | Return to Triage Agent or Investigation Agent |

### Example Orchestration Decision

```json
{
  "next_agent": "soc_review_step",
  "workflow_decision": "escalate_for_soc_review",
  "routing_reason": "High severity incident requires human validation"
}
```

---

## 17. Required Escalation Output Fields

When this policy is applied, the agent output should include:

```json
{
  "escalation_required": true,
  "escalation_level": "soc_review",
  "escalation_target": "SOC Analyst",
  "escalation_reason": "High severity incident involving likely compromise",
  "recommended_next_step": "Send to SOC Analyst Review"
}
```

For more serious cases:

```json
{
  "escalation_required": true,
  "escalation_level": "incident_response",
  "escalation_target": "Incident Response Team",
  "escalation_reason": "Confirmed malware compromise affecting multiple hosts",
  "recommended_next_step": "Start incident response workflow"
}
```

---

## 18. Final Report Requirements

When escalation occurs, the final report should record:

- Whether escalation was required
- Escalation level
- Escalation target
- Escalation reason
- Evidence supporting escalation
- SOC analyst decision, if available
- Incident response actions, if available
- Management notification status, if applicable
- Final outcome

---

## 19. Policy Summary

Use this simplified logic:

| Situation | Escalation Decision |
|---|---|
| Low severity and benign activity | No escalation |
| Medium severity with unclear evidence | SOC Review if needed |
| High severity | SOC Review |
| Critical severity | SOC Review and likely Incident Response |
| Confirmed compromise | Incident Response |
| Containment pending approval | SOC Review or Approval Step |
| Multiple affected systems | Incident Response |
| Business-critical impact | Incident Response or Management Notification |
| Missing required decision fields | Return to Triage or Investigation, or escalate to SOC Review |

The system should escalate cases when the risk is serious, the evidence is uncertain, or human judgement is required.