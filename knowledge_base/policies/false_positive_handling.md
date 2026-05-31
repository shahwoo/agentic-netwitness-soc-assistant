# False Positive Handling Policy

## 1. Purpose

This policy defines how false positive alerts should be identified, handled, documented, and closed within the Agentic AI Threat Hunting and Autonomous Investigation Assistant.

The purpose is to ensure that benign alerts are not escalated unnecessarily, while still preserving enough evidence to justify why the alert was classified as a false positive.

This policy supports:

- Alert fatigue reduction
- Consistent triage decisions
- Safer case closure
- Better reporting quality
- SOC analyst review when needed
- Future tuning of detection rules and playbooks

---

## 2. Scope

This policy applies to all alerts processed by the system, including:

- Low severity alerts
- Medium severity alerts
- Alerts with clean threat intelligence results
- Alerts caused by authorised activity
- Alerts caused by known safe tools
- Alerts caused by testing, scanning, or administrative behaviour
- Alerts that are reviewed and confirmed benign by a SOC analyst

This policy may be used by:

- Triage Agent
- Investigation Agent
- Reporting Agent
- Orchestration Agent
- Threat Intelligence module
- SOC analyst review workflow

---

## 3. Definition of a False Positive

A false positive is an alert that was triggered by a detection rule, SIEM correlation rule, or security tool, but the activity is later determined to be non-malicious.

A false positive does not mean the alert was useless. It means the alert was reviewed and the evidence did not support a real security incident.

---

## 4. False Positive Classification Levels

The system uses the following false positive classification levels:

| Classification | Meaning |
|---|---|
| Confirmed False Positive | Evidence strongly shows that the activity is benign |
| Likely False Positive | Evidence suggests benign activity, but some uncertainty remains |
| Not False Positive | Evidence suggests suspicious or malicious activity |
| Needs Review | There is not enough evidence to decide |

---

## 5. Conditions for Confirmed False Positive

An alert may be classified as Confirmed False Positive when most of the following are true:

- Threat intelligence results are clean
- File hash is not malicious
- IP address, domain, or URL has no strong malicious reputation
- Activity matches expected user behaviour
- Activity matches authorised administrative activity
- Activity matches approved software or system behaviour
- No malware execution is observed
- No credential compromise is observed
- No lateral movement is observed
- No command-and-control communication is observed
- No data exfiltration is observed
- No business-critical asset is affected
- Similar previous cases were closed as false positives
- SOC analyst confirms the activity is benign

### Example Scenarios

- Internal vulnerability scan from an authorised scanner
- Admin login from an expected location
- Security testing activity approved by the organisation
- Software update process triggering suspicious network activity
- Backup software accessing many files
- Endpoint management tool running PowerShell scripts
- Clean file hash detected by a low-confidence rule
- User accessing a suspicious-looking but legitimate business website

### Required Output

```json
{
  "classification": "False Positive",
  "false_positive_status": "confirmed_false_positive",
  "severity": "Low",
  "confidence": "High",
  "recommended_action": "Close alert",
  "containment_required": false,
  "escalation_required": false
}
```

---

## 6. Conditions for Likely False Positive

An alert may be classified as Likely False Positive when the evidence appears benign, but there is still some uncertainty.

### Conditions

Classify as Likely False Positive when one or more of the following are true:

- Threat intelligence is mostly clean but incomplete
- Activity appears normal but cannot be fully verified
- The affected user or host has limited context
- Alert triggered once and did not repeat
- No confirmed malicious payload is found
- No additional suspicious activity is observed
- Similar previous cases were benign

### Example Scenarios

- One suspicious login from a slightly unusual location
- Single suspicious URL access with no confirmed payload
- Script execution that appears related to endpoint management
- Suspicious attachment blocked before delivery, with no user interaction
- IP address has low abuse reports but no strong malicious reputation

### Required Output

```json
{
  "classification": "Likely False Positive",
  "false_positive_status": "likely_false_positive",
  "severity": "Low",
  "confidence": "Medium",
  "recommended_action": "Monitor or close after SOC review",
  "containment_required": false,
  "escalation_required": false
}
```

---

## 7. When Not to Classify as False Positive

The system must not classify an alert as a false positive when strong suspicious or malicious evidence exists.

### Do Not Close as False Positive If Any Are True

- Confirmed malicious IOC is present
- File hash is detected as malicious by multiple sources
- IP address is linked to command-and-control infrastructure
- Domain or URL is linked to phishing or malware delivery
- Malware execution is observed
- Suspicious process activity is detected
- Credential compromise is suspected
- Lateral movement is detected
- Data exfiltration is suspected
- Ransomware behaviour is detected
- Privileged account misuse is observed
- Multiple related alerts appear across hosts or users
- Business-critical asset is affected
- Threat intelligence links the IOC to known campaigns

### Required Output

```json
{
  "classification": "True Positive",
  "false_positive_status": "not_false_positive",
  "recommended_action": "Continue investigation",
  "containment_required": true,
  "escalation_required": true
}
```

---

## 8. Needs Review Handling

If the system cannot confidently decide whether an alert is a false positive, it should use Needs Review.

### Conditions

Use Needs Review when:

- Evidence is incomplete
- Threat intelligence results conflict
- Severity is High or Critical but confidence is Low
- Key fields are missing
- User or host context is unclear
- Alert behaviour is suspicious but not confirmed malicious
- The activity may be authorised, but no approval evidence is available

### Required Output

```json
{
  "classification": "Needs Review",
  "false_positive_status": "needs_review",
  "confidence": "Low",
  "recommended_action": "Return to Investigation Agent or send to SOC Analyst Review",
  "escalation_required": true
}
```

---

## 9. Threat Intelligence Guidance

Threat intelligence should support false positive decisions, but it should not be the only deciding factor.

| Threat Intelligence Result | False Positive Impact |
|---|---|
| No detections across sources | Supports false positive classification |
| One low-confidence suspicious result | May support likely false positive |
| Mixed results across sources | Requires further review |
| Multiple malicious detections | Do not classify as false positive |
| Known malware, phishing, C2, or ransomware link | Do not classify as false positive |

Threat intelligence sources may include:

- VirusTotal
- AbuseIPDB
- AlienVault OTX
- Internal blocklists
- Previous case history
- Known allowlists

---

## 10. Authorised Activity Checks

Before classifying an alert as a false positive, the system should check whether the activity is authorised.

Authorised activity may include:

- Scheduled vulnerability scanning
- Penetration testing
- Red team exercises
- System administration
- Software deployment
- Endpoint management
- Backup activity
- Patch management
- Network monitoring
- Security tool testing

If the activity is authorised, the system should record the reason.

### Example Output

```json
{
  "authorised_activity_detected": true,
  "authorised_activity_type": "Internal vulnerability scanning",
  "authorised_activity_reason": "Source IP belongs to approved vulnerability scanner",
  "classification": "False Positive"
}
```

---

## 11. Evidence Required Before Closure

Before closing an alert as a false positive, the system should have enough evidence to justify the decision.

### Required Evidence

At least three of the following should be available:

- Clean threat intelligence result
- Known authorised source IP, host, account, or tool
- No malware execution
- No suspicious process behaviour
- No lateral movement
- No credential compromise
- No data exfiltration
- No repeated activity
- Similar prior case closed as false positive
- SOC analyst confirmation

### Required Output

```json
{
  "closure_ready": true,
  "closure_reason": "Threat intelligence is clean, activity matches authorised admin behaviour, and no compromise evidence was found"
}
```

---

## 12. False Positive Reporting Requirements

False positives should be documented before closure.

The report should include:

- Alert ID
- Incident ID, if available
- Alert name
- Original severity
- Final severity
- Confidence
- Classification
- False positive status
- Evidence reviewed
- Reason for false positive decision
- Authorised activity, if applicable
- SOC analyst comments, if applicable
- Recommended rule tuning, if applicable
- Final action taken

### Example Report Output

```json
{
  "report_required": true,
  "report_type": "false_positive_report",
  "report_status": "ready_for_closure",
  "false_positive_reason": "Activity matched authorised vulnerability scanning and no malicious indicators were found"
}
```

---

## 13. SOC Analyst Review Requirements

SOC analyst review is required before closing a false positive when:

- Severity was originally High or Critical
- Confidence is Low
- Evidence is incomplete
- Threat intelligence results conflict
- A privileged account is involved
- A business-critical asset is involved
- The alert is part of multiple related alerts
- The system recommends changing a detection rule
- The same false positive pattern repeats frequently

### Required Output

```json
{
  "soc_review_required": true,
  "soc_review_status": "pending",
  "review_reason": "High severity alert requires analyst confirmation before false positive closure"
}
```

---

## 14. Rule Tuning Recommendations

When an alert is confirmed as a false positive, the system may recommend rule tuning.

Rule tuning may include:

- Adding an authorised source IP to an allowlist
- Adding an approved admin account to an allowlist
- Excluding known safe software behaviour
- Adjusting detection thresholds
- Adding context checks before triggering the alert
- Reducing severity for known benign activity
- Creating a separate rule for testing or admin activity

### Example Output

```json
{
  "rule_tuning_recommended": true,
  "rule_tuning_reason": "Repeated alerts are triggered by an approved vulnerability scanner",
  "recommended_tuning_action": "Add scanner source IP to authorised scanner allowlist"
}
```

---

## 15. Learning Loop Update

Confirmed false positives should be used to improve future system decisions.

The system may update:

- Prior case examples
- False positive patterns
- Approved activity references
- Rule tuning recommendations
- SOC analyst feedback records
- RAG knowledge base, only after analyst approval

### Learning Loop Requirements

The system should not automatically update permanent policies without SOC analyst approval.

### Example Output

```json
{
  "learning_loop_update_recommended": true,
  "learning_loop_update_type": "false_positive_pattern",
  "learning_loop_approval_required": true,
  "learning_loop_reason": "Repeated benign scanner activity should be stored as a known false positive pattern"
}
```

---

## 16. Orchestration Routing Rules

The Orchestration Agent should route false positive cases based on classification and review status.

| Condition | Next Step |
|---|---|
| Confirmed False Positive and closure ready | Reporting Agent |
| False Positive report ready | Close case |
| Likely False Positive with uncertainty | SOC Analyst Review or Monitoring |
| Needs Review | Investigation Agent or SOC Analyst Review |
| Not False Positive | Continue Investigation Agent |
| Missing key evidence | Return to Triage Agent or Investigation Agent |

### Example Orchestration Decision

```json
{
  "next_agent": "reporting_agent",
  "workflow_decision": "generate_false_positive_report",
  "routing_reason": "Alert classified as false positive and ready for closure documentation"
}
```

---

## 17. Required Agent Output Fields

When this policy is applied, the agent output should include:

```json
{
  "classification": "False Positive",
  "false_positive_status": "confirmed_false_positive",
  "false_positive_reason": "Activity matched authorised administrative behaviour and no compromise evidence was found",
  "severity": "Low",
  "confidence": "High",
  "containment_required": false,
  "escalation_required": false,
  "soc_review_required": false,
  "report_required": true,
  "report_type": "false_positive_report",
  "recommended_action": "Close alert after report generation"
}
```

For uncertain cases:

```json
{
  "classification": "Needs Review",
  "false_positive_status": "needs_review",
  "false_positive_reason": "Evidence is incomplete and threat intelligence results are unclear",
  "confidence": "Low",
  "soc_review_required": true,
  "recommended_action": "Send to SOC Analyst Review"
}
```

---

## 18. Policy Summary

Use this simplified logic:

| Situation | Decision |
|---|---|
| Clean threat intelligence, authorised activity, no compromise evidence | Confirmed False Positive |
| Mostly benign but incomplete evidence | Likely False Positive |
| Conflicting or missing evidence | Needs Review |
| Malicious IOC, malware, C2, credential compromise, lateral movement, or data exfiltration | Not False Positive |
| High or Critical original severity | Require SOC analyst review before closure |
| Repeated benign pattern | Recommend rule tuning |
| Confirmed false positive | Generate false positive report before closure |

The system should only close an alert as a false positive when the evidence supports a safe and explainable closure decision.