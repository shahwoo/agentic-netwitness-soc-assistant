# SOC Triage SOP

## 1. Purpose

This Standard Operating Procedure (SOP) defines how security alerts should be triaged within the Agentic AI Threat Hunting and Autonomous Investigation Assistant.

The purpose of SOC triage is to review the alert evidence, assess threat intelligence enrichment results, determine severity and confidence, classify the alert, and decide the next workflow action.

The Triage Agent should not perform deep investigation. Its role is to make an initial evidence-based decision and route the case correctly.

---

## 2. Scope

This SOP applies to alerts received from NetWitness SIEM after they have been parsed, normalised, and enriched with threat intelligence.

This SOP is used by:

- Triage Agent
- Orchestration Agent
- Threat Intelligence module
- SOC analyst review workflow
- Reporting Agent

---

## 3. Required Inputs

Before triage begins, the Triage Agent should receive the following inputs:

- Parsed and normalised alert data
- Alert ID
- Incident ID, if available
- Alert name
- Alert timestamp
- Source IP address
- Destination IP address
- Affected host
- Affected user
- File hash, if available
- Domain, URL, or email sender, if available
- Process details, if available
- Email details, if available
- NetWitness event details
- Threat intelligence enrichment results
- Relevant policies from the knowledge base
- Relevant playbooks from the knowledge base
- Prior case references, if available

Expected input file:

```json
{
  "current_stage": "enrichment_completed",
  "alert_id": "example-alert-id",
  "incident_id": "example-incident-id",
  "alert_name": "Suspicious Activity Detected",
  "entities": {
    "source_ips": [],
    "destination_ips": [],
    "users": [],
    "hosts": [],
    "domains": [],
    "urls": [],
    "file_hashes": []
  },
  "threat_intelligence": {},
  "enrichment_risk_score": 0,
  "enrichment_risk_level": "Low | Medium | High | Critical"
}
```

---

## 4. Required Knowledge Base References

During triage, the Triage Agent should retrieve and apply relevant guidance from:

- `policies/incident_severity_policy.md`
- `policies/containment_approval_policy.md`
- `policies/escalation_policy.md`
- `policies/false_positive_handling_policy.md`
- `procedures/threat_intel_enrichment_sop.md`
- Relevant attack-specific playbooks, such as phishing, malware, ransomware, or credential compromise playbooks

---

## 5. Triage Responsibilities

The Triage Agent is responsible for:

1. Reviewing alert evidence
2. Reviewing threat intelligence enrichment results
3. Identifying affected entities
4. Determining the likely scenario
5. Assigning severity
6. Assigning confidence
7. Classifying the alert
8. Deciding whether containment is required
9. Deciding whether SOC analyst approval is required
10. Deciding whether escalation is required
11. Recommending the next workflow action
12. Producing a structured triage result

---

## 6. Triage Procedure

### Step 1: Confirm Alert Context

The Triage Agent should first confirm the basic alert context.

Check:

- What triggered the alert?
- When did the alert occur?
- Which host is affected?
- Which user is affected?
- Which IP addresses are involved?
- Which domains, URLs, or file hashes are involved?
- Is the alert related to email, endpoint, network, process, file, or web activity?

If the alert context is incomplete, the Triage Agent should continue with available evidence but reduce confidence.

---

### Step 2: Review Extracted Entities

The Triage Agent should review all extracted entities.

Important entities include:

- Source IP addresses
- Destination IP addresses
- User accounts
- Hostnames
- Domains
- URLs
- File names
- File hashes
- Email senders
- Email recipients
- Process names
- Parent processes
- Command-line arguments

The Triage Agent should identify which entities are most important to the alert.

---

### Step 3: Review Threat Intelligence Results

Before finalising triage, the Triage Agent should review enriched IOC results from the Threat Intelligence module.

Threat intelligence may include:

- VirusTotal detections
- AbuseIPDB reputation
- AlienVault OTX pulses
- Known malicious IP addresses
- Known malicious domains
- Known malicious URLs
- Known malicious file hashes
- Malware family names
- Related threat reports
- Internal blocklist or allowlist matches

The Triage Agent should use threat intelligence to support severity and confidence decisions.

If threat intelligence enrichment is unavailable, incomplete, or timed out, the Triage Agent may continue using available alert evidence, but confidence should be reduced.

---

### Step 4: Determine the Likely Scenario

The Triage Agent should infer the most likely security scenario based on the available evidence.

Examples of likely scenarios:

- Phishing email with suspicious attachment
- Malware infection
- Ransomware activity
- Suspicious login
- Credential compromise
- Command-and-control communication
- Data exfiltration
- Lateral movement
- Benign administrative activity
- False positive triggered by authorised tool

The likely scenario should be short and specific.

Example:

```json
{
  "likely_scenario": "Endpoint malware infection involving a malicious file hash and suspicious outbound communication"
}
```

---

### Step 5: Assign Severity

The Triage Agent should assign one of the following severity levels:

- Low
- Medium
- High
- Critical

Severity should be based on:

- Alert evidence
- Threat intelligence results
- Type of attack
- Affected asset criticality
- Affected user criticality
- Number of affected systems
- Evidence of compromise
- Business impact
- Presence of malware, ransomware, C2, credential compromise, lateral movement, or data exfiltration

The Triage Agent should apply `incident_severity_policy.md` when making this decision.

---

### Step 6: Assign Confidence

The Triage Agent should assign one of the following confidence levels:

- Low
- Medium
- High

Confidence should be based on how strong and complete the evidence is.

Use the following guidance:

| Confidence | Meaning |
|---|---|
| Low | Evidence is incomplete, weak, conflicting, or unclear |
| Medium | Some evidence supports the decision, but further investigation is useful |
| High | Strong evidence supports the decision |

Important rule:

Severity and confidence are not the same.

A case may be Critical severity but Low confidence if the potential impact is serious but the evidence is incomplete.

---

### Step 7: Classify the Alert

The Triage Agent should classify the alert as one of the following:

- True Positive
- False Positive
- Likely False Positive
- Needs Review

Use the following guidance:

| Classification | Meaning |
|---|---|
| True Positive | Evidence suggests suspicious or malicious activity |
| False Positive | Evidence strongly shows benign activity |
| Likely False Positive | Evidence appears benign but some uncertainty remains |
| Needs Review | Evidence is incomplete or unclear |

The Triage Agent should apply `false_positive_handling_policy.md` when making this decision.

---

### Step 8: Decide Whether Containment Is Required

The Triage Agent should determine whether containment is required.

Containment may be required if:

- Malware infection is suspected or confirmed
- Ransomware activity is suspected or confirmed
- Command-and-control communication is detected
- Credential compromise is suspected or confirmed
- Lateral movement is detected
- Data exfiltration is suspected or confirmed
- A business-critical asset is affected
- A privileged account is involved
- Multiple systems are affected

The Triage Agent should apply `containment_approval_policy.md`.

The system must not perform disruptive containment actions automatically without SOC analyst approval.

---

### Step 9: Decide Whether Escalation Is Required

The Triage Agent should determine whether the case requires escalation.

Escalation may be required when:

- Severity is High or Critical
- Confidence is Low but potential impact is serious
- Containment is recommended
- SOC analyst approval is required
- A privileged account is involved
- A business-critical system is involved
- Multiple systems are affected
- The report cannot be finalised due to missing key fields

The Triage Agent should apply `escalation_policy.md`.

---

### Step 10: Decide the Next Workflow Action

The Triage Agent should recommend the next workflow step.

Possible next actions:

| Condition | Recommended Next Action |
|---|---|
| Low severity and False Positive | Send to Reporting Agent for false positive report |
| Low severity and benign | Close or monitor |
| Medium severity | Send to Investigation Agent |
| High severity | Send to SOC Analyst Review or Investigation Agent |
| Critical severity | Send to SOC Analyst Approval and Investigation Agent |
| Containment pending approval | Send to Approval Step |
| Missing evidence | Return for additional enrichment or investigation |
| Needs Review | Send to SOC Analyst Review |

The Orchestration Agent should use the triage result to decide the actual next step.

---

## 7. Expected Triage Output

The Triage Agent should produce a structured output file.

Expected output file:

```text
outputs/triage_result.json
```

Required fields:

```json
{
  "current_stage": "triage_completed",
  "alert_id": "example-alert-id",
  "incident_id": "example-incident-id",
  "severity": "Low | Medium | High | Critical",
  "confidence": "Low | Medium | High",
  "classification": "True Positive | False Positive | Likely False Positive | Needs Review",
  "likely_scenario": "Short explanation of what likely happened",
  "severity_reason": "Reason for the selected severity",
  "confidence_reason": "Reason for the selected confidence level",
  "triage_summary": "Short SOC-style triage summary",
  "containment_required": false,
  "containment_status": "not_required | recommended | pending_approval",
  "recommended_containment_action": "None or specific action",
  "soc_analyst_approval_status": "not_required | pending",
  "escalation_required": false,
  "escalation_level": "none | soc_review | incident_response | management_notification",
  "recommended_next_step": "Next recommended workflow action"
}
```

---

## 8. Severity Decision Guidance

Use this simplified severity logic:

| Evidence | Suggested Severity |
|---|---|
| Weak suspicious activity only | Low |
| Suspicious activity requiring review | Medium |
| Strong malicious evidence or likely compromise | High |
| Confirmed compromise, C2, ransomware, credential theft, lateral movement, or business-critical impact | Critical |

---

## 9. Containment Decision Guidance

Use this simplified containment logic:

| Situation | Containment Decision |
|---|---|
| Low severity, weak evidence | No containment |
| Medium severity, suspicious activity | Investigate first |
| High severity, likely compromise | Recommend containment, require approval |
| Critical severity, confirmed or likely compromise | Recommend urgent containment, require approval |

---

## 10. False Positive Decision Guidance

Use this simplified false positive logic:

| Evidence | Decision |
|---|---|
| Clean threat intelligence, authorised activity, no compromise evidence | False Positive |
| Mostly benign but incomplete evidence | Likely False Positive |
| Conflicting or missing evidence | Needs Review |
| Malicious IOC, malware, C2, credential compromise, lateral movement, or data exfiltration | True Positive |

---

## 11. Missing Information Handling

The Triage Agent should not guess when important evidence is missing.

If key information is missing, the Triage Agent should:

1. Continue using available evidence
2. Lower confidence
3. Record missing fields
4. Recommend further investigation or SOC analyst review

Important missing fields may include:

- Alert ID
- Incident ID
- Affected host
- Affected user
- IOCs
- Threat intelligence results
- Severity
- Confidence
- Classification
- Likely scenario

Example output:

```json
{
  "confidence": "Low",
  "missing_fields": [
    "affected_host",
    "file_hash",
    "threat_intelligence"
  ],
  "recommended_next_step": "Send to Investigation Agent for additional evidence collection"
}
```

---

## 12. Threat Intelligence Timeout Handling

If the Threat Intelligence module times out or fails, the Triage Agent should not stop the workflow.

Instead, it should:

- Use available alert evidence
- Mark threat intelligence as unavailable
- Reduce confidence if the missing enrichment affects the decision
- Recommend investigation if uncertainty remains

Example output:

```json
{
  "threat_intelligence_status": "unavailable_or_timed_out",
  "confidence": "Medium",
  "recommended_next_step": "Send to Investigation Agent for additional review"
}
```

---

## 13. SOC Analyst Approval Handling

If containment is recommended, the Triage Agent should set:

```json
{
  "containment_required": true,
  "containment_status": "pending_approval",
  "soc_analyst_approval_status": "pending",
  "recommended_next_step": "Send to SOC Analyst Approval"
}
```

The Orchestration Agent should route this to the approval step before any disruptive containment action is taken.

---

## 14. Quality Checks Before Saving Triage Result

Before saving `triage_result.json`, the Triage Agent should confirm that:

- Severity is not empty
- Confidence is not empty
- Classification is not empty
- Likely scenario is not empty
- Recommended next step is not empty
- Containment status is valid
- Escalation status is valid
- Reasons are provided for major decisions

If any required field is missing, the Triage Agent should set a missing information status and explain what is missing.

---

## 15. Example Triage Result

```json
{
  "current_stage": "triage_completed",
  "alert_id": "INC-6125",
  "incident_id": "INC-6125",
  "severity": "Critical",
  "confidence": "High",
  "classification": "True Positive",
  "likely_scenario": "Endpoint malware infection involving a malicious file hash",
  "severity_reason": "Threat intelligence shows strong malicious detections and endpoint compromise indicators are present",
  "confidence_reason": "Multiple evidence sources support the classification, including alert evidence and threat intelligence enrichment",
  "triage_summary": "The alert is assessed as a Critical true positive due to confirmed malicious IOC evidence and likely endpoint malware activity.",
  "containment_required": true,
  "containment_status": "pending_approval",
  "recommended_containment_action": "isolate endpoint",
  "soc_analyst_approval_status": "pending",
  "escalation_required": true,
  "escalation_level": "soc_review",
  "recommended_next_step": "Send to SOC Analyst Approval"
}
```

---

## 16. SOP Summary

Use this simplified process:

1. Review alert context.
2. Review extracted entities.
3. Review threat intelligence enrichment.
4. Determine likely scenario.
5. Assign severity.
6. Assign confidence.
7. Classify the alert.
8. Decide containment requirement.
9. Decide escalation requirement.
10. Recommend next workflow action.
11. Save structured triage result.

The Triage Agent should make an evidence-based decision and route the case correctly, not perform deep investigation.