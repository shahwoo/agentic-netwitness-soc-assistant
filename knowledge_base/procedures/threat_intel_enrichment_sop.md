# Threat Intelligence Enrichment SOP

## 1. Purpose

This Standard Operating Procedure (SOP) defines how extracted Indicators of Compromise (IOCs) should be enriched using threat intelligence sources within the Agentic AI Threat Hunting and Autonomous Investigation Assistant.

The purpose of threat intelligence enrichment is to provide additional context about suspicious IP addresses, domains, URLs, file hashes, and email-related indicators before the Triage Agent finalises severity, confidence, classification, and containment decisions.

Threat intelligence enrichment supports:

- Evidence-based triage
- Severity scoring
- Confidence scoring
- True positive and false positive classification
- IOC correlation
- Investigation planning
- MITRE ATT&CK mapping
- Containment recommendations
- Reporting

---

## 2. Scope

This SOP applies after alert parsing and normalisation, and before final triage.

This SOP is used by:

- Threat Intelligence module
- Triage Agent
- Investigation Agent
- Orchestration Agent
- Reporting Agent
- Threat Hunting module

The enrichment process may use external threat intelligence sources, internal intelligence records, prior cases, and knowledge base references.

---

## 3. Position in Workflow

Threat intelligence enrichment should happen after IOC extraction and before final triage.

Expected workflow:

```text
NetWitness Alert
      ↓
Parser / Normalisation
      ↓
IOC Extraction
      ↓
Threat Intelligence Enrichment
      ↓
Triage Agent
      ↓
Investigation Agent
      ↓
Reporting Agent
```

Threat Intelligence enrichment is a supporting procedure for triage. The Triage Agent uses the enriched results to decide severity, confidence, classification, containment requirements, and escalation requirements.

---

## 4. Required Inputs

The Threat Intelligence module should receive extracted IOCs from the normalised alert.

Expected input file:

```text
outputs/normalised_alert.json
```

Required input fields may include:

- Alert ID
- Incident ID
- Alert name
- Alert timestamp
- Source IP addresses
- Destination IP addresses
- Domains
- URLs
- File hashes
- Email sender
- Email recipient
- Email subject
- Attachment names
- Process names
- Hostnames
- User accounts

Example input:

```json
{
  "current_stage": "normalisation_completed",
  "alert_id": "example-alert-id",
  "incident_id": "example-incident-id",
  "entities": {
    "source_ips": ["10.100.20.16"],
    "destination_ips": ["185.199.110.153"],
    "domains": ["example-malicious-domain.com"],
    "urls": ["http://example-malicious-domain.com/payload"],
    "file_hashes": ["example-sha256-hash"],
    "users": ["user@example.com"],
    "hosts": ["RPSOCWSWin2"]
  }
}
```

---

## 5. Supported IOC Types

The enrichment process should support the following IOC types:

| IOC Type | Example | Enrichment Purpose |
|---|---|---|
| IP address | `185.199.110.153` | Check abuse reputation, malicious hosting, C2 activity |
| Domain | `malicious-example.com` | Check phishing, malware, C2, suspicious registration |
| URL | `http://example.com/payload.exe` | Check malicious downloads, phishing pages, payload delivery |
| File hash | SHA256 / MD5 / SHA1 | Check malware detections and known malicious files |
| Email sender | `attacker@example.com` | Check phishing sender reputation |
| File name | `invoice.exe` | Support suspicious attachment analysis |
| Hostname | `RPSOCWSWin2` | Support internal correlation |
| User account | `jolin_j` | Support identity-based investigation |

Not every IOC type will be supported by every threat intelligence source.

---

## 6. Threat Intelligence Sources

The system may use the following sources:

- VirusTotal
- AbuseIPDB
- AlienVault OTX
- Internal blocklists
- Internal allowlists
- Prior incident records
- Previous investigation results
- Known false positive records
- ChromaDB knowledge base references
- PostgreSQL case history

The system should clearly record which sources were used and whether each source returned useful information.

---

## 7. Enrichment Procedure

### Step 1: Receive Extracted IOCs

The Threat Intelligence module should receive IOCs from the parsed and normalised alert output.

The module should check whether IOCs exist before performing enrichment.

If no IOCs are found, the module should return an enrichment result that explains that no enrichment was possible.

Example output:

```json
{
  "threat_intelligence_status": "no_iocs_found",
  "enrichment_performed": false,
  "recommended_next_step": "Send alert to Triage Agent using available alert evidence"
}
```

---

### Step 2: Validate and Deduplicate IOCs

Before enrichment, the module should validate and deduplicate IOCs.

The module should:

- Remove duplicate IOCs
- Ignore empty values
- Ignore invalid IP addresses
- Ignore invalid hashes
- Ignore malformed URLs
- Separate private/internal IP addresses from public IP addresses
- Mark private IP addresses for internal correlation instead of external reputation lookup

Example:

```json
{
  "ioc_validation": {
    "valid_public_ips": ["185.199.110.153"],
    "private_ips": ["10.100.20.16"],
    "valid_domains": ["example-malicious-domain.com"],
    "valid_file_hashes": ["example-sha256-hash"],
    "invalid_iocs": []
  }
}
```

---

### Step 3: Enrich IP Addresses

For public IP addresses, the module should check reputation and abuse history.

The module may collect:

- Abuse confidence score
- Number of abuse reports
- Country
- ISP or organisation
- Tor or proxy status
- Malware or C2 association
- Last reported date
- Related threat reports

Private IP addresses should not be checked using public reputation services. They should be marked for internal investigation or correlation.

Example output:

```json
{
  "ip_reputation": [
    {
      "ioc": "185.199.110.153",
      "ioc_type": "ip",
      "source": "AbuseIPDB",
      "abuse_confidence_score": 85,
      "reputation": "malicious",
      "summary": "IP has high abuse confidence and multiple reports"
    }
  ]
}
```

---

### Step 4: Enrich Domains and URLs

For domains and URLs, the module should check whether they are linked to phishing, malware delivery, command-and-control, or suspicious infrastructure.

The module may collect:

- Malicious detections
- Suspicious detections
- Phishing classification
- Malware delivery classification
- Known C2 classification
- Related threat reports
- Domain age or suspicious registration, if available
- Redirect behaviour, if available

Example output:

```json
{
  "domain_url_reputation": [
    {
      "ioc": "example-malicious-domain.com",
      "ioc_type": "domain",
      "source": "VirusTotal",
      "malicious_detections": 12,
      "suspicious_detections": 3,
      "reputation": "malicious",
      "summary": "Domain has multiple malicious detections and is linked to malware delivery"
    }
  ]
}
```

---

### Step 5: Enrich File Hashes

For file hashes, the module should check malware reputation and detection results.

The module may collect:

- Malicious detection count
- Suspicious detection count
- Malware family name, if available
- File type
- First seen date
- Last analysed date
- Known threat labels
- Sandbox behaviour, if available
- Related threat reports

Example output:

```json
{
  "file_hash_reputation": [
    {
      "ioc": "example-sha256-hash",
      "ioc_type": "file_hash",
      "source": "VirusTotal",
      "malicious_detections": 66,
      "suspicious_detections": 2,
      "malware_family": "Possible Trojan",
      "reputation": "malicious",
      "summary": "File hash has high malicious detection count"
    }
  ]
}
```

---

### Step 6: Check AlienVault OTX Pulses

For supported IOCs, the module should check whether the IOC appears in AlienVault OTX pulses or related threat reports.

The module may collect:

- Number of related pulses
- Pulse names
- Related malware families
- Related adversary groups, if available
- Related attack campaigns
- Tags
- References

Example output:

```json
{
  "otx_results": [
    {
      "ioc": "example-sha256-hash",
      "related_pulse_count": 50,
      "reputation": "malicious",
      "summary": "IOC appears in multiple OTX pulses linked to malicious activity"
    }
  ]
}
```

---

### Step 7: Check Internal Allowlist and Blocklist

The module should check whether the IOC appears in internal allowlists or blocklists.

Internal allowlists may include:

- Approved vulnerability scanners
- Approved admin tools
- Approved software update servers
- Approved endpoint management tools
- Approved test domains
- Approved security testing infrastructure

Internal blocklists may include:

- Known malicious IPs
- Known phishing domains
- Known malware hashes
- Known suspicious senders
- Previously confirmed malicious infrastructure

Example output:

```json
{
  "internal_intelligence": {
    "allowlist_matches": [],
    "blocklist_matches": [
      {
        "ioc": "example-malicious-domain.com",
        "reason": "Previously confirmed malicious domain"
      }
    ]
  }
}
```

---

### Step 8: Check Prior Case History

The module should check whether the IOC or similar behaviour appears in prior cases.

Prior case matching may include:

- Same file hash
- Same domain
- Same destination IP
- Same email sender
- Same host
- Same user
- Similar alert name
- Similar attack behaviour sequence

Example output:

```json
{
  "prior_case_matches": [
    {
      "case_id": "CASE-002",
      "match_type": "same_file_hash",
      "previous_classification": "True Positive",
      "previous_severity": "High",
      "summary": "Same file hash was previously linked to malware activity"
    }
  ]
}
```

---

## 8. Enrichment Risk Scoring

The Threat Intelligence module should calculate an enrichment risk score based on IOC reputation.

Suggested scoring:

| Evidence | Score Impact |
|---|---|
| No IOCs found | 0 |
| Clean IOC results | 0 to 10 |
| Suspicious IOC result | 20 to 40 |
| Multiple suspicious results | 40 to 60 |
| Confirmed malicious IOC | 70 to 90 |
| Multiple malicious sources agree | 90 to 100 |
| Known malware, ransomware, C2, or phishing infrastructure | 90 to 100 |

Suggested risk levels:

| Risk Score | Risk Level |
|---|---|
| 0 to 24 | Low |
| 25 to 49 | Medium |
| 50 to 74 | High |
| 75 to 100 | Critical |

Example output:

```json
{
  "enrichment_risk_score": 95,
  "enrichment_risk_level": "Critical",
  "enrichment_risk_reason": "File hash has high malicious detections and appears in multiple OTX pulses"
}
```

---

## 9. Confidence Guidance

Threat intelligence confidence should be based on the quality and agreement of sources.

| Confidence | Meaning |
|---|---|
| Low | Few sources available, incomplete results, or conflicting evidence |
| Medium | Some supporting evidence exists, but not enough for strong confirmation |
| High | Multiple reliable sources agree or strong malicious evidence exists |

Example output:

```json
{
  "enrichment_confidence": "High",
  "enrichment_confidence_reason": "VirusTotal and AlienVault OTX both indicate malicious reputation"
}
```

---

## 10. Handling Conflicting Results

Threat intelligence results may conflict.

Examples:

- VirusTotal detects a file as malicious, but internal allowlist marks it as approved
- AbuseIPDB reports an IP as suspicious, but it belongs to a known business partner
- OTX has old pulses, but no recent malicious activity exists
- Only one vendor flags an IOC while most others show clean

When results conflict, the module should:

1. Record the conflict
2. Avoid overconfident conclusions
3. Lower enrichment confidence
4. Recommend further investigation
5. Avoid automatic containment decisions based only on conflicting results

Example output:

```json
{
  "conflicting_intelligence": true,
  "conflict_summary": "External reputation source marks the IP as suspicious, but internal allowlist marks it as approved",
  "enrichment_confidence": "Low",
  "recommended_next_step": "Send to Triage Agent for careful review"
}
```

---

## 11. Timeout and Failure Handling

Threat intelligence enrichment may fail because of API timeout, rate limits, missing API keys, or unavailable services.

If enrichment fails, the module should not stop the workflow.

Instead, it should:

- Record the failed source
- Record the error reason if available
- Continue with other available sources
- Return partial enrichment results
- Mark enrichment status as partial or unavailable
- Recommend triage using available alert evidence

Example output:

```json
{
  "threat_intelligence_status": "partial_enrichment_completed",
  "failed_sources": [
    {
      "source": "VirusTotal",
      "reason": "API timeout"
    }
  ],
  "available_sources_used": [
    "AbuseIPDB",
    "AlienVault OTX"
  ],
  "recommended_next_step": "Send to Triage Agent with partial enrichment results"
}
```

If all enrichment fails:

```json
{
  "threat_intelligence_status": "enrichment_unavailable",
  "enrichment_performed": false,
  "enrichment_confidence": "Low",
  "recommended_next_step": "Send to Triage Agent using available alert evidence"
}
```

---

## 12. False Positive Support

Threat intelligence should also support false positive handling.

The enrichment result should help identify:

- Clean IOCs
- Internal allowlist matches
- Authorised scanner activity
- Approved admin tools
- Known benign software
- Previous false positive cases
- Lack of malicious detections

However, a clean threat intelligence result does not automatically mean the alert is false positive. The Triage Agent must still consider alert behaviour, affected asset, user context, and investigation evidence.

---

## 13. Containment Support

Threat intelligence enrichment should not execute containment.

It may only recommend whether containment should be considered.

Containment may be considered when:

- Multiple sources confirm the IOC is malicious
- IOC is linked to malware
- IOC is linked to ransomware
- IOC is linked to command-and-control infrastructure
- IOC is linked to phishing infrastructure
- IOC is present on multiple hosts
- IOC is linked to prior confirmed incidents

Example output:

```json
{
  "containment_consideration": true,
  "containment_reason": "IOC is confirmed malicious by multiple sources and linked to malware delivery"
}
```

The Triage Agent or Investigation Agent should decide whether containment is required, based on the containment approval policy.

---

## 14. Investigation Support

The Investigation Agent should reuse enriched threat intelligence results to support deeper investigation.

Threat intelligence results may support:

- Investigation starting point selection
- Playbook selection
- IOC correlation
- Timeline building
- Attack behaviour mapping
- MITRE ATT&CK mapping
- Business impact assessment
- Updated severity score
- Updated confidence score
- Containment recommendation
- Eradication and recovery recommendations

If investigation discovers new IOCs, the Investigation Agent may request additional threat intelligence enrichment.

Example output:

```json
{
  "additional_enrichment_required": true,
  "new_iocs_found": {
    "domains": ["newly-discovered-domain.com"],
    "file_hashes": ["newly-discovered-file-hash"]
  },
  "recommended_next_step": "Return new IOCs to Threat Intelligence module"
}
```

---

## 15. Required Output

The Threat Intelligence module should produce:

```text
outputs/enriched_alert.json
```

Required output fields:

```json
{
  "current_stage": "enrichment_completed",
  "alert_id": "example-alert-id",
  "incident_id": "example-incident-id",
  "enrichment_performed": true,
  "threat_intelligence_status": "enrichment_completed",
  "ioc_summary": {
    "total_iocs": 0,
    "malicious_iocs": 0,
    "suspicious_iocs": 0,
    "clean_iocs": 0,
    "unknown_iocs": 0
  },
  "enriched_iocs": [],
  "source_results": {
    "virustotal": [],
    "abuseipdb": [],
    "alienvault_otx": [],
    "internal_intelligence": [],
    "prior_cases": []
  },
  "enrichment_risk_score": 0,
  "enrichment_risk_level": "Low | Medium | High | Critical",
  "enrichment_risk_reason": "Short explanation of enrichment risk",
  "enrichment_confidence": "Low | Medium | High",
  "enrichment_confidence_reason": "Short explanation of enrichment confidence",
  "conflicting_intelligence": false,
  "failed_sources": [],
  "containment_consideration": false,
  "recommended_next_step": "Send to Triage Agent"
}
```

---

## 16. Quality Checks Before Saving Enrichment Result

Before saving `enriched_alert.json`, the Threat Intelligence module should confirm that:

- Alert ID is preserved
- Incident ID is preserved, if available
- Original alert context is not lost
- Extracted IOCs are preserved
- IOC validation was performed
- Enrichment source results are recorded
- Failed sources are recorded, if any
- Risk score is assigned
- Risk level is assigned
- Confidence is assigned
- Reasons are provided for risk and confidence
- Recommended next step is clear

The module must not overwrite original alert evidence with only enrichment data. It should append enrichment context to the existing alert context.

---

## 17. Routing Summary

Use the following routing logic:

| Condition | Next Step |
|---|---|
| Enrichment completed | Send to Triage Agent |
| Partial enrichment completed | Send to Triage Agent with lower confidence |
| No IOCs found | Send to Triage Agent using available alert evidence |
| Enrichment unavailable | Send to Triage Agent using available alert evidence |
| Conflicting intelligence | Send to Triage Agent for careful review |
| New IOCs discovered during investigation | Return to Threat Intelligence module for additional enrichment |

---

## 18. SOP Summary

Use this simplified process:

1. Receive extracted IOCs from the normalised alert.
2. Validate and deduplicate IOCs.
3. Separate public IOCs from private/internal indicators.
4. Enrich IP addresses, domains, URLs, and file hashes.
5. Check VirusTotal, AbuseIPDB, AlienVault OTX, internal intelligence, and prior cases where available.
6. Record source results and failed sources.
7. Calculate enrichment risk score.
8. Assign enrichment risk level.
9. Assign enrichment confidence.
10. Record conflicting intelligence if present.
11. Preserve original alert context.
12. Save `outputs/enriched_alert.json`.
13. Send enriched result to the Triage Agent.