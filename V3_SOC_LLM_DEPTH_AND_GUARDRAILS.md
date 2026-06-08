# V3 SOC LLM Depth and Guardrails

This version improves the Reporting Agent narrative layer.

## Added

- A deeper SOC analyst prompt for the LLM
- Longer technical analysis narrative
- Business-cybersecurity impact language
- SOC terminology such as phishing delivery, endpoint telemetry, IOC reputation, blast radius, containment approval, credential exposure, and MITRE ATT&CK
- LLM quality validation
- Automatic deterministic fallback when the LLM output is poor
- `llm_quality_status` and `llm_quality_issues` in `reporting_result.json`
- LLM quality checks in the SOC Analyst Review report

## Important

The LLM still cannot modify factual fields. It only refines narrative fields.

Protected fields:
- severity
- confidence
- classification
- IOCs
- affected assets
- affected users
- evidence
- timeline
- containment decision
- approval status
