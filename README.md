# Reporting Agent, Agentic AI SOC Automation Platform

This package implements only the Reporting Agent component.

## What it does

The Reporting Agent converts already-produced SOC workflow outputs into analyst-ready reports. It reads `inputs/enriched_alert.json`, `inputs/triage_result.json`, `inputs/investigation_result.json`, and optional `inputs/approval_result.json`.

It generates Markdown reports and supporting JSON under `outputs/<incident_id>/`.

## What it does not do

It does not investigate, triage, decide containment, approve containment, create incident facts, replace SOC analyst judgement, or load stale orchestration outputs.

## Design

```text
Core Reporting Agent = deterministic local JSON + Jinja2 Markdown report generation
Enhancement Layer = optional Ollama narrative refinement
Context Layer = ChromaDB RAG or direct file fallback
Storage Layer = PostgreSQL or local JSON fallback
```

PostgreSQL, ChromaDB, Docker, and Ollama are optional.

## Run

```bash
pip install jinja2 pytest
python agents/reporting_agent.py
```

Custom fixture:

```bash
python agents/reporting_agent.py --input-dir fixtures/complete_phishing_case --output-dir outputs/test_run
```

## Tests

```bash
pytest
```

## Optional LLM

```bash
set REPORTING_USE_LLM=true
set REPORTING_OLLAMA_MODEL=llama3.2:1b
python agents/reporting_agent.py
```

The LLM only improves narrative wording. It must not modify severity, confidence, IOCs, affected assets, affected users, evidence, timeline, approval status, containment decision, classification, or raw investigation findings.

## Optional RAG / ChromaDB

Direct file RAG is enabled by default. ChromaDB is optional:

```bash
python database/chromadb/ingest_knowledge_base.py
```

This version only loads incident severity policy, containment approval policy, reporting timeline policy, report writing SOP, evidence collection SOP, investigation SOP, and phishing response playbook. Malware and ransomware playbooks are excluded.

## Optional PostgreSQL

```bash
docker compose up -d postgres
psql -U postgres -d reporting_agent -f database/postgres/schema.sql
```

Enable storage:

```bash
set REPORTING_USE_POSTGRES=true
python agents/reporting_agent.py
```

## FYP simplifications

Direct file RAG fallback, local JSON inputs, Markdown reports, optional PostgreSQL, optional LLM, and phishing playbook only. Future improvements can include Pydantic models, PDF export, live NetWitness integration, prior-case similarity, and analyst edit/version workflow.


# V2 Reporting Quality Improvements

This update fixes the previous shallow report/LLM output.

## Main improvements

- Stronger SOC-specific LLM prompt
- More incident-specific deterministic narrative fallback
- Evidence-backed findings now include phishing delivery, suspicious PowerShell/process activity, malicious/suspicious IOCs, and approval status where supported
- IOC evidence references are linked where safely possible
- Phishing-specific evidence gaps are added automatically
- Raw RAG chunk dumping is removed from the Markdown report
- Policy Application Summary replaces long raw snippets
- Full RAG snippets remain in enriched_reporting_context.json
- Impact assessment is scenario-specific
- Status values are humanised, for example Pending Analyst Decision instead of pending

## Safety rules retained

- LLM cannot modify severity, confidence, classification, IOCs, assets, users, evidence, timeline, approval status, or containment decision
- Core report generation remains deterministic
- Jinja2 remains the renderer
- RAG provides reporting context only


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
