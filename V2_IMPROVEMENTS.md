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
