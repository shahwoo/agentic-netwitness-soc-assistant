# LLM Enabled Version

This package is the same Reporting Agent system, but `REPORTING_USE_LLM` now defaults to `true`.

Default behaviour:

```text
Core report generation: deterministic Python + Jinja2
LLM usage: enabled by default for executive summary narrative refinement
LLM model: llama3.2:1b unless changed using REPORTING_OLLAMA_MODEL
Fallback: if Ollama is unavailable, the report still generates using deterministic narrative
```

Run:

```bash
python agents/reporting_agent.py
```

Recommended Ollama setup:

```bash
ollama pull llama3.2:1b
ollama list
```

The LLM is still not allowed to modify severity, confidence, classification, IOCs, affected assets, affected users, evidence, timeline, approval status, or containment decision.
