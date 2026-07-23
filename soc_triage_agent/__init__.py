"""
soc_triage_agent package
========================
The implementation lives in soc_triage_agent.py inside this folder.
This re-export keeps app.py's original import working unchanged:

    from soc_triage_agent import CiscoLLMConfig, soc_triage_chat_respond, ...
"""

from .soc_triage_agent import (
    CiscoLLMConfig,
    build_llm,
    TriageAgent,
    soc_triage_chat_respond,
    deep_triage_supplement,
    _TRIAGE_TRIGGER,
    render_triage_trace,
    format_ticket_display,
)

__all__ = [
    "CiscoLLMConfig",
    "build_llm",
    "TriageAgent",
    "soc_triage_chat_respond",
    "deep_triage_supplement",
    "_TRIAGE_TRIGGER",
    "render_triage_trace",
    "format_ticket_display",
]
