"""
Configuration for the Reporting Agent.

Defaults are safe for a student FYP:
- deterministic reporting is always available
- OpenAI, Ollama, ChromaDB and PostgreSQL are optional
- missing integrations never break basic report generation
"""

from pathlib import Path
import os


# ============================================================
# Project Paths
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_DIR = Path(os.getenv("REPORTING_INPUT_DIR", PROJECT_ROOT / "inputs"))
OUTPUT_DIR = Path(os.getenv("REPORTING_OUTPUT_DIR", PROJECT_ROOT / "outputs"))
TEMPLATE_DIR = Path(os.getenv("REPORTING_TEMPLATE_DIR", PROJECT_ROOT / "report_templates"))
KNOWLEDGE_BASE_DIR = Path(os.getenv("REPORTING_KB_DIR", PROJECT_ROOT / "knowledge_base"))


# ============================================================
# LLM Provider Settings
# ============================================================

# Main switch for LLM narrative refinement.
# If false, the Reporting Agent will use deterministic narrative only.
USE_LLM = os.getenv("REPORTING_USE_LLM", "true").strip().lower() == "true"

# Provider options:
# - openai
# - ollama
#
# Since you are using the OpenAI API, keep this as openai.
LLM_PROVIDER = os.getenv("REPORTING_LLM_PROVIDER", "openai").strip().lower()

# Narrative depth mode, currently used as a descriptive setting.
LLM_NARRATIVE_DEPTH = os.getenv("REPORTING_LLM_NARRATIVE_DEPTH", "soc_deep").strip().lower()


# ============================================================
# OpenAI Settings
# ============================================================

# Do not hardcode your API key here.
# Set OPENAI_API_KEY in PowerShell or your system environment instead.
#
# Example:
# $env:OPENAI_API_KEY="your_api_key_here"
OPENAI_MODEL = os.getenv("REPORTING_OPENAI_MODEL", "gpt-4o-mini")

# Timeout for OpenAI calls.
OPENAI_TIMEOUT_SECONDS = float(os.getenv("REPORTING_OPENAI_TIMEOUT_SECONDS", "25"))

# Maximum text the OpenAI model can generate per section.
# Lower = faster, shorter output.
# Higher = more detailed, slower output.
OPENAI_MAX_OUTPUT_TOKENS = int(os.getenv("REPORTING_OPENAI_MAX_OUTPUT_TOKENS", "500"))


# ============================================================
# Ollama Settings, Optional Fallback
# ============================================================

# Ollama is optional now.
# It is only used if REPORTING_LLM_PROVIDER="ollama".
OLLAMA_MODEL = os.getenv("REPORTING_OLLAMA_MODEL", "llama3.2:1b")
OLLAMA_BASE_URL = os.getenv("REPORTING_OLLAMA_BASE_URL", "http://localhost:11434")

# Fast preflight timeout so the Reporting Agent does not hang if Ollama is unavailable.
OLLAMA_PREFLIGHT_TIMEOUT_SECONDS = float(
    os.getenv("REPORTING_OLLAMA_PREFLIGHT_TIMEOUT_SECONDS", "1.5")
)

# Maximum Ollama generation length.
LLM_NUM_PREDICT = int(os.getenv("REPORTING_LLM_NUM_PREDICT", "380"))


# ============================================================
# RAG / ChromaDB Settings
# ============================================================

# Main switch for reporting-context retrieval.
USE_RAG = os.getenv("REPORTING_USE_RAG", "true").strip().lower() == "true"

# Use ChromaDB if true.
# If false, Reporting Agent uses direct lightweight file reading.
USE_CHROMADB = os.getenv("REPORTING_USE_CHROMADB", "false").strip().lower() == "true"

# Test switch to simulate RAG failure.
FORCE_RAG_FAILURE = os.getenv("REPORTING_FORCE_RAG_FAILURE", "false").strip().lower() == "true"

CHROMA_DB_PATH = Path(
    os.getenv(
        "REPORTING_CHROMA_DB_PATH",
        PROJECT_ROOT / "database" / "chromadb" / "chroma_store",
    )
)

CHROMA_COLLECTION_NAME = os.getenv(
    "REPORTING_CHROMA_COLLECTION_NAME",
    "reporting_knowledge_base",
)


# ============================================================
# PostgreSQL Settings
# ============================================================

# PostgreSQL is optional.
# The Reporting Agent must still work even if PostgreSQL is disabled or unavailable.
USE_POSTGRES = os.getenv("REPORTING_USE_POSTGRES", "false").strip().lower() == "true"

POSTGRES_DSN = os.getenv(
    "REPORTING_POSTGRES_DSN",
    "postgresql://postgres:postgres@localhost:5432/reporting_agent",
)


# ============================================================
# Knowledge Base Files Used by Reporting Agent
# ============================================================

# Only these files should be loaded for the current Reporting Agent version.
# Malware and ransomware playbooks are intentionally excluded.
REQUIRED_KB_FILES = [
    "policies/incident_severity_policy.md",
    "policies/containment_approval_policy.md",
    "policies/reporting_timeline_policy.md",
    "procedures/report_writing_sop.md",
    "procedures/evidence_collection_sop.md",
    "procedures/investigation_sop.md",
    "playbooks/phishing_response_playbook.md",
]