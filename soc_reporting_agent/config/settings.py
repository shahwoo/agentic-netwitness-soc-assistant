from pathlib import Path
import os

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INPUT_DIR = Path(os.getenv("REPORTING_INPUT_DIR", PROJECT_ROOT / "inputs"))
OUTPUT_DIR = Path(os.getenv("REPORTING_OUTPUT_DIR", PROJECT_ROOT / "outputs"))
TEMPLATE_DIR = Path(os.getenv("REPORTING_TEMPLATE_DIR", PROJECT_ROOT / "report_templates"))
KNOWLEDGE_BASE_DIR = Path(os.getenv("REPORTING_KB_DIR", PROJECT_ROOT / "knowledge_base"))

USE_LLM = os.getenv("REPORTING_USE_LLM", "false").lower() == "true"
LLM_PROVIDER = os.getenv("REPORTING_LLM_PROVIDER", "ollama").strip().lower()
LLM_MODEL = os.getenv("REPORTING_LLM_MODEL", "gpt-4o-mini").strip()
OLLAMA_MODEL = os.getenv("REPORTING_OLLAMA_MODEL", "llama3.2:3b").strip()
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", os.getenv("REPORTING_OLLAMA_BASE_URL", "http://localhost:11434")).strip().rstrip("/")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "").strip() or None

# LLM reliability controls. These are deliberately conservative for SOC reporting.
LLM_TIMEOUT_SECONDS = int(os.getenv("REPORTING_LLM_TIMEOUT", os.getenv("REPORTING_LLM_TIMEOUT_SECONDS", os.getenv("REPORTING_OLLAMA_TIMEOUT_SECONDS", "120"))))
LLM_NUM_PREDICT = int(os.getenv("REPORTING_LLM_NUM_PREDICT", "2200"))
LLM_TEMPERATURE = float(os.getenv("REPORTING_LLM_TEMPERATURE", "0.2"))
# Fixed sampling seed for reproducible narratives (OpenAI chat completions and
# TGI both accept it). Empty/unset -> no seed sent.
_seed_raw = os.getenv("REPORTING_LLM_SEED", "").strip()
LLM_SEED = int(_seed_raw) if _seed_raw.lstrip("-").isdigit() else None
LLM_NARRATIVE_DEPTH = os.getenv("REPORTING_LLM_NARRATIVE_DEPTH", "analyst").strip().lower()
REPORTING_REPORT_DETAIL_LEVEL = os.getenv("REPORTING_REPORT_DETAIL_LEVEL", LLM_NARRATIVE_DEPTH).strip().lower()
REPORT_DETAIL_LEVEL = REPORTING_REPORT_DETAIL_LEVEL
LLM_MOCK_MODE = os.getenv("REPORTING_LLM_MOCK_MODE", "good").strip().lower()
LLM_MAX_RETRIES = int(os.getenv("REPORTING_LLM_MAX_RETRIES", "2"))
LLM_ENABLE_PROVIDER_FALLBACK = os.getenv("REPORTING_LLM_ENABLE_PROVIDER_FALLBACK", "true").lower() == "true"
LLM_FALLBACK_PROVIDER = os.getenv("REPORTING_LLM_FALLBACK_PROVIDER", "").strip().lower()
LLM_CACHE_ENABLED = os.getenv("REPORTING_LLM_CACHE_ENABLED", "true").lower() == "true"
LLM_CACHE_DIR = Path(os.getenv("REPORTING_LLM_CACHE_DIR", PROJECT_ROOT / "outputs" / "report_cache"))

USE_RAG = os.getenv("REPORTING_USE_RAG", "true").lower() == "true"
USE_CHROMADB = os.getenv("REPORTING_USE_CHROMADB", "false").lower() == "true"
FORCE_RAG_FAILURE = os.getenv("REPORTING_FORCE_RAG_FAILURE", "false").lower() == "true"
CHROMA_DB_PATH = Path(os.getenv("REPORTING_CHROMA_DB_PATH", PROJECT_ROOT / "database" / "chromadb" / "chroma_store"))
CHROMA_COLLECTION_NAME = os.getenv("REPORTING_CHROMA_COLLECTION_NAME", "reporting_knowledge_base")

USE_POSTGRES = os.getenv("REPORTING_USE_POSTGRES", "false").lower() == "true"
POSTGRES_DSN = os.getenv("POSTGRES_DSN") or os.getenv("REPORTING_POSTGRES_DSN", "postgresql://postgres:postgres@localhost:5432/aegis_soc")

REQUIRED_KB_FILES = [
    "policies/incident_severity_policy.md",
    "policies/containment_approval_policy.md",
    "policies/reporting_timeline_policy.md",
    "procedures/report_writing_sop.md",
    "procedures/evidence_collection_sop.md",
    "procedures/investigation_sop.md",
    "playbooks/phishing_response_playbook.md",
    "playbooks/ransomware_response_playbook.md",
]


def configured_llm_providers() -> list[str]:
    """Return provider order for LLM calls.

    The first provider is the configured primary provider. If provider fallback is
    enabled, a secondary provider can be set with REPORTING_LLM_FALLBACK_PROVIDER.
    This avoids silently trying unrelated providers unless explicitly configured.
    """
    primary = (LLM_PROVIDER or "").strip().lower()
    providers: list[str] = []
    if primary:
        providers.append(primary)
    if LLM_ENABLE_PROVIDER_FALLBACK and LLM_FALLBACK_PROVIDER and LLM_FALLBACK_PROVIDER not in providers:
        providers.append(LLM_FALLBACK_PROVIDER)
    return providers or ["mock"]


def selected_model_for_provider(provider: str) -> str:
    provider = (provider or "").strip().lower()
    if provider == "openai":
        return LLM_MODEL
    if provider == "ollama":
        return OLLAMA_MODEL
    if provider == "mock":
        return f"mock-{LLM_MOCK_MODE}"
    return LLM_MODEL or OLLAMA_MODEL


def selected_llm_model() -> str:
    """Return the model that should be used for the active primary provider.

    Important: OpenAI provider must never be overridden by REPORTING_OLLAMA_MODEL.
    """
    return selected_model_for_provider(LLM_PROVIDER)
