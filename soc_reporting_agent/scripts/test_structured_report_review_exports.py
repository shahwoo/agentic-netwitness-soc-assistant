from __future__ import annotations

import json
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from reporting.editable_reports import (
    CORE_REPORT_KEYS,
    build_report_manifest,
    confirm_section,
    export_section_docx,
    export_section_pdf,
    list_reports,
    read_section,
    save_section,
)

TEST_ROOT = ROOT / "testdata" / "structured_report_review_exports"
OUTPUTS = TEST_ROOT / "outputs"
GENERATED = TEST_ROOT / "generated"
RESULTS = TEST_ROOT / "test_results.json"


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main() -> int:
    if TEST_ROOT.exists():
        shutil.rmtree(TEST_ROOT)
    GENERATED.mkdir(parents=True, exist_ok=True)
    OUTPUTS.mkdir(parents=True, exist_ok=True)

    incident_id = "INC-STRUCTURED-0001"
    generated_sections = {}
    for key in CORE_REPORT_KEYS:
        path = GENERATED / f"{key}.txt"
        title = key.replace("_", " ").title()
        write(path, f"# {title}\n\n| Field | Value |\n|---|---|\n| Incident ID | {incident_id} |\n| Status | Generated for analyst review |\n\n| Timeline Field | Timeline Value |\n|---|---|\n| First Seen | 2026-07-03T00:00:00Z |\n\nThis is generated draft content.")
        generated_sections[key] = str(path)

    results = []
    manifest = build_report_manifest(OUTPUTS, incident_id, generated_sections, context={"ticket_id": "TKT-STRUCTURED-0001"})
    listed = list_reports(OUTPUTS, incident_id=incident_id)
    results.append({"name": "four_core_reports_created", "passed": len(listed["reports"]) == 4})
    read_generated = read_section(OUTPUTS, "final_incident_report", incident_id=incident_id)
    generated_tables = [block for block in read_generated.get("blocks", []) if isinstance(block, dict) and block.get("type") == "table"]
    results.append({"name": "generated_markdown_tables_preserved_as_blocks", "passed": len(generated_tables) >= 2})

    try:
        export_section_pdf(OUTPUTS, "executive_summary", incident_id=incident_id)
        locked = False
    except PermissionError:
        locked = True
    results.append({"name": "pdf_locked_before_confirmation", "passed": locked})

    blocks = [
        {"type": "heading", "level": 1, "text": "Executive Summary"},
        {"type": "table", "columns": ["Field", "Value"], "rows": [["Incident ID", incident_id], ["Analyst Decision", "Reviewed and approved"]]},
        {"type": "paragraph", "text": "SOC analyst edited this report inside dashboard tables."},
    ]
    saved = save_section(OUTPUTS, "executive_summary", "", analyst="Unit Test Analyst", incident_id=incident_id, blocks=blocks)
    read_back = read_section(OUTPUTS, "executive_summary", incident_id=incident_id)
    results.append({"name": "structured_draft_saved", "passed": read_back.get("blocks") == blocks and saved.get("section", {}).get("status") == "draft"})

    confirmed = confirm_section(OUTPUTS, "executive_summary", analyst="Unit Test Analyst", incident_id=incident_id)
    results.append({"name": "confirmed_after_draft", "passed": confirmed.get("section", {}).get("status") == "confirmed" and bool(confirmed.get("section", {}).get("confirmed_path"))})

    docx = export_section_docx(OUTPUTS, "executive_summary", incident_id=incident_id)
    pdf = export_section_pdf(OUTPUTS, "executive_summary", incident_id=incident_id)
    results.append({"name": "docx_export_after_confirmation", "passed": Path(docx["path"]).exists() and Path(docx["path"]).stat().st_size > 0})
    results.append({"name": "pdf_export_after_confirmation", "passed": Path(pdf["path"]).exists() and Path(pdf["path"]).stat().st_size > 0})
    docx_xml = ""
    with zipfile.ZipFile(docx["path"]) as archive:
        docx_xml = archive.read("word/document.xml").decode("utf-8", errors="replace")
    results.append({"name": "docx_has_real_table_xml", "passed": "<w:tbl>" in docx_xml})
    results.append({"name": "docx_has_no_raw_markdown_table_separator", "passed": "|---" not in docx_xml and "---|" not in docx_xml})

    passed = sum(1 for r in results if r["passed"])
    summary = {"passed": passed, "failed": len(results) - passed, "results": results}
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
