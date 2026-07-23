from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from config import settings
from reporting.editable_reports import REPORT_SECTION_CONFIG, build_report_manifest, editable_dir
from reporting.structured_report import markdown_to_blocks, blocks_to_plain_text, save_blocks

# All report templates are actively used. The source templates are the uploaded
# report_templates/*.md.j2 files, but the Reporting Agent now writes editable
# plain-text sections for SOC analyst review instead of Markdown-first outputs.
TEMPLATES = {
    "executive_summary": (REPORT_SECTION_CONFIG["executive_summary"]["template"], REPORT_SECTION_CONFIG["executive_summary"]["filename"]),
    "technical_findings": (REPORT_SECTION_CONFIG["technical_findings"]["template"], REPORT_SECTION_CONFIG["technical_findings"]["filename"]),
    "soc_analyst_review": (REPORT_SECTION_CONFIG["soc_analyst_review"]["template"], REPORT_SECTION_CONFIG["soc_analyst_review"]["filename"]),
    "soc_triage_review": (REPORT_SECTION_CONFIG["soc_triage_review"]["template"], REPORT_SECTION_CONFIG["soc_triage_review"]["filename"]),
    "final_incident_report": (REPORT_SECTION_CONFIG["final_incident_report"]["template"], REPORT_SECTION_CONFIG["final_incident_report"]["filename"]),
}


def render_reports(context: dict[str, Any], output_dir: Path | None = None, template_dir: Path | None = None) -> dict[str, str]:
    template_dir = template_dir or settings.TEMPLATE_DIR
    root = output_dir or settings.OUTPUT_DIR
    incident_id = context["incident_id"]
    incident_root = root / incident_id
    incident_root.mkdir(parents=True, exist_ok=True)
    editable_root = editable_dir(root, incident_id)
    editable_root.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(enabled_extensions=()),
        trim_blocks=False,
        lstrip_blocks=False,
        keep_trailing_newline=True,
    )
    generated: dict[str, str] = {}
    for key, (template_name, output_name) in TEMPLATES.items():
        rendered_template = env.get_template(template_name).render(**context)
        blocks = markdown_to_blocks(rendered_template)
        plain_text = blocks_to_plain_text(blocks)
        path = editable_root / output_name
        path.write_text(plain_text, encoding="utf-8")
        block_path = editable_root / f"{key}.json"
        save_blocks(block_path, blocks)
        generated[key] = str(path)
        generated[f"{key}_structured"] = str(block_path)

    # Backwards-compatible plain-text aliases for older dashboard code/tests.
    final_text = editable_root / REPORT_SECTION_CONFIG["final_incident_report"]["filename"]
    if final_text.exists():
        (incident_root / "final_report.txt").write_text(final_text.read_text(encoding="utf-8"), encoding="utf-8")
        generated["final_report_text"] = str(incident_root / "final_report.txt")

    manifest = build_report_manifest(root, incident_id, generated, context)
    generated["report_manifest"] = str((root / incident_id / "reports" / "report_manifest.json"))
    return generated
