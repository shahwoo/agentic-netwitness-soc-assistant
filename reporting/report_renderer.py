from pathlib import Path
from typing import Any
from jinja2 import Environment, FileSystemLoader, select_autoescape
from config import settings
TEMPLATES={'final_report':('incident_report_template.md.j2','final_report.md'),'executive_summary':('executive_summary_template.md.j2','executive_summary.md'),'technical_findings':('technical_findings_template.md.j2','technical_findings.md'),'soc_analyst_review':('soc_analyst_review_template.md.j2','soc_analyst_review.md')}
def render_reports(context: dict[str,Any], output_dir: Path|None=None, template_dir: Path|None=None) -> dict[str,str]:
    template_dir=template_dir or settings.TEMPLATE_DIR; root=output_dir or settings.OUTPUT_DIR; incident=root/context['incident_id']; incident.mkdir(parents=True, exist_ok=True)
    env=Environment(loader=FileSystemLoader(str(template_dir)), autoescape=select_autoescape(enabled_extensions=()), trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=True)
    generated={}
    for key,(tn,out) in TEMPLATES.items():
        content=env.get_template(tn).render(**context); path=incident/out; path.write_text(content, encoding='utf-8'); generated[key]=str(path)
    return generated
