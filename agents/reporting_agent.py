import argparse
from pathlib import Path
import sys
PROJECT_ROOT=Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path: sys.path.insert(0, str(PROJECT_ROOT))
from config import settings
from reporting.input_loader import load_reporting_inputs
from reporting.context_builder import build_context
from reporting.report_renderer import render_reports
from reporting.output_writer import write_outputs, try_store_postgres, write_json
def parse_args():
    p=argparse.ArgumentParser(description='Reporting Agent')
    p.add_argument('--input-dir', type=Path, default=settings.INPUT_DIR)
    p.add_argument('--output-dir', type=Path, default=settings.OUTPUT_DIR)
    return p.parse_args()
def main():
    args=parse_args(); print('[Reporting Agent] Starting reporting workflow...'); print(f'[Reporting Agent] Input directory: {args.input_dir}'); print(f'[Reporting Agent] Output directory: {args.output_dir}')
    inputs,warnings=load_reporting_inputs(args.input_dir); context=build_context(inputs,warnings); generated=render_reports(context, output_dir=args.output_dir); rr=write_outputs(context, generated, output_dir=args.output_dir); pg_used,pg_status=try_store_postgres(rr, context); rr['postgres_used']=pg_used; rr['postgres_status']=pg_status; write_json(args.output_dir/context['incident_id']/'reporting_result.json', rr)
    print('[Reporting Agent] Reports generated.'); print(f"[Reporting Agent] Incident ID: {context['incident_id']}"); print(f"[Reporting Agent] Report status: {context['report_status']}"); print(f"[Reporting Agent] Validation status: {context['validation_status']}"); print(f"[Reporting Agent] RAG status: {context['rag_status']}"); print(f"[Reporting Agent] LLM status: {context['llm_status']}"); print(f'[Reporting Agent] PostgreSQL status: {pg_status}')
    if context['missing_required_fields']:
        print('[Reporting Agent] Missing required fields:')
        for f in context['missing_required_fields']: print(f'- {f}')
    print('[Reporting Agent] Generated reports:')
    for name,path in generated.items(): print(f'- {name}: {path}')
    return 0
if __name__=='__main__': raise SystemExit(main())
