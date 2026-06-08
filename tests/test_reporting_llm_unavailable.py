import json, os, subprocess, sys
from pathlib import Path
PROJECT_ROOT=Path(__file__).resolve().parent.parent
AGENT=PROJECT_ROOT/'agents'/'reporting_agent.py'
def run_agent(fixture_name, extra_env=None):
    input_dir=PROJECT_ROOT/'fixtures'/fixture_name; output_dir=PROJECT_ROOT/'outputs'/f'test_{fixture_name}'
    env=os.environ.copy(); env['REPORTING_USE_LLM']='false'; env['REPORTING_USE_RAG']='true'; env['REPORTING_USE_CHROMADB']='false'; env['REPORTING_USE_POSTGRES']='false'
    if extra_env: env.update(extra_env)
    r=subprocess.run([sys.executable,str(AGENT),'--input-dir',str(input_dir),'--output-dir',str(output_dir)],cwd=PROJECT_ROOT,text=True,capture_output=True,timeout=45,env=env)
    assert r.returncode==0, r.stdout+'\n'+r.stderr
    triage=json.loads((input_dir/'triage_result.json').read_text(encoding='utf-8')); inc=triage['incident_id']; idir=output_dir/inc
    rr=json.loads((idir/'reporting_result.json').read_text(encoding='utf-8')); ctx=json.loads((idir/'enriched_reporting_context.json').read_text(encoding='utf-8'))
    for fn in ['final_report.md','executive_summary.md','technical_findings.md','soc_analyst_review.md']:
        assert (idir/fn).exists(), f'Missing {fn}'
        text=(idir/fn).read_text(encoding='utf-8')
        assert "{'" not in text
    return rr, ctx, idir

def test_llm_unavailable_falls_back():
    result, context, incident_dir = run_agent('llm_unavailable_case', {'REPORTING_USE_LLM':'true','REPORTING_OLLAMA_MODEL':'definitely-not-a-real-local-model'})
    assert result['report_status'] == 'ready_for_analyst_review'
    assert result['llm_used'] in [False, True]
    assert 'fallback' in result['llm_status'] or result['llm_status'] in ['disabled','success']
    assert (incident_dir/'executive_summary.md').exists()
