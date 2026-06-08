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

def test_complete_case_ready_for_review():
    result, context, incident_dir = run_agent('complete_phishing_case')
    assert result['report_status'] == 'ready_for_analyst_review'
    assert result['validation_status'] == 'passed'
    assert result['missing_required_fields'] == []
    assert context['rag_used'] is True
    assert 'playbooks/phishing_response_playbook.md' in context['loaded_knowledge_files']
    assert not any('malware' in f or 'ransomware' in f for f in context['loaded_knowledge_files'])
    assert 'malicious-domain.com' in (incident_dir/'final_report.md').read_text(encoding='utf-8')


def test_v2_report_quality_improvements_present():
    result, context, incident_dir = run_agent("complete_phishing_case")
    final_report = (incident_dir / "final_report.md").read_text(encoding="utf-8")
    assert "Policy Application Summary" in final_report
    assert "Raw retrieved RAG snippets are stored" in final_report
    assert "Send to Investigation Ag..." not in final_report
    assert "Pending Analyst Decision" in final_report
    assert "Confirm whether the user clicked" in final_report
    assert "Policy Application Summary" in final_report
    assert context["policy_application_summary"]
    assert context["impact_assessment"]["business"]
    assert "Suspicious phishing email delivery was observed" in final_report


def test_v3_llm_quality_fields_present():
    result, context, incident_dir = run_agent("complete_phishing_case")
    assert "llm_quality_status" in result
    assert "llm_quality_issues" in result
    final_report = (incident_dir / "final_report.md").read_text(encoding="utf-8")
    assert "LLM Quality Status" in final_report
    assert final_report.count("Current business impact is limited to") == 1
    assert "Policy Application Summary" in final_report
