from pathlib import Path
from typing import Any
from config import settings
def _chunk_text(text, size=1400):
    ps=[p.strip() for p in text.split('\n\n') if p.strip()]; chunks=[]; cur=''
    for p in ps:
        if len(cur)+len(p)+2 <= size: cur=f'{cur}\n\n{p}'.strip()
        else:
            if cur: chunks.append(cur)
            cur=p[:size]
    if cur: chunks.append(cur)
    return chunks
def _score(q, c):
    terms={t.lower() for t in q.replace('_',' ').split() if len(t)>3}; cl=c.lower(); return sum(1 for t in terms if t in cl)
def direct_file_retrieval(context, kb_dir: Path, max_chunks=5):
    query=' '.join([str(context.get('likely_scenario','')), str(context.get('classification','')), str(context.get('severity',{}).get('label','')), 'reporting severity containment approval evidence collection phishing playbook analyst review'])
    loaded=[]; candidates=[]
    for rel in settings.REQUIRED_KB_FILES:
        path=kb_dir/rel
        if not path.exists(): continue
        loaded.append(rel)
        text=path.read_text(encoding='utf-8', errors='replace')
        for i,ch in enumerate(_chunk_text(text)):
            candidates.append({'source':rel,'chunk_id':f'{rel}::chunk-{i}','content':ch,'score':_score(query,ch)})
    candidates.sort(key=lambda x:x['score'], reverse=True)
    return candidates[:max_chunks], loaded
def chromadb_retrieval(context, kb_dir: Path, max_chunks=5):
    import chromadb
    client=chromadb.PersistentClient(path=str(settings.CHROMA_DB_PATH))
    collection=client.get_or_create_collection(settings.CHROMA_COLLECTION_NAME)
    q=f"Scenario: {context.get('likely_scenario')} Severity: {context.get('severity',{}).get('label')} Classification: {context.get('classification')} reporting policy severity policy containment approval evidence collection phishing playbook"
    res=collection.query(query_texts=[q], n_results=max_chunks)
    docs=res.get('documents',[[]])[0]; metas=res.get('metadatas',[[]])[0]
    out=[]; loaded=set()
    for doc,meta in zip(docs,metas):
        src=meta.get('source','unknown') if isinstance(meta,dict) else 'unknown'; loaded.add(src)
        out.append({'source':src,'chunk_id':str(meta.get('chunk_id','unknown')) if isinstance(meta,dict) else 'unknown','content':doc,'score':'chromadb'})
    return out, sorted(loaded)
def retrieve_reporting_context(context: dict[str,Any], kb_dir: Path|None=None):
    kb_dir=kb_dir or settings.KNOWLEDGE_BASE_DIR
    excluded=['malware_response_playbook.md','ransomware_response_playbook.md']
    if not settings.USE_RAG: return {'rag_used':False,'rag_status':'disabled','retrieved_context':[],'loaded_knowledge_files':[],'excluded_playbooks':excluded}
    if settings.FORCE_RAG_FAILURE: return {'rag_used':False,'rag_status':'forced_failure_for_test','retrieved_context':[],'loaded_knowledge_files':[],'excluded_playbooks':excluded}
    if settings.USE_CHROMADB:
        try:
            docs,loaded=chromadb_retrieval(context,kb_dir)
            return {'rag_used':True,'rag_status':'success_chromadb','retrieved_context':docs,'loaded_knowledge_files':loaded,'excluded_playbooks':excluded}
        except Exception as e:
            docs,loaded=direct_file_retrieval(context,kb_dir)
            return {'rag_used':True,'rag_status':f'chromadb_failed_direct_file_fallback: {e}','retrieved_context':docs,'loaded_knowledge_files':loaded,'excluded_playbooks':excluded}
    docs,loaded=direct_file_retrieval(context,kb_dir)
    return {'rag_used':True,'rag_status':'success_direct_file_retrieval','retrieved_context':docs,'loaded_knowledge_files':loaded,'excluded_playbooks':excluded}
