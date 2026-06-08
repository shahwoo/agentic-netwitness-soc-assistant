from pathlib import Path
import sys
PROJECT_ROOT=Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path: sys.path.insert(0,str(PROJECT_ROOT))
from config import settings
def chunks(text,size=1400):
    ps=[p.strip() for p in text.split('\n\n') if p.strip()]; out=[]; cur=''
    for p in ps:
        if len(cur)+len(p)+2<=size: cur=f'{cur}\n\n{p}'.strip()
        else:
            if cur: out.append(cur)
            cur=p[:size]
    if cur: out.append(cur)
    return out
def main():
    try: import chromadb
    except Exception as e: print(f'ChromaDB unavailable: {e}'); return 1
    client=chromadb.PersistentClient(path=str(settings.CHROMA_DB_PATH)); col=client.get_or_create_collection(settings.CHROMA_COLLECTION_NAME)
    ids=[]; docs=[]; metas=[]
    for rel in settings.REQUIRED_KB_FILES:
        path=settings.KNOWLEDGE_BASE_DIR/rel
        if not path.exists(): continue
        for i,ch in enumerate(chunks(path.read_text(encoding='utf-8', errors='replace'))): ids.append(f'{rel}::chunk-{i}'); docs.append(ch); metas.append({'source':rel,'chunk_id':i})
    if ids: col.upsert(ids=ids, documents=docs, metadatas=metas)
    print(f'Ingested {len(ids)} chunks. Malware and ransomware playbooks excluded.'); return 0
if __name__=='__main__': raise SystemExit(main())
