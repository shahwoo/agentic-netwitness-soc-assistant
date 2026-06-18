import os
import chromadb
from chromadb.utils import embedding_functions

# Initialize persistent local ChromaDB client
DB_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "ChromaDatabase"))
client = chromadb.PersistentClient(path=DB_DIR)

# Use default local embedding function (SentenceTransformers / ONNX MiniLM-L6-v2)
default_ef = embedding_functions.DefaultEmbeddingFunction()

# Create or retrieve the collection configured for cosine similarity
collection = client.get_or_create_collection(
    name="soc_alerts",
    embedding_function=default_ef,
    metadata={"hnsw:space": "cosine"}
)

def clear_collection():
    """Helper function to reset collection database."""
    global collection
    try:
        client.delete_collection("soc_alerts")
    except Exception:
        pass
    collection = client.get_or_create_collection(
        name="soc_alerts",
        embedding_function=default_ef,
        metadata={"hnsw:space": "cosine"}
    )

def ingest_logs(logs_list: list):
    """Upserts list of processed logs containing 'id', 'document', and 'metadata' into ChromaDB."""
    if not logs_list:
        return
    ids = [log["id"] for log in logs_list]
    documents = [log["document"] for log in logs_list]
    metadatas = [log["metadata"] for log in logs_list]
    collection.upsert(ids=ids, documents=documents, metadatas=metadatas)

def query_semantic(query_text: str, timestamp_epoch: int = None, time_window_sec: int = 86400, n_results: int = 10) -> list:
    """Queries ChromaDB using semantic vector similarity and optional numerical temporal pre-filtering."""
    where_filter = None
    if timestamp_epoch is not None:
        where_filter = {
            "$and": [
                {"timestamp_epoch": {"$gte": int(timestamp_epoch - time_window_sec)}},
                {"timestamp_epoch": {"$lte": int(timestamp_epoch + time_window_sec)}}
            ]
        }
    
    results = collection.query(
        query_texts=[query_text],
        n_results=n_results,
        where=where_filter
    )
    
    parsed = []
    if results and results["ids"] and results["ids"][0]:
        for idx in range(len(results["ids"][0])):
            alert_id = results["ids"][0][idx]
            dist = results["distances"][0][idx]
            doc = results["documents"][0][idx]
            meta = results["metadatas"][0][idx]
            parsed.append((alert_id, dist, doc, meta))
    return parsed

def get_alerts_by_temporal_window(timestamp_epoch: int, time_window_sec: int = 86400) -> list:
    """Gets all alerts falling inside a specific temporal window via numerical metadata filters."""
    where_filter = {
        "$and": [
            {"timestamp_epoch": {"$gte": int(timestamp_epoch - time_window_sec)}},
            {"timestamp_epoch": {"$lte": int(timestamp_epoch + time_window_sec)}}
        ]
    }
    results = collection.get(where=where_filter)
    parsed = []
    if results and results["ids"]:
        for idx in range(len(results["ids"])):
            alert_id = results["ids"][idx]
            doc = results["documents"][idx] if results["documents"] else ""
            meta = results["metadatas"][idx]
            parsed.append((alert_id, doc, meta))
    return parsed

def correlate_rrf(active_indicators: list, query_text: str = None, timestamp_epoch: int = None, time_window_sec: int = 86400, k: int = 60, n_results: int = 10) -> list:
    """Correlates alerts using Reciprocal Rank Fusion (RRF) of semantic search and metadata matches."""
    if not active_indicators and not query_text:
        return []
        
    if not query_text:
        query_text = " ".join(str(ind) for ind in active_indicators)
        
    # 1. Semantic query
    semantic_candidates = query_semantic(
        query_text=query_text,
        timestamp_epoch=timestamp_epoch,
        time_window_sec=time_window_sec,
        n_results=n_results
    )
    
    # 2. Retrieve candidates for metadata matching (optionally scoped by time)
    if timestamp_epoch is not None:
        all_candidates = get_alerts_by_temporal_window(timestamp_epoch, time_window_sec)
    else:
        results = collection.get()
        all_candidates = []
        if results and results["ids"]:
            for idx in range(len(results["ids"])):
                all_candidates.append((
                    results["ids"][idx],
                    results["documents"][idx] if results["documents"] else "",
                    results["metadatas"][idx]
                ))
                
    # Calculate metadata match scores
    metadata_ranked_candidates = []
    for alert_id, doc, meta in all_candidates:
        match_count = 0
        for ind in active_indicators:
            ind_lower = str(ind).lower()
            # Exact metadata checks
            if meta.get("username", "").lower() == ind_lower:
                match_count += 1
            elif meta.get("hostname", "").lower() == ind_lower:
                match_count += 1
            # Contains checks for comma-separated items
            elif ind_lower in [x.strip().lower() for x in meta.get("ips", "").split(",") if x.strip()]:
                match_count += 1
            elif ind_lower in [x.strip().lower() for x in meta.get("domains", "").split(",") if x.strip()]:
                match_count += 1
            elif ind_lower in [x.strip().lower() for x in meta.get("emails", "").split(",") if x.strip()]:
                match_count += 1
            elif meta.get("incident_id", "").lower() == ind_lower:
                match_count += 1
                
        if match_count > 0:
            metadata_ranked_candidates.append((alert_id, match_count, doc, meta))
            
    # 3. Compute RRF scores
    semantic_ranked_ids = [item[0] for item in sorted(semantic_candidates, key=lambda x: x[1])]
    metadata_ranked_ids = [item[0] for item in sorted(metadata_ranked_candidates, key=lambda x: x[1], reverse=True)]
    
    doc_meta_map = {}
    for alert_id, _, doc, meta in semantic_candidates:
        doc_meta_map[alert_id] = (doc, meta)
    for alert_id, _, doc, meta in metadata_ranked_candidates:
        doc_meta_map[alert_id] = (doc, meta)
        
    rrf_scores = {}
    for rank, alert_id in enumerate(semantic_ranked_ids):
        rrf_scores[alert_id] = rrf_scores.get(alert_id, 0.0) + 1.0 / (k + (rank + 1))
        
    for rank, alert_id in enumerate(metadata_ranked_ids):
        rrf_scores[alert_id] = rrf_scores.get(alert_id, 0.0) + 1.0 / (k + (rank + 1))
        
    # Sort fused results by score descending
    fused_sorted = sorted(rrf_scores.items(), key=lambda x: x[1], reverse=True)
    
    final_results = []
    for alert_id, score in fused_sorted:
        doc, meta = doc_meta_map[alert_id]
        final_results.append((alert_id, score, doc, meta))
        
    return final_results
