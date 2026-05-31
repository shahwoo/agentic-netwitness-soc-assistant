import os
import chromadb
from sentence_transformers import SentenceTransformer


# ==============================
# Configuration
# ==============================

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CHROMA_DB_DIR = os.path.join(PROJECT_ROOT, "chroma_store")

COLLECTION_NAME = "soc_knowledge_base"

EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"

DEFAULT_TOP_K = 5


# ==============================
# RAG retrieval function
# ==============================

def retrieve_relevant_context(query, top_k=DEFAULT_TOP_K, category_filter=None):
    """
    Searches the SOC knowledge base and returns relevant chunks.

    Args:
        query:
            The question or investigation context to search for.

        top_k:
            Number of chunks to retrieve.

        category_filter:
            Optional filter.

            Example values:
            - "playbook"
            - "policy"
            - "procedure"
            - "report_template"

    Returns:
        A dictionary containing retrieved chunks and formatted context.
    """

    if not query or not query.strip():
        return {
            "success": False,
            "error": "Query cannot be empty.",
            "results": [],
            "formatted_context": ""
        }

    if not os.path.exists(CHROMA_DB_DIR):
        return {
            "success": False,
            "error": "ChromaDB store not found. Run rag/ingest_knowledge_base.py first.",
            "results": [],
            "formatted_context": ""
        }

    embedding_model = SentenceTransformer(EMBEDDING_MODEL_NAME)

    chroma_client = chromadb.PersistentClient(path=CHROMA_DB_DIR)

    try:
        collection = chroma_client.get_collection(name=COLLECTION_NAME)

    except Exception:
        return {
            "success": False,
            "error": f"Collection '{COLLECTION_NAME}' not found. Run ingestion first.",
            "results": [],
            "formatted_context": ""
        }

    query_embedding = embedding_model.encode([query]).tolist()[0]

    where_filter = None

    if category_filter:
        where_filter = {
            "category": category_filter
        }

    search_results = collection.query(
        query_embeddings=[query_embedding],
        n_results=top_k,
        where=where_filter
    )

    retrieved_chunks = []

    documents = search_results.get("documents", [[]])[0]
    metadatas = search_results.get("metadatas", [[]])[0]
    distances = search_results.get("distances", [[]])[0]

    for index, document in enumerate(documents):
        metadata = metadatas[index] if index < len(metadatas) else {}
        distance = distances[index] if index < len(distances) else None

        retrieved_chunks.append({
            "content": document,
            "source_file": metadata.get("source_file", "unknown"),
            "file_name": metadata.get("file_name", "unknown"),
            "category": metadata.get("category", "unknown"),
            "chunk_index": metadata.get("chunk_index", "unknown"),
            "distance": distance
        })

    formatted_context = format_retrieved_context(retrieved_chunks)

    return {
        "success": True,
        "query": query,
        "top_k": top_k,
        "category_filter": category_filter,
        "results": retrieved_chunks,
        "formatted_context": formatted_context
    }


def format_retrieved_context(retrieved_chunks):
    """
    Converts retrieved chunks into a clean text format that agents can use.
    """

    if not retrieved_chunks:
        return ""

    formatted_parts = []

    for index, chunk in enumerate(retrieved_chunks, start=1):
        source_file = chunk.get("source_file", "unknown")
        category = chunk.get("category", "unknown")
        content = chunk.get("content", "")

        formatted_part = f"""
[Retrieved Context {index}]
Source: {source_file}
Category: {category}

{content}
""".strip()

        formatted_parts.append(formatted_part)

    return "\n\n---\n\n".join(formatted_parts)


# ==============================
# Simple command-line test
# ==============================

if __name__ == "__main__":
    print("[RAG] SOC Knowledge Base Retrieval Test")
    print("=" * 50)

    user_query = input("Enter your query: ")

    result = retrieve_relevant_context(
        query=user_query,
        top_k=5
    )

    if not result["success"]:
        print(f"[ERROR] {result['error']}")

    else:
        print("\n[RAG] Retrieved Context:")
        print("=" * 50)
        print(result["formatted_context"])