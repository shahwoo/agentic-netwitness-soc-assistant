import os
import hashlib
import chromadb
from sentence_transformers import SentenceTransformer


# ==============================
# Configuration
# ==============================

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

KNOWLEDGE_BASE_DIR = os.path.join(PROJECT_ROOT, "knowledge_base")
CHROMA_DB_DIR = os.path.join(PROJECT_ROOT, "chroma_store")

COLLECTION_NAME = "soc_knowledge_base"

SUPPORTED_EXTENSIONS = [".md", ".yaml", ".yml", ".txt"]

CHUNK_SIZE = 900
CHUNK_OVERLAP = 150

EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"


# ==============================
# Helper functions
# ==============================

def read_text_file(file_path):
    """
    Reads a text-based knowledge base file.
    """

    with open(file_path, "r", encoding="utf-8") as file:
        return file.read()


def get_file_category(file_path):
    """
    Identifies whether the file is from playbooks, policies, procedures,
    or report_templates.
    """

    normalised_path = file_path.replace("\\", "/")

    if "/playbooks/" in normalised_path:
        return "playbook"

    if "/policies/" in normalised_path:
        return "policy"

    if "/procedures/" in normalised_path:
        return "procedure"

    if "/report_templates/" in normalised_path:
        return "report_template"

    return "unknown"


def create_document_id(file_path, chunk_index):
    """
    Creates a stable unique ID for each chunk.
    """

    raw_id = f"{file_path}-{chunk_index}"
    return hashlib.md5(raw_id.encode("utf-8")).hexdigest()


def split_text_into_chunks(text, chunk_size=900, chunk_overlap=150):
    """
    Splits a long document into smaller overlapping chunks.

    Example:
    Chunk 1: characters 0 to 900
    Chunk 2: characters 750 to 1650
    Chunk 3: characters 1500 to 2400

    The overlap helps prevent important context from being cut off.
    """

    chunks = []

    if not text:
        return chunks

    start = 0
    text_length = len(text)

    while start < text_length:
        end = start + chunk_size
        chunk = text[start:end].strip()

        if chunk:
            chunks.append(chunk)

        start = end - chunk_overlap

    return chunks


def collect_knowledge_base_files():
    """
    Finds all supported files inside the knowledge_base folder.
    """

    knowledge_files = []

    for root, dirs, files in os.walk(KNOWLEDGE_BASE_DIR):
        for filename in files:
            file_extension = os.path.splitext(filename)[1].lower()

            if file_extension in SUPPORTED_EXTENSIONS:
                file_path = os.path.join(root, filename)
                knowledge_files.append(file_path)

    return knowledge_files


# ==============================
# Main ingestion logic
# ==============================

def ingest_knowledge_base():
    """
    Reads the knowledge base, creates embeddings, and stores them in ChromaDB.
    """

    print("[RAG] Starting knowledge base ingestion...")

    if not os.path.exists(KNOWLEDGE_BASE_DIR):
        print(f"[ERROR] Knowledge base folder not found: {KNOWLEDGE_BASE_DIR}")
        return

    embedding_model = SentenceTransformer(EMBEDDING_MODEL_NAME)

    chroma_client = chromadb.PersistentClient(path=CHROMA_DB_DIR)

    collection = chroma_client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={
            "description": "SOC playbooks, policies, procedures, and report templates"
        }
    )

    knowledge_files = collect_knowledge_base_files()

    if not knowledge_files:
        print("[WARNING] No knowledge base files found.")
        return

    print(f"[RAG] Found {len(knowledge_files)} knowledge base files.")

    documents = []
    metadatas = []
    ids = []

    for file_path in knowledge_files:
        relative_path = os.path.relpath(file_path, PROJECT_ROOT)
        file_name = os.path.basename(file_path)
        file_category = get_file_category(file_path)

        print(f"[RAG] Reading: {relative_path}")

        file_content = read_text_file(file_path)
        chunks = split_text_into_chunks(
            file_content,
            chunk_size=CHUNK_SIZE,
            chunk_overlap=CHUNK_OVERLAP
        )

        for chunk_index, chunk in enumerate(chunks):
            document_id = create_document_id(relative_path, chunk_index)

            documents.append(chunk)

            metadatas.append({
                "source_file": relative_path,
                "file_name": file_name,
                "category": file_category,
                "chunk_index": chunk_index
            })

            ids.append(document_id)

    if not documents:
        print("[WARNING] No document chunks were created.")
        return

    print(f"[RAG] Created {len(documents)} chunks.")
    print("[RAG] Creating embeddings...")

    embeddings = embedding_model.encode(documents).tolist()

    print("[RAG] Storing chunks in ChromaDB...")

    collection.upsert(
        documents=documents,
        embeddings=embeddings,
        metadatas=metadatas,
        ids=ids
    )

    print("[RAG] Knowledge base ingestion completed successfully.")
    print(f"[RAG] ChromaDB stored at: {CHROMA_DB_DIR}")
    print(f"[RAG] Collection name: {COLLECTION_NAME}")


if __name__ == "__main__":
    ingest_knowledge_base()