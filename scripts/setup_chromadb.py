import subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
raise SystemExit(subprocess.call([sys.executable, str(ROOT/'database'/'chromadb'/'ingest_knowledge_base.py')], cwd=ROOT))
