import subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
raise SystemExit(subprocess.call([sys.executable, str(ROOT/'agents'/'reporting_agent.py')], cwd=ROOT))
