from pathlib import Path
import shutil
outputs=Path(__file__).resolve().parents[2]/'outputs'
for c in outputs.iterdir():
    if c.is_dir(): shutil.rmtree(c)
print('Cleaned outputs.')
