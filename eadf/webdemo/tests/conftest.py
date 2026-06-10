import sys
from pathlib import Path

# Put the webdemo package dir on sys.path so `import presets`, `import runner` work
# both when running `python server.py` and under pytest.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
