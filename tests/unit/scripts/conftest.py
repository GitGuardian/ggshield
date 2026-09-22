import sys
from pathlib import Path


# The perfbench scripts import each other by module name, so they only work with
# their own directory on sys.path
PERFBENCH_DIR = Path(__file__).parents[3] / "scripts" / "perfbench"
sys.path.insert(0, str(PERFBENCH_DIR))
