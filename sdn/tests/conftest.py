import sys
from pathlib import Path

SDN_ROOT = Path(__file__).resolve().parents[1]
if str(SDN_ROOT) not in sys.path:
    sys.path.insert(0, str(SDN_ROOT))
