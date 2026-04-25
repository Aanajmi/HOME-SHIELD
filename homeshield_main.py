"""HomeShield — Run this file directly to use the tool.

Usage:
    python homeshield_main.py --help
    python homeshield_main.py measure --label baseline_iot_run1 --vantage iot --iface en0 --rounds 5
    python homeshield_main.py diff --before outputs/baseline/run.json --after outputs/hardened/run.json
    python homeshield_main.py report --diff outputs/diff.json --out reports/report.html
    python homeshield_main.py pcap-parse --pcap evidence/pcaps/capture.pcap
"""

import sys
import os

# Ensure the package directory is on the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from homeshield.cli import main

if __name__ == "__main__":
    main()
