#!/usr/bin/env python3
"""Entry point for the hierarchical SAST triage pipeline.

Run from the repository root:  python main.py <command> [options]
(``python main.py -h`` for the command list). Installing the package
(``pip install -e .``) also exposes the ``sast-triage`` console script.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from sast_triage.cli import main

if __name__ == "__main__":
    sys.exit(main())
