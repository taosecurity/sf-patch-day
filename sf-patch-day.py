# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Richard Bejtlich
"""Entry script: python -I sf-patch-day.py <command> [options]. (-I leaves the script's own folder off the import
path, so it is added here.)"""
import os
import sys

if sys.version_info < (3, 9):
    print("RESULT: CANNOT CHECK: sf-patch-day needs Python 3.9 or newer. Fix: install it from https://www.python.org")
    sys.exit(3)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sf_patch_day.cli import main  # noqa: E402

sys.exit(main())
