#!/usr/bin/env python3
"""KSIF graphical interface entry point.

Run with:  python gui.py
Or use the packaged executable produced by scripts/build_exe.py.
"""

from __future__ import annotations

import sys

from ui.gui import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
