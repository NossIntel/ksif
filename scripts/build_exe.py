#!/usr/bin/env python3
"""Build a standalone KSIF GUI executable with PyInstaller.

Usage:
    python scripts/build_exe.py            # one-file GUI build
    python scripts/build_exe.py --console  # keep a console window (debugging)

The result is dist/KSIF (KSIF.exe on Windows). All Python dependencies are
bundled, so the executable runs without installing anything. External security
tools (nmap, nuclei, ...) are still detected at runtime and are not bundled.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Module action packages are imported dynamically (importlib), so PyInstaller
# cannot see them by static analysis: name them explicitly.
HIDDEN_IMPORTS = [
    "modules.network_discovery.actions",
    "modules.osint.actions",
    "modules.web_security.actions",
    "modules.wifi_audit.actions",
    "modules.password_lab.actions",
    "modules.vulnerability_intelligence.actions",
    "modules.reporting.builder",
    "modules.reporting.renderers",
]


def ensure_pyinstaller() -> None:
    try:
        import PyInstaller  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        print("Installing PyInstaller…")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "pyinstaller"])


def build(console: bool) -> int:
    ensure_pyinstaller()
    sep = ";" if os.name == "nt" else ":"
    migrations = ROOT / "core" / "migrations"
    args = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile",
        "--name", "KSIF", "--distpath", str(ROOT / "dist"), "--workpath", str(ROOT / "build"),
        "--specpath", str(ROOT / "build"),
        "--add-data", f"{migrations}{sep}core/migrations",
        "--collect-submodules", "modules", "--collect-submodules", "integrations",
    ]
    for name in HIDDEN_IMPORTS:
        args += ["--hidden-import", name]
    if not console:
        args.append("--windowed")
    args.append(str(ROOT / "gui.py"))
    print("Running:", " ".join(args))
    result = subprocess.run(args, cwd=ROOT)
    if result.returncode == 0:
        exe = ROOT / "dist" / ("KSIF.exe" if os.name == "nt" else "KSIF")
        print(f"\nBuilt: {exe}")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(build("--console" in sys.argv))
