"""PyInstaller entry point: a double-click (no arguments) runs the Windows UI."""
import sys

from v6race.cli import main

raise SystemExit(main(sys.argv[1:] or ["windows"]))
