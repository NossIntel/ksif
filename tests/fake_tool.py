"""Stand-in for external tools during tests.

usage: fake_tool.py <dir> <binary> <args...>

Behaviour is driven by files in <dir>:
  <binary>.out   -> printed to stdout
  <binary>.err   -> printed to stderr
  <binary>.code  -> exit code (default 0)
  <binary>.file  -> "<flag>" : the argument following <flag> is a path where
                    the content of <binary>.filedata is written (tools that
                    only write results to a file, e.g. nikto -output)
The received arguments are appended to <binary>.args (one JSON list per call).
"""

import json
import sys
from pathlib import Path


def main() -> int:
    base, binary, args = Path(sys.argv[1]), sys.argv[2], sys.argv[3:]
    with (base / f"{binary}.args").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(args) + "\n")
    file_flag = base / f"{binary}.file"
    if file_flag.exists():
        flag = file_flag.read_text(encoding="utf-8").strip()
        data = (base / f"{binary}.filedata").read_text(encoding="utf-8")
        for index, arg in enumerate(args):
            if arg == flag and index + 1 < len(args):
                Path(args[index + 1]).write_text(data, encoding="utf-8")
            elif arg.startswith(flag + "="):
                Path(arg.split("=", 1)[1]).write_text(data, encoding="utf-8")
    out = base / f"{binary}.out"
    if out.exists():
        sys.stdout.write(out.read_text(encoding="utf-8"))
    err = base / f"{binary}.err"
    if err.exists():
        sys.stderr.write(err.read_text(encoding="utf-8"))
    code = base / f"{binary}.code"
    return int(code.read_text().strip()) if code.exists() else 0


if __name__ == "__main__":
    sys.exit(main())
