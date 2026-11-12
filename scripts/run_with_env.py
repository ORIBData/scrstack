#!/usr/bin/env python3
"""Execute a command with literal KEY=VALUE entries from .env."""

import os
import re
import sys
from pathlib import Path


def main():
    if len(sys.argv) < 2:
        print("usage: run_with_env.py COMMAND [ARGS...]", file=sys.stderr)
        return 2
    path = Path(".env")
    if not path.is_file():
        print("Create .env from .env.example first", file=sys.stderr)
        return 2
    env = os.environ.copy()
    seen = set()
    for number, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            print(f".env line {number} must be KEY=VALUE", file=sys.stderr)
            return 2
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) or key in seen:
            print(f".env line {number} has an invalid or duplicate key", file=sys.stderr)
            return 2
        seen.add(key)
        if value[:1] in ("'", '"'):
            if len(value) < 2 or value[-1] != value[0]:
                print(f".env line {number} has an unterminated quote", file=sys.stderr)
                return 2
            value = value[1:-1]
        env[key] = value
    if Path(sys.argv[1]).name == "scrs" and len(sys.argv) > 2 and sys.argv[2] == "api":
        env.pop("SCRS_DATABASE_ADMIN_URL", None)
    os.execvpe(sys.argv[1], sys.argv[1:], env)


if __name__ == "__main__":
    sys.exit(main())
