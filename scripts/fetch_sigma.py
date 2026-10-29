#!/usr/bin/env python3
"""Fetch the SigmaHQ rule corpus for `python -m siemlab sigma-audit`.

Does a shallow, blobless, sparse clone of https://github.com/SigmaHQ/sigma into
``vendor/sigma`` — only the Windows rules, which is all this lab's telemetry can
exercise. That's a few thousand rules instead of the whole repository history.

The corpus is NOT vendored into this repository: it is upstream content with its
own license (Detection Rule License 1.1), it changes constantly, and pinning a
stale copy would undercut the entire point of auditing against rules maintained
by other people. ``vendor/`` is gitignored; run this to populate it.

    python scripts/fetch_sigma.py
    python scripts/fetch_sigma.py --update     # refresh an existing clone
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys

REPO = "https://github.com/SigmaHQ/sigma.git"
DEST = os.path.join("vendor", "sigma")
SPARSE_PATH = "rules/windows"


def _run(cmd: list[str], cwd: str | None = None) -> int:
    print("  $", " ".join(cmd))
    return subprocess.call(cmd, cwd=cwd)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dest", default=DEST, help=f"clone destination (default: {DEST})")
    ap.add_argument("--update", action="store_true", help="git pull an existing clone")
    ap.add_argument("--all-rules", action="store_true",
                    help="fetch the whole rules/ tree, not just Windows")
    args = ap.parse_args(argv)

    if shutil.which("git") is None:
        print("error: git is not on PATH", file=sys.stderr)
        return 1

    sparse = "rules" if args.all_rules else SPARSE_PATH

    if os.path.isdir(os.path.join(args.dest, ".git")):
        if args.update:
            print(f"updating existing clone in {args.dest}")
            return _run(["git", "pull", "--ff-only"], cwd=args.dest)
        print(f"{args.dest} already exists; pass --update to refresh it")
        return 0

    os.makedirs(os.path.dirname(args.dest) or ".", exist_ok=True)
    print(f"cloning {REPO} (shallow, sparse: {sparse}) -> {args.dest}")
    rc = _run(["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse",
               REPO, args.dest])
    if rc != 0:
        return rc
    rc = _run(["git", "sparse-checkout", "set", sparse], cwd=args.dest)
    if rc != 0:
        return rc

    count = sum(len([f for f in files if f.endswith(".yml")])
                for _, _, files in os.walk(os.path.join(args.dest, sparse)))
    print(f"\ndone: {count} Sigma rules under {os.path.join(args.dest, sparse)}")
    print("now run:  python -m siemlab sigma-audit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
