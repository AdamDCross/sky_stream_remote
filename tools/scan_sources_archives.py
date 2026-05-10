#!/usr/bin/env python3

import argparse
import re
import sys
import time
from pathlib import Path
from typing import Iterable, Iterator, Tuple


def iter_archives(root: Path) -> list[Path]:
    archives: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        name = path.name.lower()
        if name.endswith((
            ".tar.gz",
            ".tgz",
            ".tar.xz",
            ".tar.bz2",
            ".zip",
            ".tar",
        )):
            archives.append(path)
    archives.sort(key=lambda p: p.stat().st_size)
    return archives


def iter_members(archive: Path) -> Iterable[str]:
    name = archive.name.lower()

    if name.endswith(".zip"):
        import zipfile

        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                yield info.filename
        return

    import tarfile

    mode = "r"
    if name.endswith((".tar.gz", ".tgz")):
        mode = "r:gz"
    elif name.endswith(".tar.xz"):
        mode = "r:xz"
    elif name.endswith(".tar.bz2"):
        mode = "r:bz2"

    with tarfile.open(archive, mode) as tf:
        for member in tf.getmembers():
            if member.name:
                yield member.name


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Scan archive member filenames under sources/ for a regex (fast triage)."
        )
    )
    parser.add_argument(
        "--root",
        default="sources",
        help="Root directory to scan (default: sources)",
    )
    parser.add_argument(
        "--pattern",
        default=(
            r"(rdk[-_]?rics|\\brics\\b|remote[_-]?app|remoteapp|monarch|entos|"
            r"mdns|dns[-_]?sd|avahi|bonjour|zeroconf)"
        ),
        help="Regex to match against archive member names",
    )
    parser.add_argument(
        "--max-archives",
        type=int,
        default=400,
        help="Max number of archives to scan (smallest first)",
    )
    parser.add_argument(
        "--max-seconds",
        type=float,
        default=120.0,
        help="Time budget in seconds",
    )
    parser.add_argument(
        "--max-hits",
        type=int,
        default=200,
        help="Max number of hit archives to print",
    )
    args = parser.parse_args()

    root = Path(args.root)
    if not root.exists():
        print(f"root not found: {root}", file=sys.stderr)
        return 2

    needle = re.compile(args.pattern, re.IGNORECASE)

    archives = iter_archives(root)
    print(f"archives: {len(archives)}")

    start = time.time()
    hits: list[Tuple[Path, str]] = []

    scanned = 0
    for archive in archives:
        if scanned >= args.max_archives:
            break
        if (time.time() - start) > args.max_seconds:
            break

        scanned += 1

        try:
            for member in iter_members(archive):
                if needle.search(member):
                    hits.append((archive, member))
                    break
        except Exception:
            # unreadable archive, skip
            continue

    elapsed = time.time() - start
    print(f"scanned: {scanned} hits: {len(hits)} elapsed_s: {elapsed:.1f}")

    for archive, member in hits[: args.max_hits]:
        print(f"{archive}\t{member}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
