#!/usr/bin/env python3

import argparse
import re
import sys
import tarfile
import time
from pathlib import Path
from typing import Iterable


TEXT_EXTS = (
    ".bb",
    ".bbappend",
    ".inc",
    ".conf",
    ".cfg",
    ".service",
    ".socket",
    ".timer",
    ".sh",
    ".py",
    ".pl",
    ".rb",
    ".js",
    ".ts",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".mk",
    ".cmake",
    ".patch",
    ".txt",
    ".md",
    ".json",
    ".xml",
)


def iter_recipe_archives(root: Path) -> list[Path]:
    archives: list[Path] = []
    for p in root.rglob("*-recipe.tar.*"):
        if p.is_file():
            archives.append(p)
    archives.sort(key=lambda p: p.stat().st_size)
    return archives


def is_text_member(name: str) -> bool:
    lname = name.lower()
    return any(lname.endswith(ext) for ext in TEXT_EXTS)


def tar_mode_for(path: Path) -> str:
    name = path.name.lower()
    if name.endswith(".tar.gz"):
        return "r:gz"
    if name.endswith(".tar.xz"):
        return "r:xz"
    if name.endswith(".tar.bz2"):
        return "r:bz2"
    if name.endswith(".tar"):
        return "r"
    # best-effort fallback
    return "r:*"


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Scan inside *-recipe.tar.* for protocol/service identifiers."
    )
    ap.add_argument("--root", default="sources", help="Root folder (default: sources)")
    ap.add_argument(
        "--pattern",
        default=(
            r"(_rdk-rics\\._tcp|rdk[-_]?rics|\\brics\\b|remote_app_|"
            r"soft remote|soft_remote|monarch|entos|\\b8091\\b|"
            r"websocket|\\bwss?://|dns-sd|_services\\._dns-sd\\._udp|"
            r"mdns|avahi|bonjour|zeroconf)"
        ),
        help="Regex to search within text members",
    )
    ap.add_argument("--max-seconds", type=float, default=110.0)
    ap.add_argument("--max-archives", type=int, default=1000)
    ap.add_argument("--max-member-bytes", type=int, default=1_000_000)
    ap.add_argument("--max-hits", type=int, default=200)
    args = ap.parse_args()

    root = Path(args.root)
    if not root.exists():
        print(f"root not found: {root}", file=sys.stderr)
        return 2

    needle = re.compile(args.pattern, re.IGNORECASE)

    archives = iter_recipe_archives(root)
    print(f"recipe_archives: {len(archives)}")

    hits = 0
    scanned = 0
    start = time.time()

    for archive in archives:
        if scanned >= args.max_archives:
            break
        if (time.time() - start) > args.max_seconds:
            break
        if hits >= args.max_hits:
            break

        scanned += 1

        try:
            with tarfile.open(archive, tar_mode_for(archive)) as tf:
                for member in tf.getmembers():
                    if hits >= args.max_hits:
                        break
                    if not member.isfile():
                        continue
                    if member.size <= 0 or member.size > args.max_member_bytes:
                        continue
                    if not is_text_member(member.name):
                        continue

                    f = tf.extractfile(member)
                    if f is None:
                        continue
                    try:
                        data = f.read(args.max_member_bytes)
                    finally:
                        f.close()

                    text = data.decode("utf-8", errors="replace")
                    if needle.search(text):
                        print(f"{archive}\t{member.name}")
                        hits += 1
                        # keep scanning this archive for more hits; recipes can have multiple relevant files
        except Exception:
            continue

    elapsed = time.time() - start
    print(f"scanned_archives: {scanned} hits: {hits} elapsed_s: {elapsed:.1f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
