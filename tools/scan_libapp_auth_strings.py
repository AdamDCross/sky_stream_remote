#!/usr/bin/env python3

import argparse
import re
import subprocess
import sys
from pathlib import Path


PROTOCOL_TERMS = (
    "Pair Request",
    "Bind Request",
    "Key Command Request",
    "authtoken",
    "pairingcode",
    "stbnonce",
    "controllernonce",
    "keyatomic",
    "Soft Remote",
    "IPRemote",
)

CRYPTO_PATTERNS = (
    "Digest",
    "digest",
    "Hmac",
    "sha256",
    "sha512",
    "sha1",
    "md5",
    "base64",
    "utf8",
    "Uint8List",
    "SecretKey",
    "Random.secure",
    "crypto",
    "encrypt",
    "decrypt",
    "nonce",
    "hash",
)


def default_libapp_path() -> Path:
    cwd_candidate = Path("libapp.so")
    if cwd_candidate.exists():
        return cwd_candidate

    script_candidate = Path(__file__).resolve().parent.parent / "libapp.so"
    if script_candidate.exists():
        return script_candidate

    return cwd_candidate


def load_strings(libapp: Path, min_length: int) -> list[tuple[int, str]]:
    proc = subprocess.run(
        ["strings", "-a", "-t", "x", "-n", str(min_length), str(libapp)],
        check=False,
        capture_output=True,
        text=True,
        errors="ignore",
    )
    if proc.returncode != 0:
        print(proc.stderr.strip(), file=sys.stderr)
        raise SystemExit(proc.returncode)

    items: list[tuple[int, str]] = []
    for line in proc.stdout.splitlines():
        match = re.match(r"^\s*([0-9a-fA-F]+)\s+(.*)$", line)
        if not match:
            continue
        items.append((int(match.group(1), 16), match.group(2)))
    return items


def search_with_context(
    items: list[tuple[int, str]],
    patterns: tuple[str, ...],
    context: int,
) -> None:
    for pattern in patterns:
        hits = [idx for idx, (_, text) in enumerate(items) if pattern in text]
        if not hits:
            continue

        print(f"=== {pattern} ({len(hits)} hit(s)) ===")
        for idx in hits:
            start = max(0, idx - context)
            end = min(len(items), idx + context + 1)
            print(f"-- context around match #{idx + 1} --")
            for pos in range(start, end):
                offset, text = items[pos]
                marker = ">>" if pos == idx else "  "
                print(f"{marker} 0x{offset:06x}  {text}")
        print()


def print_summary(items: list[tuple[int, str]]) -> None:
    print("Protocol anchor summary:")
    for term in PROTOCOL_TERMS:
        first_hit = next(((offset, text) for offset, text in items if term in text), None)
        if first_hit is None:
            print(f"- {term}: not found")
            continue
        offset, text = first_hit
        print(f"- {term}: 0x{offset:06x}  {text}")
    print()


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Scan Flutter libapp.so strings for auth/protocol anchors and nearby "
            "crypto-ish terms."
        )
    )
    ap.add_argument(
        "--libapp",
        type=Path,
        default=default_libapp_path(),
        help="Path to libapp.so (defaults to ./libapp.so or ../libapp.so)",
    )
    ap.add_argument(
        "--min-length",
        type=int,
        default=4,
        help="Minimum string length passed to strings(1)",
    )
    ap.add_argument(
        "--context",
        type=int,
        default=3,
        help="Number of nearby strings to print before/after each hit",
    )
    ap.add_argument(
        "--mode",
        choices=("protocol", "crypto", "all"),
        default="all",
        help="Which pattern set to print",
    )
    args = ap.parse_args()

    if not args.libapp.exists():
        print(f"libapp not found: {args.libapp}", file=sys.stderr)
        return 2

    items = load_strings(args.libapp, args.min_length)
    print_summary(items)

    if args.mode in ("protocol", "all"):
        search_with_context(items, PROTOCOL_TERMS, args.context)

    if args.mode in ("crypto", "all"):
        search_with_context(items, CRYPTO_PATTERNS, args.context)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
