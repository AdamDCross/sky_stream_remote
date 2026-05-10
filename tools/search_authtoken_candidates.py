#!/usr/bin/env python3

import argparse
import base64
import hashlib
import hmac
import itertools
import json
import uuid
from pathlib import Path
from typing import Callable, Optional, Union


CORE_FIELDS = ("pairingcode", "stbnonce", "tid", "controllernonce")
SEPARATORS = ("", ":", "|", ",", "\n", " ", "::")


def load_sessions(path: Path) -> list[dict]:
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    by_conn: dict[int, dict] = {}

    for row in rows:
        if row.get("event") != "websocket_frame":
            continue

        payload = row.get("payload_json") or {}
        command_name = payload.get("command_name")
        direction = row.get("direction")
        conn_id = row.get("connection_id")
        if conn_id is None:
            continue

        session = by_conn.setdefault(conn_id, {})
        if direction in ("client_to_oracle", "client_to_upstream") and command_name == "Pair Request":
            session["pair_req"] = payload
            session["pair_req_text"] = row.get("payload_text")
        elif direction in ("oracle_to_client", "upstream_to_client") and command_name == "Pair Request":
            session["pair_resp"] = payload
            session["pair_resp_text"] = row.get("payload_text")
        elif direction in ("client_to_oracle", "client_to_upstream") and command_name == "Bind Request":
            session["bind_req"] = payload
            session["bind_req_text"] = row.get("payload_text")

    sessions = []
    for conn_id in sorted(by_conn):
        session = by_conn[conn_id]
        if {"pair_req", "pair_resp", "bind_req"} <= session.keys():
            sessions.append(session)
    return sessions


def distinct_sessions(paths: list[Path]) -> list[dict]:
    seen = set()
    sessions: list[dict] = []

    for path in paths:
        for session in load_sessions(path):
            pair_req = session["pair_req"]
            pair_resp = session["pair_resp"]
            bind_req = session["bind_req"]
            key = (
                pair_req.get("tid"),
                pair_req.get("controllernonce"),
                pair_resp.get("pairingcode"),
                pair_resp.get("stbnonce"),
                bind_req.get("authtoken"),
            )
            if key in seen:
                continue
            seen.add(key)
            sessions.append(
                {
                    "source": str(path),
                    "pairingcode": pair_resp["pairingcode"],
                    "stbnonce": pair_resp["stbnonce"],
                    "tid": pair_req["tid"],
                    "controllernonce": pair_req["controllernonce"],
                    "pair_req_command": pair_req["command_name"],
                    "pair_resp_command": pair_resp["command_name"],
                    "bind_command": bind_req["command_name"],
                    "client_name": pair_req["name"],
                    "manufacturer": pair_req["manufacturer"],
                    "model": pair_req["model"],
                    "device_name": pair_resp["name"],
                    "status": str(pair_resp["status"]).lower(),
                    "pair_req_text": session["pair_req_text"],
                    "pair_resp_text": session["pair_resp_text"],
                    "bind_token": bind_req["authtoken"],
                }
            )

    return sessions


def b64_sha256_text(text: str) -> str:
    return base64.b64encode(hashlib.sha256(text.encode()).digest()).decode()


def b64_sha256_bytes(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


def run_candidate(
    sessions: list[dict],
    label: str,
    builder: Callable[[dict], Union[str, bytes]],
) -> tuple[bool, Optional[str]]:
    first_candidate = None
    for session in sessions:
        built = builder(session)
        token = (
            b64_sha256_bytes(built)
            if isinstance(built, bytes)
            else b64_sha256_text(built)
        )
        if first_candidate is None:
            first_candidate = token
        if token != session["bind_token"]:
            return False, None
    return True, label


def search_candidates(sessions: list[dict]) -> tuple[int, list[str]]:
    hits: list[str] = []
    tried = 0

    for perm in itertools.permutations(CORE_FIELDS, 4):
        for sep in SEPARATORS:
            ok, hit = run_candidate(
                sessions,
                f"join4 perm={perm} sep={sep!r}",
                lambda s, perm=perm, sep=sep: sep.join(s[field] for field in perm),
            )
            tried += 1
            if ok and hit:
                hits.append(hit)

            for kv_sep in ("=", ":"):
                ok, hit = run_candidate(
                    sessions,
                    f"labeled4 perm={perm} sep={sep!r} kv={kv_sep!r}",
                    lambda s, perm=perm, sep=sep, kv_sep=kv_sep: sep.join(
                        f"{field}{kv_sep}{s[field]}" for field in perm
                    ),
                )
                tried += 1
                if ok and hit:
                    hits.append(hit)

    orders = (
        CORE_FIELDS,
        ("pairingcode", "stbnonce", "controllernonce", "tid", "client_name", "manufacturer", "model"),
        (
            "pair_req_command",
            "tid",
            "client_name",
            "manufacturer",
            "model",
            "controllernonce",
            "pairingcode",
            "stbnonce",
            "bind_command",
        ),
        ("pair_resp_command", "device_name", "pairingcode", "status", "stbnonce", "tid", "controllernonce"),
    )

    for order in orders:
        for size in range(1, min(6, len(order)) + 1):
            for subset in itertools.combinations(order, size):
                for sep in SEPARATORS:
                    ok, hit = run_candidate(
                        sessions,
                        f"subset fields={subset} sep={sep!r}",
                        lambda s, subset=subset, sep=sep: sep.join(s[field] for field in subset),
                    )
                    tried += 1
                    if ok and hit:
                        hits.append(hit)

    text_patterns = (
        ("pair_req_text", lambda s: s["pair_req_text"]),
        ("pair_resp_text", lambda s: s["pair_resp_text"]),
        ("pair_req+pair_resp", lambda s: s["pair_req_text"] + s["pair_resp_text"]),
        ("pair_resp+pair_req", lambda s: s["pair_resp_text"] + s["pair_req_text"]),
        ("pair_req+pair_resp+bind", lambda s: s["pair_req_text"] + s["pair_resp_text"] + s["bind_command"]),
        ("pairingcode+stbnonce+pair_req", lambda s: s["pairingcode"] + s["stbnonce"] + s["pair_req_text"]),
        ("pair_resp+controllernonce", lambda s: s["pair_resp_text"] + s["controllernonce"]),
    )
    for label, builder in text_patterns:
        ok, hit = run_candidate(sessions, f"text {label}", builder)
        tried += 1
        if ok and hit:
            hits.append(hit)

    for key_field in CORE_FIELDS:
        msg_fields = tuple(field for field in CORE_FIELDS if field != key_field)
        for perm in itertools.permutations(msg_fields):
            for sep in SEPARATORS:
                label = f"hmac key={key_field} msg={perm} sep={sep!r}"

                def builder(session: dict, key_field=key_field, perm=perm, sep=sep) -> bytes:
                    key = session[key_field].encode()
                    msg = sep.join(session[field] for field in perm).encode()
                    return hmac.new(key, msg, hashlib.sha256).digest()

                first = None
                ok = True
                for session in sessions:
                    token = base64.b64encode(builder(session)).decode()
                    if first is None:
                        first = token
                    if token != session["bind_token"]:
                        ok = False
                        break
                tried += 1
                if ok:
                    hits.append(label)

    byte_orders = (
        CORE_FIELDS,
        ("pairingcode", "stbnonce", "tid", "controllernonce"),
    )
    for order in byte_orders:
        for mode in ("text", "uuid-bytes"):
            ok, hit = run_candidate(
                sessions,
                f"bytes order={order} mode={mode}",
                lambda s, order=order, mode=mode: b"".join(
                    uuid.UUID(s[field]).bytes
                    if mode == "uuid-bytes" and field in ("tid", "controllernonce")
                    else s[field].encode()
                    for field in order
                ),
            )
            tried += 1
            if ok and hit:
                hits.append(hit)

    return tried, hits


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Search captured Pair/Bind sessions for simple authtoken derivation formulas "
            "such as base64(SHA-256(...)) over observed fields."
        )
    )
    parser.add_argument(
        "logs",
        nargs="*",
        default=["tools/oracle-repeat.jsonl", "tools/bridge.jsonl"],
        help="JSONL log files to mine for Pair/Bind sessions",
    )
    args = parser.parse_args()

    paths = [Path(path) for path in args.logs]
    missing = [str(path) for path in paths if not path.exists()]
    if missing:
        raise SystemExit(f"missing log files: {', '.join(missing)}")

    sessions = distinct_sessions(paths)
    if not sessions:
        raise SystemExit("no complete Pair/Bind sessions found")

    tried, hits = search_candidates(sessions)

    print(f"sessions: {len(sessions)}")
    print(f"candidates_tested: {tried}")
    if hits:
        print("hits:")
        for hit in hits:
            print(f"- {hit}")
        return 0

    print("hits: none")
    print("sample:")
    for session in sessions[:4]:
        print(
            json.dumps(
                {
                    "source": session["source"],
                    "pairingcode": session["pairingcode"],
                    "stbnonce": session["stbnonce"],
                    "tid": session["tid"],
                    "controllernonce": session["controllernonce"],
                    "bind_token": session["bind_token"],
                },
                ensure_ascii=False,
            )
        )
        naive = b64_sha256_text(
            session["pairingcode"]
            + session["stbnonce"]
            + session["tid"]
            + session["controllernonce"]
        )
        print(f"naive_sha256_b64={naive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
