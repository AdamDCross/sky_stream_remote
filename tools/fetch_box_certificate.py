#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import socket
import ssl
import struct
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

    HAVE_CRYPTOGRAPHY = True
except ImportError:
    x509 = None
    hashes = None
    serialization = None
    dsa = None
    ec = None
    rsa = None
    HAVE_CRYPTOGRAPHY = False


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = Path(__file__).resolve().parents[1]
CLIENT_CERT_FILENAME = "xfinity.xcal.tv-ComcastRDKD2DECCICA1-20241014-20241114.pem"
CLIENT_KEY_FILENAME = "soft_remote_key.pem"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "out" / "box-certificates"
DEFAULT_SNI = "entos-streambox.localdomain"
AUTH_SALT = "biT43y"
OP_TEXT = 0x1
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA


def find_default_client_material(filename: str, repo_relative_path: str) -> Path:
    script_local = SCRIPT_DIR / filename
    if script_local.exists():
        return script_local

    repo_root_local = REPO_ROOT / filename
    if repo_root_local.exists():
        return repo_root_local

    return REPO_ROOT / repo_relative_path


DEFAULT_CLIENT_CERT = find_default_client_material(
    CLIENT_CERT_FILENAME,
    "assets/flutter_assets/packages/soft_remote_app/assets/certs/"
    "xfinity.xcal.tv-ComcastRDKD2DECCICA1-20241014-20241114.pem",
)
DEFAULT_CLIENT_KEY = find_default_client_material(
    CLIENT_KEY_FILENAME,
    "assets/flutter_assets/packages/soft_remote_app/assets/certs/soft_remote_key.pem",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Connect to the box over TLS, save the peer certificate, and extract its public key.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("host", help="Box IP or hostname")
    parser.add_argument("--port", type=int, default=8091, help="TLS port on the box")
    parser.add_argument("--sni", default=DEFAULT_SNI, help="TLS SNI / server_hostname to use")
    parser.add_argument("--timeout", type=float, default=10.0, help="Socket timeout in seconds")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory where certificate artifacts are written",
    )
    parser.add_argument(
        "--prefix",
        help="File prefix for written artifacts. Defaults to host plus timestamp.",
    )
    parser.add_argument(
        "--client-cert",
        type=Path,
        default=DEFAULT_CLIENT_CERT,
        help="PEM file containing the client certificate/chain to present to the box",
    )
    parser.add_argument(
        "--client-key",
        type=Path,
        default=DEFAULT_CLIENT_KEY,
        help="PEM private key corresponding to --client-cert",
    )
    parser.add_argument(
        "--no-client-cert",
        action="store_true",
        help="Do not present the app's bundled client certificate",
    )
    parser.add_argument(
        "--probe-websocket",
        action="store_true",
        help="After the TLS probe, open a second connection and attempt a WebSocket upgrade.",
    )
    parser.add_argument(
        "--websocket-profile",
        choices=("tui", "ha"),
        default="tui",
        help="Header profile to use for the WebSocket upgrade probe.",
    )
    parser.add_argument(
        "--websocket-path",
        default="/iptarget",
        help="Request path used for the WebSocket upgrade probe.",
    )
    parser.add_argument(
        "--host-header",
        default=None,
        help="Override the HTTP Host header for the WebSocket probe.",
    )
    parser.add_argument(
        "--origin",
        default=None,
        help="Override the Origin header for the WebSocket probe.",
    )
    parser.add_argument(
        "--response-preview-bytes",
        type=int,
        default=400,
        help="How many response bytes to print for the WebSocket probe.",
    )
    parser.add_argument(
        "--probe-rics",
        action="store_true",
        help="After the TLS probe, perform WebSocket upgrade plus RICS Pair/Bind.",
    )
    return parser.parse_args()


def ensure_client_material(cert_path: Path | None, key_path: Path | None) -> tuple[Path | None, Path | None]:
    if cert_path is None and key_path is None:
        return None, None
    if cert_path is None or key_path is None:
        raise FileNotFoundError("Both client certificate and client key are required together")
    if not cert_path.exists():
        raise FileNotFoundError(f"Client certificate not found: {cert_path}")
    if not key_path.exists():
        raise FileNotFoundError(f"Client key not found: {key_path}")
    return cert_path, key_path


def build_client_context(cert_path: Path | None, key_path: Path | None) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["http/1.1"])
    if cert_path and key_path:
        context.load_cert_chain(str(cert_path), str(key_path))
    return context


def sanitize_prefix(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-._")
    return cleaned or "box"


def utc_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def cert_metadata(cert: object | None, der_bytes: bytes, tls_info: dict[str, object]) -> dict[str, object]:
    metadata: dict[str, object] = {
        "der_sha256": hashlib.sha256(der_bytes).hexdigest(),
        "tls": tls_info,
    }

    if not HAVE_CRYPTOGRAPHY or cert is None:
        metadata["note"] = (
            "Install the cryptography package to extract parsed certificate "
            "metadata and public key details."
        )
        return metadata

    public_key = cert.public_key()
    metadata.update(
        {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": hex(cert.serial_number),
            "signature_hash_algorithm": getattr(cert.signature_hash_algorithm, "name", None),
            "not_valid_before": utc_iso(cert.not_valid_before),
            "not_valid_after": utc_iso(cert.not_valid_after),
            "cert_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        }
    )

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        numbers = public_key.public_numbers()
        metadata["public_key"] = {
            "type": "EC",
            "curve": public_key.curve.name,
            "key_size": public_key.key_size,
            "x": format(numbers.x, "x"),
            "y": format(numbers.y, "x"),
            "compressed_point_hex": public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.CompressedPoint,
            ).hex(),
            "uncompressed_point_hex": public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            ).hex(),
        }
    elif isinstance(public_key, rsa.RSAPublicKey):
        numbers = public_key.public_numbers()
        metadata["public_key"] = {
            "type": "RSA",
            "key_size": public_key.key_size,
            "modulus": format(numbers.n, "x"),
            "public_exponent": numbers.e,
        }
    elif isinstance(public_key, dsa.DSAPublicKey):
        numbers = public_key.public_numbers()
        metadata["public_key"] = {
            "type": "DSA",
            "key_size": public_key.key_size,
            "y": format(numbers.y, "x"),
        }
    else:
        metadata["public_key"] = {
            "type": public_key.__class__.__name__,
        }
    return metadata


def save_artifacts(
    cert: object | None,
    der_bytes: bytes,
    tls_info: dict[str, object],
    out_dir: Path,
    prefix: str,
) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)

    leaf_der_path = out_dir / f"{prefix}-leaf-cert.der"
    leaf_pem_path = out_dir / f"{prefix}-leaf-cert.pem"
    public_key_pem_path = out_dir / f"{prefix}-public-key.pem"
    metadata_path = out_dir / f"{prefix}-metadata.json"

    leaf_der_path.write_bytes(der_bytes)
    leaf_pem_path.write_text(ssl.DER_cert_to_PEM_cert(der_bytes), encoding="ascii")

    metadata = cert_metadata(cert, der_bytes, tls_info)
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    written = {
        "leaf_der": leaf_der_path,
        "leaf_pem": leaf_pem_path,
        "metadata_json": metadata_path,
    }

    if not HAVE_CRYPTOGRAPHY or cert is None:
        return written

    public_key = cert.public_key()
    public_key_pem_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    written["public_key_pem"] = public_key_pem_path

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        compressed_path = out_dir / f"{prefix}-ec-public-key-compressed.bin"
        uncompressed_path = out_dir / f"{prefix}-ec-public-key-uncompressed.bin"
        compressed_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )
        uncompressed_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        compressed_path.write_bytes(compressed_bytes)
        uncompressed_path.write_bytes(uncompressed_bytes)
        written["ec_compressed_bin"] = compressed_path
        written["ec_uncompressed_bin"] = uncompressed_path

    return written


def fetch_peer_certificate(
    host: str,
    port: int,
    sni: str,
    timeout: float,
    context: ssl.SSLContext,
) -> tuple[object | None, bytes, dict[str, object]]:
    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        raw_sock.settimeout(timeout)
        with context.wrap_socket(raw_sock, server_hostname=sni) as tls_sock:
            der_bytes = tls_sock.getpeercert(binary_form=True)
            if not der_bytes:
                raise RuntimeError("Peer did not present a certificate")
            cert = x509.load_der_x509_certificate(der_bytes) if HAVE_CRYPTOGRAPHY else None
            tls_info = {
                "host": host,
                "port": port,
                "sni": sni,
                "version": tls_sock.version(),
                "cipher": tls_sock.cipher()[0] if tls_sock.cipher() else None,
                "alpn": tls_sock.selected_alpn_protocol(),
            }
            return cert, der_bytes, tls_info


def websocket_probe_defaults(
    host: str,
    port: int,
    sni: str,
    profile: str,
) -> tuple[str, str]:
    if profile == "ha":
        return f"{sni}:{port}", f"https://{host}:{port}/"
    return f"{host}:{port}", f"https://{host}:{port}/"


def probe_websocket_upgrade(
    host: str,
    port: int,
    sni: str,
    timeout: float,
    context: ssl.SSLContext,
    path: str,
    host_header: str,
    origin: str,
) -> dict[str, object]:
    ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"Origin: {origin}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {ws_key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Cache-Control: no-cache\r\n"
        "Accept-Encoding: gzip\r\n"
        "User-Agent: Dart/3.9 (dart:io)\r\n"
        "\r\n"
    ).encode("ascii")

    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        raw_sock.settimeout(timeout)
        with context.wrap_socket(raw_sock, server_hostname=sni) as tls_sock:
            tls_sock.sendall(request)
            chunks: list[bytes] = []
            while True:
                try:
                    chunk = tls_sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
                if b"\r\n\r\n" in b"".join(chunks):
                    break

    raw_response = b"".join(chunks)
    status_line = raw_response.split(b"\r\n", 1)[0].decode("utf-8", "replace") if raw_response else ""
    return {
        "request": request.decode("ascii"),
        "status_line": status_line,
        "response_bytes": raw_response,
        "response_text": raw_response.decode("utf-8", "replace"),
        "response_hex": raw_response.hex(),
    }


def compute_cert_fingerprint(cert_path: Path) -> str:
    raw = cert_path.read_text(encoding="utf-8")
    pem_blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
        raw,
        re.DOTALL,
    )
    if not pem_blocks:
        raise RuntimeError(f"No certificate found in {cert_path}")
    leaf_der = base64.b64decode(pem_blocks[0].replace("\n", ""))
    return hashlib.sha256(leaf_der).hexdigest()


def compute_authtoken(
    cert_fingerprint: str,
    pairingcode: str,
    controllernonce: str,
    stbnonce: str,
) -> str:
    decoded_fp = bytes.fromhex(cert_fingerprint)
    stage1_input = decoded_fp + pairingcode.encode("utf-8") + controllernonce.encode("utf-8")
    stage1 = hashlib.sha256(stage1_input).digest()
    stage2_input = stbnonce.encode("utf-8") + stage1 + AUTH_SALT.encode("utf-8")
    stage2 = hashlib.sha256(stage2_input).digest()
    return base64.b64encode(stage2).decode("utf-8")


def ws_mask(data: bytes, mask_key: bytes) -> bytes:
    return bytes(b ^ mask_key[i % 4] for i, b in enumerate(data))


def build_ws_frame(payload: bytes, opcode: int = OP_TEXT) -> bytes:
    mask_key = os.urandom(4)
    header = bytes([0x80 | opcode])
    length = len(payload)
    if length < 126:
        header += bytes([0x80 | length])
    elif length < 65536:
        header += bytes([0x80 | 126]) + struct.pack("!H", length)
    else:
        header += bytes([0x80 | 127]) + struct.pack("!Q", length)
    return header + mask_key + ws_mask(payload, mask_key)


def recv_exact(sock: ssl.SSLSocket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = sock.recv(length - len(chunks))
        if not chunk:
            raise ConnectionError("socket closed")
        chunks.extend(chunk)
    return bytes(chunks)


def read_ws_frame(sock: ssl.SSLSocket) -> tuple[int, bytes]:
    head = recv_exact(sock, 2)
    opcode = head[0] & 0x0F
    masked = bool(head[1] & 0x80)
    length = head[1] & 0x7F
    if length == 126:
        length = struct.unpack("!H", recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", recv_exact(sock, 8))[0]
    if masked:
        mask_key = recv_exact(sock, 4)
        raw = recv_exact(sock, length)
        payload = ws_mask(raw, mask_key)
    else:
        payload = recv_exact(sock, length)
    return opcode, payload


def websocket_upgrade(
    host: str,
    port: int,
    sni: str,
    timeout: float,
    context: ssl.SSLContext,
    path: str,
    host_header: str,
    origin: str,
) -> tuple[ssl.SSLSocket, str]:
    ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"Origin: {origin}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {ws_key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Cache-Control: no-cache\r\n"
        "Accept-Encoding: gzip\r\n"
        "User-Agent: Dart/3.9 (dart:io)\r\n"
        "\r\n"
    ).encode("ascii")

    raw_sock = socket.create_connection((host, port), timeout=timeout)
    raw_sock.settimeout(timeout)
    tls_sock = context.wrap_socket(raw_sock, server_hostname=sni)
    tls_sock.sendall(request)
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = tls_sock.recv(4096)
        if not chunk:
            tls_sock.close()
            raise RuntimeError("Connection closed during WebSocket upgrade")
        response += chunk
    status_line = response.split(b"\r\n", 1)[0].decode("utf-8", "replace")
    if "101" not in status_line:
        tls_sock.close()
        raise RuntimeError(f"WebSocket upgrade failed: {status_line}")
    return tls_sock, status_line


def recv_rics_json(sock: ssl.SSLSocket) -> dict[str, object]:
    while True:
        opcode, payload = read_ws_frame(sock)
        if opcode == OP_TEXT:
            return json.loads(payload.decode("utf-8"))
        if opcode == OP_PING:
            sock.sendall(build_ws_frame(payload, OP_PONG))
            continue
        if opcode == OP_CLOSE:
            raise RuntimeError("WebSocket closed by server")


def probe_rics_pair_bind(
    host: str,
    port: int,
    sni: str,
    timeout: float,
    context: ssl.SSLContext,
    path: str,
    host_header: str,
    origin: str,
    cert_path: Path,
) -> dict[str, object]:
    tls_sock, status_line = websocket_upgrade(
        host=host,
        port=port,
        sni=sni,
        timeout=timeout,
        context=context,
        path=path,
        host_header=host_header,
        origin=origin,
    )
    try:
        tid = str(uuid.uuid4())
        controllernonce = str(uuid.uuid4())
        pair_request = {
            "command_name": "Pair Request",
            "tid": tid,
            "name": "Soft Remote",
            "manufacturer": "Comcast",
            "model": "IPRemote",
            "controllernonce": controllernonce,
        }
        tls_sock.sendall(build_ws_frame(json.dumps(pair_request).encode("utf-8")))
        pair_response = recv_rics_json(tls_sock)

        bind_response: dict[str, object] | None = None
        if pair_response.get("status"):
            pairingcode = str(pair_response.get("pairingcode", ""))
            stbnonce = str(pair_response.get("stbnonce", ""))
            cert_fingerprint = compute_cert_fingerprint(cert_path)
            authtoken = compute_authtoken(
                cert_fingerprint=cert_fingerprint,
                pairingcode=pairingcode,
                controllernonce=controllernonce,
                stbnonce=stbnonce,
            )
            bind_request = {
                "command_name": "Bind Request",
                "tid": tid,
                "authtoken": authtoken,
            }
            tls_sock.sendall(build_ws_frame(json.dumps(bind_request).encode("utf-8")))
            bind_response = recv_rics_json(tls_sock)

        try:
            tls_sock.sendall(build_ws_frame(b"", OP_CLOSE))
        except OSError:
            pass

        return {
            "status_line": status_line,
            "pair_request": pair_request,
            "pair_response": pair_response,
            "bind_response": bind_response,
        }
    finally:
        tls_sock.close()


def main() -> int:
    args = parse_args()

    cert_path: Path | None = None if args.no_client_cert else args.client_cert
    key_path: Path | None = None if args.no_client_cert else args.client_key
    cert_path, key_path = ensure_client_material(cert_path, key_path)
    context = build_client_context(cert_path, key_path)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    prefix = args.prefix or f"{sanitize_prefix(args.host)}-{timestamp}"

    cert, der_bytes, tls_info = fetch_peer_certificate(
        host=args.host,
        port=args.port,
        sni=args.sni,
        timeout=args.timeout,
        context=context,
    )
    written = save_artifacts(
        cert=cert,
        der_bytes=der_bytes,
        tls_info=tls_info,
        out_dir=args.out_dir,
        prefix=prefix,
    )

    print(f"Connected to {args.host}:{args.port} with SNI {args.sni}")
    print(f"TLS:     version={tls_info['version']} cipher={tls_info['cipher']} alpn={tls_info['alpn']}")
    if HAVE_CRYPTOGRAPHY and cert is not None:
        public_key = cert.public_key()
        print(f"Subject: {cert.subject.rfc4514_string()}")
        print(f"Issuer:  {cert.issuer.rfc4514_string()}")
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            print(f"EC key:  curve={public_key.curve.name} size={public_key.key_size}")
        else:
            print(f"Public key type: {public_key.__class__.__name__}")
    else:
        print("Certificate parsing unavailable: install 'cryptography' for subject/issuer/public-key details")
    for label, path in written.items():
        print(f"{label}: {path}")

    if args.probe_websocket:
        default_host_header, default_origin = websocket_probe_defaults(
            args.host,
            args.port,
            args.sni,
            args.websocket_profile,
        )
        host_header = args.host_header or default_host_header
        origin = args.origin or default_origin
        probe = probe_websocket_upgrade(
            host=args.host,
            port=args.port,
            sni=args.sni,
            timeout=args.timeout,
            context=context,
            path=args.websocket_path,
            host_header=host_header,
            origin=origin,
        )
        preview_len = max(args.response_preview_bytes, 0)
        response_bytes = probe["response_bytes"]
        assert isinstance(response_bytes, bytes)
        response_text = probe["response_text"]
        assert isinstance(response_text, str)
        response_hex = probe["response_hex"]
        assert isinstance(response_hex, str)

        print("WebSocket probe:")
        print(f"  profile:     {args.websocket_profile}")
        print(f"  path:        {args.websocket_path}")
        print(f"  Host:        {host_header}")
        print(f"  Origin:      {origin}")
        print(f"  status line: {probe['status_line'] or '<no response>'}")
        print(f"  bytes:       {len(response_bytes)}")
        print(f"  text:        {response_text[:preview_len]}")
        print(f"  hex:         {response_hex[: preview_len * 2]}")

    if args.probe_rics:
        if cert_path is None:
            raise RuntimeError("--probe-rics requires a client certificate")
        default_host_header, default_origin = websocket_probe_defaults(
            args.host,
            args.port,
            args.sni,
            args.websocket_profile,
        )
        host_header = args.host_header or default_host_header
        origin = args.origin or default_origin
        rics = probe_rics_pair_bind(
            host=args.host,
            port=args.port,
            sni=args.sni,
            timeout=args.timeout,
            context=context,
            path=args.websocket_path,
            host_header=host_header,
            origin=origin,
            cert_path=cert_path,
        )
        print("RICS probe:")
        print(f"  status line: {rics['status_line']}")
        print(f"  pair:        {json.dumps(rics['pair_response'], sort_keys=True)}")
        bind_response = rics["bind_response"]
        if bind_response is not None:
            print(f"  bind:        {json.dumps(bind_response, sort_keys=True)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
