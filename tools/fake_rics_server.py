#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta
import hashlib
import ipaddress
import itertools
import json
import logging
import os
import re
import socket
import ssl
import struct
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353
DNS_TYPE_A = 1
DNS_TYPE_PTR = 12
DNS_TYPE_TXT = 16
DNS_TYPE_AAAA = 28
DNS_TYPE_SRV = 33
DNS_TYPE_ANY = 255
DNS_CLASS_IN = 1


def normalize_name(name: str) -> str:
    return name.rstrip(".").lower()


def encode_dns_name(name: str) -> bytes:
    labels = [label for label in name.rstrip(".").split(".") if label]
    return b"".join(bytes([len(label)]) + label.encode("utf-8") for label in labels) + b"\x00"


def parse_dns_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    original_offset = offset
    max_hops = 32

    while max_hops > 0:
        max_hops -= 1
        if offset >= len(packet):
            raise ValueError("DNS name exceeds packet length")

        length = packet[offset]
        if length == 0:
            offset += 1
            break

        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("Truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if not jumped:
                original_offset = offset + 2
                jumped = True
            offset = pointer
            continue

        offset += 1
        label = packet[offset : offset + length]
        labels.append(label.decode("utf-8", errors="replace"))
        offset += length

    return ".".join(labels), (original_offset if jumped else offset)


def encode_txt_record(txt: dict[str, str]) -> bytes:
    chunks: list[bytes] = []
    for key, value in txt.items():
        entry = f"{key}={value}".encode("utf-8")
        if len(entry) > 255:
            raise ValueError(f"TXT entry too long: {key}")
        chunks.append(bytes([len(entry)]) + entry)
    return b"".join(chunks) or b"\x00"


def build_rr(name: str, rr_type: int, ttl: int, rdata: bytes, cache_flush: bool = False) -> bytes:
    rr_class = DNS_CLASS_IN | (0x8000 if cache_flush else 0)
    return (
        encode_dns_name(name)
        + struct.pack("!HHIH", rr_type, rr_class, ttl, len(rdata))
        + rdata
    )


def websocket_accept(key: str) -> str:
    magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    digest = hashlib.sha1((key + magic).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = sock.recv(length - len(chunks))
        if not chunk:
            raise ConnectionError("socket closed")
        chunks.extend(chunk)
    return bytes(chunks)


def parse_pem_certificates(pem_bytes: bytes) -> list[x509.Certificate]:
    pattern = re.compile(
        b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        re.DOTALL,
    )
    certs: list[x509.Certificate] = []
    for match in pattern.findall(pem_bytes):
        certs.append(x509.load_pem_x509_certificate(match))
    return certs


def format_certificate(cert: x509.Certificate) -> str:
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    return f"subject={subject}; issuer={issuer}"


def format_preview(data: bytes, limit: int = 32) -> str:
    preview = data[:limit].hex()
    if len(data) > limit:
        preview += "..."
    return preview


@dataclass
class WebSocketFrame:
    fin: bool
    opcode: int
    payload: bytes
    masked: bool
    rsv1: bool = False
    rsv2: bool = False
    rsv3: bool = False


@dataclass
class JsonEventLogger:
    path: Path
    lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def emit(self, event: dict[str, object]) -> None:
        record = {
            "ts": datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
            **event,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(record, separators=(",", ":"), sort_keys=True)
        with self.lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")


@dataclass
class OracleCase:
    pairingcode: str
    stbnonce: str
    device_name: str = "Living Room"
    bind_id: int = 1
    label: str | None = None


def load_oracle_cases(path: Path) -> list[OracleCase]:
    raw_text = path.read_text(encoding="utf-8")
    stripped = raw_text.strip()
    if not stripped:
        raise ValueError(f"Oracle case file is empty: {path}")

    if stripped.startswith("["):
        raw_cases = json.loads(stripped)
    else:
        raw_cases = [
            json.loads(line)
            for line in raw_text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]

    cases: list[OracleCase] = []
    for index, raw_case in enumerate(raw_cases, start=1):
        if not isinstance(raw_case, dict):
            raise ValueError(f"Oracle case #{index} is not an object")
        pairingcode = raw_case.get("pairingcode")
        stbnonce = raw_case.get("stbnonce")
        if not isinstance(pairingcode, str) or not isinstance(stbnonce, str):
            raise ValueError(f"Oracle case #{index} must include string pairingcode and stbnonce")
        bind_id = raw_case.get("bind_id", 1)
        if not isinstance(bind_id, int):
            raise ValueError(f"Oracle case #{index} bind_id must be an integer")
        label = raw_case.get("label")
        device_name = raw_case.get("device_name", "Living Room")
        if label is not None and not isinstance(label, str):
            raise ValueError(f"Oracle case #{index} label must be a string")
        if not isinstance(device_name, str):
            raise ValueError(f"Oracle case #{index} device_name must be a string")
        cases.append(
            OracleCase(
                pairingcode=pairingcode,
                stbnonce=stbnonce,
                device_name=device_name,
                bind_id=bind_id,
                label=label,
            )
        )

    if not cases:
        raise ValueError(f"No usable oracle cases found in {path}")
    return cases


def find_default_client_chain(script_path: Path) -> Path | None:
    candidate = (
        script_path.parent.parent
        / "assets"
        / "flutter_assets"
        / "packages"
        / "soft_remote_app"
        / "assets"
        / "certs"
        / "xfinity.xcal.tv-ComcastRDKD2DECCICA1-20241014-20241114.pem"
    )
    return candidate if candidate.exists() else None


def find_default_client_key(script_path: Path) -> Path | None:
    candidate = (
        script_path.parent.parent
        / "assets"
        / "flutter_assets"
        / "packages"
        / "soft_remote_app"
        / "assets"
        / "certs"
        / "soft_remote_key.pem"
    )
    return candidate if candidate.exists() else None


def detect_bind_ip() -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))
        return probe.getsockname()[0]
    finally:
        probe.close()


def generate_self_signed_cert(
    cert_path: Path,
    key_path: Path,
    dns_names: Iterable[str],
    ip_addresses: Iterable[str],
) -> None:
    key = ec.generate_private_key(ec.SECP256R1())

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fake Sky Remote Target"),
            x509.NameAttribute(NameOID.COMMON_NAME, "entos-streambox.localdomain"),
        ]
    )

    san_items: list[x509.GeneralName] = []
    for name in dns_names:
        san_items.append(x509.DNSName(name))
    for raw_ip in ip_addresses:
        san_items.append(x509.IPAddress(ipaddress.ip_address(raw_ip)))

    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san_items), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )


def extract_ca_bundle(source_pem: Path, output_pem: Path) -> bool:
    certs = parse_pem_certificates(source_pem.read_bytes())
    ca_certs: list[x509.Certificate] = []

    for cert in certs:
        try:
            constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            is_ca = constraints.ca
        except x509.ExtensionNotFound:
            is_ca = cert.subject == cert.issuer
        if is_ca:
            ca_certs.append(cert)

    if not ca_certs:
        return False

    output_pem.write_bytes(
        b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in ca_certs)
    )
    return True


@dataclass
class FakeRicsService:
    bind_ip: str
    port: int
    hostname: str = "entos-streambox.local"
    service_type: str = "_rdk-rics._tcp.local"
    device_id: str = "02:00:DE:AD:BE:EF"
    wol_mac: str = "02:00:de:ad:be:ef"
    wol_retry_interval_ms: int = 500
    wol_timeout_ms: int = 10000
    custom_instance_name: str | None = None
    instance_name: str = field(init=False)

    def __post_init__(self) -> None:
        if self.custom_instance_name:
            base_name = self.custom_instance_name.rstrip(".")
            if normalize_name(base_name).endswith(normalize_name(self.service_type)):
                self.instance_name = base_name
            else:
                self.instance_name = f"{base_name}.{self.service_type}"
            return

        suffix = self.device_id[-8:]
        self.instance_name = f"Living Room [{suffix}].{self.service_type}"

    @property
    def txt_records(self) -> dict[str, str]:
        return {
            "device_id": self.device_id,
            "wol_ip": self.bind_ip,
            "wol_mac": self.wol_mac,
            "wol_ri": str(self.wol_retry_interval_ms),
            "wol_to": str(self.wol_timeout_ms),
        }

    def build_records(self) -> dict[str, bytes]:
        ptr_services = build_rr(
            "_services._dns-sd._udp.local",
            DNS_TYPE_PTR,
            120,
            encode_dns_name(self.service_type),
        )
        ptr_service_type = build_rr(
            self.service_type,
            DNS_TYPE_PTR,
            120,
            encode_dns_name(self.instance_name),
        )
        srv_rdata = struct.pack("!HHH", 0, 0, self.port) + encode_dns_name(self.hostname)
        srv = build_rr(self.instance_name, DNS_TYPE_SRV, 120, srv_rdata, cache_flush=True)
        txt = build_rr(
            self.instance_name,
            DNS_TYPE_TXT,
            120,
            encode_txt_record(self.txt_records),
            cache_flush=True,
        )
        a = build_rr(
            self.hostname,
            DNS_TYPE_A,
            120,
            socket.inet_aton(self.bind_ip),
            cache_flush=True,
        )
        return {
            "meta": ptr_services,
            "ptr": ptr_service_type,
            "srv": srv,
            "txt": txt,
            "a": a,
        }


class MdnsResponder(threading.Thread):
    def __init__(self, service: FakeRicsService, stop_event: threading.Event) -> None:
        super().__init__(daemon=True)
        self.service = service
        self.stop_event = stop_event
        self.sock: socket.socket | None = None

    def run(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock = sock
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass

        sock.bind(("", MDNS_PORT))
        membership = socket.inet_aton(MDNS_GROUP) + socket.inet_aton(self.service.bind_ip)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(self.service.bind_ip))
        sock.settimeout(1.0)

        logging.info(
            "mDNS responder active for %s on %s:%s",
            self.service.instance_name,
            self.service.bind_ip,
            self.service.port,
        )

        self.send_announcement()
        next_announce = time.time() + 5

        while not self.stop_event.is_set():
            try:
                packet, addr = sock.recvfrom(9000)
            except socket.timeout:
                packet = None
            except OSError:
                break

            if packet:
                try:
                    self.handle_query(packet, addr)
                except Exception as exc:  # noqa: BLE001
                    logging.warning("mDNS query handling failed from %s: %s", addr, exc)

            if time.time() >= next_announce:
                self.send_announcement()
                next_announce = time.time() + 5

    def handle_query(self, packet: bytes, addr: tuple[str, int]) -> None:
        if len(packet) < 12:
            return

        query_id, flags, question_count, _, _, _ = struct.unpack("!HHHHHH", packet[:12])
        if flags & 0x8000:
            return

        offset = 12
        questions: list[tuple[str, int]] = []
        for _ in range(question_count):
            name, offset = parse_dns_name(packet, offset)
            qtype, _qclass = struct.unpack("!HH", packet[offset : offset + 4])
            offset += 4
            questions.append((normalize_name(name), qtype))

        interesting = False
        records = self.service.build_records()
        answer_parts: list[bytes] = []

        for qname, qtype in questions:
            if qname == normalize_name("_services._dns-sd._udp.local") and qtype in (DNS_TYPE_PTR, DNS_TYPE_ANY):
                answer_parts.extend([records["meta"]])
                interesting = True
            elif qname == normalize_name(self.service.service_type) and qtype in (DNS_TYPE_PTR, DNS_TYPE_ANY):
                answer_parts.extend([records["ptr"], records["srv"], records["txt"], records["a"]])
                interesting = True
            elif qname == normalize_name(self.service.instance_name) and qtype in (DNS_TYPE_SRV, DNS_TYPE_TXT, DNS_TYPE_ANY):
                answer_parts.extend([records["srv"], records["txt"], records["a"]])
                interesting = True
            elif qname == normalize_name(self.service.hostname) and qtype in (DNS_TYPE_A, DNS_TYPE_ANY):
                answer_parts.extend([records["a"]])
                interesting = True

        if not interesting:
            return

        response = (
            struct.pack("!HHHHHH", query_id, 0x8400, 0, len(answer_parts), 0, 0)
            + b"".join(answer_parts)
        )

        logging.info("mDNS query from %s for %s", addr, ", ".join(name for name, _ in questions))
        self.sock.sendto(response, (MDNS_GROUP, MDNS_PORT))

    def send_announcement(self) -> None:
        if not self.sock:
            return
        records = self.service.build_records()
        payload = struct.pack("!HHHHHH", 0, 0x8400, 0, 5, 0, 0) + b"".join(
            [records["meta"], records["ptr"], records["srv"], records["txt"], records["a"]]
        )
        self.sock.sendto(payload, (MDNS_GROUP, MDNS_PORT))
        logging.info(
            "mDNS announce: service=%s host=%s ip=%s port=%s",
            self.service.instance_name,
            self.service.hostname,
            self.service.bind_ip,
            self.service.port,
        )

    def stop(self) -> None:
        if self.sock:
            self.sock.close()


class TlsWebSocketProbe(threading.Thread):
    def __init__(
        self,
        service: FakeRicsService,
        ssl_context: ssl.SSLContext,
        stop_event: threading.Event,
        bridge_host: str | None = None,
        bridge_port: int = 8091,
        bridge_sni: str | None = None,
        bridge_client_context: ssl.SSLContext | None = None,
        json_logger: JsonEventLogger | None = None,
        oracle_pairingcode: str | None = None,
        oracle_stbnonce: str | None = None,
        oracle_device_name: str = "Living Room",
        oracle_bind_id: int = 1,
        oracle_cases: list[OracleCase] | None = None,
        oracle_close_after_bind: bool = False,
        oracle_repeat_count: int = 1,
        oracle_stop_after_binds: int | None = None,
    ) -> None:
        super().__init__(daemon=True)
        self.service = service
        self.ssl_context = ssl_context
        self.stop_event = stop_event
        self.bridge_host = bridge_host
        self.bridge_port = bridge_port
        self.bridge_sni = bridge_sni
        self.bridge_client_context = bridge_client_context
        self.json_logger = json_logger
        self.oracle_pairingcode = oracle_pairingcode
        self.oracle_stbnonce = oracle_stbnonce
        self.oracle_device_name = oracle_device_name
        self.oracle_bind_id = oracle_bind_id
        self.oracle_cases = oracle_cases or []
        self.oracle_close_after_bind = oracle_close_after_bind
        self.oracle_repeat_count = max(1, oracle_repeat_count)
        self.oracle_stop_after_binds = oracle_stop_after_binds
        self.connection_ids = itertools.count(1)
        self.oracle_case_ids = itertools.count(0)
        self.oracle_binds_captured = 0
        self.oracle_lock = threading.Lock()
        self.listener: socket.socket | None = None

    def next_oracle_case(self) -> OracleCase:
        if self.oracle_cases:
            index = next(self.oracle_case_ids)
            selected_index = min(index // self.oracle_repeat_count, len(self.oracle_cases) - 1)
            return self.oracle_cases[selected_index]
        return OracleCase(
            pairingcode=self.oracle_pairingcode or "",
            stbnonce=self.oracle_stbnonce or "",
            device_name=self.oracle_device_name,
            bind_id=self.oracle_bind_id,
        )

    def record_oracle_bind(self, connection_id: int, addr: tuple[str, int], payload_json: dict[str, object], oracle_case: OracleCase) -> None:
        with self.oracle_lock:
            self.oracle_binds_captured += 1
            bind_capture_count = self.oracle_binds_captured

        self.emit_json(
            {
                "event": "oracle_bind_request",
                "connection_id": connection_id,
                "client_addr": f"{addr[0]}:{addr[1]}",
                "label": oracle_case.label,
                "request": payload_json,
                "oracle_pairingcode": oracle_case.pairingcode,
                "oracle_stbnonce": oracle_case.stbnonce,
                "oracle_bind_capture_count": bind_capture_count,
            }
        )

        if self.oracle_stop_after_binds is not None and bind_capture_count >= self.oracle_stop_after_binds:
            logging.info(
                "[conn %s] Oracle stop-after reached: captured_binds=%s limit=%s",
                connection_id,
                bind_capture_count,
                self.oracle_stop_after_binds,
            )
            self.emit_json(
                {
                    "event": "oracle_stop_after_reached",
                    "connection_id": connection_id,
                    "client_addr": f"{addr[0]}:{addr[1]}",
                    "captured_binds": bind_capture_count,
                    "limit": self.oracle_stop_after_binds,
                }
            )
            self.stop_event.set()

    def run(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener = listener
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.service.bind_ip, self.service.port))
        listener.listen(20)
        listener.settimeout(1.0)
        logging.info("TLS/WebSocket listener active on %s:%s", self.service.bind_ip, self.service.port)

        while not self.stop_event.is_set():
            try:
                client, addr = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self.handle_client,
                args=(client, addr),
                daemon=True,
            ).start()

    def handle_client(self, client: socket.socket, addr: tuple[str, int]) -> None:
        connection_id = next(self.connection_ids)
        logging.info("[conn %s] TCP connect from %s", connection_id, addr)
        self.emit_json(
            {
                "event": "tcp_connect",
                "connection_id": connection_id,
                "client_addr": f"{addr[0]}:{addr[1]}",
            }
        )
        client.settimeout(5.0)
        try:
            tls_sock = self.ssl_context.wrap_socket(client, server_side=True)
        except ssl.SSLError as exc:
            logging.warning("[conn %s] TLS handshake failed from %s: %s", connection_id, addr, exc)
            self.emit_json(
                {
                    "event": "tls_handshake_failed",
                    "connection_id": connection_id,
                    "client_addr": f"{addr[0]}:{addr[1]}",
                    "error": str(exc),
                }
            )
            client.close()
            return
        except Exception as exc:  # noqa: BLE001
            logging.warning("[conn %s] TLS setup failed from %s: %s", connection_id, addr, exc)
            self.emit_json(
                {
                    "event": "tls_setup_failed",
                    "connection_id": connection_id,
                    "client_addr": f"{addr[0]}:{addr[1]}",
                    "error": str(exc),
                }
            )
            client.close()
            return

        try:
            logging.info(
                "[conn %s] TLS established from %s: version=%s cipher=%s alpn=%s sni=%s",
                connection_id,
                addr,
                tls_sock.version(),
                tls_sock.cipher(),
                tls_sock.selected_alpn_protocol(),
                getattr(tls_sock, "_copilot_sni", None),
            )
            self.emit_json(
                {
                    "event": "tls_established",
                    "connection_id": connection_id,
                    "client_addr": f"{addr[0]}:{addr[1]}",
                    "tls_version": tls_sock.version(),
                    "cipher": tls_sock.cipher()[0] if tls_sock.cipher() else None,
                    "alpn": tls_sock.selected_alpn_protocol(),
                    "sni": getattr(tls_sock, "_copilot_sni", None),
                }
            )

            peer = tls_sock.getpeercert(binary_form=True)
            if peer:
                peer_cert = x509.load_der_x509_certificate(peer)
                cert_summary = format_certificate(peer_cert)
                logging.info("[conn %s] Client certificate: %s", connection_id, cert_summary)
                self.emit_json(
                    {
                        "event": "client_certificate",
                        "connection_id": connection_id,
                        "client_addr": f"{addr[0]}:{addr[1]}",
                        "summary": cert_summary,
                    }
                )
            else:
                logging.info("[conn %s] Client did not present a certificate", connection_id)
                self.emit_json(
                    {
                        "event": "client_certificate",
                        "connection_id": connection_id,
                        "client_addr": f"{addr[0]}:{addr[1]}",
                        "summary": None,
                    }
                )

            request_bytes = self.read_http_request(tls_sock)
            if not request_bytes:
                logging.info("[conn %s] No HTTP/WebSocket request bytes received after TLS handshake", connection_id)
                return

            request_text = request_bytes.decode("iso-8859-1", errors="replace")
            logging.info("[conn %s] HTTP request from %s:\n%s", connection_id, addr, request_text.rstrip())
            request_line, headers = self.parse_http_request(request_text)
            self.emit_json(
                {
                    "event": "http_request",
                    "connection_id": connection_id,
                    "client_addr": f"{addr[0]}:{addr[1]}",
                    "request_line": request_line,
                    "headers": headers,
                }
            )

            upgrade = headers.get("upgrade", "").lower()
            ws_key = headers.get("sec-websocket-key")

            if upgrade == "websocket" and ws_key:
                upstream_tls: ssl.SSLSocket | None = None
                oracle_case: OracleCase | None = None
                if self.bridge_host:
                    upstream_tls = self.connect_upstream_websocket(connection_id, addr, request_line, headers)
                elif self.oracle_cases or (self.oracle_pairingcode is not None and self.oracle_stbnonce is not None):
                    oracle_case = self.next_oracle_case()
                    logging.info(
                        "[conn %s] Oracle case selected: label=%r pairingcode=%r stbnonce=%r bind_id=%s",
                        connection_id,
                        oracle_case.label,
                        oracle_case.pairingcode,
                        oracle_case.stbnonce,
                        oracle_case.bind_id,
                    )
                    self.emit_json(
                        {
                            "event": "oracle_case_selected",
                            "connection_id": connection_id,
                            "client_addr": f"{addr[0]}:{addr[1]}",
                            "label": oracle_case.label,
                            "pairingcode": oracle_case.pairingcode,
                            "stbnonce": oracle_case.stbnonce,
                            "device_name": oracle_case.device_name,
                            "bind_id": oracle_case.bind_id,
                        }
                    )
                response = (
                    "HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Accept: {websocket_accept(ws_key)}\r\n"
                    "\r\n"
                )
                tls_sock.sendall(response.encode("ascii"))
                logging.info("[conn %s] Sent WebSocket 101 Switching Protocols to %s for %s", connection_id, addr, request_line)
                self.emit_json(
                    {
                        "event": "http_response",
                        "connection_id": connection_id,
                        "client_addr": f"{addr[0]}:{addr[1]}",
                        "status_line": "HTTP/1.1 101 Switching Protocols",
                    }
                )
                if upstream_tls:
                    try:
                        self.bridge_websocket_frames(connection_id, tls_sock, upstream_tls, addr)
                    finally:
                        try:
                            upstream_tls.close()
                        except Exception:  # noqa: BLE001
                            pass
                elif self.oracle_cases or (self.oracle_pairingcode is not None and self.oracle_stbnonce is not None):
                    if oracle_case is None:
                        raise RuntimeError("Oracle case was not initialized")
                    self.run_pairing_oracle(connection_id, tls_sock, addr, oracle_case)
                else:
                    self.read_websocket_frames(connection_id, tls_sock, addr)
            else:
                body = b"fake-rics-server: TLS established, no WebSocket upgrade detected\n"
                response = (
                    "HTTP/1.1 400 Bad Request\r\n"
                    "Content-Type: text/plain\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                ).encode("ascii") + body
                tls_sock.sendall(response)
        except Exception as exc:  # noqa: BLE001
            logging.warning("[conn %s] Connection handling failed for %s: %s", connection_id, addr, exc)
            self.emit_json(
                {
                    "event": "connection_error",
                    "connection_id": connection_id,
                    "client_addr": f"{addr[0]}:{addr[1]}",
                    "error": str(exc),
                }
            )
        finally:
            try:
                tls_sock.close()
            except Exception:  # noqa: BLE001
                pass
            self.emit_json(
                {
                    "event": "connection_closed",
                    "connection_id": connection_id,
                    "client_addr": f"{addr[0]}:{addr[1]}",
                }
            )

    @staticmethod
    def read_http_request(tls_sock: ssl.SSLSocket) -> bytes:
        data = bytearray()
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = tls_sock.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

    @staticmethod
    def parse_http_request(request_text: str) -> tuple[str, dict[str, str]]:
        lines = request_text.split("\r\n")
        request_line = lines[0] if lines else ""
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
        return request_line, headers

    @staticmethod
    def read_websocket_frame(sock: socket.socket) -> WebSocketFrame | None:
        header = sock.recv(2)
        if not header:
            return None

        first, second = header
        fin = bool(first & 0x80)
        rsv1 = bool(first & 0x40)
        rsv2 = bool(first & 0x20)
        rsv3 = bool(first & 0x10)
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        payload_len = second & 0x7F

        if payload_len == 126:
            payload_len = struct.unpack("!H", recv_exact(sock, 2))[0]
        elif payload_len == 127:
            payload_len = struct.unpack("!Q", recv_exact(sock, 8))[0]

        mask_key = recv_exact(sock, 4) if masked else b""
        payload = recv_exact(sock, payload_len) if payload_len else b""
        if masked:
            payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

        return WebSocketFrame(
            fin=fin,
            opcode=opcode,
            payload=payload,
            masked=masked,
            rsv1=rsv1,
            rsv2=rsv2,
            rsv3=rsv3,
        )

    @staticmethod
    def send_websocket_frame(sock: socket.socket, frame: WebSocketFrame, masked: bool) -> None:
        first = (
            (0x80 if frame.fin else 0)
            | (0x40 if frame.rsv1 else 0)
            | (0x20 if frame.rsv2 else 0)
            | (0x10 if frame.rsv3 else 0)
            | frame.opcode
        )
        payload = frame.payload
        mask_bit = 0x80 if masked else 0

        if len(payload) < 126:
            header = bytes([first, mask_bit | len(payload)])
        elif len(payload) < 65536:
            header = bytes([first, mask_bit | 126]) + struct.pack("!H", len(payload))
        else:
            header = bytes([first, mask_bit | 127]) + struct.pack("!Q", len(payload))

        if masked:
            mask_key = os.urandom(4)
            payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
            sock.sendall(header + mask_key + payload)
            return

        sock.sendall(header + payload)

    @staticmethod
    def decode_frame_payload(frame: WebSocketFrame) -> tuple[str | None, object | None]:
        try:
            payload_text = frame.payload.decode("utf-8")
        except UnicodeDecodeError:
            return None, None

        payload_json = None
        if payload_text[:1] in ("{", "["):
            try:
                payload_json = json.loads(payload_text)
            except json.JSONDecodeError:
                payload_json = None
        return payload_text, payload_json

    def emit_json(self, event: dict[str, object]) -> None:
        if self.json_logger:
            self.json_logger.emit(event)

    def send_logged_frame(
        self,
        sock: socket.socket,
        frame: WebSocketFrame,
        *,
        connection_id: int,
        direction: str,
        addr: tuple[str, int] | str,
        prefix: str,
        masked: bool = False,
    ) -> None:
        self.send_websocket_frame(sock, frame, masked=masked)
        self.log_websocket_frame(prefix, connection_id, direction, addr, frame)

    def send_json_message(
        self,
        sock: socket.socket,
        payload: dict[str, object],
        *,
        connection_id: int,
        direction: str,
        addr: tuple[str, int] | str,
        prefix: str,
        masked: bool = False,
    ) -> None:
        frame = WebSocketFrame(
            fin=True,
            opcode=0x1,
            payload=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            masked=False,
        )
        self.send_logged_frame(
            sock,
            frame,
            connection_id=connection_id,
            direction=direction,
            addr=addr,
            prefix=prefix,
            masked=masked,
        )

    def log_websocket_frame(
        self,
        prefix: str,
        connection_id: int,
        direction: str,
        addr: tuple[str, int] | str,
        frame: WebSocketFrame,
    ) -> None:
        payload_text, payload_json = self.decode_frame_payload(frame)

        logging.info(
            "[conn %s] %s %s: fin=%s opcode=0x%x len=%s text=%r hex=%s",
            connection_id,
            prefix,
            addr,
            frame.fin,
            frame.opcode,
            len(frame.payload),
            (payload_text or "")[:500],
            frame.payload[:64].hex(),
        )
        self.emit_json(
            {
                "event": "websocket_frame",
                "connection_id": connection_id,
                "direction": direction,
                "peer": str(addr),
                "fin": frame.fin,
                "opcode": frame.opcode,
                "masked": frame.masked,
                "payload_length": len(frame.payload),
                "payload_text": payload_text,
                "payload_json": payload_json,
                "payload_base64": base64.b64encode(frame.payload).decode("ascii"),
            }
        )

    def read_websocket_frames(self, connection_id: int, tls_sock: ssl.SSLSocket, addr: tuple[str, int]) -> None:
        tls_sock.settimeout(10.0)
        while True:
            frame = self.read_websocket_frame(tls_sock)
            if frame is None:
                logging.info("[conn %s] WebSocket connection from %s closed", connection_id, addr)
                return
            self.log_websocket_frame("WebSocket frame from", connection_id, "client_to_server", addr, frame)

            if frame.opcode == 0x8:
                return
            if frame.opcode == 0x9:
                self.send_websocket_frame(
                    tls_sock,
                    WebSocketFrame(fin=True, opcode=0xA, payload=frame.payload, masked=False),
                    masked=False,
                )

    def run_pairing_oracle(
        self,
        connection_id: int,
        tls_sock: ssl.SSLSocket,
        addr: tuple[str, int],
        oracle_case: OracleCase,
    ) -> None:
        tls_sock.settimeout(10.0)
        next_bind_id = oracle_case.bind_id
        while True:
            frame = self.read_websocket_frame(tls_sock)
            if frame is None:
                logging.info("[conn %s] Pairing oracle connection from %s closed", connection_id, addr)
                return

            self.log_websocket_frame("Oracle frame client -> server", connection_id, "client_to_oracle", addr, frame)
            if frame.opcode == 0x8:
                return
            if frame.opcode == 0x9:
                self.send_logged_frame(
                    tls_sock,
                    WebSocketFrame(fin=True, opcode=0xA, payload=frame.payload, masked=False),
                    connection_id=connection_id,
                    direction="oracle_to_client",
                    addr=addr,
                    prefix="Oracle frame server -> client",
                    masked=False,
                )
                continue
            if frame.opcode != 0x1:
                continue

            payload_text, payload_json = self.decode_frame_payload(frame)
            if not isinstance(payload_json, dict):
                continue

            command_name = payload_json.get("command_name")
            tid = payload_json.get("tid")

            if command_name == "Pair Request":
                response: dict[str, object] = {
                    "command_name": "Pair Request",
                    "name": oracle_case.device_name,
                    "pairingcode": oracle_case.pairingcode,
                    "status": True,
                    "stbnonce": oracle_case.stbnonce,
                }
                if tid is not None:
                    response["tid"] = tid
                self.emit_json(
                    {
                        "event": "oracle_pair_request",
                        "connection_id": connection_id,
                        "client_addr": f"{addr[0]}:{addr[1]}",
                        "label": oracle_case.label,
                        "request": payload_json,
                        "response": response,
                    }
                )
                self.send_json_message(
                    tls_sock,
                    response,
                    connection_id=connection_id,
                    direction="oracle_to_client",
                    addr=addr,
                    prefix="Oracle frame server -> client",
                )
                continue

            if command_name == "Bind Request":
                self.record_oracle_bind(connection_id, addr, payload_json, oracle_case)
                response = {
                    "bind_id": next_bind_id,
                    "command_name": "Bind Request",
                    "status": True,
                }
                if tid is not None:
                    response["tid"] = tid
                self.send_json_message(
                    tls_sock,
                    response,
                    connection_id=connection_id,
                    direction="oracle_to_client",
                    addr=addr,
                    prefix="Oracle frame server -> client",
                )
                next_bind_id += 1
                if self.oracle_close_after_bind:
                    self.send_logged_frame(
                        tls_sock,
                        WebSocketFrame(fin=True, opcode=0x8, payload=b"", masked=False),
                        connection_id=connection_id,
                        direction="oracle_to_client",
                        addr=addr,
                        prefix="Oracle frame server -> client",
                        masked=False,
                    )
                    return
                continue

            if command_name == "Key Command Request":
                response = {
                    "command_name": "Key Command Request",
                    "status": True,
                }
                if tid is not None:
                    response["tid"] = tid
                self.send_json_message(
                    tls_sock,
                    response,
                    connection_id=connection_id,
                    direction="oracle_to_client",
                    addr=addr,
                    prefix="Oracle frame server -> client",
                )
                continue

    def connect_upstream_websocket(
        self,
        connection_id: int,
        addr: tuple[str, int],
        request_line: str,
        headers: dict[str, str],
    ) -> ssl.SSLSocket:
        if not self.bridge_host or not self.bridge_client_context:
            raise RuntimeError("Bridge mode is not configured")

        parts = request_line.split()
        path = parts[1] if len(parts) >= 2 else "/iptarget"
        upstream_name = self.bridge_sni or self.bridge_host
        raw_sock = socket.create_connection((self.bridge_host, self.bridge_port), timeout=10.0)
        raw_sock.settimeout(10.0)
        tls_sock = self.bridge_client_context.wrap_socket(raw_sock, server_hostname=upstream_name)
        logging.info(
            "[conn %s] Upstream TLS established for %s: host=%s:%s version=%s cipher=%s sni=%s",
            connection_id,
            addr,
            self.bridge_host,
            self.bridge_port,
            tls_sock.version(),
            tls_sock.cipher(),
            upstream_name,
        )
        self.emit_json(
            {
                "event": "upstream_tls_established",
                "connection_id": connection_id,
                "client_addr": f"{addr[0]}:{addr[1]}",
                "upstream_addr": f"{self.bridge_host}:{self.bridge_port}",
                "tls_version": tls_sock.version(),
                "cipher": tls_sock.cipher()[0] if tls_sock.cipher() else None,
                "sni": upstream_name,
            }
        )

        ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
        user_agent = headers.get("user-agent", "Dart/3.9 (dart:io)")
        host_header = f"{upstream_name}:{self.bridge_port}"
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"origin: https://{host_header}/\r\n"
            f"User-Agent: {user_agent}\r\n"
            "Connection: Upgrade\r\n"
            "Cache-Control: no-cache\r\n"
            "Accept-Encoding: gzip\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            "Upgrade: websocket\r\n"
            "\r\n"
        )
        tls_sock.sendall(request.encode("ascii"))
        logging.info(
            "[conn %s] Forwarded WebSocket upgrade for %s to upstream %s:%s",
            connection_id,
            addr,
            self.bridge_host,
            self.bridge_port,
        )
        self.emit_json(
            {
                "event": "upstream_http_request",
                "connection_id": connection_id,
                "client_addr": f"{addr[0]}:{addr[1]}",
                "request_line": f"GET {path} HTTP/1.1",
                "headers": {
                    "host": host_header,
                    "origin": f"https://{host_header}/",
                    "user-agent": user_agent,
                    "connection": "Upgrade",
                    "cache-control": "no-cache",
                    "accept-encoding": "gzip",
                    "sec-websocket-version": "13",
                    "sec-websocket-key": ws_key,
                    "upgrade": "websocket",
                },
            }
        )

        response_bytes = self.read_http_request(tls_sock)
        if not response_bytes:
            raise ConnectionError("No upstream HTTP response received")
        response_text = response_bytes.decode("iso-8859-1", errors="replace")
        logging.info("[conn %s] Upstream HTTP response for %s:\n%s", connection_id, addr, response_text.rstrip())
        status_line = response_text.split("\r\n", 1)[0]
        self.emit_json(
            {
                "event": "upstream_http_response",
                "connection_id": connection_id,
                "client_addr": f"{addr[0]}:{addr[1]}",
                "status_line": status_line,
                "raw": response_text.rstrip(),
            }
        )
        if " 101 " not in f" {status_line} " and not status_line.endswith(" 101"):
            raise ConnectionError(f"Upstream WebSocket upgrade failed: {status_line}")
        return tls_sock

    def bridge_websocket_frames(
        self,
        connection_id: int,
        client_tls: ssl.SSLSocket,
        upstream_tls: ssl.SSLSocket,
        addr: tuple[str, int],
    ) -> None:
        client_tls.settimeout(10.0)
        upstream_tls.settimeout(10.0)
        labels = (
            ("client -> upstream", client_tls, upstream_tls, True),
            ("upstream -> client", upstream_tls, client_tls, False),
        )

        def relay(label: str, source: socket.socket, target: socket.socket, target_masked: bool) -> None:
            direction = label.replace(" ", "_").replace("->", "to").replace("__", "_")
            while True:
                try:
                    frame = self.read_websocket_frame(source)
                except (ConnectionError, OSError, socket.timeout) as exc:
                    logging.info("[conn %s] Bridge relay %s ended: %s", connection_id, label, exc)
                    break

                if frame is None:
                    logging.info("[conn %s] Bridge relay %s closed", connection_id, label)
                    break

                self.log_websocket_frame(f"Bridge frame {label}", connection_id, direction, addr, frame)
                try:
                    self.send_websocket_frame(target, frame, masked=target_masked)
                except (ConnectionError, OSError, socket.timeout) as exc:
                    logging.info("[conn %s] Bridge relay %s send failed: %s", connection_id, label, exc)
                    break

                if frame.opcode == 0x8:
                    break

            for sock in (target, source):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        threads = [
            threading.Thread(target=relay, args=label_data, daemon=True)
            for label_data in labels
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    def stop(self) -> None:
        if self.listener:
            self.listener.close()


class TcpProxyServer(threading.Thread):
    def __init__(
        self,
        service: FakeRicsService,
        upstream_host: str,
        upstream_port: int,
        stop_event: threading.Event,
        preview_bytes: int = 32,
        burst_gap_ms: int = 300,
        max_chunk_logs: int = 8,
        capture_dir: Path | None = None,
    ) -> None:
        super().__init__(daemon=True)
        self.service = service
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.stop_event = stop_event
        self.preview_bytes = preview_bytes
        self.burst_gap_seconds = burst_gap_ms / 1000.0
        self.max_chunk_logs = max_chunk_logs
        self.capture_dir = capture_dir
        self.listener: socket.socket | None = None
        self.connection_ids = itertools.count(1)

    def run(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener = listener
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.service.bind_ip, self.service.port))
        listener.listen(20)
        listener.settimeout(1.0)
        logging.info(
            "TCP proxy listener active on %s:%s -> %s:%s",
            self.service.bind_ip,
            self.service.port,
            self.upstream_host,
            self.upstream_port,
        )

        while not self.stop_event.is_set():
            try:
                client, addr = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            threading.Thread(
                target=self.handle_client,
                args=(client, addr),
                daemon=True,
            ).start()

    def handle_client(self, client: socket.socket, addr: tuple[str, int]) -> None:
        connection_id = next(self.connection_ids)
        capture_client = None
        capture_upstream = None
        logging.info(
            "[conn %s] Proxy accepted %s -> forwarding to %s:%s",
            connection_id,
            addr,
            self.upstream_host,
            self.upstream_port,
        )
        try:
            upstream = socket.create_connection((self.upstream_host, self.upstream_port), timeout=10.0)
        except OSError as exc:
            logging.warning(
                "[conn %s] Proxy failed to connect upstream %s:%s for %s: %s",
                connection_id,
                self.upstream_host,
                self.upstream_port,
                addr,
                exc,
            )
            client.close()
            return

        client.settimeout(10.0)
        upstream.settimeout(10.0)

        if self.capture_dir:
            self.capture_dir.mkdir(parents=True, exist_ok=True)
            prefix = f"conn-{connection_id:04d}"
            capture_client_path = self.capture_dir / f"{prefix}-client_to_upstream.bin"
            capture_upstream_path = self.capture_dir / f"{prefix}-upstream_to_client.bin"
            metadata_path = self.capture_dir / f"{prefix}-meta.txt"
            metadata_path.write_text(
                "\n".join(
                    [
                        f"connection_id={connection_id}",
                        f"client_addr={addr[0]}:{addr[1]}",
                        f"listen_addr={self.service.bind_ip}:{self.service.port}",
                        f"upstream_addr={self.upstream_host}:{self.upstream_port}",
                        f"started_at={datetime.utcnow().isoformat()}Z",
                        f"client_to_upstream={capture_client_path.name}",
                        f"upstream_to_client={capture_upstream_path.name}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            capture_client = capture_client_path.open("wb")
            capture_upstream = capture_upstream_path.open("wb")
            logging.info(
                "[conn %s] Raw capture enabled: %s, %s",
                connection_id,
                capture_client_path,
                capture_upstream_path,
            )

        left = threading.Thread(
            target=self.relay,
            args=(client, upstream, connection_id, f"{addr[0]}:{addr[1]} -> upstream", capture_client),
            daemon=True,
        )
        right = threading.Thread(
            target=self.relay,
            args=(upstream, client, connection_id, f"upstream -> {addr[0]}:{addr[1]}", capture_upstream),
            daemon=True,
        )
        left.start()
        right.start()
        left.join()
        right.join()

        try:
            client.close()
        finally:
            upstream.close()
            if capture_client:
                capture_client.close()
            if capture_upstream:
                capture_upstream.close()
        logging.info("[conn %s] Proxy connection closed for %s", connection_id, addr)

    def relay(
        self,
        source: socket.socket,
        target: socket.socket,
        connection_id: int,
        label: str,
        capture_file,
    ) -> None:
        chunk_count = 0
        burst_count = 0
        total = 0
        burst_chunks = 0
        burst_bytes = 0
        burst_first_preview: str | None = None
        burst_started_at: float | None = None
        last_chunk_at: float | None = None
        suppressed_chunk_logs = False

        def flush_burst(reason: str) -> None:
            nonlocal burst_count, burst_chunks, burst_bytes, burst_first_preview, burst_started_at, last_chunk_at
            if burst_chunks == 0 or burst_started_at is None or last_chunk_at is None:
                return
            burst_count += 1
            duration_ms = max(0, int((last_chunk_at - burst_started_at) * 1000))
            logging.info(
                "[conn %s] burst %s #%s chunks=%s bytes=%s duration_ms=%s first_hex=%s reason=%s",
                connection_id,
                label,
                burst_count,
                burst_chunks,
                burst_bytes,
                duration_ms,
                burst_first_preview,
                reason,
            )
            burst_chunks = 0
            burst_bytes = 0
            burst_first_preview = None
            burst_started_at = None
            last_chunk_at = None

        while True:
            try:
                chunk = source.recv(8192)
            except (ConnectionError, OSError, socket.timeout):
                flush_burst("recv-error")
                break

            if not chunk:
                flush_burst("eof")
                break

            now = time.monotonic()
            if last_chunk_at is not None and now - last_chunk_at >= self.burst_gap_seconds:
                flush_burst("idle-gap")

            if burst_chunks == 0:
                burst_started_at = now
                burst_first_preview = format_preview(chunk, self.preview_bytes)

            chunk_count += 1
            burst_chunks += 1
            burst_bytes += len(chunk)
            last_chunk_at = now

            if chunk_count <= self.max_chunk_logs:
                logging.info(
                    "[conn %s] chunk %s %s len=%s hex=%s",
                    connection_id,
                    chunk_count,
                    label,
                    len(chunk),
                    format_preview(chunk, self.preview_bytes),
                )
            elif not suppressed_chunk_logs:
                logging.info(
                    "[conn %s] chunk logging suppressed for %s after %s chunks",
                    connection_id,
                    label,
                    self.max_chunk_logs,
                )
                suppressed_chunk_logs = True

            total += len(chunk)
            if capture_file:
                capture_file.write(chunk)
                capture_file.flush()
            try:
                target.sendall(chunk)
            except (ConnectionError, OSError, socket.timeout):
                flush_burst("send-error")
                break

        logging.info(
            "[conn %s] relay finished %s total_bytes=%s total_chunks=%s bursts=%s",
            connection_id,
            label,
            total,
            chunk_count,
            burst_count,
        )
        for sock in (target, source):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def stop(self) -> None:
        if self.listener:
            self.listener.close()


def build_ssl_context(
    cert_path: Path,
    key_path: Path,
    client_chain_path: Path | None,
) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(cert_path), str(key_path))
    context.set_alpn_protocols(["http/1.1"])

    if client_chain_path and client_chain_path.exists():
        with tempfile.NamedTemporaryFile("wb", delete=False, prefix="fake-rics-ca-", suffix=".pem") as tmp:
            tmp_path = Path(tmp.name)
        if extract_ca_bundle(client_chain_path, tmp_path):
            context.load_verify_locations(cafile=str(tmp_path))
            context.verify_mode = ssl.CERT_OPTIONAL
            logging.info("Client cert verification enabled with CA bundle from %s", client_chain_path)
        else:
            logging.warning("No CA certificates found in %s; client cert request disabled", client_chain_path)
            context.verify_mode = ssl.CERT_NONE
    else:
        context.verify_mode = ssl.CERT_NONE

    def servername_callback(sock: ssl.SSLSocket, server_name: str | None, _ctx: ssl.SSLContext) -> None:
        setattr(sock, "_copilot_sni", server_name)
        logging.info("TLS SNI from %s: %s", sock.getpeername(), server_name)

    context.set_servername_callback(servername_callback)
    return context


def build_client_ssl_context(
    client_chain_path: Path | None,
    client_key_path: Path | None,
) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["http/1.1"])

    if client_chain_path and client_key_path:
        context.load_cert_chain(str(client_chain_path), str(client_key_path))
        logging.info(
            "Upstream client certificate enabled with chain=%s key=%s",
            client_chain_path,
            client_key_path,
        )
    elif client_chain_path or client_key_path:
        raise ValueError("Both client chain and client key are required for bridge mode")

    return context


def parse_args() -> argparse.Namespace:
    script_path = Path(__file__).resolve()
    default_client_chain = find_default_client_chain(script_path)
    default_client_key = find_default_client_key(script_path)

    parser = argparse.ArgumentParser(
        description="Advertise a fake _rdk-rics._tcp target and log TLS/WebSocket handshakes.",
    )
    parser.add_argument("--bind-ip", default=None, help="LAN IPv4 address to advertise and bind.")
    parser.add_argument("--port", type=int, default=8091, help="TCP port for the fake box.")
    parser.add_argument("--hostname", default="entos-streambox.localdomain", help="mDNS hostname to advertise.")
    parser.add_argument(
        "--instance-name",
        default=None,
        help="Explicit mDNS instance name to advertise, without the service-type suffix.",
    )
    parser.add_argument(
        "--device-id",
        default="02:00:DE:AD:BE:EF",
        help="device_id TXT value and instance name suffix.",
    )
    parser.add_argument(
        "--wol-mac",
        default="02:00:de:ad:be:ef",
        help="wol_mac TXT value.",
    )
    parser.add_argument(
        "--cert-file",
        default=None,
        help="Server certificate PEM. If omitted, a self-signed cert is generated.",
    )
    parser.add_argument(
        "--key-file",
        default=None,
        help="Server private key PEM. If omitted, a self-signed key is generated.",
    )
    parser.add_argument(
        "--client-chain",
        default=str(default_client_chain) if default_client_chain else None,
        help="PEM containing the app's client cert chain; used to request/verify client certs.",
    )
    parser.add_argument(
        "--upstream-host",
        default=None,
        help="If set, run in transparent TCP proxy mode and forward connections to this host.",
    )
    parser.add_argument(
        "--upstream-port",
        type=int,
        default=8091,
        help="Upstream TCP port used with --upstream-host.",
    )
    parser.add_argument(
        "--bridge-host",
        default=None,
        help="In direct TLS/WebSocket mode, bridge plaintext WebSocket frames to this upstream box.",
    )
    parser.add_argument(
        "--bridge-port",
        type=int,
        default=8091,
        help="Upstream TLS/WebSocket port used with --bridge-host.",
    )
    parser.add_argument(
        "--bridge-sni",
        default=None,
        help="SNI/Host/Origin name to use when connecting to --bridge-host. Defaults to --hostname.",
    )
    parser.add_argument(
        "--client-key-file",
        default=str(default_client_key) if default_client_key else None,
        help="PEM private key used with --client-chain when connecting to --bridge-host.",
    )
    parser.add_argument(
        "--oracle-pairingcode",
        default=None,
        help="In direct TLS/WebSocket mode, respond locally to Pair Request with this pairingcode.",
    )
    parser.add_argument(
        "--oracle-stbnonce",
        default=None,
        help="In direct TLS/WebSocket mode, respond locally to Pair Request with this stbnonce.",
    )
    parser.add_argument(
        "--oracle-device-name",
        default="Living Room",
        help="Device name returned by the local pairing oracle response.",
    )
    parser.add_argument(
        "--oracle-bind-id",
        type=int,
        default=1,
        help="Starting bind_id returned by the local pairing oracle.",
    )
    parser.add_argument(
        "--oracle-cases-file",
        default=None,
        help="JSON/JSONL file of oracle cases served sequentially across new sessions.",
    )
    parser.add_argument(
        "--oracle-close-after-bind",
        action="store_true",
        help="In oracle mode, send a close frame immediately after the Bind Request response.",
    )
    parser.add_argument(
        "--oracle-repeat-count",
        type=int,
        default=1,
        help="When using --oracle-cases-file, serve each case for this many successive sessions before advancing.",
    )
    parser.add_argument(
        "--oracle-stop-after-binds",
        type=int,
        default=None,
        help="In oracle mode, stop the server after capturing this many Bind Request messages.",
    )
    parser.add_argument(
        "--preview-bytes",
        type=int,
        default=32,
        help="How many bytes of each logged chunk/burst preview to include in hex.",
    )
    parser.add_argument(
        "--burst-gap-ms",
        type=int,
        default=300,
        help="Idle gap in milliseconds used to split traffic into burst summaries.",
    )
    parser.add_argument(
        "--max-chunk-logs",
        type=int,
        default=8,
        help="Maximum per-direction chunk logs before suppressing detailed chunk output.",
    )
    parser.add_argument(
        "--capture-dir",
        default=None,
        help="If set in proxy mode, write raw per-connection binary captures into this directory.",
    )
    parser.add_argument(
        "--json-log-file",
        default=None,
        help="If set, append newline-delimited JSON events for direct TLS/WebSocket sessions to this file.",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")
    args = parser.parse_args()
    oracle_enabled = (
        args.oracle_pairingcode is not None
        or args.oracle_stbnonce is not None
        or args.oracle_cases_file is not None
    )
    if args.oracle_cases_file and (args.oracle_pairingcode is not None or args.oracle_stbnonce is not None):
        parser.error("--oracle-cases-file cannot be combined with --oracle-pairingcode/--oracle-stbnonce")
    if (
        args.oracle_cases_file is None
        and oracle_enabled
        and (args.oracle_pairingcode is None or args.oracle_stbnonce is None)
    ):
        parser.error("--oracle-pairingcode and --oracle-stbnonce must be supplied together")
    if oracle_enabled and args.upstream_host:
        parser.error("oracle mode cannot be combined with --upstream-host proxy mode")
    if oracle_enabled and args.bridge_host:
        parser.error("oracle mode cannot be combined with --bridge-host mode")
    if args.oracle_repeat_count < 1:
        parser.error("--oracle-repeat-count must be >= 1")
    if args.oracle_stop_after_binds is not None and args.oracle_stop_after_binds < 1:
        parser.error("--oracle-stop-after-binds must be >= 1")
    return args


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    bind_ip = args.bind_ip or detect_bind_ip()
    json_logger = JsonEventLogger(Path(args.json_log_file)) if args.json_log_file else None
    oracle_cases = load_oracle_cases(Path(args.oracle_cases_file)) if args.oracle_cases_file else []
    service = FakeRicsService(
        bind_ip=bind_ip,
        port=args.port,
        hostname=args.hostname,
        device_id=args.device_id,
        wol_mac=args.wol_mac,
        custom_instance_name=args.instance_name,
    )

    temp_dir_obj = None
    stop_event = threading.Event()
    mdns = MdnsResponder(service, stop_event)
    if args.upstream_host:
        listener = TcpProxyServer(
            service,
            args.upstream_host,
            args.upstream_port,
            stop_event,
            preview_bytes=args.preview_bytes,
            burst_gap_ms=args.burst_gap_ms,
            max_chunk_logs=args.max_chunk_logs,
            capture_dir=Path(args.capture_dir) if args.capture_dir else None,
        )
        logging.info(
            "Transparent proxy mode enabled: advertised %s:%s -> upstream %s:%s",
            service.bind_ip,
            service.port,
            args.upstream_host,
            args.upstream_port,
        )
    else:
        if args.cert_file and args.key_file:
            cert_path = Path(args.cert_file)
            key_path = Path(args.key_file)
        else:
            temp_dir_obj = tempfile.TemporaryDirectory(prefix="fake-rics-server-")
            temp_dir = Path(temp_dir_obj.name)
            cert_path = temp_dir / "server-cert.pem"
            key_path = temp_dir / "server-key.pem"
            generate_self_signed_cert(
                cert_path,
                key_path,
                dns_names=["entos-streambox.localdomain", args.hostname.rstrip(".")],
                ip_addresses=[bind_ip],
            )
            logging.info("Generated self-signed server cert at %s", cert_path)

        client_chain_path = Path(args.client_chain) if args.client_chain else None
        ssl_context = build_ssl_context(cert_path, key_path, client_chain_path)
        bridge_client_context = None
        if args.bridge_host:
            bridge_client_context = build_client_ssl_context(
                client_chain_path,
                Path(args.client_key_file) if args.client_key_file else None,
            )
            logging.info(
                "WebSocket bridge mode enabled: app TLS terminates locally; upstream=%s:%s sni=%s",
                args.bridge_host,
                args.bridge_port,
                args.bridge_sni or args.hostname.rstrip("."),
            )
        elif oracle_cases:
            logging.info(
                "Pairing oracle sweep enabled: cases=%s repeat_count=%s close_after_bind=%s stop_after_binds=%s source=%s",
                len(oracle_cases),
                args.oracle_repeat_count,
                args.oracle_close_after_bind,
                args.oracle_stop_after_binds,
                args.oracle_cases_file,
            )
        elif args.oracle_pairingcode is not None:
            logging.info(
                "Pairing oracle mode enabled: local responses pairingcode=%r stbnonce=%r device_name=%r bind_id_start=%s close_after_bind=%s stop_after_binds=%s",
                args.oracle_pairingcode,
                args.oracle_stbnonce,
                args.oracle_device_name,
                args.oracle_bind_id,
                args.oracle_close_after_bind,
                args.oracle_stop_after_binds,
            )
        listener = TlsWebSocketProbe(
            service,
            ssl_context,
            stop_event,
            bridge_host=args.bridge_host,
            bridge_port=args.bridge_port,
            bridge_sni=args.bridge_sni or args.hostname.rstrip("."),
            bridge_client_context=bridge_client_context,
            json_logger=json_logger,
            oracle_pairingcode=args.oracle_pairingcode,
            oracle_stbnonce=args.oracle_stbnonce,
            oracle_device_name=args.oracle_device_name,
            oracle_bind_id=args.oracle_bind_id,
            oracle_cases=oracle_cases,
            oracle_close_after_bind=args.oracle_close_after_bind,
            oracle_repeat_count=args.oracle_repeat_count,
            oracle_stop_after_binds=args.oracle_stop_after_binds,
        )

    mdns.start()
    listener.start()

    logging.info(
        "Fake RICS server ready. Service=%s host=%s bind=%s port=%s",
        service.instance_name,
        service.hostname,
        service.bind_ip,
        service.port,
    )

    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Stopping fake RICS server")
    finally:
        stop_event.set()
        mdns.stop()
        listener.stop()
        if temp_dir_obj is not None:
            temp_dir_obj.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
