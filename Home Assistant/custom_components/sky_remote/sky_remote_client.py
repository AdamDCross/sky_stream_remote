"""Sky Remote protocol client for Home Assistant.

Handles mTLS WebSocket connection, pairing, binding, auth token
derivation, key commands, and Wake-on-LAN.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import socket
import ssl
import struct
import tempfile
import uuid

from .const import (
    AUTH_SALT,
    DEFAULT_PORT,
)

_LOGGER = logging.getLogger(__name__)

# WebSocket opcodes
_OP_TEXT = 0x1
_OP_CLOSE = 0x8
_OP_PING = 0x9
_OP_PONG = 0xA

_CERT_PATTERN = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


class SkyRemoteError(Exception):
    """Base exception for Sky Remote errors."""


class SkyRemoteConnectionError(SkyRemoteError):
    """Connection failed."""


class SkyRemoteAuthError(SkyRemoteError):
    """Authentication (pair/bind) failed."""


def send_wol(mac_address: str) -> None:
    """Send a Wake-on-LAN magic packet."""
    mac = mac_address.replace(":", "").replace("-", "")
    if len(mac) != 12:
        raise ValueError(f"Invalid MAC address: {mac_address}")
    mac_bytes = bytes.fromhex(mac)
    magic = b"\xff" * 6 + mac_bytes * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(magic, ("255.255.255.255", 9))


async def is_box_reachable(
    host: str, port: int = DEFAULT_PORT, timeout: float = 1.5
) -> bool:
    """Quick TCP probe to check if the box is awake."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (OSError, asyncio.TimeoutError):
        return False


def _get_cert_paths() -> tuple[Path, Path]:
    """Locate the packaged client certificate chain and private key."""
    package_dir = Path(__file__).resolve().parent
    cert_dir = package_dir / "certs"

    cert_path: Path | None = None
    key_path: Path | None = None
    pem_files = sorted(cert_dir.glob("*.pem"))

    for pem_path in pem_files:
        pem_name = pem_path.name.lower()
        if key_path is None and "key" in pem_name:
            key_path = pem_path
        elif cert_path is None and "key" not in pem_name:
            cert_path = pem_path

        if cert_path is None or key_path is None:
            pem_text = pem_path.read_text(encoding="utf-8")
            if key_path is None and "PRIVATE KEY" in pem_text:
                key_path = pem_path
            elif cert_path is None and "BEGIN CERTIFICATE" in pem_text:
                cert_path = pem_path

        if cert_path is not None and key_path is not None:
            break

    if cert_path is not None and key_path is not None:
        return cert_path, key_path

    raise SkyRemoteError(
        f"Client certificate files not found in {cert_dir}"
    )


def _read_cert_chain_pem(cert_path: Path) -> str:
    """Read a certificate chain PEM file and keep certificate blocks only."""
    pem_blocks = _CERT_PATTERN.findall(cert_path.read_text(encoding="utf-8"))
    if not pem_blocks:
        raise SkyRemoteError("No certificate found for fingerprint")
    return "\n".join(pem_blocks) + "\n"


def _compute_cert_fingerprint(cert_chain_pem: str) -> str:
    """SHA-256 of the leaf client certificate DER."""
    pem_blocks = _CERT_PATTERN.findall(cert_chain_pem)
    if not pem_blocks:
        raise SkyRemoteError("No certificate found for fingerprint")
    leaf_der = base64.b64decode(
        pem_blocks[0]
        .replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .replace("\n", "")
    )
    return hashlib.sha256(leaf_der).hexdigest()


def compute_authtoken(
    cert_fingerprint: str,
    pairingcode: str,
    controllernonce: str,
    stbnonce: str,
) -> str:
    """Compute the auth token for a Bind Request.

    inner  = SHA256( hex_decode(cert_fingerprint) || pairingcode || controllernonce )
    token  = Base64( SHA256( stbnonce || inner || "biT43y" ) )
    """
    decoded_fp = bytes.fromhex(cert_fingerprint)
    stage1_input = (
        decoded_fp
        + pairingcode.encode("utf-8")
        + controllernonce.encode("utf-8")
    )
    stage1 = hashlib.sha256(stage1_input).digest()

    stage2_input = (
        stbnonce.encode("utf-8") + stage1 + AUTH_SALT
    )
    stage2 = hashlib.sha256(stage2_input).digest()

    return base64.b64encode(stage2).decode("utf-8")


def _create_ssl_context(cert_chain_pem: str, key_path: Path) -> ssl.SSLContext:
    """Create an SSL context with the packaged mTLS client certificate."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])

    with tempfile.NamedTemporaryFile(
        mode="w",
        prefix="skyremote_",
        suffix=".pem",
        delete=False,
        encoding="utf-8",
    ) as cert_file:
        cert_file.write(cert_chain_pem)
        cert_path = cert_file.name

    try:
        ctx.load_cert_chain(certfile=cert_path, keyfile=os.fspath(key_path))
    finally:
        os.unlink(cert_path)

    return ctx


# Pre-compute at module load — cert never changes
_CERT_PATH, _KEY_PATH = _get_cert_paths()
_CERT_CHAIN_PEM = _read_cert_chain_pem(_CERT_PATH)
_CERT_FINGERPRINT = _compute_cert_fingerprint(_CERT_CHAIN_PEM)
_SSL_CONTEXT = _create_ssl_context(_CERT_CHAIN_PEM, _KEY_PATH)


def _ws_mask(data: bytes, mask_key: bytes) -> bytes:
    """Apply WebSocket masking."""
    return bytes(b ^ mask_key[i % 4] for i, b in enumerate(data))


def _build_ws_frame(payload: bytes, opcode: int = _OP_TEXT) -> bytes:
    """Build a masked WebSocket frame (client → server must be masked)."""
    mask_key = os.urandom(4)
    header = bytes([0x80 | opcode])  # FIN + opcode
    length = len(payload)
    if length < 126:
        header += bytes([0x80 | length])  # MASK bit + length
    elif length < 65536:
        header += bytes([0x80 | 126]) + struct.pack("!H", length)
    else:
        header += bytes([0x80 | 127]) + struct.pack("!Q", length)
    return header + mask_key + _ws_mask(payload, mask_key)


async def _read_ws_frame(
    reader: asyncio.StreamReader,
) -> tuple[int, bytes]:
    """Read one WebSocket frame, return (opcode, payload)."""
    head = await reader.readexactly(2)
    opcode = head[0] & 0x0F
    masked = bool(head[1] & 0x80)
    length = head[1] & 0x7F

    if length == 126:
        length = struct.unpack("!H", await reader.readexactly(2))[0]
    elif length == 127:
        length = struct.unpack("!Q", await reader.readexactly(8))[0]

    if masked:
        mask_key = await reader.readexactly(4)
        raw = await reader.readexactly(length)
        payload = _ws_mask(raw, mask_key)
    else:
        payload = await reader.readexactly(length)

    return opcode, payload


class SkyRemoteClient:
    """Async client for the Sky STB RICS protocol."""

    def __init__(self, host: str, port: int = DEFAULT_PORT) -> None:
        self.host = host
        self.port = port
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self.tid: str = str(uuid.uuid4())
        self.controllernonce: str = str(uuid.uuid4())
        self.bind_id: int | None = None
        self.authtoken: str | None = None
        self.device_name: str | None = None
        self._ssl_ctx = _SSL_CONTEXT
        self._connected = False
        self._reader_task: asyncio.Task | None = None
        self._recv_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._request_lock = asyncio.Lock()

    @property
    def connected(self) -> bool:
        """Return True if the WebSocket is open and bound."""
        return (
            self._connected
            and self._writer is not None
            and self.bind_id is not None
        )

    async def connect(self) -> None:
        """Open mTLS WebSocket connection to the STB.

        Uses raw asyncio TLS with explicit server_hostname for correct SNI,
        then performs a manual WebSocket upgrade handshake.
        """
        try:
            # Raw TLS connection with SNI set to sky.xcal.tv
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.host,
                    self.port,
                    ssl=self._ssl_ctx,
                    server_hostname="sky.xcal.tv",
                ),
                timeout=10,
            )

            # WebSocket upgrade handshake
            ws_key = base64.b64encode(os.urandom(16)).decode()
            upgrade = (
                f"GET /iptarget HTTP/1.1\r\n"
                f"Host: sky.xcal.tv:{self.port}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"Origin: https://{self.host}:{self.port}/\r\n"
                f"User-Agent: Dart/3.9 (dart:io)\r\n"
                f"Cache-Control: no-cache\r\n"
                f"Accept-Encoding: gzip\r\n"
                f"\r\n"
            )
            self._writer.write(upgrade.encode())
            await self._writer.drain()

            # Read HTTP response (101 Switching Protocols)
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = await asyncio.wait_for(
                    self._reader.read(4096), timeout=10
                )
                if not chunk:
                    raise SkyRemoteConnectionError("Connection closed during handshake")
                response += chunk

            status_line = response.split(b"\r\n")[0].decode(errors="replace")
            if "101" not in status_line:
                raise SkyRemoteConnectionError(
                    f"WebSocket upgrade failed: {status_line}"
                )

            self._connected = True
            # Fresh queue so stale frames from a prior session can't leak in
            self._recv_queue = asyncio.Queue()
            self._reader_task = asyncio.create_task(self._read_loop())
            _LOGGER.debug("WebSocket connected to %s:%s", self.host, self.port)
        except SkyRemoteConnectionError:
            self._connected = False
            raise
        except Exception as err:
            self._connected = False
            raise SkyRemoteConnectionError(
                f"Failed to connect to {self.host}:{self.port}: {err}"
            ) from err

    async def _read_loop(self) -> None:
        """Continuously read frames while connected.

        Answers server keepalive pings even when no command is in
        flight, queues text frames for `_recv`, and flips the
        connected flag promptly when the link drops.
        """
        try:
            while True:
                opcode, payload = await _read_ws_frame(self._reader)
                if opcode == _OP_TEXT:
                    await self._recv_queue.put(payload)
                elif opcode == _OP_PING:
                    if self._writer:
                        self._writer.write(_build_ws_frame(payload, _OP_PONG))
                        await self._writer.drain()
                elif opcode == _OP_CLOSE:
                    _LOGGER.debug("WebSocket closed by server")
                    break
                # Other frame types (pong, continuation) are ignored
        except asyncio.CancelledError:
            raise
        except (asyncio.IncompleteReadError, ConnectionResetError, OSError) as err:
            _LOGGER.debug("Connection lost: %s", err)
        finally:
            self._connected = False

    async def disconnect(self) -> None:
        """Close the WebSocket connection."""
        self._connected = False
        self.bind_id = None
        self.authtoken = None
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None
        if self._writer:
            try:
                # Send WebSocket close frame
                self._writer.write(_build_ws_frame(b"", _OP_CLOSE))
                await self._writer.drain()
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            self._writer = None
            self._reader = None

    async def _send(self, msg: dict) -> None:
        if not self._writer or not self._connected:
            raise SkyRemoteConnectionError("Not connected")
        try:
            payload = json.dumps(msg).encode("utf-8")
            self._writer.write(_build_ws_frame(payload, _OP_TEXT))
            await self._writer.drain()
        except (ConnectionResetError, OSError, BrokenPipeError) as err:
            self._connected = False
            raise SkyRemoteConnectionError(f"Connection lost: {err}") from err

    async def _recv(self, timeout: float = 10.0) -> dict:
        if not self._connected:
            raise SkyRemoteConnectionError("Not connected")
        try:
            payload = await asyncio.wait_for(
                self._recv_queue.get(), timeout=timeout
            )
        except asyncio.TimeoutError as err:
            if not self._connected:
                raise SkyRemoteConnectionError("Connection lost") from err
            raise SkyRemoteConnectionError(
                "Timed out waiting for STB response"
            ) from err
        return json.loads(payload.decode("utf-8"))

    async def pair(self) -> dict:
        """Send Pair Request, return Pair Response."""
        self.tid = str(uuid.uuid4())
        self.controllernonce = str(uuid.uuid4())
        async with self._request_lock:
            await self._send({
                "command_name": "Pair Request",
                "tid": self.tid,
                "name": "Soft Remote",
                "manufacturer": "Comcast",
                "model": "IPRemote",
                "controllernonce": self.controllernonce,
            })
            resp = await self._recv()
        if not resp.get("status"):
            raise SkyRemoteAuthError(f"Pair failed: {resp}")
        self.device_name = resp.get("name", "Unknown")
        _LOGGER.debug("Paired with %s", self.device_name)
        return resp

    async def bind(self, pairingcode: str, stbnonce: str) -> dict:
        """Compute auth token and send Bind Request."""
        self.authtoken = compute_authtoken(
            cert_fingerprint=_CERT_FINGERPRINT,
            pairingcode=pairingcode,
            controllernonce=self.controllernonce,
            stbnonce=stbnonce,
        )
        async with self._request_lock:
            await self._send({
                "command_name": "Bind Request",
                "tid": self.tid,
                "authtoken": self.authtoken,
            })
            resp = await self._recv()
        if not resp.get("status"):
            raise SkyRemoteAuthError(f"Bind failed: {resp}")
        self.bind_id = resp.get("bind_id")
        _LOGGER.info("Bound to %s (bind_id=%s)", self.device_name, self.bind_id)
        return resp

    async def connect_and_bind(self) -> None:
        """Full connection sequence: connect → pair → bind."""
        await self.connect()
        pair_resp = await self.pair()
        pairingcode = pair_resp.get("pairingcode", "")
        stbnonce = pair_resp.get("stbnonce", "")
        await self.bind(pairingcode, stbnonce)

    async def send_key(self, key: str) -> dict:
        """Send a key command. Returns the STB response."""
        if not self.connected:
            raise SkyRemoteConnectionError("Not connected/bound")
        async with self._request_lock:
            await self._send({
                "command_name": "Key Command Request",
                "tid": self.tid,
                "authtoken": self.authtoken,
                "bind_id": self.bind_id,
                "cmd": "keyatomic",
                "key": key,
            })
            resp = await self._recv(timeout=5.0)
        if not resp.get("status"):
            _LOGGER.warning("Key %s rejected by STB: %s", key, resp)
        return resp
