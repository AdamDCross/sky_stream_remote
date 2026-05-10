#!/usr/bin/env python3
"""
Sky Remote — Independent LAN remote control client for Sky devices.

Discovers Sky STBs via mDNS, establishes mTLS WebSocket connection,
pairs, authenticates, and sends key commands with a curses-based TUI.

Protocol reverse-engineered from com.entos.monarch.remote.uk APK.
"""

import argparse
import asyncio
import base64
import curses
import hashlib
import json
import locale
import os
import pathlib
import socket
import ssl
import struct
import sys
import tempfile
import time
import uuid

locale.setlocale(locale.LC_ALL, "")

CACHE_DIR = pathlib.Path.home() / ".sky_remote"
DEVICE_CACHE = CACHE_DIR / "last_device.json"


def save_device_cache(host: str, port: int, mac: str, name: str):
    """Cache last successfully connected device details."""
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        DEVICE_CACHE.write_text(json.dumps({
            "host": host, "port": port, "mac": mac, "name": name,
        }))
    except OSError:
        pass


def load_device_cache():
    """Load cached device details, returns dict or None."""
    try:
        if DEVICE_CACHE.exists():
            return json.loads(DEVICE_CACHE.read_text())
    except (OSError, json.JSONDecodeError):
        pass
    return None

try:
    from zeroconf import ServiceBrowser, ServiceStateChange, Zeroconf
except ImportError:
    print("Missing dependency: pip install zeroconf")
    sys.exit(1)

try:
    import websockets
    import websockets.client
except ImportError:
    print("Missing dependency: pip install websockets")
    sys.exit(1)


# --------------------------------------------------
# Embedded certificates (from APK assets)
# --------------------------------------------------

CLIENT_KEY_PEM = """\
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIC6SaKhxcT/GDHtglEHWdhuczo5CN9aUPqcvBt06nTNqoAoGCCqGSM49
AwEHoUQDQgAEOTYzQwBDZtPe22jtWJfqPf4FPwevN/s4pSMSVPStJvqpnM5CFFzi
p8JGCNEvGnj/9rhRy7Pw2fTkAjjDOTHspA==
-----END EC PRIVATE KEY-----
"""

CLIENT_CERT_PEM = """\
-----BEGIN CERTIFICATE-----
MIICqzCCAlGgAwIBAgIUBpcPWUFHiLVOTsI1KdIWQiAHwKcwCgYIKoZIzj0EAwIw
JDEiMCAGA1UEAwwZQ29tY2FzdCBSREsgRDJEIEVDQyBJQ0EgMTAeFw0yNTA1MDI4
MTU1MDVaFw0yNjA1MjgxNzU1MDVaMIGfMTIwMAYKCZImiZPyLGQBAQwiMURKNHhT
M1J2OUQzVkpOdEpxN1FEcVVrenhzWGtacjNyeTEUMBIGA1UEAwwLc2t5LnhjYWwu
dHYxEDAOBgNVBAsMB1hmaW5pdHkxEDAOBgNVBAoMB0NvbWNhc3QxDjAMBgNVBAcM
BUVzc2V4MRIwEAYDVQQIDAlCcmVudHdvb2QxCzAJBgNVBAYTAkdCMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEOTYzQwBDZtPe22jtWJfqPf4FPwevN/s4pSMSVPSt
JvqpnM5CFFzip8JGCNEvGnj/9rhRy7Pw2fTkAjjDOTHspKOB5DCB4TA+BgNVHREE
NzA1gRppcGNvbnRyb2wtcmljc0ByZGsuc2VydmljZYEXc2t5LXNvZnRyZW1vdGVA
cmRrLnVzZXIwCwYDVR0PBAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAwGA1Ud
EwEB/wQCMAAwHwYDVR0jBBgwFoAUcE8ZliAdb1LD6xZrZrpo6oI4Q64wLwYIKwYB
BQUHAQEEIzAhMB8GCCsGAQUFBzABhhNodHRwOi8vb2NzcC54cGtpLmlvMB0GA1Ud
DgQWBBR1S6mo2MU0DG/Di7CBdbXw+vKtoTAKBggqhkjOPQQDAgNIADBFAiAG0zGM
btylRpcpcd3QexdI6B+PZ4pTmOVoFpUo4LVb0QIhAJGIPyF9DagqIYcUns8ZseRJ
wjP5FMrLKuNUQfELO2nv
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBsjCCAVegAwIBAgIUBzGYtexCSQ6tKXt7/gD6qKRCtk8wCgYIKoZIzj0EAwIw
IzEhMB8GA1UEAwwYQ29tY2FzdCBSREsgRDJEIEVDQyBSb290MCAXDTI0MDIyODE5
MjYwMVoYDzIwNTQwMjIwMTkxMzQxWjAkMSIwIAYDVQQDDBlDb21jYXN0IFJESyBE
MkQgRUNDIElDQSAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWbM/CXd9amo4
t5pmcJZGbhxuZP3e2EOTNu9j5nWuSlwz3bQ/cqYCJi23YFQFAntxqhcwCC3Vi4v0
ZMcXYtMULKNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBSG/d1b
GTbWy61CNEUbH76lmvZn1DAdBgNVHQ4EFgQUcE8ZliAdb1LD6xZrZrpo6oI4Q64w
DgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMCA0kAMEYCIQDzM8oTpL6AC5Gwd1d/
fb94ipyQgswBbffeHZTURsPw8gIhALGKUGBLCAtwdXLiqMCeTBesliac+yZR3b/D
J3MEo+oy
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBsDCCAVagAwIBAgIUMi5R+Ioo/aAFMjepe9XGPrUMtxowCgYIKoZIzj0EAwIw
IzEhMB8GA1UEAwwYQ29tY2FzdCBSREsgRDJEIEVDQyBSb290MCAXDTI0MDIyODE5
MTM0MloYDzIwNTQwMjIwMTkxMzQxWjAjMSEwHwYDVQQDDBhDb21jYXN0IFJESyBE
MkQgRUNDIFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQM6kHWOmISlcpU
TE+nxDShDp/QDmucVh0wWpHNFu/NDXRcPwNd6LPeShyM5TlBcUFzjgI7qsFqoDpW
eB0jKk8zo2YwZDASBgNVHRMBAf8ECDAGAQH/AgEBMB8GA1UdIwQYMBaAFIb93VsZ
NtbLrUI0RRsfvqWa9mfUMB0GA1UdDgQWBBSG/d1bGTbWy61CNEUbH76lmvZn1DAO
BgNVHQ8BAf8EBAMCAYYwCgYIKoZIzj0EAwIDSAAwRQIgUTTH19CiP120ax8p3dYO
IPbVsSWOfz01ZKit6T0TXncCIQDm9btfvUhVRyhHEScynV1v95q4podgkTTVJawo
GrD1ZA==
-----END CERTIFICATE-----
"""

AUTH_SALT = "biT43y"

MDNS_SERVICE_TYPE = "_rdk-rics._tcp.local."


# --------------------------------------------------
# Wake-on-LAN
# --------------------------------------------------

def send_wol(mac_address: str):
    """Send a Wake-on-LAN magic packet."""
    mac = mac_address.replace(":", "").replace("-", "")
    if len(mac) != 12:
        return
    mac_bytes = bytes.fromhex(mac)
    magic = b"\xff" * 6 + mac_bytes * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(magic, ("255.255.255.255", 9))


def is_box_reachable(host: str, port: int = 8091, timeout: float = 1.5) -> bool:
    """Quick TCP probe to check if the box is awake."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


# --------------------------------------------------
# mDNS discovery
# --------------------------------------------------

class SkyDeviceInfo:
    def __init__(self, name: str, host: str, port: int, addresses: list,
                 properties: dict = None):
        self.name = name
        self.host = host
        self.port = port
        self.addresses = addresses
        self.properties = properties or {}
        self.mac = self.properties.get("wol_mac") \
            or self.properties.get("wowl_mac") \
            or self.properties.get("device_id")

    def __str__(self):
        addr = self.addresses[0] if self.addresses else self.host
        return f"{self.name} @ {addr}:{self.port}"


def discover_devices(timeout: float = 5.0) -> list:
    """Discover Sky devices on the LAN via mDNS."""
    devices = []

    class Listener:
        def remove_service(self, zc, type_, name):
            pass

        def update_service(self, zc, type_, name):
            pass

        def add_service(self, zc, type_, name):
            try:
                info = zc.get_service_info(type_, name)
            except Exception:
                info = None
            if info:
                props = {}
                if info.properties:
                    for k, v in info.properties.items():
                        key = k.decode("utf-8", errors="replace") if isinstance(k, bytes) else str(k)
                        val = v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)
                        props[key] = val

                addresses = [socket.inet_ntoa(addr) for addr in info.addresses]
                dev = SkyDeviceInfo(
                    name=info.name,
                    host=info.server,
                    port=info.port,
                    addresses=addresses,
                    properties=props,
                )
                devices.append(dev)

    zc = Zeroconf()
    listener = Listener()
    browser = ServiceBrowser(zc, MDNS_SERVICE_TYPE, listener)

    # Poll with early exit — return as soon as a device is found
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if devices:
            break
        time.sleep(0.2)

    zc.close()
    return devices


# --------------------------------------------------
# Auth token derivation (CONFIRMED)
# --------------------------------------------------

def compute_authtoken(cert_fingerprint: str, pairingcode: str,
                      controllernonce: str, stbnonce: str) -> str:
    """
    Compute the auth token for a Bind Request.

    cert_fingerprint = SHA256(client_certificate_DER) as 64 hex chars
    controllernonce  = UUID string sent in the Pair Request

    inner  = SHA256( hex_decode(cert_fingerprint) || pairingcode || controllernonce )
    token  = Base64( SHA256( stbnonce || inner || "biT43y" ) )
    """
    decoded_fp = bytes.fromhex(cert_fingerprint)
    stage1_input = decoded_fp + pairingcode.encode("utf-8") + controllernonce.encode("utf-8")
    stage1 = hashlib.sha256(stage1_input).digest()

    stage2_input = stbnonce.encode("utf-8") + stage1 + AUTH_SALT.encode("utf-8")
    stage2 = hashlib.sha256(stage2_input).digest()

    return base64.b64encode(stage2).decode("utf-8")


# --------------------------------------------------
# TLS / SSL context
# --------------------------------------------------

def create_ssl_context() -> ssl.SSLContext:
    """Create an SSL context with the mTLS client certificate.
    
    Prefers disk files (alongside the APK) if present; falls back to
    the embedded PEM constants.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])

    # Try loading from disk files next to the APK root
    apk_root = pathlib.Path(__file__).resolve().parent.parent
    disk_key = apk_root / "soft_remote_key.pem"
    disk_cert = apk_root / "xfinity.xcal.tv-ComcastRDKD2DECCICA1-20241014-20241114.pem"

    if disk_key.exists() and disk_cert.exists():
        import re
        # Disk cert file may have text headers; extract PEM blocks only
        raw = disk_cert.read_text()
        pem_blocks = re.findall(
            r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
            raw, re.DOTALL,
        )
        cert_pem = "\n".join(pem_blocks) + "\n"
        key_pem = disk_key.read_text()
    else:
        cert_pem = CLIENT_CERT_PEM
        key_pem = CLIENT_KEY_PEM

    tmpdir = tempfile.mkdtemp(prefix="skyremote_")
    cert_path = os.path.join(tmpdir, "client.pem")
    key_path = os.path.join(tmpdir, "client.key")

    with open(cert_path, "w") as f:
        f.write(cert_pem)
    with open(key_path, "w") as f:
        f.write(key_pem)

    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx


# --------------------------------------------------
# Protocol client
# --------------------------------------------------

class SkyRemoteClient:
    def __init__(self, host: str, port: int = 8091):
        self.host = host
        self.port = port
        self.ws = None
        self.tid = str(uuid.uuid4())
        self.controllernonce = str(uuid.uuid4())  # UUID sent on wire
        self.bind_id = None
        self.authtoken = None
        self.device_name = None
        self._ssl_ctx = create_ssl_context()
        self._cert_fingerprint = self._compute_cert_fingerprint()

    async def connect(self):
        uri = f"wss://{self.host}:{self.port}/iptarget"
        extra_headers = {
            "Cache-Control": "no-cache",
            "Accept-Encoding": "gzip",
        }
        self._ssl_ctx.check_hostname = False
        self.ws = await websockets.client.connect(
            uri,
            ssl=self._ssl_ctx,
            server_hostname="sky.xcal.tv",
            origin=f"https://{self.host}:{self.port}/",
            user_agent_header="Dart/3.9 (dart:io)",
            extra_headers=extra_headers,
            compression=None,
            open_timeout=10,
            ping_interval=20,
            ping_timeout=20,
        )

    def _compute_cert_fingerprint(self) -> str:
        """SHA-256 of the leaf client certificate DER — used in auth token."""
        import re as _re
        apk_root = pathlib.Path(__file__).resolve().parent.parent
        disk_cert = apk_root / "xfinity.xcal.tv-ComcastRDKD2DECCICA1-20241014-20241114.pem"
        if disk_cert.exists():
            raw = disk_cert.read_text()
        else:
            raw = CLIENT_CERT_PEM
        pem_blocks = _re.findall(
            r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
            raw, _re.DOTALL,
        )
        if not pem_blocks:
            raise RuntimeError("No certificate found for fingerprint")
        leaf_der = base64.b64decode(pem_blocks[0].replace("\n", ""))
        return hashlib.sha256(leaf_der).hexdigest()

    async def close(self):
        if self.ws:
            await self.ws.close()

    async def _send(self, msg: dict):
        await self.ws.send(json.dumps(msg))

    async def _recv(self, timeout: float = 10.0) -> dict:
        raw = await asyncio.wait_for(self.ws.recv(), timeout=timeout)
        return json.loads(raw)

    async def pair(self) -> dict:
        """Send Pair Request, return Pair Response."""
        await self._send({
            "command_name": "Pair Request",
            "tid": self.tid,
            "name": "Soft Remote",
            "manufacturer": "Comcast",
            "model": "IPRemote",
            "controllernonce": self.controllernonce,
        })
        resp = await self._recv()
        if resp.get("status"):
            self.device_name = resp.get("name", "Unknown")
        return resp

    async def bind(self, pairingcode: str, stbnonce: str) -> dict:
        """Compute auth token and send Bind Request."""
        # local+0x13 = SHA256(client_cert_DER) — both sides know the cert
        # local+0xb  = controllernonce UUID — sent in Pair Request
        self.authtoken = compute_authtoken(
            cert_fingerprint=self._cert_fingerprint,
            pairingcode=pairingcode,
            controllernonce=self.controllernonce,
            stbnonce=stbnonce,
        )
        await self._send({
            "command_name": "Bind Request",
            "tid": self.tid,
            "authtoken": self.authtoken,
        })
        resp = await self._recv()
        if resp.get("status"):
            self.bind_id = resp.get("bind_id")
        return resp

    async def send_key(self, key: str) -> dict:
        """Send a key command."""
        if self.bind_id is None:
            raise RuntimeError("Not bound — pair and bind first")
        await self._send({
            "command_name": "Key Command Request",
            "tid": self.tid,
            "authtoken": self.authtoken,
            "bind_id": self.bind_id,
            "cmd": "keyatomic",
            "key": key,
        })
        resp = await self._recv(timeout=5.0)
        return resp


# --------------------------------------------------
# Terminal UI
# --------------------------------------------------

# Verified working key names (tested against real Sky STB)
# Source: App enum (VAa Dart enum) + brute-tested box extras
VERIFIED_KEYS = [
    # App enum keys (24 keys from VAa Dart enum in APK)
    "Power", "Home", "Enter", "Dismiss", "AccessMenu", "Option",
    "Search", "Settings", "MediaPlay", "Plus",
    "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight",
    "Digit0", "Digit1", "Digit2", "Digit3", "Digit4",
    "Digit5", "Digit6", "Digit7", "Digit8", "Digit9",
    # Box extras (15 keys accepted by STB but not in app enum)
    "Backspace", "Info", "Source",
    "ChannelUp", "ChannelDown",
    "VolumeUp", "VolumeDown", "VolumeMute",
    "MediaRecord", "MediaRewind", "MediaFastForward",
    "Red", "Green", "Yellow", "Blue",
]

# Keyboard → remote key mapping for TUI
KEYMAP = {}


def build_keymap():
    """Build keyboard-to-remote-key mapping."""
    KEYMAP[curses.KEY_UP] = "ArrowUp"
    KEYMAP[curses.KEY_DOWN] = "ArrowDown"
    KEYMAP[curses.KEY_LEFT] = "ArrowLeft"
    KEYMAP[curses.KEY_RIGHT] = "ArrowRight"
    KEYMAP[curses.KEY_ENTER] = "Enter"
    KEYMAP[10] = "Enter"         # Enter
    KEYMAP[13] = "Enter"         # CR
    KEYMAP[27] = "Dismiss"       # Escape → Back/Dismiss
    KEYMAP[curses.KEY_BACKSPACE] = "Backspace"
    KEYMAP[127] = "Backspace"    # Backspace (macOS)
    KEYMAP[ord("h")] = "Home"
    KEYMAP[ord("H")] = "Home"
    KEYMAP[ord("m")] = "AccessMenu"
    KEYMAP[ord("M")] = "AccessMenu"
    KEYMAP[ord("i")] = "Info"
    KEYMAP[ord("I")] = "Info"
    KEYMAP[ord("o")] = "Option"
    KEYMAP[ord("O")] = "Option"
    KEYMAP[ord("s")] = "Settings"
    KEYMAP[ord("S")] = "Search"
    KEYMAP[ord("p")] = "Power"
    KEYMAP[ord("P")] = "Power"
    # 'w'/'W' handled specially as smart wake (WoL + Power if needed)
    KEYMAP[ord(" ")] = "MediaPlay"      # Space = Play (no PlayPause on box)
    KEYMAP[ord("r")] = "MediaRecord"
    KEYMAP[ord("R")] = "MediaRecord"
    KEYMAP[ord("x")] = "MediaRewind"
    KEYMAP[ord("X")] = "MediaFastForward"
    KEYMAP[ord("+")] = "ChannelUp"
    KEYMAP[ord("=")] = "ChannelUp"
    KEYMAP[ord("-")] = "ChannelDown"
    KEYMAP[ord(".")] = "VolumeUp"
    KEYMAP[ord(",")] = "VolumeDown"
    KEYMAP[ord("/")] = "VolumeMute"
    KEYMAP[curses.KEY_PPAGE] = "ChannelUp"
    KEYMAP[curses.KEY_NPAGE] = "ChannelDown"
    # Digit keys
    for d in range(10):
        KEYMAP[ord(str(d))] = f"Digit{d}"
    # Function/colour keys
    KEYMAP[curses.KEY_F1] = "Red"
    KEYMAP[curses.KEY_F2] = "Green"
    KEYMAP[curses.KEY_F3] = "Yellow"
    KEYMAP[curses.KEY_F4] = "Blue"
    # Source / Plus (Sky+)
    KEYMAP[ord("e")] = "Source"
    KEYMAP[ord("l")] = "Plus"
    KEYMAP[ord("L")] = "Plus"


STATUS_LINE = ""
LAST_KEY = ""
MSG_LOG = []  # Rolling log of all received WS messages
MAX_LOG_LINES = 10


def draw_remote(stdscr, device_name: str, connected: bool):
    """Draw the remote control TUI layout."""
    import curses.textpad
    stdscr.clear()
    h, w = stdscr.getmaxyx()

    def cprint(y, x, text, attr=0):
        if 0 <= y < h and 0 <= x < w:
            try:
                stdscr.addnstr(y, x, text, w - x, attr)
            except curses.error:
                pass

    def hline(y, x, length):
        """Draw a horizontal line using ACS characters."""
        if 0 <= y < h and 0 <= x < w:
            try:
                stdscr.hline(y, x, curses.ACS_HLINE, min(length, w - x))
            except curses.error:
                pass

    def box(uly, ulx, lry, lrx):
        """Draw a box using curses.textpad.rectangle (ACS native chars)."""
        try:
            curses.textpad.rectangle(stdscr, uly, ulx, lry, lrx)
        except curses.error:
            pass

    def hdiv(y, x1, x2):
        """Draw a horizontal divider with T-junctions at edges."""
        if 0 <= y < h:
            try:
                stdscr.addch(y, x1, curses.ACS_LTEE)
                stdscr.hline(y, x1 + 1, curses.ACS_HLINE, x2 - x1 - 1)
                stdscr.addch(y, x2, curses.ACS_RTEE)
            except curses.error:
                pass

    # Title box
    box(0, 2, 2, 36)
    cprint(1, 12, "SKY REMOTE CONTROL", curses.A_BOLD)

    status = "* CONNECTED" if connected else "  DISCONNECTED"
    attr = curses.color_pair(1) if connected else curses.color_pair(2)
    cprint(3, 4, f"Device: {device_name}  {status}", attr)

    # Main remote box
    L, R = 4, 35  # left and right edges
    box(5, L, 24, R)

    # Section labels inside the box
    cprint(6,  L+2, "[p] Power         [h] Home")
    cprint(7,  L+2, "[s] Settings      [m] Menu")
    cprint(8,  L+2, "[i] Info          [o] Opt")

    hdiv(9, L, R)

    cprint(10, L+2, "            [Up]")
    cprint(11, L+2, "      [Lt] [Enter] [Rt]")
    cprint(12, L+2, "            [Dn]")

    hdiv(13, L, R)

    cprint(14, L+2, "[Esc] Back      [i] Info")
    cprint(15, L+2, "[o] Option      [s] Settings")

    hdiv(16, L, R)

    cprint(17, L+2, "[+/-] Ch Up/Dn  [,/.] Vol")
    cprint(18, L+2, "[/] Mute   [Space] Play")
    cprint(19, L+2, "[r] Record [x/X] Rew/FF")
    cprint(20, L+2, "[0-9] Digits  [S] Search")
    cprint(21, L+2, "[e] Source   [l] Sky+")
    cprint(22, L+2, "[F1]", curses.color_pair(2))
    cprint(22, L+6, "R ", 0)
    cprint(22, L+8, "[F2]", curses.color_pair(1))
    cprint(22, L+12, "G ", 0)
    cprint(22, L+14, "[F3]", curses.color_pair(3))
    cprint(22, L+18, "Y ", 0)
    cprint(22, L+20, "[F4]", curses.color_pair(4))
    cprint(22, L+24, "B", 0)
    cprint(23, L+2, "[q] Quit")

    # Status area
    y = 26
    cprint(y, 4, f"Last: {LAST_KEY}", curses.A_DIM)
    y += 1
    cprint(y, 4, f"{STATUS_LINE}", curses.A_DIM)

    # Message log
    y += 2
    hline(y, 4, 31)
    cprint(y, 10, " Received Messages ", curses.A_BOLD)
    y += 1
    for msg in MSG_LOG[-min(MAX_LOG_LINES, max(h - y - 1, 1)):]:
        cprint(y, 4, msg, curses.A_DIM)
        y += 1
        if y >= h - 1:
            break
        if y >= h - 1:
            break

    stdscr.refresh()


async def tui_main(stdscr, client: SkyRemoteClient):
    """Main TUI event loop."""
    global STATUS_LINE, LAST_KEY, MSG_LOG

    curses.curs_set(0)
    curses.set_escdelay(50)  # Faster ESC key detection (default 1000ms)
    stdscr.nodelay(True)
    stdscr.timeout(100)

    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_GREEN, -1)
    curses.init_pair(2, curses.COLOR_RED, -1)
    curses.init_pair(3, curses.COLOR_YELLOW, -1)
    curses.init_pair(4, curses.COLOR_BLUE, -1)
    curses.init_pair(5, curses.COLOR_CYAN, -1)

    build_keymap()

    connected = client.bind_id is not None
    device_name = client.device_name or "Unknown"

    # Background task to listen for unsolicited messages
    incoming = asyncio.Queue()

    async def ws_listener():
        try:
            while True:
                raw = await client.ws.recv()
                await incoming.put(raw)
        except Exception:
            pass

    listener_task = asyncio.create_task(ws_listener())

    while True:
        # Drain any incoming messages
        while not incoming.empty():
            try:
                raw = incoming.get_nowait()
                ts = time.strftime("%H:%M:%S")
                MSG_LOG.append(f"[{ts}] {raw}")
            except asyncio.QueueEmpty:
                break

        draw_remote(stdscr, device_name, connected)

        try:
            key = stdscr.getch()
        except curses.error:
            key = -1

        if key == -1:
            await asyncio.sleep(0.05)
            continue

        if key == ord("q") or key == ord("Q"):
            break

        remote_key = KEYMAP.get(key)
        if remote_key:
            LAST_KEY = remote_key
            try:
                await client._send({
                    "command_name": "Key Command Request",
                    "tid": client.tid,
                    "authtoken": client.authtoken,
                    "bind_id": client.bind_id,
                    "cmd": "keyatomic",
                    "key": remote_key,
                })
                STATUS_LINE = f"→ {remote_key} sent"
            except Exception as e:
                STATUS_LINE = f"✗ Error: {e}"
                connected = False
        else:
            STATUS_LINE = f"Unmapped key: {key}"

    listener_task.cancel()
    try:
        await listener_task
    except asyncio.CancelledError:
        pass


# --------------------------------------------------
# Main flow
# --------------------------------------------------

def format_pairing_code(code: str) -> str:
    """Format a raw digit string into the protocol's space-padded format.
    
    The app formats the pairing code as space-separated digits with
    leading spaces to fill 20 characters total.
    E.g. "8008800088" -> "               8 0 0 8 8 0 0 0 8 8"
    Wait — looking at the capture: " 8 0 0 8 8 0 0 0 8 8" is 20 chars.
    Pattern: each digit preceded by a space, total = 2*N chars with leading
    spaces to pad to 20.
    """
    # Convert each digit to " D" format, then left-pad to 20 chars
    spaced = " ".join(code.strip())
    return spaced.rjust(20)


async def run(args, device=None):
    if args.host:
        # Banner not yet printed for --host mode
        print("+==================================+")
        print("|       SKY REMOTE CONTROL         |")
        print("+==================================+")
        print()

    # -- Step 1: Discovery --
    if device:
        if not args.host:
            print()  # spacing after discovery output
    elif args.host:
        host = args.host
        port = args.port or 8091
        print(f"Using specified device: {host}:{port}")
        device = SkyDeviceInfo("Manual", host, port, [host])
    else:
        print("❌ No device provided. Use --host to specify manually.")
        return

    host = device.addresses[0] if device.addresses else device.host
    port = device.port

    # -- Step 1b: Smart Wake --
    mac = device.mac or args.mac
    if not mac:
        cached = load_device_cache()
        if cached and cached.get("host") == host:
            mac = cached.get("mac")
    woke_via_wol = False
    if mac:
        reachable = is_box_reachable(host, port)
        if reachable:
            print(f"✓ Box is already awake at {host}:{port}")
        else:
            print(f"📡 Box unreachable — sending Wake-on-LAN to {mac}...")
            send_wol(mac)
            woke_via_wol = True
            # Wait for the box to boot, polling until reachable
            print("⏳ Waiting for box to come online...", end="", flush=True)
            for i in range(15):
                time.sleep(2)
                print(".", end="", flush=True)
                if is_box_reachable(host, port):
                    print(f" ready! ({(i+1)*2}s)")
                    break
            else:
                print()
                print("⚠️  Box didn't respond after 30s — trying to connect anyway...")

    # -- Step 2: Connect --
    print(f"🔌 Connecting to {host}:{port}...")
    client = SkyRemoteClient(host, port)

    try:
        await client.connect()
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return

    print("✅ WebSocket connected (mTLS)")

    # -- Step 3: Pair --
    print("🤝 Sending Pair Request...")
    try:
        pair_resp = await client.pair()
    except Exception as e:
        print(f"❌ Pair failed: {e}")
        await client.close()
        return

    if not pair_resp.get("status"):
        print(f"❌ Pair rejected: {pair_resp}")
        await client.close()
        return

    device_name = pair_resp.get("name", "Unknown")
    stbnonce = pair_resp.get("stbnonce")
    pairingcode = pair_resp.get("pairingcode")
    print(f"✅ Paired with: {device_name}")
    print(f"   STB Nonce: {stbnonce}")
    if args.verbose:
        print(f"   Full response: {pair_resp}")

    # -- Step 4: Get pairing code --
    if pairingcode:
        # Device sends the pairing code in the response (auto-pair)
        print(f"   Pairing code (auto): \"{pairingcode}\"")
    else:
        # Fallback: ask the user if not in response
        print()
        print("📺 A pairing code should now be displayed on your TV.")
        raw_code = input("Enter pairing code (digits only): ").strip()
        pairingcode = format_pairing_code(raw_code)
        print(f"   Formatted: \"{pairingcode}\"")

    # -- Step 5: Bind --
    print("🔐 Computing auth token and binding...")
    try:
        bind_resp = await client.bind(pairingcode, stbnonce)
    except Exception as e:
        print(f"❌ Bind failed: {e}")
        await client.close()
        return

    if not bind_resp.get("status"):
        print(f"❌ Bind rejected: {bind_resp}")
        await client.close()
        return

    print(f"✅ Bound! bind_id={client.bind_id}")

    # If we woke via WoL, send Power to bring box out of standby
    if woke_via_wol:
        print("⚡ Sending Power to wake from standby...")
        await asyncio.sleep(1)  # Brief pause for box to be ready
        try:
            await client.send_key("Power")
            print("✅ Power sent — box should be loading")
        except Exception as e:
            print(f"⚠️  Power send failed (try manually): {e}")

    # Cache device for future quick-connect / WoL
    save_device_cache(host, port, mac, device_name)

    print()

    # -- Step 6: Launch TUI --
    print("Launching remote control interface...")

    def curses_wrapper(stdscr):
        asyncio.get_event_loop().run_until_complete(tui_main(stdscr, client))

    # We need to run curses in a way compatible with our async loop
    # Use curses.wrapper with a nested event loop
    loop = asyncio.get_event_loop()

    def run_tui():
        curses.wrapper(lambda stdscr: loop.run_until_complete(tui_main(stdscr, client)))

    # Since we're already in an async context, we need a different approach
    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()
    stdscr.keypad(True)

    try:
        await tui_main(stdscr, client)
    finally:
        curses.endwin()
        await client.close()
        print("👋 Disconnected. Goodbye!")


def main():
    parser = argparse.ArgumentParser(
        description="Sky Remote — LAN remote control for Sky devices",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  %(prog)s                          # Auto-discover and connect
  %(prog)s --host 192.168.1.100     # Connect to specific IP
  %(prog)s --mac AA:BB:CC:DD:EE:FF  # Send WoL before connecting
""",
    )
    parser.add_argument("--host", help="Device IP address (skip discovery)")
    parser.add_argument("--port", type=int, default=8091, help="Device port (default: 8091)")
    parser.add_argument("--mac", help="MAC address for Wake-on-LAN")
    parser.add_argument("--timeout", type=float, default=8.0,
                        help="mDNS discovery timeout in seconds (default: 8)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose/debug logging")
    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG)

    # Discovery runs in sync context (before asyncio event loop)
    device = None
    if args.host:
        device = SkyDeviceInfo("Manual", args.host, args.port or 8091, [args.host])
        if args.mac:
            device.mac = args.mac
    else:
        print("+==================================+")
        print("|       SKY REMOTE CONTROL         |")
        print("+==================================+")
        print()
        print("🔍 Searching for Sky devices on the network...")
        devices = discover_devices(timeout=args.timeout)

        if not devices:
            # Try cached device as fallback
            cached = load_device_cache()
            if cached:
                print(f"📋 No devices discovered — using cached: {cached['name']} @ {cached['host']}")
                device = SkyDeviceInfo(cached["name"], cached["host"],
                                      cached["port"], [cached["host"]])
                device.mac = cached.get("mac")
            else:
                print("❌ No Sky devices found. Use --host to specify manually.")
                return
        elif len(devices) == 1:
            device = devices[0]
            print(f"✅ Found: {device}")
        else:
            print(f"Found {len(devices)} devices:")
            for i, d in enumerate(devices):
                print(f"  [{i + 1}] {d}")
            choice = input("Select device [1]: ").strip()
            idx = int(choice) - 1 if choice else 0
            device = devices[idx]

    try:
        asyncio.run(run(args, device=device))
    except KeyboardInterrupt:
        print("\n👋 Interrupted. Goodbye!")


if __name__ == "__main__":
    main()
