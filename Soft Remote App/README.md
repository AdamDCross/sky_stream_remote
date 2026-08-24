# Sky Stream Soft Remote App

This folder contains a standalone Python Sky Stream soft remote TUI plus the extracted reference assets from the original app.

## Requirements

- Python 3.9+
- `websockets` (13.0 or newer — the script uses the modern `websockets.asyncio` API)
- `zeroconf`

Install the Python dependencies with:

```bash
pip install "websockets>=13" zeroconf
```

## Usage

From this folder, run:

```bash
python3 sky_remote.py
```

Useful options:

- `--host <ip>` to skip discovery.
- `--mac <mac>` to send Wake-on-LAN before connecting.
- `--timeout <seconds>` to adjust discovery time.
- `-v` / `--verbose` for debug logging.

The script now reads its client certificate chain and private key from `./certs/`, using the refreshed certificate files copied from the Home Assistant integration.
