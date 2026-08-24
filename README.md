# Sky Stream Remote

This repository collects the reverse-engineered Sky Stream / Sky Glass remote-control protocol, a Home Assistant integration, and a standalone Python soft remote.

## Contents

- `Home Assistant/` — manual-install Home Assistant integration and certificates.
- `Soft Remote App/` — standalone Python LAN remote plus reference UI assets and certificates.
- `Docs/` — protocol reference and a short summary of how the implementation was verified.

## Certificates

Both `certs/` directories contain the mTLS client certificate chain and EC private key that the Sky box requires. Two things worth knowing:

- **The committed private key is public by design.** It is the shared client identity extracted from the official Sky Remote APK — identical for every installation of the app worldwide. It grants no user-specific access, so it is not a leaked secret that needs rotating.
- **The certificate expires.** The current pair is valid **2026-04-30 → 2027-04-30** (the validity window is encoded in the certificate filename). Once expired, the box will reject the TLS handshake and both clients will fail with generic connection errors — if that happens, replace the PEM files in *both* `Home Assistant/custom_components/sky_remote/certs/` and `Soft Remote App/certs/` with a refreshed pair extracted from a current version of the official app.
