# SSL Tools

A web-based toolkit for working with TLS/SSL certificates. Runs as a local Flask
service and covers four common tasks: issuing certificates, verifying them,
inspecting live servers, and converting between formats - without touching the
command line or remembering openssl flags.

## Features

### Issue certificates
Obtain free Let's Encrypt certificates via the DNS-01 challenge:

- enter one or more domains, including wildcards (`*.example.com`)
- get ready-to-use TXT records for your DNS provider (click any cell to copy)
- automatic propagation check through public DNS resolvers over TCP
  (Google / Cloudflare / Quad9, configurable)
- optional background auto-checker - polls every N seconds until propagated
- resumable sessions: state persists across server restarts and can be shared
  between devices via a `?session=<uuid>` URL
- issue and download leaf certificate, intermediate chain, and private key

### Verify certificates
Analyze a PEM certificate, optionally together with its chain and private key:

- parse subject, issuer, SANs, validity dates, serial, signature algorithm
- verify the signature chain: leaf -> intermediate -> root
- build a full chain of trust from the leaf alone, by chasing AIA URLs and
  falling back to the local CA store (`certifi` / system bundle)
- optionally include the self-signed root in the output
- visualize the chain of trust, tolerate cross-signed intermediates and
  out-of-order input
- verify that the private key matches the certificate

### Check live certificate
Connect to a remote host and inspect what it actually serves:

- TLS version and cipher suite
- full certificate chain presented by the server
- trust verification against the system CA store
- download leaf / full chain as PEM, or copy to clipboard

### Convert certificates
Universal format converter with automatic input detection:

- **input (auto-detected):** PEM (all block types), DER, PFX/P12 (binary and
  base64 text), PKCS#7/P7B (DER and PEM), base64-encoded wrappers
- **output:** PEM (separate files, fullchain, bundle, cert+chain only), DER,
  PKCS#7/P7B (binary and PEM), PFX/PKCS#12 (AES and base64 text), public key
  (PEM and OpenSSH), private key in PKCS#1
- focused on what real web servers expect: nginx, Apache, haproxy, IIS, Tomcat

### GlobalSign intermediates
Inject a GlobalSign intermediate into the chain field via a built-in catalog.
Appends to the end of the existing chain - never overwrites.

### UI

- dark / light / auto theme (follows `prefers-color-scheme` by default)
- remembered across reloads via `localStorage`

## Stack

- **Backend:** Python 3.10+, Flask, `cryptography`, `simple_acme_dns`, `dnspython`
- **Frontend:** vanilla JavaScript, split into modules under `static/js/`
  (no build step)
- **Storage:** ACME accounts, issued certificates and pending sessions stored
  on disk (`accounts/`, `certs/`, `sessions/`)
- **Config:** environment variables loaded from a local `.env` file

## Requirements

- Python 3.10+
- `cryptography` >= 42.0 (required for PKCS#7 support)
- A domain you control, with the ability to add TXT records (for issuance)
- Outbound TCP access to Let's Encrypt and to public DNS resolvers on port 53

## Installation

```bash
git clone https://github.com/arkain123/ssl.mare.of.by
cd ssl.mare.of.by

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

Example `requirements.txt`:

```
flask
python-dotenv
cryptography>=42.0
simple-acme-dns
dnspython
```

## Configuration

All runtime settings are read from environment variables. Copy the provided
example file and adjust it for your environment:

```bash
cp .env.example .env
```

### `.env.example`

```env
# ---------- ACME / Let's Encrypt ----------
# Use the staging URL for testing:
# https://acme-staging-v02.api.letsencrypt.org/directory
LE_URL=https://acme-v02.api.letsencrypt.org/directory
ACCOUNT_EMAIL=admin@gmail.com

# ---------- DNS propagation checks ----------
# Comma-separated public resolvers queried over TCP, in order.
NAMESERVERS=8.8.8.8,1.1.1.1,9.9.9.9

# Per-resolver DNS query timeout, seconds
DNS_QUERY_TIMEOUT=3

# Hard wall-clock limit for one query, seconds
DNS_SUBPROCESS_TIMEOUT=6

# ---------- DNS auto-check (UI polling) ----------
# Browser polling interval for auto-check, milliseconds
DNS_AUTO_INTERVAL_MS=30000

# Total attempts before the auto-checker gives up
# 240 x 30s = 2 hours
DNS_AUTO_MAX_ATTEMPTS=240

# Delay before the first auto-check tick, milliseconds
DNS_AUTO_START_DELAY_MS=3000

# ---------- Chain builder ----------
# Maximum depth when chasing issuers via AIA / local CA store
CHAIN_MAX_DEPTH=10

# AIA download timeout for intermediate fetches, seconds
AIA_FETCH_TIMEOUT=10

# User-Agent used when fetching AIA certificates
AIA_USER_AGENT=SSL-Tools-Chain-Builder/1.0

# ---------- Certificate verification ----------
# Warn in the UI when a certificate expires within this many days
CERT_EXPIRY_WARN_DAYS=14

# ---------- Live certificate check ----------
# TLS connect timeout when fetching a live certificate, seconds
LIVE_CHECK_TIMEOUT=10

# ---------- Uploads / limits ----------
# Max size of an uploaded file, MB
CONVERT_MAX_UPLOAD_MB=10

# Max size of a text response rendered inline, bytes
CONVERT_MAX_INLINE_TEXT_BYTES=65536

# ---------- Storage ----------
# Absolute path to the project directory (used for accounts/, certs/, sessions/)
BASE_DIR=/path/to/project

# Where ACME account state lives (relative to BASE_DIR)
ACCOUNTS_DIR=accounts

# Where issued certificates are written (relative to BASE_DIR)
CERTS_DIR=certs

# Where pending ACME sessions are persisted (relative to BASE_DIR)
SESSIONS_DIR=sessions

# ---------- Flask ----------
FLASK_HOST=127.0.0.1
FLASK_PORT=5023
FLASK_DEBUG=false

# ---------- Logging ----------
LOG_LEVEL=INFO
```

### Variables

| Variable | Default | Description |
|---|---|---|
| `LE_URL` | Let's Encrypt prod | ACME directory endpoint. Use staging for tests. |
| `ACCOUNT_EMAIL` | — | Contact email registered with the ACME account. |
| `NAMESERVERS` | `8.8.8.8,1.1.1.1,9.9.9.9` | Resolvers for TXT checks (TCP, tried in order). |
| `DNS_QUERY_TIMEOUT` | `3` | Per-resolver query timeout, seconds. |
| `DNS_SUBPROCESS_TIMEOUT` | `6` | Hard limit per one dig/dnspython call. |
| `DNS_AUTO_INTERVAL_MS` | `30000` | Browser polling interval for auto-check. |
| `DNS_AUTO_MAX_ATTEMPTS` | `240` | Attempts before auto-check gives up. |
| `DNS_AUTO_START_DELAY_MS` | `3000` | Delay before first auto-check tick. |
| `CHAIN_MAX_DEPTH` | `10` | Max depth of AIA chain chasing. |
| `AIA_FETCH_TIMEOUT` | `10` | AIA download timeout, seconds. |
| `AIA_USER_AGENT` | `SSL-Tools-Chain-Builder/1.0` | User-Agent for AIA fetches. |
| `CERT_EXPIRY_WARN_DAYS` | `14` | Yellow "expires soon" threshold. |
| `LIVE_CHECK_TIMEOUT` | `10` | TLS connect timeout for live check. |
| `CONVERT_MAX_UPLOAD_MB` | `10` | Max upload size for convert. |
| `CONVERT_MAX_INLINE_TEXT_BYTES` | `65536` | Files larger are download-only. |
| `BASE_DIR` | project dir | Root for accounts/certs/sessions. |
| `ACCOUNTS_DIR` | `accounts` | Relative to BASE_DIR. |
| `CERTS_DIR` | `certs` | Relative to BASE_DIR. |
| `SESSIONS_DIR` | `sessions` | Relative to BASE_DIR. |
| `FLASK_HOST` | `127.0.0.1` | Flask bind address. |
| `FLASK_PORT` | `5023` | Flask port. |
| `FLASK_DEBUG` | `false` | Do not enable on a public host. |
| `LOG_LEVEL` | `INFO` | Python logging level. |

The `.env` file is loaded at startup via `python-dotenv`. It is ignored by Git
and should never be committed.

## Usage

```bash
python app.py
```

Then open `http://<FLASK_HOST>:<FLASK_PORT>` in a browser (by default,
`http://127.0.0.1:5023`).

The UI has tabs for each task:

- **Issue certificate** - enter domains, add the shown TXT records to DNS
  (click a cell to copy), then either wait for the auto-checker or click
  **Check DNS**, then **Get certificate**.
- **Verify certificate** - paste a certificate, optional chain, and optional
  private key. Use **Build chain** to construct a full chain of trust from the
  leaf alone, or inject a GlobalSign intermediate from the built-in catalog.
- **Check live certificate** - enter a hostname (optionally with a port) and
  inspect what the server presents. Download leaf / full chain as PEM.
- **Convert** - upload or paste a certificate file, click **Inspect** to see
  what was detected, then pick an output format and download the result.

### Sessions and cross-device resume

Pending ACME sessions are persisted to `sessions/`. If the server restarts, or
you want to continue from another device, the state (including the ACME account
key and CSR) is restored from `client_state`.

After creating or restoring a session, the URL contains `?session=<uuid>`. Copy
the URL to share a session, or use the **Share** button in the saved-requests
list. Once a certificate is issued, the session is deleted automatically.

## Convert: supported formats

### Input (auto-detected)

| Format | Notes |
|---|---|
| PEM | Any block type: certs, keys, CSR, public key |
| DER | Certificate, private key, CSR, public key, PFX |
| PFX / PKCS#12 | Binary DER, password-protected |
| PFX as base64 text | As produced by `keytool`, `certutil -encode`, ESET |
| PKCS#7 / P7B | Binary DER and PEM variants |

### Output

| Target | Produces |
|---|---|
| PEM - separate files | `certificate.crt`, `chain.crt`, `private.key` |
| PEM - fullchain + key | `fullchain.pem`, `privkey.pem` (certbot layout) |
| PEM - single bundle | `bundle.pem` (cert + chain + key) |
| PEM - cert + chain only | `fullchain.pem` without private key |
| DER - certificate only | `certificate.der` |
| PKCS#7 / P7B - binary | `certificate.p7b` |
| PKCS#7 / P7B - PEM | `certificate.p7b.pem` |
| PFX / PKCS#12 | `certificate.pfx` (AES encryption, password required) |
| PFX - base64 text | `certificate.pfx.txt` |
| Public key - PEM | `public.key` (SPKI) |
| Public key - OpenSSH | `public.key` (`ssh-rsa AAAA...`) |
| Private key - PKCS#1 | `private.key` (RSA traditional format) |

## Project layout

```
.
├── app.py                    # Flask app and HTTP routes
├── acme_manager.py           # ACME client wrapper, issuance logic
├── verifier.py               # Certificate parsing, chain verification/building
├── converter.py              # Format detection, parsing, and serialization
├── dns_check.py              # TXT resolution via public resolvers (TCP)
├── session_store.py          # Persistence of pending ACME sessions
├── globalsign_catalog.py     # Bundled GlobalSign intermediate catalog
├── templates/
│   └── index.html            # Single-page UI
├── static/
│   ├── style.css             # Theme + layout
│   └── js/
│       ├── core.js           # Theme, tabs, shared helpers
│       ├── issue.js          # ACME + auto-check
│       ├── verify.js         # Verify + build chain + live check
│       ├── convert.js        # Convert + GlobalSign injector
│       └── app.js            # Bootstrap
├── globalsign_intermediates/ # PEM files for the GlobalSign catalog
├── .env.example              # Template for local configuration
├── accounts/                 # ACME account state (created at runtime)
├── certs/                    # Issued certificates (created at runtime)
└── sessions/                 # Pending sessions (created at runtime)
```

## API

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/create` | Start an ACME order, return TXT records |
| POST | `/api/check` | Verify DNS propagation for a session |
| POST | `/api/issue` | Issue the certificate |
| GET | `/api/sessions` | List saved sessions |
| GET | `/api/sessions/<id>` | Load one session (rebuilds ACME client if possible) |
| DELETE | `/api/sessions/<id>` | Delete a session |
| POST | `/api/verify` | Verify a PEM certificate, chain, key |
| POST | `/api/build_chain` | Build a full chain from a leaf certificate |
| POST | `/api/check_live` | Fetch and verify a live server cert |
| GET | `/api/globalsign-intermediates` | Bundled GlobalSign intermediate catalog |
| GET | `/api/config` | Public runtime configuration for the frontend |
| POST | `/api/convert/inspect` | Detect the format and report the contents |
| POST | `/api/convert/output` | Convert to the selected target format |

Both convert endpoints accept the same input shape:

```json
{
  "input_b64":  "base64 of the file (optional)",
  "input_text": "or the raw text content (optional)",
  "password":   "input password if encrypted (optional)"
}
```

`/api/convert/output` additionally accepts:

```json
{
  "target": "pem-separate | pem-fullchain | pem-bundle | pem-cert-chain |
             der | pkcs7 | pkcs7-pem | pkcs12 | pkcs12-p12 | pkcs12-b64 |
             pubkey-pem | pubkey-openssh | key-pkcs1",
  "output_password": "password for output PKCS#12 (required for pkcs12*)",
  "output_password_confirm": "confirmation (optional)",
  "friendly_name": "PKCS#12 friendlyName (optional)"
}
```

`/api/build_chain` accepts:

```json
{
  "certificate": "-----BEGIN CERTIFICATE-----...",
  "include_root": false
}
```

Response for `/api/convert/output`:

```json
{
  "success": true,
  "files": [
    { "name": "certificate.crt", "b64": "...", "size": 1234, "text": "..." }
  ]
}
```

`text` is present for text files (shown in the UI) and `null` for binary files
(downloaded only). Files larger than `CONVERT_MAX_INLINE_TEXT_BYTES` are always
returned with `text: null`.

## Security notes

- Do not expose it publicly without TLS in front of it (I also recommend protecting the service with authentication).
- Private keys are written to disk in `certs/` in plain PEM. Protect this
  directory.
- ACME account keys are stored in `accounts/`. Treat them as secrets.
- Pending sessions in `sessions/` contain the account key and CSR - protect
  this directory too.

## Limitations

- PFX files are written with modern AES encryption. Legacy RC2/3DES output is
  not supported by the `cryptography` library and would require `pyOpenSSL` or
  the `openssl` binary.
- Encrypted PKCS#8 private keys (`-----BEGIN ENCRYPTED PRIVATE KEY-----`) are
  accepted on input only if the correct password is supplied.
- JKS/JCEKS keystores are not supported; convert them to PKCS#12 first with
  `keytool -importkeystore`.
- Chain building relies on public AIA endpoints and the local CA store. If the
  issuer is only reachable via an internal CA, the chain cannot be completed
  automatically - paste the missing intermediate into the chain field.
