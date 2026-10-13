# SSL Tools

A web-based toolkit for working with TLS/SSL certificates. Runs as a local Flask
service and covers three common tasks: issuing certificates, verifying them, and
converting between formats — without touching the command line or remembering
openssl flags.

## Features

### Issue certificates
Obtain free Let's Encrypt certificates via the DNS-01 challenge:
- enter one or more domains, including wildcards (`*.example.com`)
- get ready-to-use TXT records for your DNS provider
- automatic propagation check through public resolvers
- issue and download leaf certificate, intermediate chain, and private key

### Verify certificates
Analyze a PEM certificate, optionally together with its chain and private key:
- parse subject, issuer, SANs, validity dates, serial, signature algorithm
- verify the signature chain: leaf -> intermediate -> root
- visualize the chain of trust
- check that the private key matches the certificate

### Check live certificate
Connect to a remote host and inspect what it actually serves:
- TLS version and cipher suite
- full certificate chain presented by the server
- trust verification against the system CA store

### Convert certificates (in progress)
Universal format converter:
- **input (auto-detected):** PEM, DER, PFX/P12, P7B, base64-encoded text
- **output:** PEM (separate files or single bundle), PFX (modern or legacy),
  DER, P7B
- focused on what real web servers expect: nginx, Apache, haproxy, IIS, Tomcat

## Stack

- **Backend:** Python, Flask, `cryptography`, `simple_acme_dns`, `dnspython`
- **Frontend:** a single HTML file with vanilla JavaScript, no build step
- **Storage:** ACME accounts and issued certificates stored on disk
  (`accounts/`, `certs/`)
- **Config:** environment variables loaded from a local `.env` file

## Requirements

- Python 3.10+
- A domain you control, with the ability to add TXT records (for issuance)
- Outbound access to Let's Encrypt and to public DNS resolvers

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
cryptography
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
# Let's Encrypt ACME directory URL
LE_URL=https://acme-v02.api.letsencrypt.org/directory

# Contact email registered with the ACME account
ACCOUNT_EMAIL=admin@gmail.com

# Comma-separated list of DNS resolvers used for TXT propagation checks
NAMESERVERS=1.1.1.1,8.8.8.8

# Absolute path to the project directory (used for accounts/ and certs/)
BASE_DIR=/path/to/project

# Flask bind address and port
FLASK_HOST=127.0.0.1
FLASK_PORT=5023

# Flask debug mode (true/false). Keep false in production.
FLASK_DEBUG=false
```

### Variables

| Variable         | Description                                                        | Example                                  |
|------------------|--------------------------------------------------------------------|------------------------------------------|
| `LE_URL`         | ACME directory endpoint. Use the staging URL for testing.          | `https://acme-v02.api.letsencrypt.org/directory` |
| `ACCOUNT_EMAIL`  | Contact email used when registering the ACME account.              | `admin@gmail.com`                        |
| `NAMESERVERS`    | Comma-separated DNS resolvers for TXT record checks.               | `1.1.1.1,8.8.8.8`                        |
| `BASE_DIR`       | Absolute path to the project. `accounts/` and `certs/` live here.  | `/home/user/apps/ssl.mare.of.by`         |
| `FLASK_HOST`     | Interface Flask binds to. Keep `127.0.0.1` for local-only access.  | `127.0.0.1`                              |
| `FLASK_PORT`     | Port Flask listens on.                                             | `5023`                                   |
| `FLASK_DEBUG`    | Enables Flask debug mode. Do not enable on a public host.          | `false`                                  |

The `.env` file is loaded at startup via `python-dotenv`. It is ignored by Git
and should never be committed.

## Usage

```bash
python app.py
```

Then open `http://<FLASK_HOST>:<FLASK_PORT>` in a browser (by default,
`http://127.0.0.1:5023`).

The UI has tabs for each task:

- **Issue certificate** — enter domains, add the shown TXT records to DNS,
  click Check DNS, then Get certificate.
- **Verify certificate** — paste a certificate, optional chain, and optional
  private key.
- **Check live certificate** — enter a hostname (optionally with a port) and
  inspect what the server presents.
- **Convert** — convert between supported certificate formats.

## Project layout

```
.
├── app.py                # Flask app and HTTP routes
├── acme_manager.py       # ACME client wrapper, issuance logic
├── verifier.py           # Certificate parsing and chain verification
├── converter.py          # Format conversion (PEM, DER, PFX, P7B, base64)
├── templates/
│   └── index.html        # Single-page UI
├── .env.example          # Template for local configuration
├── accounts/             # ACME account state (created at runtime)
└── certs/                # Issued certificates (created at runtime)
```

## API

| Method | Endpoint                | Purpose                                  |
|--------|-------------------------|------------------------------------------|
| POST   | `/api/create`           | Start an ACME order, return TXT records  |
| POST   | `/api/check`            | Verify DNS propagation for a session     |
| POST   | `/api/issue`            | Issue the certificate                    |
| POST   | `/api/verify`           | Verify a PEM certificate, chain, key     |
| POST   | `/api/check_live`       | Fetch and verify a live server cert      |
| POST   | `/api/convert/pfx2pem`  | Extract key, cert, chain from PFX        |
| POST   | `/api/convert/pem2pfx`  | Pack PEM key, cert, chain into PFX       |

## Security notes

- Do not expose it publicly TLS in front of it.
- Private keys are written to disk in `certs/` in plain PEM. Protect this
  directory.
- ACME account keys are stored in `accounts/`. Treat them as secrets.
