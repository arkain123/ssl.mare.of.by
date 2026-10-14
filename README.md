# SSL Tools

A web-based toolkit for working with TLS/SSL certificates. Runs as a local Flask
service and covers three common tasks: issuing certificates, verifying them, and
converting between formats - without touching the command line or remembering
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

### Convert certificates
Universal format converter with automatic input detection:
- **input (auto-detected):** PEM (all block types), DER, PFX/P12 (binary and
  base64 text), PKCS#7/P7B (DER and PEM), base64-encoded wrappers
- **output:** PEM (separate files, fullchain, bundle, cert+chain only), DER,
  PKCS#7/P7B (binary and PEM), PFX/PKCS#12 (AES and base64 text), public key
  (PEM and OpenSSH), private key in PKCS#1
- focused on what real web servers expect: nginx, Apache, haproxy, IIS, Tomcat

## Stack

- **Backend:** Python, Flask, `cryptography`, `simple_acme_dns`, `dnspython`
- **Frontend:** a single HTML file with vanilla JavaScript, no build step
- **Storage:** ACME accounts and issued certificates stored on disk
  (`accounts/`, `certs/`)
- **Config:** environment variables loaded from a local `.env` file

## Requirements

- Python 3.10+
- `cryptography` >= 42.0 (required for PKCS#7 support)
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

- **Issue certificate** - enter domains, add the shown TXT records to DNS,
  click Check DNS, then Get certificate.
- **Verify certificate** - paste a certificate, optional chain, and optional
  private key.
- **Check live certificate** - enter a hostname (optionally with a port) and
  inspect what the server presents.
- **Convert** - upload or paste a certificate file, click Inspect to see what
  was detected, then pick an output format and download the result.

## Convert: supported formats

### Input (auto-detected)

| Format                       | Notes                                              |
|------------------------------|----------------------------------------------------|
| PEM                          | Any block type: certs, keys, CSR, public key       |
| DER                          | Certificate, private key, CSR, public key, PFX     |
| PFX / PKCS#12                | Binary DER, password-protected                     |
| PFX as base64 text           | As produced by `keytool`, `certutil -encode`, ESET |
| PKCS#7 / P7B                 | Binary DER and PEM variants                        |

### Output

| Target                       | Produces                                            |
|------------------------------|-----------------------------------------------------|
| PEM - separate files         | `certificate.crt`, `chain.crt`, `private.key`       |
| PEM - fullchain + key        | `fullchain.pem`, `privkey.pem` (certbot layout)     |
| PEM - single bundle          | `bundle.pem` (cert + chain + key)                   |
| PEM - cert + chain only      | `fullchain.pem` without private key                 |
| DER - certificate only       | `certificate.der`                                   |
| PKCS#7 / P7B - binary        | `certificate.p7b`                                   |
| PKCS#7 / P7B - PEM           | `certificate.p7b.pem`                               |
| PFX / PKCS#12                | `certificate.pfx` (AES encryption, password)        |
| PFX - base64 text            | `certificate.pfx.txt`                               |
| Public key - PEM             | `public.key` (SPKI)                                 |
| Public key - OpenSSH         | `public.key` (`ssh-rsa AAAA...`)                    |
| Private key - PKCS#1         | `private.key` (RSA traditional format)              |

## Project layout

```
.
├── app.py                # Flask app and HTTP routes
├── acme_manager.py       # ACME client wrapper, issuance logic
├── verifier.py           # Certificate parsing and chain verification
├── converter.py          # Format detection, parsing, and serialization
├── templates/
│   └── index.html        # Single-page UI
├── .env.example          # Template for local configuration
├── accounts/             # ACME account state (created at runtime)
└── certs/                # Issued certificates (created at runtime)
```

## API

| Method | Endpoint                | Purpose                                     |
|--------|-------------------------|---------------------------------------------|
| POST   | `/api/create`           | Start an ACME order, return TXT records     |
| POST   | `/api/check`            | Verify DNS propagation for a session        |
| POST   | `/api/issue`            | Issue the certificate                       |
| POST   | `/api/verify`           | Verify a PEM certificate, chain, key        |
| POST   | `/api/check_live`       | Fetch and verify a live server cert         |
| POST   | `/api/convert/inspect`  | Detect the format and report the contents   |
| POST   | `/api/convert/output`   | Convert to the selected target format       |

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
             der | pkcs7 | pkcs7-pem | pfx | pfx-b64 |
             pubkey-pem | pubkey-openssh | key-pkcs1",
  "output_password": "password for output PFX (optional)",
  "output_password_confirm": "confirmation (optional)"
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
(downloaded only).

## Security notes

- Do not expose it publicly without authentication and TLS in front of it.
- Private keys are written to disk in `certs/` in plain PEM. Protect this
  directory.
- ACME account keys are stored in `accounts/`. Treat them as secrets.

## Limitations

- PFX files are written with modern AES encryption. Legacy RC2/3DES output is
  not supported by the `cryptography` library and would require `pyOpenSSL` or
  the `openssl` binary.
- Encrypted PKCS#8 private keys (`-----BEGIN ENCRYPTED PRIVATE KEY-----`) are
  accepted on input only if the correct password is supplied.
- JKS/JCEKS keystores are not supported; convert them to PKCS#12 first with
  `keytool -importkeystore`.

