import base64
import os
import sys
import uuid
import logging
from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template
from acme_manager import ACMEManager
from verifier import verify_inputs, fetch_remote_certificate
from converter import pfx_to_pem, pem_to_pfx

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
    force=True,
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
manager = ACMEManager()

HOST = os.getenv("FLASK_HOST", "127.0.0.1")
PORT = int(os.getenv("FLASK_PORT", "5023"))
DEBUG = os.getenv("FLASK_DEBUG", "false").lower() in ("1", "true", "yes")


@app.route("/")
def index():
    logger.info("[http] GET / from %s", request.remote_addr)
    return render_template("index.html")


@app.route("/api/create", methods=["POST"])
def api_create():
    data = request.get_json(silent=True) or {}
    domains = [d.strip() for d in data.get("domains", "").split(",") if d.strip()]
    logger.info("[api/create] domains=%s", domains)

    if not domains:
        logger.warning("[api/create] no domains provided")
        return jsonify({"error": "Please specify at least one domain"}), 400

    session_id = str(uuid.uuid4())
    try:
        tokens = manager.create_request(session_id, domains)

        token_rows = []
        for fqdn, token_list in tokens.items():
            for token in token_list:
                token_rows.append({"fqdn": fqdn, "value": token})

        logger.info("[api/create] returning %d token row(s)", len(token_rows))
        return jsonify({
            "session_id": session_id,
            "tokens": token_rows,
        })
    except Exception as e:
        logger.exception("[api/create] failed: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json(silent=True) or {}
    session_id = data.get("session_id")
    logger.info("[api/check] session=%s", session_id)
    if not session_id:
        return jsonify({"error": "Missing session_id"}), 400

    success, message = manager.check_dns(session_id)
    logger.info("[api/check] success=%s message=%s", success, message)
    return jsonify({"success": success, "message": message})


@app.route("/api/issue", methods=["POST"])
def api_issue():
    data = request.get_json(silent=True) or {}
    session_id = data.get("session_id")
    logger.info("[api/issue] session=%s", session_id)
    if not session_id:
        return jsonify({"error": "Missing session_id"}), 400

    session = manager.sessions.get(session_id)
    if not session:
        logger.warning("[api/issue] session %s not found", session_id)
        return jsonify({"error": "Session not found"}), 404

    try:
        result = manager.issue_certificate(session_id)
        return jsonify({
            "success": True,
            "certificate": result["certificate"],
            "chain": result["chain"],
            "private_key": result["private_key"],
            "paths": {
                "cert": result["cert_path"],
                "chain": result["chain_path"],
                "key": result["key_path"],
            },
        })
    except Exception as e:
        logger.exception("[api/issue] failed: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/verify", methods=["POST"])
def api_verify():
    data = request.get_json(silent=True) or {}
    cert_pem = data.get("certificate", "")
    chain_pem = data.get("chain", "")
    key_pem = data.get("private_key", "")

    logger.info("[api/verify] cert=%d bytes, chain=%d bytes, key=%d bytes",
                len(cert_pem), len(chain_pem), len(key_pem))

    if not cert_pem.strip():
        return jsonify({"success": False, "errors": ["Certificate is required"]}), 400

    try:
        result = verify_inputs(cert_pem, chain_pem, key_pem)
        return jsonify(result)
    except Exception as e:
        logger.exception("[api/verify] failed: %s", e)
        return jsonify({"success": False, "errors": [str(e)]}), 500


@app.route("/api/convert/pfx2pem", methods=["POST"])
def api_convert_pfx2pem():
    data = request.get_json(silent=True) or {}
    pfx_b64 = data.get("pfx", "")
    password = data.get("password", "")

    logger.info("[api/convert/pfx2pem] payload=%d b64 chars", len(pfx_b64))

    if not pfx_b64:
        return jsonify({"success": False, "error": "PFX data is required"}), 400

    try:
        # Frontend always re-encodes the file as base64 for transport.
        pfx_bytes = base64.b64decode(pfx_b64)
    except Exception as e:
        return jsonify({"success": False, "error": f"Invalid transport base64: {e}"}), 400

    try:
        # normalize_pfx_bytes() inside pfx_to_pem will handle the case
        # where pfx_bytes is itself ASCII base64 (e.g. keytool output).
        result = pfx_to_pem(pfx_bytes, password)
        return jsonify({"success": True, **result})
    except Exception as e:
        logger.exception("[api/convert/pfx2pem] failed: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/convert/pem2pfx", methods=["POST"])
def api_convert_pem2pfx():
    data = request.get_json(silent=True) or {}
    key_pem = data.get("private_key", "") or ""
    cert_pem = data.get("certificate", "") or ""
    chain_pem = data.get("chain", "") or ""
    password = data.get("password", "") or ""
    confirm = data.get("password_confirm", "") or ""
    output_format = (data.get("output_format") or "binary").lower()

    logger.info(
        "[api/convert/pem2pfx] key=%d cert=%d chain=%d format=%s",
        len(key_pem), len(cert_pem), len(chain_pem), output_format,
    )

    if not key_pem.strip():
        return jsonify({"success": False, "error": "Private key is required"}), 400
    if not cert_pem.strip():
        return jsonify({"success": False, "error": "Certificate is required"}), 400
    if password != confirm:
        return jsonify({"success": False, "error": "Passwords do not match"}), 400

    try:
        pfx_bytes = pem_to_pfx(key_pem, cert_pem, chain_pem, password)
    except Exception as e:
        logger.exception("[api/convert/pem2pfx] failed: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500

    payload = {
        "success": True,
        "size": len(pfx_bytes),
        "output_format": output_format,
        "pfx_b64": base64.b64encode(pfx_bytes).decode("ascii"),
    }

    if output_format == "base64":
        # Text form - wrap at 64 chars like openssl / certutil do
        raw_b64 = base64.b64encode(pfx_bytes).decode("ascii")
        wrapped = "\n".join(raw_b64[i:i + 64] for i in range(0, len(raw_b64), 64))
        payload["pfx_text"] = wrapped + "\n"

    return jsonify(payload)


@app.route("/api/check_live", methods=["POST"])
def api_check_live():
    data = request.get_json(silent=True) or {}
    raw = (data.get("hostname") or "").strip()
    if not raw:
        return jsonify({"success": False, "errors": ["Hostname is required"]}), 400

    hostname = raw
    if "://" in hostname:
        hostname = hostname.split("://", 1)[1]
    hostname = hostname.split("/", 1)[0]

    port = 443
    if ":" in hostname:
        h, p = hostname.rsplit(":", 1)
        if p.isdigit():
            hostname, port = h, int(p)

    logger.info("[api/check_live] hostname=%s port=%d", hostname, port)

    try:
        fetched = fetch_remote_certificate(hostname, port=port)
    except Exception as e:
        logger.exception("[api/check_live] fetch failed: %s", e)
        return jsonify({"success": False, "errors": [str(e)]}), 500

    if not fetched.get("ok"):
        return jsonify({
            "success": False,
            "errors": [f"Connection failed: {fetched.get('connect_error')}"],
            "warnings": [],
        })

    if not fetched["chain_pem"]:
        return jsonify({
            "success": False,
            "errors": ["Server did not present any certificate"],
            "warnings": [],
        })

    leaf_pem = fetched["chain_pem"][0]
    chain_pem = "\n".join(fetched["chain_pem"][1:])

    result = verify_inputs(leaf_pem, chain_pem, "")
    result["connection"] = {
        "hostname": fetched["hostname"],
        "port": fetched["port"],
        "tls_version": fetched["tls_version"],
        "cipher": fetched["cipher"],
        "verify_ok": fetched["verify_ok"],
        "verify_error": fetched["verify_error"],
    }
    return jsonify(result)


if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=DEBUG)
