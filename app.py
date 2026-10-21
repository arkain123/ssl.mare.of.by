import os
import sys
import uuid
import base64
import logging
from flask import Flask, request, jsonify, render_template
from datetime import datetime, timezone
from acme_manager import ACMEManager
from converter import parse_anything, serialize_bundle, bundle_summary, PKCS12_TARGETS
from globalsign_catalog import grouped_catalog
from verifier import verify_inputs, fetch_remote_certificate, build_certificate_chain


logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
    force=True,
)
logger = logging.getLogger(__name__)

CONVERT_MAX_INLINE_TEXT_BYTES = int(os.getenv("CONVERT_MAX_INLINE_TEXT_BYTES", "65536"))
CONVERT_MAX_UPLOAD_MB = int(os.getenv("CONVERT_MAX_UPLOAD_MB", "10"))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = CONVERT_MAX_UPLOAD_MB * 1024 * 1024
manager = ACMEManager()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_text_content(name: str, content: bytes) -> bool:
    """Decide if a produced file is safe to show in a <textarea>."""
    if name.endswith((".der", ".pfx", ".p12", ".jks", ".keystore")):
        return False
    if name.endswith((".pem", ".crt", ".key", ".txt", ".csr", ".pub")):
        return True
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return printable / max(len(text), 1) > 0.9


# ---------------------------------------------------------------------------
# Routes - UI
# ---------------------------------------------------------------------------

@app.route("/favicon.ico")
def favicon():
    return app.send_static_file("icons/favicon.ico")


@app.route("/")
def index():
    logger.info("[http] GET / from %s", request.remote_addr)
    return render_template("index.html")


@app.route("/api/config", methods=["GET"])
def api_config():
    return jsonify({
        "dns_auto_interval_ms":    int(os.getenv("DNS_AUTO_INTERVAL_MS", "30000")),
        "dns_auto_max_attempts":   int(os.getenv("DNS_AUTO_MAX_ATTEMPTS", "240")),
        "dns_auto_start_delay_ms": int(os.getenv("DNS_AUTO_START_DELAY_MS", "3000")),
        "cert_expiry_warn_days":   int(os.getenv("CERT_EXPIRY_WARN_DAYS", "14")),
        "convert_max_inline_text_bytes": CONVERT_MAX_INLINE_TEXT_BYTES,
    })

# ---------------------------------------------------------------------------
# Routes - ACME
# ---------------------------------------------------------------------------

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

    session = manager.sessions.get(session_id)
    if not session:
        return jsonify({
            "success": False,
            "message": "Session not found or expired. Please create a new request.",
        })

    if not session.get("client"):
        return jsonify({
            "success": False,
            "message": "ACME client was not restored (server restart). "
                       "Please create a new request.",
        })

    success, message = manager.check_dns(session_id)

    if success:
        import session_store
        sess = session_store.load_session(session_id)
        if sess and sess.get("auto_check_status") == "pending":
            sess["auto_check_status"] = "verified"
            sess["auto_check_last_message"] = message
            session_store.save_session(session_id, sess)

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
        return jsonify({
            "error": "Session not found or expired. Please create a new request."
        }), 404

    if not session.get("client"):
        return jsonify({
            "error": "ACME client was not restored (server restart). "
                     "Please create a new request."
        }), 400

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
    except ValueError as e:
        logger.warning("[api/issue] rejected: %s", e)
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("[api/issue] failed: %s", e)
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Routes - DNS auto-check status
# ---------------------------------------------------------------------------

@app.route("/api/check_status", methods=["POST"])
def api_check_status():
    data = request.get_json(silent=True) or {}
    session_id = data.get("session_id")
    if not session_id:
        return jsonify({"error": "Missing session_id"}), 400

    import session_store
    session = session_store.load_session(session_id)
    if not session:
        return jsonify({"success": False, "error": "Session not found"}), 404

    return jsonify({
        "success": True,
        "session_id": session_id,
        "status": session.get("auto_check_status", "unknown"),
        "attempts": int(session.get("auto_check_attempts", 0)),
        "max_attempts": int(os.getenv("DNS_AUTO_MAX_ATTEMPTS", "240")),
        "interval_ms": int(os.getenv("DNS_AUTO_INTERVAL_MS", "30000")),
        "started_at": session.get("auto_check_started_at"),
        "last_at": session.get("auto_check_last_at"),
        "last_message": session.get("auto_check_last_message"),
    })


@app.route("/api/check_auto_toggle", methods=["POST"])
def api_check_auto_toggle():
    data = request.get_json(silent=True) or {}
    session_id = data.get("session_id")
    enabled = bool(data.get("enabled", True))
    if not session_id:
        return jsonify({"error": "Missing session_id"}), 400

    import session_store
    session = session_store.load_session(session_id)
    if not session:
        return jsonify({"success": False, "error": "Session not found"}), 404

    prev = session.get("auto_check_status")
    now_iso = datetime.now(timezone.utc).isoformat()

    if enabled:
        if prev == "verified":
            return jsonify({
                "success": False,
                "error": "Auto-check already verified",
            }), 400
        if prev in ("failed", "stopped", "expired"):
            session["auto_check_attempts"] = 0
            session["auto_check_started_at"] = now_iso
            session["auto_check_last_at"] = None
        session["auto_check_status"] = "pending"
        if not session.get("auto_check_started_at"):
            session["auto_check_started_at"] = now_iso
    else:
        if prev == "pending":
            session["auto_check_status"] = "stopped"

    session_store.save_session(session_id, session)
    return jsonify({
        "success": True,
        "status": session.get("auto_check_status"),
        "attempts": int(session.get("auto_check_attempts", 0)),
    })


# ---------------------------------------------------------------------------
# Routes - Sessions (persistence)
# ---------------------------------------------------------------------------

def _session_public(session, session_id):
    """Strip the (unserializable) client object from a session dict."""
    return {
        "session_id": session_id,
        "domains": session.get("domains") or [],
        "tokens": session.get("tokens") or {},
        "created_at": session.get("created_at"),
        "status": session.get("status", "pending"),
        "has_client": session.get("client") is not None,
    }


@app.route("/api/sessions", methods=["GET"])
def api_sessions_list():
    import session_store
    metas = session_store.list_metadata()
    logger.info("[api/sessions] returning %d session(s)", len(metas))
    return jsonify({"success": True, "sessions": metas})


@app.route("/api/sessions/<session_id>", methods=["GET"])
def api_session_get(session_id):
    session = manager.sessions.get(session_id)

    if not session:
        import session_store
        loaded = session_store.load_session(session_id)
        if not loaded:
            return jsonify({"success": False, "error": "Session not found"}), 404

        # Rebuild the ACME client from persisted state so that
        # /api/check and /api/issue work on any device / after restart.
        if not loaded.get("client") and loaded.get("client_state"):
            try:
                from acme_manager import _client_from_state
                client = _client_from_state(loaded["client_state"])
                if client:
                    loaded["client"] = client
                    logger.info("[api/sessions/%s] client rebuilt from state",
                                session_id)
            except Exception as e:
                logger.warning("[api/sessions/%s] rebuild failed: %s",
                               session_id, e)

        manager.sessions[session_id] = loaded
        logger.info("[api/sessions/%s] restored from disk into memory", session_id)
        return jsonify({"success": True, **_session_public(loaded, session_id)})

    logger.info("[api/sessions/%s] served from memory", session_id)
    return jsonify({"success": True, **_session_public(session, session_id)})


@app.route("/api/sessions/<session_id>", methods=["DELETE"])
def api_session_delete(session_id):
    import session_store
    manager.sessions.pop(session_id, None)
    session_store.delete_session(session_id)
    logger.info("[api/sessions/%s] deleted", session_id)
    return jsonify({"success": True})


# ---------------------------------------------------------------------------
# Routes - Verify
# ---------------------------------------------------------------------------

@app.route("/api/build_chain", methods=["POST"])
def api_build_chain():
    data = request.get_json(silent=True) or {}
    cert_pem = (data.get("certificate") or "").strip()
    include_root = bool(data.get("include_root", False))

    if not cert_pem:
        return jsonify({
            "success": False,
            "errors": ["Certificate is required"],
            "chain": [],
            "warnings": [],
            "found_root": False,
            "root_included": False,
            "excluded_root": None,
            "complete": False,
        }), 400

    logger.info("[api/build_chain] input=%d bytes include_root=%s",
                len(cert_pem), include_root)

    try:
        result = build_certificate_chain(cert_pem, include_root=include_root)
    except Exception as e:
        logger.exception("[api/build_chain] failed: %s", e)
        return jsonify({
            "success": False,
            "errors": [str(e)],
            "chain": [],
            "warnings": [],
            "found_root": False,
            "root_included": False,
            "excluded_root": None,
            "complete": False,
        }), 500

    logger.info(
        "[api/build_chain] built %d cert(s), root_found=%s root_included=%s, "
        "errors=%d warnings=%d",
        len(result.get("chain", [])),
        result.get("found_root"),
        result.get("root_included"),
        len(result.get("errors", [])),
        len(result.get("warnings", [])),
    )
    return jsonify(result)


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


@app.route("/api/globalsign-intermediates", methods=["GET"])
def api_globalsign_intermediates():
    groups = grouped_catalog()
    total = sum(len(g["items"]) for g in groups)
    logger.info("[api/globalsign-intermediates] serving %d certificate(s) in %d group(s)",
                total, len(groups))
    return jsonify({"success": True, "groups": groups})


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
    result["chain_pem"] = fetched.get("chain_pem") or []
    return jsonify(result)


# ---------------------------------------------------------------------------
# Routes - Convert
# ---------------------------------------------------------------------------

def _read_convert_payload(data):
    """Extract raw bytes from {'input_b64': ...} or {'input_text': ...}."""
    raw_b64 = data.get("input_b64", "")
    text = data.get("input_text", "")
    if raw_b64:
        try:
            return base64.b64decode(raw_b64)
        except Exception as e:
            raise ValueError(f"Invalid base64 transport: {e}")
    if text:
        return text.encode("utf-8")
    raise ValueError("Provide a file or paste text")


@app.route("/api/convert/inspect", methods=["POST"])
def api_convert_inspect():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "") or ""

    try:
        raw = _read_convert_payload(data)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

    logger.info("[api/convert/inspect] input=%d bytes", len(raw))

    try:
        bundle = parse_anything(raw, password)
        summary = bundle_summary(bundle)
        logger.info("[api/convert/inspect] detected=%s", summary.get("source_format"))
        return jsonify({"success": True, **summary})
    except Exception as e:
        logger.exception("[api/convert/inspect] failed: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/convert/output", methods=["POST"])
def api_convert_output():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "") or ""
    target = data.get("target", "") or ""
    out_pw = data.get("output_password", "") or ""
    out_pw2 = data.get("output_password_confirm", "") or ""
    friendly_name = (data.get("friendly_name", "") or "").strip()

    if not target:
        return jsonify({"success": False, "error": "Target format is required"}), 400

    # PKCS#12 targets require a password. Other targets ignore it entirely,
    # so leftover values from a previously-selected format cannot block us.
    if target in PKCS12_TARGETS:
        if not out_pw:
            return jsonify({
                "success": False,
                "error": "PKCS#12 (PFX) output requires a password (passphrase)",
            }), 400
        if out_pw != out_pw2:
            return jsonify({
                "success": False,
                "error": "Output passwords do not match",
            }), 400
    else:
        out_pw = out_pw2 = friendly_name = ""

    try:
        raw = _read_convert_payload(data)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

    logger.info("[api/convert/output] target=%s input=%d bytes", target, len(raw))

    try:
        bundle = parse_anything(raw, password)
    except Exception as e:
        logger.exception("[api/convert/output] parse failed: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500

    try:
        outputs = serialize_bundle(
            bundle,
            target,
            output_password=out_pw,
            output_password_confirm=out_pw2 or None,
            friendly_name=friendly_name,
        )
    except ValueError as e:
        logger.warning("[api/convert/output] rejected: %s", e)
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        logger.exception("[api/convert/output] serialize failed: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500

    files = []
    for name, content in outputs.items():
        is_text = _is_text_content(name, content)
        show_text = is_text and len(content) <= CONVERT_MAX_INLINE_TEXT_BYTES
        files.append({
            "name": name,
            "b64": base64.b64encode(content).decode("ascii"),
            "size": len(content),
            "text": content.decode("utf-8", errors="replace") if show_text else None,
        })

    logger.info("[api/convert/output] produced %d file(s)", len(files))
    return jsonify({"success": True, "files": files})


if __name__ == "__main__":
    import os
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", "5023"))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() in ("1", "true", "yes")
    app.run(host=host, port=port, debug=debug)
