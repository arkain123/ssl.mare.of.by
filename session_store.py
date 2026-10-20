import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

_base = os.getenv("BASE_DIR") or os.path.dirname(os.path.abspath(__file__))
_rel = os.getenv("SESSIONS_DIR", "sessions")
SESSIONS_DIR = Path(_rel) if os.path.isabs(_rel) else Path(_base) / _rel
SESSIONS_DIR.mkdir(parents=True, exist_ok=True)


def _path(session_id):
    return SESSIONS_DIR / f"{session_id}.json"


def save_session(session_id, session):
    """Persist serializable session metadata + client state to JSON."""
    meta = {
        "session_id": session_id,
        "domains": session.get("domains") or [],
        "tokens": session.get("tokens") or {},
        "created_at": session.get("created_at"),
        "status": session.get("status", "pending"),
        "client_state": session.get("client_state"),
    }
    try:
        with _path(session_id).open("w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, default=str)
        logger.info("[session_store] saved %s", session_id)
    except Exception as e:
        logger.error("[session_store] cannot write %s: %s", session_id, e)


def load_session(session_id):
    p = _path(session_id)
    if not p.exists():
        return None
    try:
        with p.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning("[session_store] cannot read %s: %s", p, e)
        return None


def delete_session(session_id):
    p = _path(session_id)
    try:
        if p.exists():
            p.unlink()
            logger.info("[session_store] removed %s", p)
        legacy = p.with_suffix(".pickle")
        if legacy.exists():
            legacy.unlink()
            logger.info("[session_store] removed legacy %s", legacy)
    except Exception as e:
        logger.warning("[session_store] cannot remove %s: %s", p, e)


def list_metadata():
    """
    Return metadata for all persisted sessions, newest first.

    `has_client` is True only when we have both an account file on disk
    and a saved private key, i.e. `_client_from_state` can actually rebuild
    the ACMEClient.
    """
    metas = []
    for p in SESSIONS_DIR.glob("*.json"):
        try:
            with p.open("r", encoding="utf-8") as f:
                meta = json.load(f)
        except Exception as e:
            logger.warning("[session_store] cannot read %s: %s", p, e)
            continue

        state = meta.get("client_state") or {}
        account_file = state.get("account_file")
        has_account = bool(account_file and os.path.exists(account_file))
        has_key = bool(state.get("private_key_pem"))
        meta["has_client"] = has_account and has_key
        metas.append(meta)

    metas.sort(key=lambda m: m.get("created_at") or "", reverse=True)
    return metas


def mark_issued(session_id):
    """Update status in-place (for the short window before deletion)."""
    p = _path(session_id)
    if not p.exists():
        return
    try:
        with p.open("r", encoding="utf-8") as f:
            meta = json.load(f)
        meta["status"] = "issued"
        with p.open("w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, default=str)
    except Exception as e:
        logger.warning("[session_store] mark_issued failed: %s", e)
