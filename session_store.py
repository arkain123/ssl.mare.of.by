"""
Disk persistence for ACME sessions.

Layout (inside SESSIONS_DIR):

    {session_id}.json     - metadata: domains, tokens, timestamps, status
    {session_id}.pickle   - full ACMEManager session dict (best effort)

The pickle file is the one that lets resume a session after a Flask
restart. If pickling fails for any reason, it still keeps the JSON metadata
so the user can at least see and delete old requests.
"""

import json
import logging
import os
import pickle
import stat
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
SESSIONS_DIR = os.environ.get(
    "SESSIONS_DIR",
    os.path.join(os.environ.get("BASE_DIR", _PROJECT_DIR), "sessions"),
)

_SESSION_FILE_MODE = 0o600
_SESSION_DIR_MODE = 0o700


def _ensure_dir():
    os.makedirs(SESSIONS_DIR, mode=_SESSION_DIR_MODE, exist_ok=True)


def _chmod_quiet(path, mode):
    try:
        os.chmod(path, mode)
    except Exception:
        pass


def _json_path(session_id):
    return os.path.join(SESSIONS_DIR, f"{session_id}.json")


def _pickle_path(session_id):
    return os.path.join(SESSIONS_DIR, f"{session_id}.pickle")


def _public_meta(session_id, data):
    return {
        "session_id": session_id,
        "domains": data.get("domains") or [],
        "tokens": data.get("tokens") or {},
        "created_at": data.get("created_at") or datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "status": data.get("status", "pending"),
    }


def save_session(session_id, data):
    """Persist metadata + best-effort pickle of the full session."""
    _ensure_dir()

    meta = _public_meta(session_id, data)

    try:
        with open(_json_path(session_id), "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, sort_keys=True)
        _chmod_quiet(_json_path(session_id), _SESSION_FILE_MODE)
    except Exception as e:
        logger.exception("[session_store] cannot write metadata for %s: %s",
                         session_id, e)

    pickled = False
    client = data.get("client")
    if client is not None:
        try:
            with open(_pickle_path(session_id), "wb") as f:
                pickle.dump(data, f)
            _chmod_quiet(_pickle_path(session_id), _SESSION_FILE_MODE)
            pickled = True
        except Exception as e:
            logger.warning("[session_store] cannot pickle session %s: %s",
                           session_id, e)

    logger.info("[session_store] saved %s (pickled=%s)", session_id, pickled)
    return meta


def load_session(session_id):
    """Load one session. Returns dict or None. Client may be None."""
    if not os.path.exists(_json_path(session_id)):
        return None

    try:
        with open(_json_path(session_id), "r", encoding="utf-8") as f:
            meta = json.load(f)
    except Exception as e:
        logger.warning("[session_store] cannot read metadata %s: %s",
                       session_id, e)
        return None

    client = None
    pickle_present = False
    if os.path.exists(_pickle_path(session_id)):
        try:
            with open(_pickle_path(session_id), "rb") as f:
                data = pickle.load(f)
            client = data.get("client")
            meta.setdefault("domains", data.get("domains"))
            meta.setdefault("tokens", data.get("tokens"))
            pickle_present = True
        except Exception as e:
            logger.warning("[session_store] cannot unpickle %s: %s",
                           session_id, e)

    return {
        "session_id": session_id,
        "domains": meta.get("domains") or [],
        "tokens": meta.get("tokens") or {},
        "created_at": meta.get("created_at"),
        "updated_at": meta.get("updated_at"),
        "status": meta.get("status", "pending"),
        "client": client,
        "pickle_present": pickle_present,
    }


def load_all():
    """Load every stored session into a dict keyed by session_id."""
    _ensure_dir()
    sessions = {}
    try:
        entries = sorted(os.listdir(SESSIONS_DIR))
    except Exception as e:
        logger.warning("[session_store] cannot list %s: %s", SESSIONS_DIR, e)
        return sessions

    for name in entries:
        if not name.endswith(".json"):
            continue
        sid = name[:-5]
        s = load_session(sid)
        if s is None:
            continue
        if s.get("status") == "issued":
            logger.info("[session_store] skipping issued session %s", sid)
            continue
        sessions[sid] = s
    return sessions


def list_metadata():
    """Return list of metadata dicts for all sessions (no client objects)."""
    _ensure_dir()
    out = []
    for name in sorted(os.listdir(SESSIONS_DIR)):
        if not name.endswith(".json"):
            continue
        sid = name[:-5]
        try:
            with open(_json_path(sid), "r", encoding="utf-8") as f:
                meta = json.load(f)
            meta["has_client"] = os.path.exists(_pickle_path(sid))
            out.append(meta)
        except Exception as e:
            logger.warning("[session_store] cannot read %s: %s", sid, e)
    return out


def mark_issued(session_id):
    """Update status on disk without removing the file."""
    path = _json_path(session_id)
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        meta["status"] = "issued"
        meta["updated_at"] = datetime.now(timezone.utc).isoformat()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, sort_keys=True)
        _chmod_quiet(path, _SESSION_FILE_MODE)
    except Exception as e:
        logger.warning("[session_store] cannot mark issued %s: %s",
                       session_id, e)


def delete_session(session_id):
    """Remove both metadata and pickle file for a session."""
    for path in (_json_path(session_id), _pickle_path(session_id)):
        try:
            if os.path.exists(path):
                os.remove(path)
                logger.info("[session_store] removed %s", path)
        except Exception as e:
            logger.warning("[session_store] cannot remove %s: %s", path, e)
