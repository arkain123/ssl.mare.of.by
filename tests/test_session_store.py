
import json
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from app import session_store as ss


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------
@pytest.fixture()
def sessions_dir(tmp_path, monkeypatch):
    """Point SESSIONS_DIR at a clean temp directory."""
    d = tmp_path / "sessions"
    d.mkdir()
    monkeypatch.setattr(ss, "SESSIONS_DIR", d)
    return d


def _write_json(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")


# ==========================================================================
# Module-level constants
# ==========================================================================
class TestModuleConstants:
    def test_sessions_dir_is_path(self):
        assert isinstance(ss.SESSIONS_DIR, Path)

    def test_sessions_dir_created(self):
        # The module calls mkdir(parents=True, exist_ok=True) at import time
        assert ss.SESSIONS_DIR.exists()
        assert ss.SESSIONS_DIR.is_dir()

    def test_sessions_dir_is_absolute(self):
        assert ss.SESSIONS_DIR.is_absolute()

    def test_sessions_dir_ends_with_sessions_dir_name(self):
        rel = os.getenv("SESSIONS_DIR", "sessions")
        assert ss.SESSIONS_DIR.name == Path(rel).name


# ==========================================================================
# _path
# ==========================================================================
class TestPath:
    def test_builds_json_path(self, sessions_dir):
        p = ss._path("abc-123")
        assert p == sessions_dir / "abc-123.json"

    def test_returns_path_object(self, sessions_dir):
        assert isinstance(ss._path("x"), Path)

    def test_does_not_create_file(self, sessions_dir):
        ss._path("nope")
        assert not (sessions_dir / "nope.json").exists()


# ==========================================================================
# save_session
# ==========================================================================
class TestSaveSession:
    def test_writes_json_file(self, sessions_dir):
        ss.save_session("s1", {"domains": ["a.com"]})
        p = sessions_dir / "s1.json"
        assert p.exists()
        data = json.loads(p.read_text())
        assert data["domains"] == ["a.com"]

    def test_injects_session_id(self, sessions_dir):
        ss.save_session("s1", {"domains": ["a.com"]})
        data = json.loads((sessions_dir / "s1.json").read_text())
        assert data["session_id"] == "s1"

    def test_overwrites_existing_session_id(self, sessions_dir):
        ss.save_session("s1", {"session_id": "old", "domains": []})
        data = json.loads((sessions_dir / "s1.json").read_text())
        assert data["session_id"] == "s1"

    def test_strips_client_key(self, sessions_dir):
        ss.save_session("s1", {"client": MagicMock(), "domains": ["a"]})
        raw = (sessions_dir / "s1.json").read_text()
        data = json.loads(raw)
        assert "client" not in data
        assert "MagicMock" not in raw

    def test_uses_default_str_for_non_serializable_values(self, sessions_dir):
        class Unserializable:
            def __str__(self):
                return "custom-str"

        ss.save_session("s1", {"weird": Unserializable()})
        data = json.loads((sessions_dir / "s1.json").read_text())
        assert data["weird"] == "custom-str"

    def test_indent_is_two_spaces(self, sessions_dir):
        ss.save_session("s1", {"a": 1})
        raw = (sessions_dir / "s1.json").read_text()
        assert "\n  \"a\"" in raw

    def test_write_error_is_swallowed(self, sessions_dir):
        # Make open() fail with PermissionError
        with patch.object(Path, "open", side_effect=PermissionError("denied")):
            # Should not raise
            ss.save_session("s1", {"a": 1})
        assert not (sessions_dir / "s1.json").exists()

    def test_empty_session_still_writes_session_id(self, sessions_dir):
        ss.save_session("s1", {})
        data = json.loads((sessions_dir / "s1.json").read_text())
        assert data == {"session_id": "s1"}


# ==========================================================================
# load_session
# ==========================================================================
class TestLoadSession:
    def test_missing_file_returns_none(self, sessions_dir):
        assert ss.load_session("nope") is None

    def test_roundtrip(self, sessions_dir):
        ss.save_session("s1", {"domains": ["a.com"], "status": "pending"})
        loaded = ss.load_session("s1")
        assert loaded["domains"] == ["a.com"]
        assert loaded["status"] == "pending"
        assert loaded["session_id"] == "s1"

    def test_bad_json_returns_none(self, sessions_dir):
        (sessions_dir / "s1.json").write_text("not json")
        assert ss.load_session("s1") is None

    def test_read_error_returns_none(self, sessions_dir):
        (sessions_dir / "s1.json").write_text("{}")
        with patch.object(Path, "open", side_effect=PermissionError("denied")):
            assert ss.load_session("s1") is None

    def test_returns_dict(self, sessions_dir):
        ss.save_session("s1", {"x": 1})
        assert isinstance(ss.load_session("s1"), dict)

    def test_does_not_add_client_back(self, sessions_dir):
        ss.save_session("s1", {"client": MagicMock(), "x": 1})
        loaded = ss.load_session("s1")
        assert "client" not in loaded


# ==========================================================================
# delete_session
# ==========================================================================
class TestDeleteSession:
    def test_removes_json(self, sessions_dir):
        ss.save_session("s1", {"x": 1})
        ss.delete_session("s1")
        assert not (sessions_dir / "s1.json").exists()

    def test_removes_pickle(self, sessions_dir):
        (sessions_dir / "s1.pickle").write_bytes(b"\x80\x04")
        ss.delete_session("s1")
        assert not (sessions_dir / "s1.pickle").exists()

    def test_removes_lock(self, sessions_dir):
        (sessions_dir / "s1.lock").write_text("")
        ss.delete_session("s1")
        assert not (sessions_dir / "s1.lock").exists()

    def test_removes_all_three(self, sessions_dir):
        ss.save_session("s1", {"x": 1})
        (sessions_dir / "s1.pickle").write_bytes(b"\x80\x04")
        (sessions_dir / "s1.lock").write_text("")
        ss.delete_session("s1")
        assert not (sessions_dir / "s1.json").exists()
        assert not (sessions_dir / "s1.pickle").exists()
        assert not (sessions_dir / "s1.lock").exists()

    def test_missing_files_no_error(self, sessions_dir):
        # Should not raise even if nothing exists
        ss.delete_session("nope")

    def test_only_targets_given_session_id(self, sessions_dir):
        ss.save_session("s1", {"x": 1})
        ss.save_session("s2", {"x": 2})
        ss.delete_session("s1")
        assert (sessions_dir / "s2.json").exists()
        assert not (sessions_dir / "s1.json").exists()

    def test_unlink_error_is_swallowed(self, sessions_dir):
        ss.save_session("s1", {"x": 1})
        with patch.object(Path, "unlink", side_effect=PermissionError("denied")):
            # Should not raise
            ss.delete_session("s1")
        # File still present because unlink failed
        assert (sessions_dir / "s1.json").exists()

    def test_exists_error_is_swallowed(self, sessions_dir):
        with patch.object(Path, "exists", side_effect=OSError("boom")):
            # Should not raise
            ss.delete_session("s1")


# ==========================================================================
# list_metadata
# ==========================================================================
class TestListMetadata:
    def test_empty_dir(self, sessions_dir):
        assert ss.list_metadata() == []

    def test_returns_all_json_files(self, sessions_dir):
        _write_json(sessions_dir / "a.json", {"session_id": "a"})
        _write_json(sessions_dir / "b.json", {"session_id": "b"})
        metas = ss.list_metadata()
        assert len(metas) == 2
        assert {m["session_id"] for m in metas} == {"a", "b"}

    def test_ignores_non_json_files(self, sessions_dir):
        _write_json(sessions_dir / "a.json", {"session_id": "a"})
        (sessions_dir / "a.pickle").write_bytes(b"\x80\x04")
        (sessions_dir / "a.lock").write_text("")
        (sessions_dir / "notes.txt").write_text("hi")
        metas = ss.list_metadata()
        assert len(metas) == 1

    def test_bad_json_skipped(self, sessions_dir):
        _write_json(sessions_dir / "good.json", {"session_id": "good"})
        (sessions_dir / "bad.json").write_text("not json")
        metas = ss.list_metadata()
        assert len(metas) == 1
        assert metas[0]["session_id"] == "good"

    def test_session_id_defaults_to_filename_stem(self, sessions_dir):
        # Legacy session without session_id
        _write_json(sessions_dir / "legacy.json", {"domains": ["a"]})
        metas = ss.list_metadata()
        assert metas[0]["session_id"] == "legacy"

    def test_existing_session_id_kept(self, sessions_dir):
        _write_json(sessions_dir / "file.json",
                    {"session_id": "explicit"})
        metas = ss.list_metadata()
        assert metas[0]["session_id"] == "explicit"

    def test_sorted_by_created_at_desc(self, sessions_dir):
        _write_json(sessions_dir / "a.json",
                    {"session_id": "a", "created_at": "2026-01-01T00:00:00"})
        _write_json(sessions_dir / "b.json",
                    {"session_id": "b", "created_at": "2026-03-01T00:00:00"})
        _write_json(sessions_dir / "c.json",
                    {"session_id": "c", "created_at": "2026-02-01T00:00:00"})
        metas = ss.list_metadata()
        assert [m["session_id"] for m in metas] == ["b", "c", "a"]

    def test_missing_created_at_sorts_last(self, sessions_dir):
        _write_json(sessions_dir / "a.json",
                    {"session_id": "a", "created_at": "2026-01-01T00:00:00"})
        _write_json(sessions_dir / "b.json", {"session_id": "b"})
        metas = ss.list_metadata()
        assert [m["session_id"] for m in metas] == ["a", "b"]

    def test_has_client_true_when_file_and_key_present(self, sessions_dir,
                                                       tmp_path):
        account_file = tmp_path / "acc.json"
        account_file.write_text("{}")
        _write_json(sessions_dir / "a.json", {
            "session_id": "a",
            "client_state": {
                "account_file": str(account_file),
                "private_key_pem": "-----BEGIN...",
            },
        })
        metas = ss.list_metadata()
        assert metas[0]["has_client"] is True

    def test_has_client_false_when_account_file_missing(self, sessions_dir,
                                                        tmp_path):
        _write_json(sessions_dir / "a.json", {
            "session_id": "a",
            "client_state": {
                "account_file": str(tmp_path / "missing.json"),
                "private_key_pem": "-----BEGIN...",
            },
        })
        metas = ss.list_metadata()
        assert metas[0]["has_client"] is False

    def test_has_client_false_when_key_missing(self, sessions_dir, tmp_path):
        account_file = tmp_path / "acc.json"
        account_file.write_text("{}")
        _write_json(sessions_dir / "a.json", {
            "session_id": "a",
            "client_state": {"account_file": str(account_file)},
        })
        metas = ss.list_metadata()
        assert metas[0]["has_client"] is False

    def test_has_client_false_without_client_state(self, sessions_dir):
        _write_json(sessions_dir / "a.json", {"session_id": "a"})
        metas = ss.list_metadata()
        assert metas[0]["has_client"] is False

    def test_has_client_false_with_empty_client_state(self, sessions_dir):
        _write_json(sessions_dir / "a.json",
                    {"session_id": "a", "client_state": {}})
        metas = ss.list_metadata()
        assert metas[0]["has_client"] is False

    def test_has_client_false_when_account_file_null(self, sessions_dir):
        _write_json(sessions_dir / "a.json", {
            "session_id": "a",
            "client_state": {
                "account_file": None,
                "private_key_pem": "x",
            },
        })
        metas = ss.list_metadata()
        assert metas[0]["has_client"] is False

    def test_read_error_skipped(self, sessions_dir):
        _write_json(sessions_dir / "good.json", {"session_id": "good"})
        (sessions_dir / "bad.json").write_text("{}")
        original_open = Path.open

        def fake_open(self, *a, **kw):
            if self.name == "bad.json":
                raise PermissionError("denied")
            return original_open(self, *a, **kw)

        with patch.object(Path, "open", fake_open):
            metas = ss.list_metadata()
        assert len(metas) == 1
        assert metas[0]["session_id"] == "good"


# ==========================================================================
# mark_issued
# ==========================================================================
class TestMarkIssued:
    def test_missing_file_noop(self, sessions_dir):
        # Should not create the file
        ss.mark_issued("nope")
        assert not (sessions_dir / "nope.json").exists()

    def test_sets_status_to_issued(self, sessions_dir):
        _write_json(sessions_dir / "s1.json",
                    {"session_id": "s1", "status": "pending"})
        ss.mark_issued("s1")
        data = json.loads((sessions_dir / "s1.json").read_text())
        assert data["status"] == "issued"

    def test_preserves_other_fields(self, sessions_dir):
        _write_json(sessions_dir / "s1.json", {
            "session_id": "s1",
            "status": "pending",
            "domains": ["a.com"],
            "tokens": {"a.com": ["t"]},
        })
        ss.mark_issued("s1")
        data = json.loads((sessions_dir / "s1.json").read_text())
        assert data["domains"] == ["a.com"]
        assert data["tokens"] == {"a.com": ["t"]}
        assert data["status"] == "issued"

    def test_bad_json_swallowed(self, sessions_dir):
        (sessions_dir / "s1.json").write_text("not json")
        # Should not raise
        ss.mark_issued("s1")
        # File content unchanged
        assert (sessions_dir / "s1.json").read_text() == "not json"

    def test_read_error_swallowed(self, sessions_dir):
        _write_json(sessions_dir / "s1.json", {"session_id": "s1"})
        with patch.object(Path, "open", side_effect=PermissionError("denied")):
            ss.mark_issued("s1")
        # File unchanged because open() failed before any write
        data = json.loads((sessions_dir / "s1.json").read_text())
        assert "status" not in data

    def test_write_error_swallowed(self, sessions_dir):
        _write_json(sessions_dir / "s1.json",
                    {"session_id": "s1", "status": "pending"})
        real_open = Path.open
        call_count = {"n": 0}

        def fake_open(self, *a, **kw):
            call_count["n"] += 1
            # First open (read) succeeds, second open (write) fails
            if call_count["n"] >= 2:
                raise PermissionError("denied")
            return real_open(self, *a, **kw)

        with patch.object(Path, "open", fake_open):
            ss.mark_issued("s1")
        # File unchanged
        data = json.loads((sessions_dir / "s1.json").read_text())
        assert data["status"] == "pending"

    def test_uses_default_str_for_unserializable(self, sessions_dir):
        class Unserializable:
            def __str__(self):
                return "custom"

        _write_json(sessions_dir / "s1.json",
                    {"session_id": "s1", "status": "pending",
                     "weird": "custom"})
        ss.mark_issued("s1")
        data = json.loads((sessions_dir / "s1.json").read_text())
        assert data["weird"] == "custom"

    def test_indent_preserved(self, sessions_dir):
        _write_json(sessions_dir / "s1.json",
                    {"session_id": "s1", "status": "pending"})
        ss.mark_issued("s1")
        raw = (sessions_dir / "s1.json").read_text()
        assert "\n  " in raw


# ==========================================================================
# Round-trip integration
# ==========================================================================
class TestRoundTrip:
    def test_save_load_delete(self, sessions_dir):
        payload = {"domains": ["a.com"], "status": "pending",
                   "auto_check_status": "pending"}
        ss.save_session("s1", payload)
        loaded = ss.load_session("s1")
        assert loaded["domains"] == ["a.com"]
        assert loaded["status"] == "pending"
        ss.delete_session("s1")
        assert ss.load_session("s1") is None

    def test_save_list_has_client(self, sessions_dir, tmp_path):
        account_file = tmp_path / "acc.json"
        account_file.write_text("{}")
        ss.save_session("s1", {
            "domains": ["a.com"],
            "client_state": {
                "account_file": str(account_file),
                "private_key_pem": "key",
            },
        })
        metas = ss.list_metadata()
        assert len(metas) == 1
        assert metas[0]["has_client"] is True

    def test_mark_issued_then_list(self, sessions_dir):
        ss.save_session("s1", {"status": "pending"})
        ss.mark_issued("s1")
        metas = ss.list_metadata()
        assert metas[0]["status"] == "issued"
