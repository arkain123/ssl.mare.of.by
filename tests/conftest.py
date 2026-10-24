import base64
import pytest
from unittest.mock import MagicMock, patch

from app.app import app as flask_app


@pytest.fixture()
def app():
    flask_app.config.update(TESTING=True)
    yield flask_app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def fake_session():
    return {
        "session_id": "11111111-1111-1111-1111-111111111111",
        "domains": ["test.com"],
        "auto_check_status": "pending",
        "attempts": 0,
        "max_attempts": 240,
        "interval_ms": 30000,
        "started_at": "2026-10-21T11:18:39+00:00",
        "last_at": None,
        "last_message": "",
    }
