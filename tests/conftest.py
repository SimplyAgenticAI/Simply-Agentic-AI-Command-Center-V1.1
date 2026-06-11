import os
import sys
import tempfile

import pytest

# Configure environment BEFORE importing app — app.py reads env vars (DATA_DIR,
# APP_SECRET, etc.) at module import time to set up paths and config.
_TEST_DATA_DIR = tempfile.mkdtemp(prefix="saai_test_data_")
os.environ.setdefault("DATA_DIR", _TEST_DATA_DIR)
os.environ.setdefault("APP_SECRET", "test-secret-key-not-for-production")
os.environ.setdefault("WTF_CSRF_ENABLED", "false")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as app_module  # noqa: E402

app_module.app.config.update(TESTING=True)


@pytest.fixture(scope="session")
def flask_app():
    return app_module.app


@pytest.fixture()
def client(flask_app):
    with flask_app.test_client() as c:
        yield c


@pytest.fixture()
def auth_client(flask_app):
    """A test client logged in as a freshly-registered user (becomes admin,
    since it's the first user in the isolated test DATA_DIR)."""
    with flask_app.test_client() as c:
        resp = c.post("/register", data={
            "username": "smoketest",
            "email": "",
            "password": "TestPass123!",
            "password2": "TestPass123!",
            "tos_accepted": "on",
        }, follow_redirects=True)
        assert resp.status_code == 200

        token_resp = c.get("/api/csrf_token")
        csrf_token = token_resp.get_json()["csrf_token"]
        c.csrf_token = csrf_token  # stash for tests that need the header
        yield c
