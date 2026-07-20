"""Regression tests for the CSRF coverage gaps closed in V7.8.

Two holes, both from an exemption that was broader than intended:
  - `_auth_guard` returned early for /admin/, so the highest-privilege routes
    were the only ones in the app with no CSRF check at all
  - /api/extension/ was a blanket prefix exemption, which also covered the
    session-authenticated routes living under it (notably rotate_key)
"""
import pytest

import app as app_module


@pytest.fixture()
def admin_client(flask_app, monkeypatch):
    """A client holding a session plus a matching CSRF token, forced admin."""
    monkeypatch.setattr(app_module, "_is_admin_user", lambda u: True)
    monkeypatch.setattr(app_module, "load_users", lambda: {"users": {"root": {
        "username": "root", "email": "root@example.com", "is_admin": True,
        "created_at": "2026-01-01T00:00:00Z", "settings": {},
    }}})
    with flask_app.test_client() as c:
        with c.session_transaction() as sess:
            sess["user"] = "root"
        c.csrf_token = c.get("/api/csrf_token").get_json()["csrf_token"]
        yield c


# ── /admin/ must not be a CSRF-free zone ─────────────────────────────────────

def test_admin_post_without_csrf_is_rejected(admin_client):
    resp = admin_client.post("/admin/errors/clear")
    assert resp.status_code == 403


def test_admin_post_with_csrf_succeeds(admin_client):
    resp = admin_client.post("/admin/errors/clear",
                             data={"_csrf_token": admin_client.csrf_token})
    assert resp.status_code in (200, 302)


def test_admin_get_still_works(admin_client):
    assert admin_client.get("/admin/errors").status_code == 200


def test_admin_form_carries_csrf_token(admin_client):
    """The Clear-all button must ship a token now that the route enforces one."""
    body = admin_client.get("/admin/errors").data.decode("utf-8", "replace")
    assert 'name="_csrf_token"' in body


# ── /api/extension/ is exempt only for genuine key-authenticated callers ─────

def test_session_authed_extension_post_requires_csrf(admin_client):
    """rotate_key rides a session cookie, so it must be CSRF-protected."""
    assert admin_client.post("/api/extension/rotate_key").status_code == 403


def test_session_authed_extension_post_succeeds_with_csrf(admin_client):
    resp = admin_client.post("/api/extension/rotate_key",
                             headers={"X-CSRF-Token": admin_client.csrf_token})
    assert resp.status_code == 200


def test_extension_key_header_still_exempts_csrf():
    """A request carrying the extension key must not need a session token."""
    with app_module.app.test_request_context(
        "/api/extension/ping", method="POST",
        headers={"X-SA-Extension-Key": "any-non-empty-value"},
    ):
        assert app_module._csrf_valid() is True


def test_extension_path_without_key_is_not_exempt():
    with app_module.app.test_request_context("/api/extension/ping", method="POST"):
        assert app_module._csrf_valid() is False


def test_blank_extension_key_does_not_exempt():
    with app_module.app.test_request_context(
        "/api/extension/ping", method="POST", headers={"X-SA-Extension-Key": "   "},
    ):
        assert app_module._csrf_valid() is False
