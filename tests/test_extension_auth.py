"""Regression tests for the extension-key auth-guard fix.

Before this fix, `_auth_guard`'s blanket `if request.path.startswith("/api/")
and not current_user(): 401` ran before any /api/extension/ view function,
so every key-authenticated extension route was unreachable no matter what
the caller sent — `_ext_authenticate()` never even got a chance to run.
"""
import secrets

import pytest

import app as app_module

TEST_USERNAME = "exttestuser_" + secrets.token_hex(4)


@pytest.fixture()
def extension_key(flask_app, monkeypatch):
    """The real extension key for a freshly-registered test user, fetched the
    way the web UI does (session-authenticated, no X-SA-Extension-Key header
    needed). Uses its own short-lived client that fully closes before
    returning, rather than depending on the `auth_client` fixture — nesting
    two simultaneously-open test_client() contexts in one test trips Flask's
    request-context stack ("Popped wrong request context"). Signup
    auto-closes once any user exists (no Stripe configured in tests), so
    force it open for this one registration — same reasoning as
    test_upload_access_control.py monkeypatching around the rate limiter.
    TEST_USERNAME is generated once at import (module-level, not per-call)
    so every test in this file shares one already-registered account instead
    of colliding on "username already taken" on the second call. Also
    neutralises the per-IP rate limit (hundreds of earlier registrations
    across other files in the shared suite exhaust it — same fix as
    test_upload_access_control.py's test_registration_rejects_markup_email)
    and the seat-code requirement, which kicks in independently of
    _signup_enabled the moment any other user already exists."""
    monkeypatch.setattr(app_module, "_signup_enabled", lambda: True)
    monkeypatch.setattr(app_module, "_rate_limit_check", lambda key, limit: (True, ""))
    monkeypatch.setattr(app_module, "_is_valid_seat_code", lambda code: (True, ""))
    with flask_app.test_client() as c:
        c.post("/register", data={
            "username": TEST_USERNAME,
            "email": "",
            "password": "TestPass123!",
            "password2": "TestPass123!",
            "tos_accepted": "on",
        }, follow_redirects=True)
        c.post("/login", data={"username": TEST_USERNAME, "password": "TestPass123!"},
               follow_redirects=True)
        key_resp = c.get("/api/extension/my_key")
        assert key_resp.status_code == 200
        return key_resp.get_json()["key"]


# ── The guard must not block genuinely keyed requests ─────────────────────

def test_auth_route_reachable_with_valid_key(client, extension_key):
    resp = client.get("/api/extension/auth", headers={"X-SA-Extension-Key": extension_key})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["username"] == TEST_USERNAME


def test_ping_route_reachable_with_valid_key(client, extension_key):
    """api_extension_ping called two functions that didn't exist anywhere in
    app.py (_require_extension_key / _get_current_username) — dead code that
    would have thrown a 500 the moment it became reachable. Covers the fix."""
    resp = client.post("/api/extension/ping", headers={"X-SA-Extension-Key": extension_key})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["user"] == TEST_USERNAME


def test_bulk_import_reaches_the_correct_users_crm(client, extension_key):
    """End-to-end: a keyed extension call actually lands data in the right
    account's CRM, not just a 200 status."""
    resp = client.post(
        "/api/extension/bulk_import",
        headers={"X-SA-Extension-Key": extension_key},
        json={"profiles": [{"name": "Jamie Rivera", "profile_url": "https://facebook.com/jamie.rivera"}]},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["imported"] == 1

    check = client.get(
        "/api/extension/check_contact",
        headers={"X-SA-Extension-Key": extension_key},
        query_string={"url": "https://facebook.com/jamie.rivera"},
    )
    assert check.status_code == 200
    assert check.get_json()["exists"] is True


# ── The guard must still reject requests that aren't genuinely keyed ──────

def test_extension_route_401_with_no_key_at_all(client):
    resp = client.get("/api/extension/auth")
    assert resp.status_code == 401


def test_extension_route_401_with_invalid_key(client):
    """An attacker-supplied header now reaches the view (guard lets it
    through), but _ext_authenticate() must still refuse an unknown key."""
    resp = client.get("/api/extension/auth", headers={"X-SA-Extension-Key": "not-a-real-key"})
    assert resp.status_code == 401


def test_bulk_import_without_key_is_rejected(client):
    """No session and no key means _csrf_valid() rejects it before the guard's
    own auth check ever runs (unrelated to this fix — CSRF runs first for any
    unkeyed POST) — 403, not 401. Still correctly blocked either way."""
    resp = client.post("/api/extension/bulk_import", json={"profiles": []})
    assert resp.status_code == 403


# ── Session-authenticated extension routes are unaffected by the fix ──────

def test_rotate_key_still_requires_session_not_extension_key(client):
    """rotate_key has no X-SA-Extension-Key check of its own — it must stay
    blocked for a plain, session-less caller (403 from the CSRF check, same
    reasoning as above — this route was never reachable this way before)."""
    resp = client.post("/api/extension/rotate_key")
    assert resp.status_code == 403


def test_my_key_still_requires_session(client):
    resp = client.get("/api/extension/my_key")
    assert resp.status_code == 401
