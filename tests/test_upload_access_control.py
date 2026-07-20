"""Regression tests for the upload access-control and XSS fixes (V7.7).

Three bugs, all silent:
  - `/uploads/_index.json` skipped the ownership check entirely, because the
    stem "_index" splits to an empty file_id and the check was gated on it
  - `_resolve_email_attachments` read the owner off a missing index record as
    "" and let the attachment through — so any file under uploads/ could be
    mailed out
  - EMAIL_RE accepted HTML payloads, which rendered unescaped into /admin/users
"""
import re

import pytest

import app as app_module


# ── EMAIL_RE must reject markup ──────────────────────────────────────────────

@pytest.mark.parametrize("addr", [
    "a@b.co",
    "first.last+tag@sub.domain.co.uk",
    "user_name%x@mail-server.io",
])
def test_email_re_accepts_real_addresses(addr):
    assert app_module.EMAIL_RE.match(addr)


@pytest.mark.parametrize("payload", [
    "<svg/onload=alert(1)>@x.co",
    "<img/src=x/onerror=alert(1)>@a.io",
    '"><script>@a.co',
])
def test_email_re_rejects_html_payloads(payload):
    assert not app_module.EMAIL_RE.match(payload)


def test_registration_rejects_markup_email(client, monkeypatch):
    # The suite shares one DATA_DIR, so earlier registrations can exhaust the
    # per-IP signup limit. Neutralise it so this exercises the email check.
    monkeypatch.setattr(app_module, "_rate_limit_check", lambda key, limit: (True, ""))
    client.post("/register", data={
        "username": "xssprobe",
        "email": "<svg/onload=alert(1)>@x.co",
        "password": "TestPass123!",
        "password2": "TestPass123!",
        "tos_accepted": "on",
    }, follow_redirects=True)
    # Assert the security property, not the rendered error copy: no account may
    # be created carrying a markup email that later renders into /admin/users.
    assert "xssprobe" not in (app_module.load_users().get("users") or {})


# ── Path resolution must use a real boundary check, not a string prefix ───────

def test_resolve_upload_path_rejects_traversal():
    assert app_module._resolve_upload_path("../users.db") is None
    assert app_module._resolve_upload_path("a/../../../etc/passwd") is None


def test_resolve_upload_path_accepts_normal_relpath():
    fp = app_module._resolve_upload_path("20260101/abc123_report.pdf")
    assert fp is not None
    assert fp.name == "abc123_report.pdf"


# ── Ownership check must fail closed ─────────────────────────────────────────

NON_ADMIN = {"username": "alice", "is_admin": False}


def test_index_json_is_denied_to_non_admin():
    """The bug: stem "_index" -> file_id "" -> ownership check was skipped."""
    fp = app_module.UPLOADS_DIR / "_index.json"
    assert app_module._upload_access_ok(fp, NON_ADMIN) is False


def test_unindexed_file_is_denied_to_non_admin():
    fp = app_module.UPLOADS_DIR / "20260101" / "deadbeef_notmine.pdf"
    assert app_module._upload_access_ok(fp, NON_ADMIN) is False


def test_other_users_file_is_denied(monkeypatch):
    monkeypatch.setattr(app_module, "get_upload_record",
                        lambda fid: {"owner": "bob", "filename": "x.pdf"})
    fp = app_module.UPLOADS_DIR / "20260101" / "abc123_x.pdf"
    assert app_module._upload_access_ok(fp, NON_ADMIN) is False


def test_own_file_is_allowed(monkeypatch):
    monkeypatch.setattr(app_module, "get_upload_record",
                        lambda fid: {"owner": "alice", "filename": "x.pdf"})
    fp = app_module.UPLOADS_DIR / "20260101" / "abc123_x.pdf"
    assert app_module._upload_access_ok(fp, NON_ADMIN) is True


def test_legacy_ownerless_record_is_allowed(monkeypatch):
    """Records predating owner tracking must not lock users out of old files."""
    monkeypatch.setattr(app_module, "get_upload_record",
                        lambda fid: {"owner": "", "filename": "x.pdf"})
    fp = app_module.UPLOADS_DIR / "20260101" / "abc123_x.pdf"
    assert app_module._upload_access_ok(fp, NON_ADMIN) is True


def test_admin_bypasses_ownership():
    fp = app_module.UPLOADS_DIR / "_index.json"
    assert app_module._upload_access_ok(fp, {"username": "root", "is_admin": True}) is True


# ── Email attachments must refuse unindexed files ────────────────────────────

def test_email_attachment_rejects_unindexed_file(tmp_path, monkeypatch):
    """The bug: no record -> owner "" -> `if owner and ...` was False -> allowed."""
    target = app_module.UPLOADS_DIR / "_index.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('{"files": {}}', encoding="utf-8")
    with pytest.raises(ValueError, match="permission"):
        app_module._resolve_email_attachments(
            NON_ADMIN, [{"relpath": "_index.json", "filename": "_index.json"}]
        )


def test_email_attachment_rejects_traversal():
    with pytest.raises(ValueError, match="not found"):
        app_module._resolve_email_attachments(
            NON_ADMIN, [{"relpath": "../users.db", "filename": "users.db"}]
        )


# ── The admin user list must escape what it renders ──────────────────────────

def test_admin_user_list_escapes_email(client, monkeypatch):
    """Even with a payload already in the DB, the page must not emit raw markup."""
    real_load = app_module.load_users

    def poisoned():
        return {"users": {"victim": {
            "username": "victim",
            "email": "<svg/onload=alert(1)>@x.co",
            "is_admin": True,
            "created_at": "2026-01-01T00:00:00Z",
        }}}

    monkeypatch.setattr(app_module, "load_users", poisoned)
    # Drive the page directly rather than through the shared auth_client, whose
    # registration silently no-ops once another test file has claimed the name.
    monkeypatch.setattr(app_module, "_is_admin_user", lambda u: True)
    with client.session_transaction() as sess:
        sess["user"] = "victim"
    resp = client.get("/admin/users")
    assert resp.status_code == 200
    assert b"<svg/onload=" not in resp.data
    assert b"&lt;svg/onload=" in resp.data
