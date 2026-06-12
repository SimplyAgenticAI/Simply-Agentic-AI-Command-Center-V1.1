"""Regression tests for the Email Console attachment support added so
teammates can actually email generated graphics (and any other uploaded
file) as real MIME attachments instead of a plain-text link.
"""
from pathlib import Path

import app as app_module


def _make_upload(uname, filename="pic.png", content=b"fake-bytes", mimetype="image/png", subdir="20260101"):
    file_id = "abcdef1234567890abcdef1234567890"
    (app_module.UPLOADS_DIR / subdir).mkdir(parents=True, exist_ok=True)
    relpath = str(Path(subdir) / f"{file_id}_{filename}")
    out_path = app_module.UPLOADS_DIR / relpath
    out_path.write_bytes(content)
    rec = {
        "id": file_id,
        "filename": filename,
        "relpath": relpath,
        "mimetype": mimetype,
        "size_bytes": len(content),
        "uploaded_at": app_module.now_iso(),
        "owner": uname,
    }
    app_module.add_upload_record(file_id, rec)
    return rec


def test_resolve_email_attachments_valid():
    rec = _make_upload("smoketest_email_owner", filename="graphic.png")
    resolved = app_module._resolve_email_attachments({"username": "smoketest_email_owner"}, [
        {"relpath": rec["relpath"], "filename": "graphic.png"},
    ])
    assert len(resolved) == 1
    fp, filename, mimetype = resolved[0]
    assert fp.exists()
    assert filename == "graphic.png"
    assert mimetype == "image/png"


def test_resolve_email_attachments_accepts_uploads_prefixed_url():
    rec = _make_upload("smoketest_email_owner2", filename="graphic2.png")
    resolved = app_module._resolve_email_attachments({"username": "smoketest_email_owner2"}, [
        {"relpath": "/uploads/" + rec["relpath"].replace("\\", "/")},
    ])
    assert len(resolved) == 1


def test_resolve_email_attachments_rejects_other_users_files():
    rec = _make_upload("smoketest_email_owner3", filename="private.png")
    try:
        app_module._resolve_email_attachments({"username": "smoketest_someone_else", "is_admin": False}, [
            {"relpath": rec["relpath"]},
        ])
        assert False, "expected ValueError"
    except ValueError as e:
        assert "permission" in str(e).lower()


def test_resolve_email_attachments_too_many_raises():
    items = [{"relpath": "x"} for _ in range(app_module.MAX_EMAIL_ATTACHMENTS + 1)]
    try:
        app_module._resolve_email_attachments({"username": "anyone"}, items)
        assert False, "expected ValueError"
    except ValueError as e:
        assert "too many" in str(e).lower()


def test_resolve_email_attachments_missing_file_raises():
    try:
        app_module._resolve_email_attachments({"username": "anyone"}, [
            {"relpath": "20260101/doesnotexist_file.png"},
        ])
        assert False, "expected ValueError"
    except ValueError as e:
        assert "not found" in str(e).lower()


def test_send_email_validation(flask_app):
    uname = "smoketest_email_console"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)

    with flask_app.test_client() as c:
        csrf_token = c.get("/api/csrf_token").get_json()["csrf_token"]
        with c.session_transaction() as sess:
            sess["user"] = uname
        headers = {"X-CSRF-Token": csrf_token}

        resp = c.post("/api/send_email", json={
            "to": "someone@example.com",
            "subject": "Hi",
            "body": "Body text",
            "attachments": [{"relpath": "20260101/doesnotexist_file.png"}],
        }, headers=headers)
        assert resp.status_code == 400
        body = resp.get_json()
        assert body["ok"] is False
        assert "not found" in body["error"].lower()

        resp = c.post("/api/send_email", json={
            "to": "someone@example.com",
            "cc": "not-an-email",
            "subject": "Hi",
            "body": "Body text",
        }, headers=headers)
        assert resp.status_code == 400
        body = resp.get_json()
        assert body["ok"] is False
        assert "cc" in body["error"].lower()
