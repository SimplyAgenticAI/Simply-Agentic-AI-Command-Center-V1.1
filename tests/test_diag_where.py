"""V19.4: /health's last-error note says which route and app.py line failed.
(File must sort after test_client_crud.)"""
import json
import app as app_module


def test_api_error_note_keeps_route_and_line():
    with app_module.app.test_request_context("/api/usage/messages", method="GET"):
        try:
            app_module._normalize_plan_key(123)          # AttributeError raised inside app.py
        except AttributeError as e:
            app_module._handle_exception(e)
    rec = json.loads((app_module.DATA / "diag_last.json").read_text(encoding="utf-8"))["api_error"]
    assert rec["where"].startswith("GET /api/usage/messages at line ")
    assert rec["where"].endswith("in _normalize_plan_key")
    assert "AttributeError" in rec["detail"]


def test_settings_load_with_encrypted_gmail_token(flask_app):
    """V19.5: /api/user/settings crashed for anyone with Gmail connected."""
    uname = "gmailsettingsuser"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False,
        "settings": {"gmail_oauth": app_module._oauth_token_encrypt({"refresh_token": "R", "access_token": "A"})}}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    try:
        c = flask_app.test_client()
        with c.session_transaction() as s:
            s["user"] = uname
        r = c.get("/api/user/settings")
        assert r.status_code == 200 and r.get_json()["settings"]["gmail_oauth_connected"] is True
    finally:
        data = app_module.load_users()
        (data.get("users") or {}).pop(uname, None)
        app_module.save_users(data)
        app_module._invalidate_users_cache()
