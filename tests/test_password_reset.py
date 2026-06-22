"""Gold-standard password reset flow:
- request is anti-enumeration (identical response for real vs fake username)
- the reset token is delivered ONLY via email (never shown on screen)
- the emailed link lands on a verified set-password form
- the new password must be entered twice and match
- the token is single-use and invalidated after a successful reset
"""
import re

from werkzeug.security import check_password_hash

import app as m


def _seed_user(username, email, pw="OldPass123!"):
    data = m.load_users()
    data.setdefault("users", {})[username] = m._new_user(username, pw, email=email)
    m.save_users(data)


def test_reset_request_is_generic_for_unknown_user(client):
    r = client.post("/reset", data={"username": "definitely_not_a_user_xyz"}, follow_redirects=True)
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    # Same generic message regardless of existence; never reveals "Unknown username"
    assert "If an account with that username exists" in body
    assert "Unknown" not in body


def test_reset_confirm_invalid_token_is_generic(client):
    r = client.get("/reset/confirm?u=whoever&t=badtoken")
    assert r.status_code == 200
    assert "invalid or has expired" in r.get_data(as_text=True).lower()


def test_full_reset_flow_via_emailed_link(client, monkeypatch):
    uname = "resetflowuser"
    _seed_user(uname, "resetflowuser@example.com")

    # Capture the outgoing email instead of really sending it; enable the SMTP path.
    captured = {}
    monkeypatch.setattr(m, "SMTP_USER", "smtp@example.com")
    monkeypatch.setattr(m, "SMTP_PASS", "x")

    def fake_send(to_addr, subject, body, *a, **k):
        captured["to"] = to_addr
        captured["body"] = body

    monkeypatch.setattr(m, "send_email_smtp", fake_send)

    # 1) Request the reset — generic response, token never shown on screen
    r = client.post("/reset", data={"username": uname}, follow_redirects=True)
    assert r.status_code == 200
    page = r.get_data(as_text=True)
    assert "If an account with that username exists" in page
    assert captured.get("to") == "resetflowuser@example.com"
    # The raw token appears only in the email body, never in the rendered page
    mo = re.search(r"/reset/confirm\?u=[^&\s]+&t=([^\s]+)", captured["body"])
    assert mo, "reset link with token must be in the email"
    token = mo.group(1)
    assert token not in page

    # 2) The emailed link validates and shows the set-password form
    rc = client.get(f"/reset/confirm?u={uname}&t={token}")
    assert rc.status_code == 200
    assert "verified" in rc.get_data(as_text=True).lower()

    # 3) Mismatched confirmation is rejected
    rm = client.post("/reset_password", data={
        "username": uname, "token": token,
        "new_password": "NewPass123!", "new_password2": "Different123!",
    }, follow_redirects=True)
    assert "do not match" in rm.get_data(as_text=True).lower()
    # password unchanged after a failed attempt
    assert check_password_hash(m.load_users()["users"][uname]["password_hash"], "OldPass123!")

    # 4) Correct double-entry completes the reset
    rok = client.post("/reset_password", data={
        "username": uname, "token": token,
        "new_password": "NewPass123!", "new_password2": "NewPass123!",
    }, follow_redirects=True)
    assert rok.status_code == 200
    after = m.load_users()["users"][uname]
    assert check_password_hash(after["password_hash"], "NewPass123!")

    # 5) Token is single-use — cleared after success, and cannot be reused
    assert not (after.get("reset") or {}).get("token_hash")
    reuse = client.post("/reset_password", data={
        "username": uname, "token": token,
        "new_password": "Another123!", "new_password2": "Another123!",
    }, follow_redirects=True)
    assert "invalid or expired" in reuse.get_data(as_text=True).lower()
