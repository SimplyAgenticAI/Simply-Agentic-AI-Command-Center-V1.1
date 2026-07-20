"""Regression tests for OAuth state → user binding (V8.3).

The Gmail/Calendar callbacks have a file-based state fallback for hosts that
drop the session cookie across the Google redirect. That store is global, and
the callbacks only checked "does a record for this state exist?" — so an
attacker's valid state + authorization code could bind THEIR Google account to
a victim's logged-in session (OAuth account-linking CSRF). The fallback now
requires the stored state to belong to the current user.
"""
import app as app_module


def _seed_state(state, username):
    data = app_module._load_oauth_states()
    data[state] = {"username": username, "at": app_module.now_iso()}
    app_module._save_oauth_states(data)


def test_consume_records_username():
    _seed_state("state-abc", "alice")
    rec = app_module._consume_oauth_state("state-abc")
    assert rec and rec.get("username") == "alice"


def test_gmail_callback_rejects_another_users_state(monkeypatch, client):
    # Attacker seeded this state during their own /gmail/connect.
    _seed_state("attacker-state", "attacker")

    # Victim is logged in; force OAuth "ready" so we reach the state check.
    monkeypatch.setattr(app_module, "_google_oauth_ready", lambda: (True, ""))
    monkeypatch.setattr(app_module, "current_user",
                        lambda: {"username": "victim", "is_admin": False})

    called = {"exchanged": False}
    monkeypatch.setattr(app_module, "_oauth_exchange_code",
                        lambda code, path: (called.update(exchanged=True) or ({"access_token": "x"}, "")))

    resp = client.get("/gmail/callback?code=attacker_code&state=attacker-state")
    assert resp.status_code == 400
    assert b"State Mismatch" in resp.data
    assert called["exchanged"] is False, "must not exchange a code for a foreign state"


def test_gmail_callback_accepts_own_state(monkeypatch, client):
    _seed_state("victim-state", "victim")
    monkeypatch.setattr(app_module, "_google_oauth_ready", lambda: (True, ""))
    monkeypatch.setattr(app_module, "current_user",
                        lambda: {"username": "victim", "is_admin": False})

    exchanged = {"ok": False}

    def _fake_exchange(code, path):
        exchanged["ok"] = True
        return {"access_token": "tok", "refresh_token": "r"}, ""

    monkeypatch.setattr(app_module, "_oauth_exchange_code", _fake_exchange)
    monkeypatch.setattr(app_module, "_save_user_gmail_oauth", lambda u, t: None)

    resp = client.get("/gmail/callback?code=good_code&state=victim-state")
    # Own state passes the gate, so the code is exchanged (no 400 mismatch page).
    assert exchanged["ok"] is True
    assert b"State Mismatch" not in resp.data


def test_calendar_callback_rejects_another_users_state(monkeypatch, client):
    _seed_state("cal_attacker-state", "attacker")
    monkeypatch.setattr(app_module, "_google_oauth_ready", lambda: (True, ""))
    monkeypatch.setattr(app_module, "current_user",
                        lambda: {"username": "victim", "is_admin": False})

    called = {"exchanged": False}
    monkeypatch.setattr(app_module, "_oauth_exchange_code",
                        lambda code, path: (called.update(exchanged=True) or ({"access_token": "x"}, "")))

    resp = client.get("/calendar/callback?code=attacker_code&state=attacker-state")
    assert resp.status_code == 400
    assert b"State Mismatch" in resp.data
    assert called["exchanged"] is False
