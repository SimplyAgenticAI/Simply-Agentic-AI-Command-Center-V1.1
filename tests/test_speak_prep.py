"""Alive spoken delivery: /api/speak_prep fallback contract + /api/tts unchanged."""
import pytest

import app as app_module


@pytest.fixture()
def auth_client(flask_app):
    """Register-or-login (order-independent) + CSRF token."""
    with flask_app.test_client() as c:
        c.post("/register", data={
            "username": "smoketest", "email": "",
            "password": "TestPass123!", "password2": "TestPass123!",
            "tos_accepted": "on",
        }, follow_redirects=True)
        c.post("/login", data={"username": "smoketest", "password": "TestPass123!"},
               follow_redirects=True)
        c.csrf_token = c.get("/api/csrf_token").get_json()["csrf_token"]
        yield c


def test_speak_prep_requires_auth(client):
    # Unauthenticated POST is rejected — 403 (CSRF layer, which runs first) or
    # 401 (auth check) are both a locked door.
    assert client.post("/api/speak_prep", json={"text": "hi"}).status_code in (401, 403)


def test_speak_prep_fallback_contract_without_key(auth_client, monkeypatch):
    # No key anywhere -> MUST still return ok with the raw text so the Speak
    # button always produces audio. (Monkeypatch guards against a dev machine
    # having a real OPENAI_API_KEY in the environment.)
    monkeypatch.setattr(app_module, "OPENAI_API_KEY", "")
    r = auth_client.post("/api/speak_prep",
                         json={"text": "Here is your prompt for today.",
                               "teammate": "Alex", "local_hour": 9},
                         headers={"X-CSRF-Token": auth_client.csrf_token})
    assert r.status_code == 200
    d = r.get_json()
    assert d["ok"] is True
    assert d["fallback"] is True
    assert d["spoken"] == "Here is your prompt for today."
    assert "Alex" in d["delivery"]


def test_speak_prep_missing_text(auth_client):
    r = auth_client.post("/api/speak_prep", json={"text": ""},
                         headers={"X-CSRF-Token": auth_client.csrf_token})
    assert r.status_code == 400


def test_tts_with_instructions_still_requires_key(auth_client, monkeypatch):
    # The new instructions param must not change the no-key behavior (400).
    monkeypatch.setattr(app_module, "OPENAI_API_KEY", "")
    r = auth_client.post("/api/tts",
                         json={"text": "hello", "voice": "alloy", "instructions": "warm"},
                         headers={"X-CSRF-Token": auth_client.csrf_token})
    assert r.status_code == 400
