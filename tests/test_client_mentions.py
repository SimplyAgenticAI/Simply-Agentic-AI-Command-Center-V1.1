"""Contacts named in a chat message are found automatically (V10.4) — no
manual Client picker. CRM is stubbed."""
import app as app_module

CLIENTS = {"clients": {
    "c1": {"id": "c1", "name": "Sarah Jones", "company": "Bright Dental", "email": "s@bd.example", "pipeline_stage": "Interested", "notes": "Wants a new site"},
    "c2": {"id": "c2", "name": "Will Turner", "company": "", "email": "w@x.example"},
    "c3": {"id": "c3", "name": "Mark Lee", "company": "Lee Roofing"},
    "c4": {"id": "c4", "name": "Mark Diaz", "company": ""},
}}


def _names(monkeypatch, msg):
    monkeypatch.setattr(app_module, "_crm_load", lambda u: CLIENTS)
    return [c["name"] for c in app_module._crm_clients_mentioned("u", msg)]


def test_full_name_company_and_unique_first_name(monkeypatch):
    assert _names(monkeypatch, "draft a follow up to sarah jones") == ["Sarah Jones"]
    assert _names(monkeypatch, "how is the bright dental deal going?") == ["Sarah Jones"]
    assert _names(monkeypatch, "What should I say to Sarah tomorrow?") == ["Sarah Jones"]
    assert _names(monkeypatch, "email Will about the proposal") == ["Will Turner"]


def test_no_false_matches(monkeypatch):
    assert _names(monkeypatch, "I will send it later") == []               # lowercase common word
    assert _names(monkeypatch, "Mark it done") == []                       # two contacts named Mark
    assert _names(monkeypatch, "call Lee Roofing and Sarah Jones") == ["Sarah Jones", "Mark Lee"]


def test_context_block_has_real_details(monkeypatch):
    monkeypatch.setattr(app_module, "_crm_load", lambda u: CLIENTS)
    monkeypatch.setattr(app_module, "_crm_activity_log", lambda u, cid: [{"at": "2026-10-01T00:00:00Z", "detail": "Intro email sent"}])
    block = app_module._crm_mentioned_context("u", "prep me for my call with Sarah Jones")
    assert "Bright Dental" in block and "Interested" in block and "Intro email sent" in block and "client_id c1" in block
    assert app_module._crm_mentioned_context("u", "hello there") == ""


def test_malformed_api_input_is_400_not_500(flask_app):
    data = app_module.load_users()
    c = flask_app.test_client()
    # any logged-in session works; reuse an existing test user if present, else create one
    data.setdefault("users", {})["badinput"] = {"username": "badinput", "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    with c.session_transaction() as s:
        s["user"] = "badinput"
    h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
    r = c.post("/api/vault/save", headers=h, json={"text": {"x": 1}, "label": ["y"]})
    assert r.status_code == 400 and "expected format" in r.get_json()["error"]
