"""V14.5 Notepad: per-note autosave, team-knows-this notes in teammate
prompts, Turn into actions (propose → apply), voice notes.
(File must sort after test_client_crud — conftest's auth_client wants to be
the first registration.)"""
import json

import pytest

import app as app_module

U = "np145user"


@pytest.fixture()
def np(flask_app, monkeypatch):
    data = app_module.load_users()
    data.setdefault("users", {})[U] = {"username": U, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    app_module._save_notes(U, [])
    app_module._crm_save(U, {"clients": {}, "pipeline": {"stages": app_module._default_pipeline_stages()}})
    c = flask_app.test_client()
    with c.session_transaction() as s:
        s["user"] = U
    h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
    yield c, h
    data = app_module.load_users()
    (data.get("users") or {}).pop(U, None)
    app_module.save_users(data)
    app_module._invalidate_users_cache()


def test_autosave_touches_only_one_note(np):
    c, h = np
    app_module._save_notes(U, [{"id": 1, "title": "keep me", "content": "x"}])
    r = c.post("/api/notepad/note", headers=h, json={"id": 2, "title": "new", "content": "hello"}).get_json()
    assert r["ok"] and r["note"]["id"] == 2
    c.post("/api/notepad/note", headers=h, json={"id": 2, "content": "hello again", "pinned": True})
    notes = {n["id"]: n for n in app_module._load_notes(U)}
    assert notes[1]["title"] == "keep me" and notes[2]["content"] == "hello again" and notes[2]["pinned"] is True
    assert c.post("/api/notepad/delete", headers=h, json={"ids": [2]}).get_json()["deleted"] == 1
    assert [n["id"] for n in app_module._load_notes(U)] == [1]


def test_team_note_reaches_teammate_prompt(np):
    c, h = np
    c.post("/api/notepad/note", headers=h, json={"id": 5, "title": "Pricing", "content": "Starter is $499/mo, no discounts.", "team": True})
    with app_module.app.test_request_context("/"):
        from flask import session
        session["user"] = U
        app_module._invalidate_sys_prompt_cache()
        p = app_module.teammate_system_prompt(dict(app_module.PREBUILT_LOCKED["Sunshine"]), tools_enabled=True)
    assert "TEAM NOTES" in p and "$499/mo" in p


def test_turn_into_actions_proposes_and_applies(np, monkeypatch):
    c, h = np
    existing = c.post("/api/crm/clients", headers=h, json={"name": "Dana Lee", "email": "dana@example.com"}).get_json()["client"]
    monkeypatch.setattr(app_module, "call_llm", lambda *a, **k: json.dumps({
        "contacts": [{"name": "Dana Lee", "note": "wants a quote"}, {"name": "Sam Ortiz", "email": "sam@example.com", "company": "Ortiz HVAC"}],
        "tasks": [{"title": "Send Dana the quote", "date": "2031-05-02", "time": "10:00"}],
        "emails": [{"name": "Sam Ortiz", "purpose": "thanks for the call, next steps"}, {"name": "Nobody Known", "purpose": "x"}]}))
    prop = c.post("/api/notepad/actions", headers=h, json={"content": "Call with Dana Lee and Sam Ortiz today, follow up."}).get_json()
    assert prop["contacts"][0]["existing_id"] == existing["id"] and not prop["contacts"][1]["existing_id"]
    assert [e["can_send"] for e in prop["emails"]] == [True, False]

    emitted = []
    monkeypatch.setattr(app_module, "_AGENT_EVENTS_ON", True)
    monkeypatch.setattr(app_module, "_AGENT_EVENTS_INLINE", True)
    monkeypatch.setattr(app_module, "_agent_handle_event", lambda u, ev, d: emitted.append(ev))
    monkeypatch.setattr(app_module, "_agent_draft_email", lambda u, cl, purpose: ("Next steps", f"Hi {cl['name']}, {purpose}"))
    r = c.post("/api/notepad/actions/apply", headers=h, json={"contacts": prop["contacts"], "tasks": prop["tasks"],
                                                              "emails": prop["emails"][:1], "note_title": "Calls"}).get_json()
    assert r["ok"] and len(r["done"]) == 4, r
    clients = app_module._crm_load(U)["clients"].values()
    assert sorted(x["name"] for x in clients) == ["Dana Lee", "Sam Ortiz"]       # Dana not duplicated
    appr = [a for a in app_module._agent_load(U)["approvals"] if a.get("status") == "pending"]
    assert len(appr) == 1 and appr[0]["kind"] == "note_followup" and appr[0]["to"] == "sam@example.com"
    assert emitted == []          # no extra "new contact hello" draft for Sam


def test_voice_needs_a_key(np, monkeypatch):
    c, h = np
    monkeypatch.setattr(app_module, "_vc_openai_key", lambda u: "")
    import io
    r = c.post("/api/notepad/voice", headers=h, data={"audio": (io.BytesIO(b"x" * 2000), "memo.webm")},
               content_type="multipart/form-data")
    assert r.status_code == 400 and "OpenAI key" in r.get_json()["error"]
