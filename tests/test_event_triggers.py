"""Event triggers (V12.4): when a contact is created (manual add, CSV import),
the new-contact rule drafts a hello into Ready for you — or sends it if that
kind is trusted. LLM and email are mocked; events run inline."""
import json

import pytest

import app as app_module


@pytest.fixture()
def trig(flask_app, monkeypatch):
    uname = "triggeruser"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    c = flask_app.test_client()
    with c.session_transaction() as s:
        s["user"] = uname
    h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
    sent, llm_calls = [], []
    monkeypatch.setattr(app_module, "_crm_send_email_to",
                        lambda u, to, subj, body, from_name="": (sent.append((to, subj, body)) or True, "smtp", ""))
    monkeypatch.setattr(app_module, "call_llm", lambda *a, **k: llm_calls.append(1) or json.dumps(
        {"subject": "Welcome", "body": "Hi, glad to connect.", "to": "attacker@evil.example"}))
    monkeypatch.setattr(app_module, "_check_msg_limit", lambda u, p: (True, 0, 0, 0, 0, False))
    monkeypatch.setattr(app_module, "_AGENT_EVENTS_ON", True)
    monkeypatch.setattr(app_module, "_AGENT_EVENTS_INLINE", True)
    app_module._crm_save(uname, {"clients": {}, "pipeline": {"stages": app_module._default_pipeline_stages()}})
    app_module._agent_path(uname).unlink(missing_ok=True)
    return c, h, uname, sent, llm_calls


def test_new_contact_drafts_hello_and_bumps_rev(trig):
    c, h, uname, sent, _ = trig
    rev0 = c.get("/api/agent/rev").get_json()["rev"]
    r = c.post("/api/crm/clients", headers=h, json={"name": "Dana Lee", "email": "dana@x.example"}).get_json()
    assert r["ok"]
    view = c.get("/api/agent").get_json()
    ap = [a for a in view["approvals"] if a["client_id"] == r["client"]["id"]]
    assert len(ap) == 1 and ap[0]["kind"] == "new_contact" and ap[0]["trigger"] == "New contact"
    assert ap[0]["to"] == "dana@x.example" and sent == []          # drafted, not sent
    assert view["rev"] > rev0 and c.get("/api/agent/rev").get_json()["rev"] == view["rev"]
    assert any(t["kind"] == "new_contact" for t in view["trust"])
    assert [x["key"] for x in view["rules"]] == ["contact_created"]


def test_no_email_or_rule_off_means_no_draft(trig):
    c, h, uname, sent, llm_calls = trig
    c.post("/api/crm/clients", headers=h, json={"name": "No Email"})
    c.post("/api/agent/settings", headers=h, json={"rule": "contact_created", "enabled": False})
    c.post("/api/crm/clients", headers=h, json={"name": "Off Rule", "email": "off@x.example"})
    assert c.get("/api/agent").get_json()["approvals"] == [] and llm_calls == []


def test_csv_import_capped_and_skips_existing_customers(trig):
    c, h, uname, sent, llm_calls = trig
    rows = "\n".join(f"Lead {i},lead{i}@x.example,Lead" for i in range(8))
    csv_text = "name,email,stage\nOld Client,old@x.example,Client\n" + rows + "\n"
    r = c.post("/api/crm/clients/import_csv", headers=h, json={"csv_text": csv_text}).get_json()
    assert r["imported"] == 9
    ap = c.get("/api/agent").get_json()["approvals"]
    assert len(ap) == app_module.AGENT_EVENT_MAX and len(llm_calls) == app_module.AGENT_EVENT_MAX
    assert all(a["to"] != "old@x.example" for a in ap)
    assert any("more skipped" in x["text"] for x in app_module._agent_load(uname)["log"])


def test_trusted_kind_auto_sends_to_contact_only(trig):
    c, h, uname, sent, _ = trig
    c.post("/api/agent/settings", headers=h, json={"trust": "new_contact", "auto": True})
    c.post("/api/crm/clients", headers=h, json={"name": "Eve Ok", "email": "eve@x.example"})
    assert sent == [("eve@x.example", "Welcome", "Hi, glad to connect.")]      # never the model's address
    view = c.get("/api/agent").get_json()
    assert view["approvals"] == [] and [a["client_name"] for a in view["sent_for_you"]] == ["Eve Ok"]


def test_morning_intro_trust_does_not_auto_send_new_contacts(trig):
    c, h, uname, sent, _ = trig
    c.post("/api/agent/settings", headers=h, json={"trust": "intro", "auto": True})
    c.post("/api/crm/clients", headers=h, json={"name": "Sam", "email": "sam@x.example"})
    assert sent == [] and len(c.get("/api/agent").get_json()["approvals"]) == 1


def test_events_off_under_pytest_by_default():
    # unrelated tests that add contacts must never reach the model
    assert app_module._AGENT_EVENTS_ON is False
