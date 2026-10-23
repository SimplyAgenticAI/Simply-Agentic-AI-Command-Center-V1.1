"""V15.2 lead quality: deleted contacts are never re-added by automatic lead
finding, and an AI check keeps only specific teams/people (not brands).
(File must sort after test_client_crud — conftest's auth_client wants to be
the first registration.)"""
import pytest

import app as app_module

U = "leadqualuser"


@pytest.fixture()
def lq(flask_app):
    data = app_module.load_users()
    data.setdefault("users", {})[U] = {"username": U, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    app_module._crm_save(U, {"clients": {}, "pipeline": {"stages": app_module._default_pipeline_stages()}})
    (app_module._REMOVED_DIR / f"{app_module._safe_name(U)}.json").unlink(missing_ok=True)
    c = flask_app.test_client()
    with c.session_transaction() as s:
        s["user"] = U
    h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
    yield c, h
    data = app_module.load_users()
    (data.get("users") or {}).pop(U, None)
    app_module.save_users(data)
    app_module._invalidate_users_cache()


def test_deleted_leads_are_never_readded(lq, monkeypatch):
    c, h = lq
    app_module._quickstart_add_leads(U, [{"name": "Keller Williams", "company": "Keller Williams", "website": "https://www.kw.com"},
                                         {"name": "Ace Team", "company": "Ace Team", "email": "ace@ace.example"}], ["found-by-teammate"])
    ids = list(app_module._crm_load(U)["clients"])
    assert c.post("/api/crm/clients/bulk", headers=h, json={"ids": ids, "action": "delete"}).get_json()["ok"]
    monkeypatch.setattr(app_module, "call_llm", lambda *a, **k: '{"keep": [0, 1, 2]}')
    again = [{"name": "Keller Williams", "company": "Keller Williams", "website": "https://kw.com/"},   # same site
             {"name": "Ace Team Realty", "company": "Ace Team Realty", "email": "ACE@ace.example"},    # same email
             {"name": "Brand New Team", "company": "Brand New Team", "website": "https://newteam.example"}]
    kept = app_module._vet_leads(U, again, "real estate teams in NJ", 10)
    assert [k["name"] for k in kept] == ["Brand New Team"]


def test_ai_check_drops_brands_and_fails_closed(lq, monkeypatch):
    seen = {}
    def fake_llm(system, msgs, **k):
        seen["prompt"] = msgs[0]["content"]
        return '{"keep": [1]}'
    monkeypatch.setattr(app_module, "call_llm", fake_llm)
    leads = [{"name": "RE/MAX", "company": "RE/MAX", "website": "https://remax.com"},
             {"name": "The Stacey Smith Team", "company": "The Stacey Smith Team", "website": "https://staceysmithteam.example"}]
    kept = app_module._vet_leads(U, leads, "independent real estate teams in Monmouth County, NJ", 10)
    assert [k["name"] for k in kept] == ["The Stacey Smith Team"]
    assert "Monmouth County" in seen["prompt"]                     # judged against the Profile audience
    monkeypatch.setattr(app_module, "call_llm", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")))
    assert app_module._vet_leads(U, leads, "x", 10) == []          # can't check → add nothing, not junk


def test_single_delete_and_undo_are_remembered(lq):
    c, h = lq
    r = c.post("/api/crm/clients", headers=h, json={"name": "Solo Agent", "email": "solo@agent.example"}).get_json()
    assert c.delete(f"/api/crm/clients/{r['client']['id']}", headers=h).get_json()["ok"]
    assert "solo@agent.example" in app_module._crm_removed(U)["emails"]
