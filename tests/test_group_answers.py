"""Send-to-all (V10.5): each teammate answers from its own lane, and one
combined team answer is produced from all replies. LLM is mocked."""
import pytest

import app as app_module


@pytest.fixture()
def member(flask_app):
    uname = "groupuser"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    c = flask_app.test_client()
    with c.session_transaction() as s:
        s["user"] = uname
    return c, {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}


def test_lane_block_names_role_and_team_size():
    block = app_module._group_lane_block({"job_title": "Sales Specialist"}, 7)
    assert "7 teammates" in block and "as Sales Specialist" in block and "nothing distinct" in block


def test_synthesis_combines_answers(member, monkeypatch):
    c, h = member
    seen = {}

    def fake_llm(system, messages, temperature=0.6, model=None, _fallback=False):
        seen["body"] = messages[0]["content"]
        seen["system"] = system
        return "**The plan** — Raise prices.\n**Where they disagree** — none.\n**Next steps** — 1. Update pricing page (Alex)"
    monkeypatch.setattr(app_module, "call_llm", fake_llm)
    r = c.post("/api/group/synthesize", headers=h, json={"question": "Should I raise prices?", "answers": {
        "Alex": "Yes, raise them 20%.", "Sunshine": "Yes, but grandfather current clients.", "Ava": "(error)", "Luna": "…"}}).get_json()
    assert r["ok"] and r["text"].startswith("**The plan**")
    assert "### Alex" in seen["body"] and "### Sunshine" in seen["body"] and "Ava" not in seen["body"]
    assert "Where they disagree" in seen["system"]


def test_synthesis_needs_two_real_answers(member):
    c, h = member
    r = c.post("/api/group/synthesize", headers=h, json={"question": "q", "answers": {"Alex": "a", "Ava": "(timed out)"}})
    assert r.status_code == 400
