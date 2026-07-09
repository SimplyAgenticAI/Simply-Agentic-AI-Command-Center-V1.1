"""Tests for Phase 2 team orchestration (server-side engine)."""
import app as app_module


def test_parse_plan_json_tolerant():
    good = app_module._parse_plan_json('```json\n{"steps":[{"teammate":"Alex","task":"plan it"}]}\n```')
    assert good.get("steps") and good["steps"][0]["teammate"] == "Alex"
    assert app_module._parse_plan_json("not json at all") == {}


def test_orchestrate_empty_goal_is_rejected():
    res = app_module._orchestrate_goal("u", "")
    assert res["ok"] is False


def test_orchestrate_returns_dict_and_never_raises():
    # Without an API key the planner can't run -> {ok: False}, but it must always
    # return a structured dict, never raise.
    res = app_module._orchestrate_goal("orch_test_user", "grow my coaching business this quarter")
    assert isinstance(res, dict) and "ok" in res


def test_orchestrate_endpoint_requires_auth():
    with app_module.app.test_client() as c:
        resp = c.post("/api/team/orchestrate", json={"goal": "launch a newsletter"})
        assert resp.status_code in (401, 403)
        assert resp.status_code != 200


def _wire_fake_team(monkeypatch):
    """Deterministic roster + LLM + teammate runner so the orchestration logic can
    be tested end-to-end without any API key."""
    monkeypatch.setattr(app_module, "load_registry",
                        lambda u="": {"installed": {"Alex": {"job_title": "Strategist"},
                                                    "Willow": {"job_title": "Copywriter"}}})
    plan = '{"steps":[{"teammate":"Alex","task":"plan the campaign"},{"teammate":"Willow","task":"write the copy"}]}'

    def _fake_llm(system, messages, temperature=0.6, model=None, _fallback=False):
        return plan if "orchestrator" in (system or "").lower() else "FINAL SYNTHESIS"

    monkeypatch.setattr(app_module, "call_llm", _fake_llm)
    monkeypatch.setattr(app_module, "_call_teammate_prompt_for_user",
                        lambda u, tm, prompt, file_ids=None: f"{tm}-output")


def test_orchestrate_full_flow(monkeypatch):
    _wire_fake_team(monkeypatch)
    res = app_module._orchestrate_goal("u", "launch a product")
    assert res["ok"] is True
    assert [s["teammate"] for s in res["steps"]] == ["Alex", "Willow"]
    assert res["steps"][0]["output"] == "Alex-output"
    assert res["synthesis"] == "FINAL SYNTHESIS"


def test_orchestrate_events_sequence(monkeypatch):
    _wire_fake_team(monkeypatch)
    events = list(app_module._orchestrate_goal_events("u", "launch"))
    types = [e["type"] for e in events]
    assert types[0] == "plan"
    assert types.count("step") == 2
    assert "synthesis" in types
    assert types[-1] == "done"


def test_orchestrate_no_teammates_errors(monkeypatch):
    monkeypatch.setattr(app_module, "load_registry", lambda u="": {"installed": {}})
    res = app_module._orchestrate_goal("u", "do something")
    assert res["ok"] is False


def test_orchestrate_step_events_carry_actions(monkeypatch):
    # Tool-capable steps: outputs + tool summaries propagate into step events.
    _wire_fake_team(monkeypatch)
    monkeypatch.setattr(app_module, "_user_has_own_key", lambda u: True)
    monkeypatch.setattr(
        app_module, "call_llm_with_tools",
        lambda system, messages, temperature=0.65, model=None, username="anon", u=None, teammate="Alex":
        (f"{teammate}-tool-output", [{"tool": "crm_add_client", "args": {}, "result": "Added Jamie to the CRM."}]))
    # Production always runs inside a request context (the endpoint, and the SSE
    # generator via stream_with_context); teammate_system_prompt depends on it.
    with app_module.app.test_request_context():
        events = list(app_module._orchestrate_goal_events("u", "launch"))
    steps = [e for e in events if e["type"] == "step"]
    assert len(steps) == 2
    assert steps[0]["output"] == "Alex-tool-output"
    assert steps[0]["actions"] == ["Added Jamie to the CRM."]


def test_orchestrate_fallback_keeps_old_shape(monkeypatch):
    # If the tool loop fails (no key, model error), steps fall back to the plain
    # text runner and still carry an (empty) actions list - never degraded.
    _wire_fake_team(monkeypatch)
    def _boom(*a, **k):
        raise RuntimeError("no key")
    monkeypatch.setattr(app_module, "call_llm_with_tools", _boom)
    with app_module.app.test_request_context():
        events = list(app_module._orchestrate_goal_events("u", "launch"))
    steps = [e for e in events if e["type"] == "step"]
    assert steps[0]["output"] == "Alex-output"
    assert steps[0]["actions"] == []




def test_orchestrate_stream_endpoint_returns_sse_not_500(flask_app):
    # Launch-day bug: this route referenced Response/stream_with_context without
    # the function-local flask import, so EVERY request 500d before the first
    # event. A real authenticated POST must return a 200 SSE stream (whose first
    # event may legitimately be an in-band error in the key-less test env).
    with flask_app.test_client() as c:
        c.post("/register", data={"username": "smoketest", "email": "",
                                  "password": "TestPass123!", "password2": "TestPass123!",
                                  "tos_accepted": "on"}, follow_redirects=True)
        c.post("/login", data={"username": "smoketest", "password": "TestPass123!"},
               follow_redirects=True)
        tok = c.get("/api/csrf_token").get_json()["csrf_token"]
        r = c.post("/api/team/orchestrate/stream", json={"goal": "test the plumbing"},
                   headers={"X-CSRF-Token": tok})
        assert r.status_code == 200
        assert "text/event-stream" in (r.content_type or "")
        assert r.get_data(as_text=True).startswith("data:")


def test_orchestrate_step_events_carry_pending_approvals(monkeypatch):
    # Escalated tool calls (write-after-external-read guard) surface as pending
    # approval items on the step event instead of dead-ending.
    _wire_fake_team(monkeypatch)
    monkeypatch.setattr(app_module, "_user_has_own_key", lambda u: True)
    monkeypatch.setattr(
        app_module, "call_llm_with_tools",
        lambda system, messages, temperature=0.65, model=None, username="anon", u=None, teammate="Alex":
        (f"{teammate}-out", [
            {"tool": "research", "args": {"query": "niche"}, "result": "Pulled context.", "pending": False},
            {"tool": "crm_add_client", "args": {"name": "Lead Larry"}, "result": "needs approval", "pending": True},
        ]))
    with app_module.app.test_request_context():
        events = list(app_module._orchestrate_goal_events("u", "launch"))
    steps = [e for e in events if e["type"] == "step"]
    assert steps[0]["actions"] == ["Pulled context."]
    assert len(steps[0]["pending"]) == 1
    p = steps[0]["pending"][0]
    assert p["action"] == "crm_add_client"
    assert p["args"]["name"] == "Lead Larry"
    assert "Lead Larry" in p["summary"]
