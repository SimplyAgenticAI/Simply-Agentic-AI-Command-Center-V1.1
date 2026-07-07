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


