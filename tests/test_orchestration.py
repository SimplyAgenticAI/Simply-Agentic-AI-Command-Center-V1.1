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
