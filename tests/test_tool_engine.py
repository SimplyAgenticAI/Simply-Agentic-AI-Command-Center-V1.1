"""Tests for the Phase 1 teammate tool engine (additive â€” does not touch chat)."""
import app as app_module


def test_tool_defs_well_formed():
    defs = app_module._TEAMMATE_TOOL_DEFS
    assert defs, "expected at least one tool def"
    seen = set()
    for t in defs:
        assert t["name"] and t["name"] not in seen, f"duplicate/empty tool name: {t.get('name')}"
        seen.add(t["name"])
        assert t["description"]
        assert t["risk"] in ("auto", "confirm")
        assert callable(t["executor"])
        params = t["parameters"]
        assert params.get("type") == "object"
        assert "properties" in params


def test_openai_and_anthropic_schemas_build():
    oai = app_module._tools_openai_schema()
    ant = app_module._tools_anthropic_schema()
    assert len(oai) == len(ant) == len(app_module._TEAMMATE_TOOL_DEFS)
    for f in oai:
        assert f["type"] == "function"
        assert f["function"]["name"] and f["function"]["parameters"]
    for a in ant:
        assert a["name"] and a["input_schema"]


def test_risk_classification():
    assert app_module._tool_risk("generate_image") == "auto"
    assert app_module._tool_risk("crm_find_client") == "auto"
    # Unknown tool defaults to the safe side (confirm).
    assert app_module._tool_risk("does_not_exist") == "confirm"


def test_draft_email_executor():
    res = app_module._tool_draft_email("u", "Willow",
                                       {"to": "a@b.com", "subject": "Hi", "body": "Hello there"})
    assert res["ok"] is True
    assert res["draft"]["to"] == "a@b.com"
    assert res["draft"]["body"] == "Hello there"
    # Missing body fails gracefully.
    bad = app_module._tool_draft_email("u", "Willow", {"subject": "x"})
    assert bad["ok"] is False


def test_crm_add_then_find_roundtrip():
    uname = "tooltest_crm"
    add = app_module._execute_teammate_tool(
        "crm_add_client", {"name": "Jamie Cole", "email": "jamie@gsrealty.com",
                           "company": "Garden State Realty"}, uname, "Ava")
    assert add["ok"] is True
    assert add["client_id"]

    found = app_module._execute_teammate_tool(
        "crm_find_client", {"query": "jamie"}, uname, "Ava")
    assert found["ok"] is True
    assert any(m["name"] == "Jamie Cole" for m in found["matches"])

    # Search by company also works.
    found2 = app_module._execute_teammate_tool(
        "crm_find_client", {"query": "garden state"}, uname, "Ava")
    assert any("Garden State" in m["company"] for m in found2["matches"])


def test_unknown_tool_is_safe():
    res = app_module._execute_teammate_tool("nope", {}, "u", "Ava")
    assert res["ok"] is False
    assert "Unknown tool" in res["summary"]


def test_research_never_raises():
    # Without an OpenAI key RAG can't embed â€” must still return a dict, not raise.
    res = app_module._execute_teammate_tool("research", {"query": "pricing"}, "tooltest_rag", "Ava")
    assert isinstance(res, dict) and "ok" in res


def test_send_email_is_confirm_risk():
    assert app_module._tool_risk("send_email") == "confirm"
    assert "send_email" in app_module._TOOL_BY_NAME


def test_send_email_missing_fields_fails_safely():
    res = app_module._execute_teammate_tool("send_email", {"subject": "Hi"}, "u", "Willow")
    assert res["ok"] is False  # no recipient/body


def test_confirm_summary_is_human_readable():
    s = app_module._confirm_summary("send_email", {"to": "john@x.com", "subject": "Proposal"})
    assert "john@x.com" in s


def test_action_execute_endpoint_requires_auth():
    with app_module.app.test_client() as c:
        resp = c.post("/api/teammate/action/execute")
        assert resp.status_code in (401, 403)
        assert resp.status_code != 200


def test_read_url_is_auto_and_safe():
    assert app_module._tool_risk("read_url") == "auto"
    assert "read_url" in app_module._TOOL_BY_NAME
    # Empty URL fails gracefully; never raises.
    res = app_module._execute_teammate_tool("read_url", {"url": ""}, "u", "Ava")
    assert res["ok"] is False


def test_injection_guard_escalates_mutating_tools_after_external_content():
    # No untrusted content read yet â†’ auto stays auto.
    assert app_module._effective_tool_risk("crm_add_client", False) == "auto"
    # After reading untrusted external content, state-mutating auto tools escalate
    # to confirm so injected instructions can't silently write to the CRM.
    assert app_module._effective_tool_risk("crm_add_client", True) == "confirm"
    assert app_module._effective_tool_risk("crm_log_activity", True) == "confirm"
    # Non-mutating auto tools are unaffected.
    assert app_module._effective_tool_risk("generate_image", True) == "auto"
    assert app_module._effective_tool_risk("read_url", True) == "auto"
    # Already-confirm tools stay confirm regardless.
    assert app_module._effective_tool_risk("send_email", True) == "confirm"
    assert app_module._effective_tool_risk("send_email", False) == "confirm"


def test_set_session_objective_tool():
    uname = "smoketest"
    res = app_module._execute_teammate_tool(
        "set_session_objective", {"title": "Dominate Q3 outreach"}, uname, "Sunshine")
    assert res["ok"], res
    osd = app_module._os_load(uname)
    assert osd["session_objective"]["title"] == "Dominate Q3 outreach"
    # auto-risk, present in the schemas, and reachable through the chat gate
    assert app_module._tool_risk("set_session_objective") == "auto"
    assert "set_session_objective" in [t["function"]["name"] for t in app_module._tools_openai_schema()]
    assert app_module._msg_may_need_tools("Sunshine, change the session objective to launch the new funnel")
    # empty title rejected cleanly
    bad = app_module._execute_teammate_tool("set_session_objective", {}, uname, "Sunshine")
    assert bad["ok"] is False


def test_action_execute_accepts_operator_approved_auto_tool(flask_app):
    # The confirm endpoint now runs ANY registered tool on explicit operator
    # click - needed for escalated-auto approvals from Team Goal runs.
    # Own register-or-login client: the shared fixture is first-registration-wins.
    with flask_app.test_client() as c:
        c.post("/register", data={"username": "smoketest", "email": "",
                                  "password": "TestPass123!", "password2": "TestPass123!",
                                  "tos_accepted": "on"}, follow_redirects=True)
        c.post("/login", data={"username": "smoketest", "password": "TestPass123!"},
               follow_redirects=True)
        tok = c.get("/api/csrf_token").get_json()["csrf_token"]
        r = c.post("/api/teammate/action/execute",
                   json={"action": "crm_add_client",
                         "args": {"name": "Approved Andy", "email": "andy@x.com"},
                         "teammate": "Sunshine"},
                   headers={"X-CSRF-Token": tok})
        assert r.status_code == 200
        d = r.get_json()
        assert d["ok"] is True
        crm = app_module._crm_load("smoketest")
        assert any(cl.get("name") == "Approved Andy" for cl in crm["clients"].values())

        r2 = c.post("/api/teammate/action/execute",
                    json={"action": "not_a_tool", "args": {}, "teammate": "Alex"},
                    headers={"X-CSRF-Token": tok})
        assert r2.status_code == 400

