"""V19.9 Missions engine: plain-English standing jobs a teammate runs in the
background. Emails only to existing contacts (address from the record), held
actions run exactly as stored, failures auto-pause, plan limits apply.
(File must sort after test_client_crud.)"""
import json
import types
from datetime import datetime
import app as app_module


# ── fake OpenAI client: plays back a scripted list of model turns ─────────────
def _call(i, name, args):
    return types.SimpleNamespace(id=f"c{i}", function=types.SimpleNamespace(name=name, arguments=json.dumps(args)))


def _turn(content="", calls=None):
    msg = types.SimpleNamespace(content=content, tool_calls=calls or None)
    return types.SimpleNamespace(choices=[types.SimpleNamespace(message=msg, finish_reason="stop" if not calls else "tool_calls")],
                                 usage=None)


class _FakeOAI:
    def __init__(self, turns=None, fail=False):
        self.turns, self.fail, self.n = list(turns or []), fail, 0
        outer = self

        class _Comp:
            @staticmethod
            def create(**kw):
                outer.n += 1
                if outer.fail:
                    raise RuntimeError("model down")
                return outer.turns.pop(0) if outer.turns else _turn("Done.")
        self.chat = types.SimpleNamespace(completions=_Comp())


def _user(name, plan_seat=None):
    data = app_module.load_users()
    data.setdefault("users", {})[name] = {"username": name, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    p = app_module._agent_path(name)
    if p.exists():
        p.unlink()


def _drop(name):
    data = app_module.load_users()
    (data.get("users") or {}).pop(name, None)
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    p = app_module._agent_path(name)
    if p.exists():
        p.unlink()


def _client(flask_app, name):
    c = flask_app.test_client()
    with c.session_transaction() as s:
        s["user"] = name
    h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
    return c, h


MISSION = {"title": "Weekly posts", "instruction": "Draft three posts about our spring special.",
           "teammate": "Willow", "schedule": {"kind": "weekly", "hour": 9, "days": [0]}}


def test_create_validate_and_plan_limit(flask_app, monkeypatch):
    name = "missionlimits"
    _user(name)
    monkeypatch.setattr(app_module, "_get_user_plan", lambda u: "founder")
    try:
        c, h = _client(flask_app, name)
        bad = c.post("/api/missions", headers=h, json=dict(MISSION, teammate="Nobody"))
        assert bad.status_code == 400 and "Unknown teammate" in bad.get_json()["error"]
        bad = c.post("/api/missions", headers=h, json=dict(MISSION, schedule={"kind": "weekly", "hour": 9, "days": []}))
        assert bad.status_code == 400
        for i in range(3):
            assert c.post("/api/missions", headers=h, json=dict(MISSION, title=f"M{i}")).status_code == 200
        r = c.post("/api/missions", headers=h, json=MISSION)
        assert r.status_code == 403 and "3 missions" in r.get_json()["error"]
        lst = c.get("/api/missions").get_json()
        assert len(lst["missions"]) == 3 and lst["limit"] == 3
        mid = lst["missions"][0]["id"]
        assert c.post(f"/api/missions/{mid}", headers=h, json={"enabled": False}).get_json()["mission"]["enabled"] is False
        assert c.delete(f"/api/missions/{mid}", headers=h).status_code == 200
    finally:
        _drop(name)


def test_run_drafts_email_only_to_existing_contact(flask_app, monkeypatch):
    name = "missionemail"
    _user(name)
    crm = app_module._crm_load(name)
    crm.setdefault("clients", {})["cl1"] = {"id": "cl1", "name": "Ann Ortiz", "email": "ann@ortizhvac.com"}
    app_module._crm_save(name, crm)
    turns = [_turn(calls=[_call(1, "send_email", {"to": "ANN@ortizhvac.com", "subject": "Hi", "body": "Hello Ann"}),
                          _call(2, "send_email", {"to": "made.up@nowhere.com", "subject": "Hi", "body": "x"})]),
             _turn("Drafted one email for approval.")]
    fake = _FakeOAI(turns)
    monkeypatch.setattr(app_module, "get_openai_client", lambda: fake)
    try:
        c, h = _client(flask_app, name)
        mid = c.post("/api/missions", headers=h, json=dict(MISSION, teammate="Sunshine")).get_json()["mission"]["id"]
        before = app_module._get_msg_usage(name)["count"]
        res = app_module._mission_run(name, mid, "manual")
        assert res["ok"] and res["held"] == 1
        d = app_module._agent_load(name)
        held = [a for a in d["approvals"] if a.get("mission_id") == mid]
        assert len(held) == 1 and held[0]["kind"] == "mission_email"
        assert held[0]["to"] == "ann@ortizhvac.com" and held[0]["client_id"] == "cl1"   # from the record
        m = d["missions"][mid]
        assert m["last_run"]["ok"] and "running" not in m
        assert any("only email existing contacts" in s for s in m["last_run"]["steps"])
        assert app_module._get_msg_usage(name)["count"] - before == 2       # each model round counts
    finally:
        _drop(name)


def test_held_action_runs_exactly_as_stored(flask_app, monkeypatch):
    name = "missionaction"
    _user(name)
    monkeypatch.setitem(app_module._TOOL_BY_NAME["research"], "executor",
                        lambda u, t, a: {"ok": True, "summary": "Read a web page."})
    turns = [_turn(calls=[_call(1, "research", {"query": "hvac austin"})]),
             _turn(calls=[_call(2, "crm_add_client", {"name": "Real Lead", "email": "office@reallead.com"})]),
             _turn("Found one lead; adding it is waiting for approval.")]
    monkeypatch.setattr(app_module, "get_openai_client", lambda: _FakeOAI(turns))
    try:
        c, h = _client(flask_app, name)
        mid = c.post("/api/missions", headers=h, json=MISSION).get_json()["mission"]["id"]
        assert app_module._mission_run(name, mid)["held"] == 1
        a = next(x for x in app_module._agent_load(name)["approvals"] if x.get("kind") == "action")
        assert a["tool"] == "crm_add_client"
        assert not any((cl.get("name") == "Real Lead") for cl in (app_module._crm_load(name).get("clients") or {}).values())
        r = c.post(f"/api/agent/approvals/{a['id']}/approve", headers=h,
                   json={"tool": "send_email", "args": {"to": "evil@x.com"}})      # client args are ignored
        assert r.status_code == 200
        names = [cl.get("name") for cl in (app_module._crm_load(name).get("clients") or {}).values()]
        assert "Real Lead" in names
        assert next(x for x in app_module._agent_load(name)["approvals"] if x["id"] == a["id"])["status"] == "done"
    finally:
        _drop(name)


def test_failures_auto_pause_after_three(flask_app, monkeypatch):
    name = "missionfail"
    _user(name)
    monkeypatch.setattr(app_module, "get_openai_client", lambda: _FakeOAI(fail=True))
    try:
        c, h = _client(flask_app, name)
        mid = c.post("/api/missions", headers=h, json=MISSION).get_json()["mission"]["id"]
        for _ in range(3):
            assert app_module._mission_run(name, mid)["ok"] is False
        m = app_module._agent_load(name)["missions"][mid]
        assert m["enabled"] is False and "3 failed runs" in m["paused_reason"]
        m2 = c.post(f"/api/missions/{mid}", headers=h, json={"enabled": True}).get_json()["mission"]
        assert m2["enabled"] is True and not m2.get("paused_reason")
    finally:
        _drop(name)


def test_new_mission_after_todays_time_waits_for_next_run(flask_app, monkeypatch):
    name = "missionnextrun"
    _user(name)
    monkeypatch.setattr(app_module, "_user_now_local", lambda u: datetime(2026, 11, 2, 15, 0))   # Monday 3 pm
    try:
        c, h = _client(flask_app, name)
        late = c.post("/api/missions", headers=h, json=dict(MISSION, schedule={"kind": "weekdays", "hour": 8})).get_json()["mission"]["id"]
        early = c.post("/api/missions", headers=h, json=dict(MISSION, title="Evening", schedule={"kind": "weekdays", "hour": 18})).get_json()["mission"]["id"]
        ms = app_module._agent_load(name)["missions"]
        assert ms[late]["last_day"] == "2026-11-02" and ms[early]["last_day"] == ""
        view = c.get("/api/agent").get_json()
        assert "Willow" in view["mission_teammates"] and view["mission_limit"] >= 3
    finally:
        _drop(name)


def test_schedule_rules():
    mon9 = datetime(2026, 11, 2, 9, 30)        # a Monday
    sat9 = datetime(2026, 11, 7, 9, 30)
    due = app_module._mission_due
    assert due({"enabled": True, "schedule": {"kind": "daily", "hour": 9}}, mon9)
    assert not due({"enabled": True, "schedule": {"kind": "daily", "hour": 10}}, mon9)
    assert not due({"enabled": True, "schedule": {"kind": "weekdays", "hour": 9}}, sat9)
    assert due({"enabled": True, "schedule": {"kind": "weekly", "hour": 9, "days": [0]}}, mon9)
    assert not due({"enabled": True, "schedule": {"kind": "weekly", "hour": 9, "days": [1]}}, mon9)
    assert not due({"enabled": True, "last_day": "2026-11-02", "schedule": {"kind": "daily", "hour": 9}}, mon9)
    assert not due({"enabled": False, "schedule": {"kind": "daily", "hour": 9}}, mon9)


def test_tick_starts_due_missions_once_and_respects_pause_all(flask_app, monkeypatch):
    name = "missiontick"
    _user(name)
    started = []
    monkeypatch.setattr(app_module, "_mission_start_bg", lambda u, mid, src: started.append(mid))
    try:
        c, h = _client(flask_app, name)
        mid = c.post("/api/missions", headers=h, json=dict(MISSION, schedule={"kind": "daily", "hour": 0})).get_json()["mission"]["id"]
        now = datetime(2026, 11, 2, 9, 0)
        app_module._mission_tick_user(name, now)
        app_module._mission_tick_user(name, now)                  # same day: not again
        assert started == [mid]
        c.post("/api/missions/pause_all", headers=h, json={"paused": True})
        app_module._mission_tick_user(name, datetime(2026, 11, 3, 9, 0))
        assert started == [mid]
    finally:
        _drop(name)
