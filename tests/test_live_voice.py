"""V21.0 Live voice: realtime speech-to-speech calls. Admin-only by default, short-lived
keys, teammate persona + recent chat in the session, monthly minutes, every turn saved
to the thread, and abilities on calls follow chat's approval rules.
(File must sort after test_client_crud.)"""
import json
import app as app_module


class _R:
    def __init__(self, body, code=200):
        self._b, self.status_code, self.content = body, code, b"x"

    def json(self):
        return self._b


def _user(name, admin=False, plan="solo"):
    data = app_module.load_users()
    data.setdefault("users", {})[name] = {"username": name, "password_hash": "", "is_admin": admin}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    for p in (app_module._live_usage_path(name), app_module._agent_path(name)):
        if p.exists():
            p.unlink()


def _drop(name):
    data = app_module.load_users()
    (data.get("users") or {}).pop(name, None)
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    for p in (app_module._live_usage_path(name), app_module._agent_path(name)):
        if p.exists():
            p.unlink()


def _client(flask_app, name):
    c = flask_app.test_client()
    with c.session_transaction() as s:
        s["user"] = name
    return c, {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}


def test_admin_only_by_default(flask_app, monkeypatch):
    monkeypatch.setattr(app_module, "LIVE_VOICE_ACCESS", "admins")
    _user("livenormal")
    try:
        c, h = _client(flask_app, "livenormal")
        assert c.get("/api/voice/live/status").get_json()["available"] is False
        assert c.post("/api/voice/live/session", headers=h, json={"teammate": "Willow"}).status_code == 403
        monkeypatch.setattr(app_module, "LIVE_VOICE_ACCESS", "all")
        assert c.get("/api/voice/live/status").get_json()["available"] is True
    finally:
        _drop("livenormal")


def test_session_has_persona_rules_tools_and_falls_back_model(flask_app, monkeypatch):
    monkeypatch.setattr(app_module, "LIVE_VOICE_ACCESS", "all")
    monkeypatch.setattr(app_module, "OPENAI_API_KEY", "sk-server")
    monkeypatch.setattr(app_module, "LIVE_MODELS", ["gpt-realtime-mini", "gpt-realtime"])
    name = "livesession"
    _user(name)
    app_module.save_thread("Willow", [{"role": "user", "content": "Remember the spring sale"}], name)
    sent = []

    def fake_post(url, headers=None, json=None, timeout=None):
        sent.append((url, headers, json))
        if json["session"]["model"] == "gpt-realtime-mini":
            return _R({"error": {"message": "model not found"}}, 400)
        return _R({"value": "ek_test", "expires_at": 1})
    monkeypatch.setattr(app_module.requests, "post", fake_post)
    try:
        c, h = _client(flask_app, name)
        r = c.post("/api/voice/live/session", headers=h, json={"teammate": "Willow"}).get_json()
        assert r["ok"] and r["client_secret"] == "ek_test" and r["model"] == "gpt-realtime" and r["call_id"]
        url, hdr, body = sent[-1]
        assert url == "https://api.openai.com/v1/realtime/client_secrets" and hdr["Authorization"] == "Bearer sk-server"
        s = body["session"]
        assert s["type"] == "realtime" and "LIVE VOICE CALL" in s["instructions"] and "spring sale" in s["instructions"]
        assert s["audio"]["output"]["voice"] in app_module.LIVE_VOICES
        assert s["audio"]["input"]["turn_detection"]["interrupt_response"] is True
        names = {t["name"] for t in s["tools"]}
        assert "send_email" in names and "book_meeting" not in names and "create_mission" not in names
        assert body["expires_after"]["seconds"] == 120
        thr = app_module.load_thread("Willow", name)
        c.post("/api/voice/live/turn", headers=h, json={"call_id": r["call_id"], "role": "user", "text": "Hi Willow"})
        c.post("/api/voice/live/turn", headers=h, json={"call_id": r["call_id"], "role": "assistant", "text": "Hey! What's up?"})
        thr2 = app_module.load_thread("Willow", name)
        assert len(thr2) == len(thr) + 2 and thr2[-1]["via"] == "live_voice" and thr2[-2]["content"] == "🎙 Hi Willow"
    finally:
        _drop(name)


def test_minutes_are_metered_capped_and_limited(flask_app, monkeypatch):
    monkeypatch.setattr(app_module, "LIVE_VOICE_ACCESS", "all")
    monkeypatch.setattr(app_module, "OPENAI_API_KEY", "sk-server")
    monkeypatch.setattr(app_module.requests, "post", lambda *a, **k: _R({"value": "ek"}))
    monkeypatch.setattr(app_module, "_get_user_plan", lambda u: "founder")
    name = "liveminutes"
    _user(name)
    clock = [1000.0]
    monkeypatch.setattr(app_module.time, "time", lambda: clock[0])
    try:
        c, h = _client(flask_app, name)
        cid = c.post("/api/voice/live/session", headers=h, json={"teammate": "Alex"}).get_json()["call_id"]
        clock[0] += 15
        assert c.post("/api/voice/live/ping", headers=h, json={"call_id": cid}).get_json()["continue"] is True
        clock[0] += 500                                            # a stalled tab: only 30s is billed
        c.post("/api/voice/live/ping", headers=h, json={"call_id": cid})
        assert app_module._live_load(name)["seconds"] == 45
        c.post("/api/voice/live/end", headers=h, json={"call_id": cid})
        assert c.post("/api/voice/live/ping", headers=h, json={"call_id": cid}).get_json()["continue"] is False
        d = app_module._live_load(name)
        d["seconds"] = 60 * 60                                     # founder: 60 minutes used
        app_module._live_save(name, d)
        r = c.post("/api/voice/live/session", headers=h, json={"teammate": "Alex"})
        assert r.status_code == 429 and "60 live voice minutes" in r.get_json()["error"]
    finally:
        _drop(name)


def test_abilities_on_calls_follow_approval_rules(flask_app, monkeypatch):
    monkeypatch.setattr(app_module, "LIVE_VOICE_ACCESS", "all")
    monkeypatch.setattr(app_module, "OPENAI_API_KEY", "sk-server")
    monkeypatch.setattr(app_module.requests, "post", lambda *a, **k: _R({"value": "ek"}))
    monkeypatch.setitem(app_module._TOOL_BY_NAME["research"], "executor", lambda u, t, a: {"ok": True, "summary": "Read a page."})
    name = "livetools"
    _user(name)
    try:
        c, h = _client(flask_app, name)
        cid = c.post("/api/voice/live/session", headers=h, json={"teammate": "Sunshine"}).get_json()["call_id"]

        def tool(n, args):
            return json.loads(c.post("/api/voice/live/tool", headers=h,
                                     json={"call_id": cid, "name": n, "arguments": json.dumps(args)}).get_json()["output"])
        # email: never sent from the call, always a draft for approval
        out = tool("send_email", {"to": "pat@leeco.com", "subject": "Hi", "body": "Hello Pat"})
        assert "Ready for you" in out["summary"]
        appr = [a for a in app_module._agent_load(name)["approvals"] if a.get("trigger") == "Live call"]
        assert appr and appr[0]["to"] == "pat@leeco.com" and appr[0]["status"] == "pending"
        # a normal ability runs
        assert tool("crm_add_client", {"name": "Ann Lee", "email": "ann@lee.com"})["ok"]
        # after reading outside content, data changes are held
        tool("research", {"query": "hvac"})
        out = tool("crm_add_client", {"name": "Injected Co", "email": "x@inj.com"})
        assert "needs the owner's OK" in out["summary"]
        names = [cl.get("name") for cl in (app_module._crm_load(name).get("clients") or {}).values()]
        assert "Ann Lee" in names and "Injected Co" not in names
        # abilities not allowed on calls are refused
        assert "isn't available on calls" in tool("book_meeting", {})["summary"]
        c.post("/api/voice/live/end", headers=h, json={"call_id": cid})
        r = c.post("/api/voice/live/tool", headers=h, json={"call_id": cid, "name": "crm_find_client", "arguments": "{}"})
        assert r.status_code == 400
    finally:
        _drop(name)


def test_call_screen_is_wired():
    html = open("templates/index.html", encoding="utf-8").read()
    assert "https://api.openai.com/v1/realtime/calls" in html and "createDataChannel('oai-events')" in html
    assert "echoCancellation:true" in html and "window.saVoiceStopAll" in html
    assert html.count("saLiveItem") >= 3
