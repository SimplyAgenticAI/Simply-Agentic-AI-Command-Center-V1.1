"""V20.5: read-only inbox access with an app password. Never marks read / moves /
deletes; app password stored encrypted and never returned; replies to senders wait
for approval; email text counts as untrusted outside content.
(File must sort after test_client_crud.)"""
import json
import types
import app as app_module

RAW1 = (b"From: Pat Lee <pat@leeco.com>\r\nSubject: Quote for HVAC tune-up?\r\nDate: Mon, 26 Oct 2026 10:00:00 +0000\r\n"
        b"Content-Type: text/plain\r\n\r\nHi, could you send me a quote for 3 units?\r\n> old quoted text\r\n")
RAW2 = (b"From: Me <owner@gmail.com>\r\nSubject: Re: hello\r\nDate: Tue, 27 Oct 2026 10:00:00 +0000\r\n"
        b"Content-Type: text/html\r\n\r\n<p>Sent by me</p><script>x()</script>\r\n")
RAW3 = (b"From: Ann <ann@shop.com>\r\nSubject: Thanks!\r\nDate: Wed, 28 Oct 2026 10:00:00 +0000\r\n"
        b"Content-Type: text/plain\r\n\r\nGreat call yesterday.\r\n")


class FakeIMAP:
    calls = []
    fail_login = False

    def __init__(self, host, port, timeout=None):
        FakeIMAP.calls.append(("connect", host))

    def login(self, u, p):
        FakeIMAP.calls.append(("login", u))
        if FakeIMAP.fail_login:
            raise Exception("[AUTHENTICATIONFAILED] Invalid credentials")

    def select(self, box, readonly=False):
        FakeIMAP.calls.append(("select", box, readonly))
        return "OK", [b"3"]

    def uid(self, cmd, *args):
        FakeIMAP.calls.append(("uid", cmd) + args)
        if cmd == "search":
            return "OK", [b"1 2 3"]
        msgs = {b"1": (b"1 (FLAGS (\\Seen) BODY[] {1}", RAW1), b"2": (b"2 (FLAGS (\\Seen \\Answered) BODY[] {1}", RAW2),
                b"3": (b"3 (FLAGS () BODY[] {1}", RAW3)}
        return "OK", [msgs[args[0]], b")"]

    def logout(self):
        FakeIMAP.calls.append(("logout",))


def _setup(monkeypatch, name):
    import imaplib
    FakeIMAP.calls, FakeIMAP.fail_login = [], False
    monkeypatch.setattr(imaplib, "IMAP4_SSL", FakeIMAP)
    data = app_module.load_users()
    data.setdefault("users", {})[name] = {"username": name, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()


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
    return c, {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}


def test_connect_stores_encrypted_and_never_returns_password(flask_app, monkeypatch):
    name = "inboxconnect"
    _setup(monkeypatch, name)
    try:
        c, h = _client(flask_app, name)
        monkeypatch.setattr(app_module, "_FERNET", None)
        r = c.post("/api/inbox/connect", headers=h, json={"email": "owner@gmail.com", "app_password": "abcdefghijklmnop"})
        assert r.status_code == 503 and "FIELD_ENCRYPTION_KEY" in r.get_json()["error"]   # never stored as plain text
        from cryptography.fernet import Fernet
        monkeypatch.setattr(app_module, "_FERNET", Fernet(Fernet.generate_key()))
        FakeIMAP.fail_login = True
        r = c.post("/api/inbox/connect", headers=h, json={"email": "owner@gmail.com", "app_password": "wrong"})
        assert r.status_code == 400 and "app password" in r.get_json()["error"]
        FakeIMAP.fail_login = False
        r = c.post("/api/inbox/connect", headers=h, json={"email": "owner@gmail.com", "app_password": "abcd efgh ijkl mnop"})
        assert r.status_code == 200 and r.get_json()["provider"] == "gmail"
        stored = app_module.load_users()["users"][name]["settings"]["inbox"]
        assert "abcdefghijklmnop" not in json.dumps(stored)                      # encrypted at rest
        assert app_module._inbox_creds(name)["password"] == "abcdefghijklmnop"   # spaces removed
        st = c.get("/api/inbox/status").get_json()
        assert st["connected"] and st["email"] == "owner@gmail.com" and "abcd" not in json.dumps(st)
        assert ("connect", "imap.gmail.com") in FakeIMAP.calls
        assert c.post("/api/inbox/disconnect", headers=h).get_json()["ok"]
        assert not c.get("/api/inbox/status").get_json()["connected"]
    finally:
        _drop(name)


def test_reads_read_only_and_flags_unanswered(monkeypatch):
    name = "inboxread"
    _setup(monkeypatch, name)
    try:
        app_module._inbox_set(name, {"provider": "gmail", "email": "owner@gmail.com",
                                     "pw_enc": app_module._encrypt_field("pw")})
        res = app_module._tool_read_inbox(name, "Sunshine", {"count": 100})
        assert res["ok"]
        assert ("select", "INBOX", True) in FakeIMAP.calls                       # opened read-only
        fetches = [c for c in FakeIMAP.calls if c[:2] == ("uid", "fetch")]
        assert fetches and all("BODY.PEEK[]" in c[3] for c in fetches)          # never marks as read
        assert not any(c[1] in ("store", "copy", "move", "expunge") for c in FakeIMAP.calls if c[0] == "uid")
        senders = [e["from_email"] for e in res["emails"]]
        assert senders == ["ann@shop.com", "pat@leeco.com"]                      # newest first, own mail skipped
        pat = res["emails"][1]
        assert pat["answered"] is False and "quote for 3 units" in pat["text"] and "old quoted" not in pat["text"]
        assert "2 you haven't replied to" in res["summary"]
        assert "read_inbox" in app_module._EXTERNAL_CONTENT_TOOLS
    finally:
        _drop(name)


def test_mission_replies_to_senders_wait_for_approval(flask_app, monkeypatch):
    name = "inboxmission"
    _setup(monkeypatch, name)
    import test_missions as tm
    turns = [tm._turn(calls=[tm._call(1, "read_inbox", {"count": 50, "unanswered_only": True})]),
             tm._turn(calls=[tm._call(2, "send_email", {"to": "pat@leeco.com", "subject": "Re: Quote", "body": "Happy to help, Pat!"}),
                             tm._call(3, "send_email", {"to": "stranger@nowhere.com", "subject": "Hi", "body": "x"})]),
             tm._turn("Drafted 1 reply.")]
    monkeypatch.setattr(app_module, "get_openai_client", lambda: tm._FakeOAI(turns))
    sent = []
    monkeypatch.setattr(app_module, "_crm_send_email_to", lambda u, to, s, b: sent.append((to, s, b)) or (True, "smtp", ""))
    try:
        app_module._inbox_set(name, {"provider": "gmail", "email": "owner@gmail.com", "pw_enc": app_module._encrypt_field("pw")})
        c, h = _client(flask_app, name)
        mid = c.post("/api/missions", headers=h, json={"title": "Inbox", "instruction": "Find missed opportunities in my inbox.",
                                                        "teammate": "Sunshine", "schedule": {"kind": "daily", "hour": 8}}).get_json()["mission"]["id"]
        res = app_module._mission_run(name, mid)
        assert res["ok"] and res["held"] == 1 and sent == []                     # nothing sent on its own
        a = next(x for x in app_module._agent_load(name)["approvals"] if x.get("kind") == "inbox_reply")
        assert a["to"] == "pat@leeco.com"
        steps = " ".join(app_module._agent_load(name)["missions"][mid]["last_run"]["steps"])
        assert "only email existing contacts" in steps                            # stranger refused
        r = c.post(f"/api/agent/approvals/{a['id']}/approve", headers=h, json={"body": "Happy to help, Pat! Edited."})
        assert r.status_code == 200 and sent == [("pat@leeco.com", "Re: Quote", "Happy to help, Pat! Edited.")]
    finally:
        _drop(name)
