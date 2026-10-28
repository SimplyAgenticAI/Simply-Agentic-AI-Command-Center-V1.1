"""V20.6 Inbox opportunities: a sorted worklist you act on. Automated mail filtered
without AI, hot emails get a drafted reply, each email can be read / opened in Gmail /
replied to / added as a contact / reminded / done / dismissed, and handled emails
never come back on the next scan.
(File must sort after test_client_crud.)"""
import json
import app as app_module


def _raw(frm, subj, body, mid, extra=b""):
    return (b"From: " + frm + b"\r\nSubject: " + subj + b"\r\nDate: Mon, 26 Oct 2026 10:00:00 +0000\r\nMessage-ID: <"
            + mid + b">\r\n" + extra + b"Content-Type: text/plain\r\n\r\n" + body + b"\r\n")


MSGS = {
    b"1": (b"()", _raw(b"Pat Lee <pat@leeco.com>", b"Quote for 3 units?", b"Can you send me a quote for 3 units this week?", b"pat-1@leeco.com")),
    b"2": (b"()", _raw(b"Ann <ann@shop.com>", b"Following up", b"Just checking in about the proposal.", b"ann-1@shop.com")),
    b"3": (b"()", _raw(b"Deals Weekly <news@deals.com>", b"Top 10 deals", b"Big sale", b"n-1@deals.com",
                       b"List-Unsubscribe: <mailto:u@deals.com>\r\n")),
    b"4": (b"()", _raw(b"Bank <no-reply@bank.com>", b"Your statement", b"Statement ready", b"b-1@bank.com")),
    b"5": (b"(\\Answered)", _raw(b"Old <old@client.com>", b"Thanks", b"Thanks!", b"o-1@client.com")),
    b"6": (b"()", _raw(b"Me <owner@gmail.com>", b"note to self", b"x", b"me-1@gmail.com")),
}


class FakeIMAP:
    def __init__(self, host, port, timeout=None):
        pass

    def login(self, u, p):
        pass

    def select(self, box, readonly=False):
        assert readonly is True
        return "OK", [b"6"]

    def uid(self, cmd, *args):
        if cmd == "search":
            return "OK", [b" ".join(MSGS.keys())]
        assert "BODY.PEEK[]" in args[1]
        flags, raw = MSGS[args[0]]
        return "OK", [(args[0] + b" (FLAGS " + flags + b" BODY[] {1}", raw), b")"]

    def logout(self):
        pass


def fake_llm(system, messages, temperature=0, model=None, **kw):
    content = messages[0]["content"]
    if "sort a small-business owner's" in system:
        rows = json.loads(content.split("Emails:\n", 1)[1].split("\n\nFor EACH", 1)[0])
        fake_llm.classified += len(rows)
        pr = {"pat@leeco.com": "hot", "ann@shop.com": "warm"}
        return json.dumps({"items": [{"i": r["i"], "priority": pr.get(r["from"].split("<")[1].rstrip(">"), "skip"),
                                      "why": "Wants a quote" if "pat" in r["from"] else "Waiting on you",
                                      "next": "Send pricing"} for r in rows]})
    return json.dumps({"subject": "Re: Quote for 3 units?", "body": "Hi Pat, happy to send that. [price]"})


def _setup(monkeypatch, name):
    import imaplib
    monkeypatch.setattr(imaplib, "IMAP4_SSL", FakeIMAP)
    fake_llm.classified = 0
    monkeypatch.setattr(app_module, "call_llm", fake_llm)
    data = app_module.load_users()
    data.setdefault("users", {})[name] = {"username": name, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    app_module._inbox_set(name, {"provider": "gmail", "email": "owner@gmail.com", "pw_enc": app_module._encrypt_field("pw")})


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


def test_triage_builds_sorted_worklist_and_drafts_hot(flask_app, monkeypatch):
    name = "ibtriage"
    _setup(monkeypatch, name)
    try:
        res = app_module._inbox_triage(name, 100)
        assert res["ok"] and res["new"] == 2 and res["hot"] == 1 and res["drafted"] == 1
        assert fake_llm.classified == 2              # newsletter, no-reply, answered and own mail never reach the AI
        c, h = _client(flask_app, name)
        d = c.get("/api/inbox/opportunities").get_json()
        assert [x["from_email"] for x in d["items"]] == ["pat@leeco.com", "ann@shop.com"]   # hot first
        pat = d["items"][0]
        assert pat["priority"] == "hot" and pat["has_draft"] and "quote for 3 units" in pat["text"]
        assert pat["link"].startswith("https://mail.google.com/mail/u/0/#search/rfc822msgid%3Apat-1%40leeco.com")
        appr = next(a for a in app_module._agent_load(name)["approvals"] if a.get("inbox_id") == pat["id"])
        assert appr["kind"] == "inbox_reply" and appr["to"] == "pat@leeco.com" and appr["status"] == "pending"
        # a second scan doesn't re-sort or re-add anything already seen
        again = app_module._inbox_triage(name, 100)
        assert again["new"] == 0 and fake_llm.classified == 2
    finally:
        _drop(name)


def test_card_actions_and_reply_marks_handled(flask_app, monkeypatch):
    name = "ibactions"
    _setup(monkeypatch, name)
    sent = []
    monkeypatch.setattr(app_module, "_crm_send_email_to", lambda u, to, s, b: sent.append((to, s, b)) or (True, "smtp", ""))
    try:
        app_module._inbox_triage(name, 100, autodraft=False)
        c, h = _client(flask_app, name)
        items = {x["from_email"]: x for x in c.get("/api/inbox/opportunities").get_json()["items"]}
        ann, pat = items["ann@shop.com"]["id"], items["pat@leeco.com"]["id"]
        r = c.post(f"/api/inbox/opportunities/{ann}/contact", headers=h).get_json()
        assert r["ok"] and any(cl.get("email") == "ann@shop.com" for cl in (app_module._crm_load(name).get("clients") or {}).values())
        assert c.post(f"/api/inbox/opportunities/{ann}/contact", headers=h).get_json()["summary"] == "Already in your contacts."
        assert c.post(f"/api/inbox/opportunities/{ann}/remind", headers=h).get_json()["ok"]
        assert c.post(f"/api/inbox/opportunities/{ann}/dismiss", headers=h).get_json()["ok"]
        rep = c.post(f"/api/inbox/opportunities/{pat}/reply", headers=h).get_json()
        assert rep["ok"] and rep["approval"]["to"] == "pat@leeco.com"
        c.post(f"/api/agent/approvals/{rep['approval']['id']}/approve", headers=h, json={"body": "Hi Pat, $450 for all 3."})
        assert sent == [("pat@leeco.com", "Re: Quote for 3 units?", "Hi Pat, $450 for all 3.")]
        d = c.get("/api/inbox/opportunities").get_json()
        assert d["items"] == []                                    # both handled
        assert {x["status"] for x in d["done"]} == {"replied", "dismissed"}
        assert c.post(f"/api/inbox/opportunities/{ann}/reopen", headers=h).get_json()["ok"]
        assert [x["id"] for x in c.get("/api/inbox/opportunities").get_json()["items"]] == [ann]
    finally:
        _drop(name)


def test_review_inbox_is_a_teammate_ability():
    assert app_module._tool_risk("review_inbox") == "auto"
    assert "review_inbox" in app_module._SLOW_TOOLS
    assert "review_inbox" in app_module._MISSION_RULES
