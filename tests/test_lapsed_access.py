"""V19.7: cancelled / unpaid accounts lose access (and get it back when they
resubscribe); Stripe's unpaid status ends access; system email failures show on /health.
(File must sort after test_client_crud.)"""
import json
import uuid
import app as app_module


def _setup(monkeypatch, seats, users):
    store = {"seats": seats}
    monkeypatch.setattr(app_module, "_load_seats", lambda: store)
    monkeypatch.setattr(app_module, "_save_seats", lambda d: store.update(d))
    data = app_module.load_users()
    for name, rec in users.items():
        data.setdefault("users", {})[name] = dict({"username": name, "password_hash": "", "is_admin": False}, **rec)
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    return store


def _cleanup(names):
    data = app_module.load_users()
    for n in names:
        (data.get("users") or {}).pop(n, None)
    app_module.save_users(data)
    app_module._invalidate_users_cache()


def _client(flask_app, uname):
    c = flask_app.test_client()
    with c.session_transaction() as s:
        s["user"] = uname
    return c


def test_cancelled_user_is_blocked_but_comped_and_members_follow_owner(flask_app, monkeypatch):
    names = ["lapsedown", "lapsedmem", "compeduser", "paiduser"]
    _setup(monkeypatch, {
        "A": {"claimed_by": "lapsedown", "plan": "solo", "status": "cancelled"},
        "B": {"claimed_by": "paiduser", "plan": "solo", "status": "used"},
    }, {"lapsedown": {}, "lapsedmem": {"team_owner": "lapsedown"}, "compeduser": {}, "paiduser": {}})
    try:
        for who in ("lapsedown", "lapsedmem"):
            c = _client(flask_app, who)
            r = c.get("/api/usage/messages")
            assert r.status_code == 402 and r.get_json()["subscription_ended"] is True
            assert c.get("/").headers["Location"].endswith("/subscription-ended")
            page = c.get("/subscription-ended").get_data(as_text=True)
            assert "Your subscription has ended" in page and "/pricing" in page
            assert c.get("/pricing").status_code == 200          # can still pick a plan
        for who in ("compeduser", "paiduser"):
            c = _client(flask_app, who)
            assert c.get("/api/usage/messages").status_code == 200
            assert c.get("/subscription-ended").headers["Location"].endswith("/")
    finally:
        _cleanup(names)


def test_resubscribing_while_signed_in_reactivates_same_account(flask_app, monkeypatch):
    store = _setup(monkeypatch, {
        "OLD": {"claimed_by": "comeback", "plan": "solo", "status": "cancelled", "claimed_at": "2026-09-01T00:00:00Z"},
        "NEW": {"claimed_by": None, "plan": "teams", "status": "active", "created_at": "2026-11-01T00:00:00Z"},
    }, {"comeback": {}})
    monkeypatch.setattr(app_module, "_stripe_session_code", lambda sid: ("NEW", "x@example.com"))
    try:
        c = _client(flask_app, "comeback")
        r = c.get("/register?stripe_session=cs_test_1")
        assert r.status_code == 302 and r.headers["Location"].endswith("/")
        assert store["seats"]["NEW"]["claimed_by"] == "comeback"
        assert c.get("/api/usage/messages").get_json()["plan"] == "teams"
    finally:
        _cleanup(["comeback"])


def test_stripe_unpaid_ends_access_and_payment_restores_it(flask_app, monkeypatch):
    store = _setup(monkeypatch, {"S": {"claimed_by": "unpaiduser", "plan": "solo", "status": "used",
                                       "stripe_customer_id": "cus_unpaid"}}, {"unpaiduser": {}})

    def send(status):
        ev = {"id": "evt_" + uuid.uuid4().hex, "type": "customer.subscription.updated",
              "data": {"object": {"customer": "cus_unpaid", "status": status, "items": {"data": []}}}}
        monkeypatch.setattr(app_module, "_stripe_verify_webhook", lambda p, s: (True, ev))
        assert flask_app.test_client().post("/stripe/webhook", data=b"{}").status_code == 200

    try:
        send("past_due")
        assert store["seats"]["S"]["status"] == "used"          # grace while Stripe retries
        send("unpaid")
        assert store["seats"]["S"]["status"] == "inactive"
        assert app_module._account_lapsed("unpaiduser") is True
        send("active")
        assert store["seats"]["S"]["status"] == "used"
        assert app_module._account_lapsed("unpaiduser") is False
    finally:
        _cleanup(["unpaiduser"])


def test_admin_deactivated_seat_is_not_revived_by_stripe(flask_app, monkeypatch):
    store = _setup(monkeypatch, {"S": {"claimed_by": "admoff", "status": "inactive", "stripe_customer_id": "cus_admoff"}},
                   {"admoff": {}})
    ev = {"id": "evt_" + uuid.uuid4().hex, "type": "customer.subscription.updated",
          "data": {"object": {"customer": "cus_admoff", "status": "active", "items": {"data": []}}}}
    monkeypatch.setattr(app_module, "_stripe_verify_webhook", lambda p, s: (True, ev))
    try:
        flask_app.test_client().post("/stripe/webhook", data=b"{}")
        assert store["seats"]["S"]["status"] == "inactive"
    finally:
        _cleanup(["admoff"])


def test_email_failure_shows_on_health_without_addresses(monkeypatch):
    monkeypatch.setattr(app_module, "SMTP_USER", "bot@example.com")
    monkeypatch.setattr(app_module, "SMTP_PASS", "pw")

    def boom(**kw):
        raise RuntimeError("535 auth failed for bot@example.com")
    monkeypatch.setattr(app_module, "send_email_smtp_with_creds", boom)
    assert app_module._send_platform_email("client@example.com", "Welcome", "hi") is False
    rec = json.loads((app_module.DATA / "diag_last.json").read_text(encoding="utf-8"))["email_failed"]
    assert "Welcome" in rec["detail"] and "535" in rec["detail"] and "@" not in rec["detail"]
