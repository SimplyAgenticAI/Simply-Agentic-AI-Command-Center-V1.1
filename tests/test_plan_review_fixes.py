"""V19.2 review fixes: team members inherit the owner's plan, Stripe plan switches
sync to the seat, and a failed price lookup uses the plan stamped at checkout.
(File must sort after test_client_crud.)"""
import app as app_module


def _users(monkeypatch, seats, users):
    monkeypatch.setattr(app_module, "_load_seats", lambda: {"seats": seats})
    monkeypatch.setattr(app_module, "load_users", lambda: {"users": dict({"adm": {"is_admin": True}}, **users)})


def test_team_member_gets_owner_plan(monkeypatch):
    _users(monkeypatch,
           {"S": {"claimed_by": "own", "plan": "teams", "created_at": "2026-11-01T00:00:00Z", "status": "active"},
            "F": {"claimed_by": "oldf", "plan": "founder", "created_at": "2026-08-01T00:00:00Z", "status": "active"}},
           {"own": {}, "mem": {"team_owner": "own"}, "oldf": {}, "partner": {"team_owner": "oldf"},
            "loop1": {"team_owner": "loop2"}, "loop2": {"team_owner": "loop1"}})
    with app_module.app.test_request_context():
        assert app_module._get_user_plan("mem") == "teams"
        assert app_module._get_user_plan("partner") == "founder_classic"
        assert app_module._get_user_plan("loop1") == "solo"          # no infinite loop


def test_failed_price_lookup_uses_checkout_plan(monkeypatch):
    monkeypatch.setattr(app_module, "_stripe_api", lambda *a, **k: (500, {}))
    assert app_module._plan_from_stripe_session("cs_x", {"metadata": {"plan": "founder"}}) == "founder"
    assert app_module._plan_from_stripe_session("cs_x", {"metadata": {"plan": "founder_classic"}}) == "solo"
    assert app_module._plan_for_price(app_module.PLANS["founder"]["price_id"]) == "founder"


def test_checkout_stamps_plan(flask_app, monkeypatch):
    sent = {}
    monkeypatch.setattr(app_module, "_stripe_ready", lambda: True)
    monkeypatch.setattr(app_module, "_founder_seats_remaining", lambda: 50)
    monkeypatch.setattr(app_module, "_stripe_api", lambda m, p, params: sent.update(params) or (200, {"url": "u"}))
    c = flask_app.test_client()
    h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
    c.post("/stripe/create_checkout", headers=h, json={"plan": "teams"})
    assert sent["metadata[plan]"] == "teams"


def test_subscription_switch_updates_seat(flask_app, monkeypatch):
    store = {"seats": {"A": {"stripe_customer_id": "cus_1", "plan": "solo", "trial_active": True},
                       "B": {"stripe_customer_id": "cus_2", "plan": "solo"}}}
    monkeypatch.setattr(app_module, "_load_seats", lambda: store)
    monkeypatch.setattr(app_module, "_save_seats", lambda d: store.update(d))
    import uuid
    ev = {"id": "evt_v192_" + uuid.uuid4().hex, "type": "customer.subscription.updated",
          "data": {"object": {"customer": "cus_1", "status": "active",
                              "items": {"data": [{"price": {"id": app_module.PLANS["teams"]["price_id"]}}]}}}}
    monkeypatch.setattr(app_module, "_stripe_verify_webhook", lambda p, s: (True, ev))
    r = flask_app.test_client().post("/stripe/webhook", data=b"{}")
    assert r.status_code == 200
    assert store["seats"]["A"]["plan"] == "teams" and store["seats"]["A"]["trial_active"] is False
    assert store["seats"]["B"]["plan"] == "solo"


def test_teammate_screen_has_no_stale_unlimited_promise():
    html = open("templates/index.html", encoding="utf-8").read()
    assert "for unlimited custom teammates" not in html
    assert '"founder_classic": {label:"🔥 Founder Access"' in html
