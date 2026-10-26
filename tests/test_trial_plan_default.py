"""V18.8: a trial with no plan picked bills Founder (while seats remain), not Solo.
V18.9: new Founders get Solo's limits; earlier founders keep their original ones.
(File must sort after test_client_crud.)"""
import app as app_module


def _checkout_price(flask_app, monkeypatch, body):
    sent = {}
    monkeypatch.setattr(app_module, "_stripe_ready", lambda: True)
    monkeypatch.setattr(app_module, "_founder_seats_remaining", lambda: 50)
    monkeypatch.setattr(app_module, "_stripe_api",
                        lambda m, p, params: sent.update(params) or (200, {"url": "https://checkout.stripe.com/x"}))
    c = flask_app.test_client()
    h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
    c.post("/stripe/create_checkout", headers=h, json=body)
    return sent.get("line_items[0][price]"), sent.get("success_url", "")


def test_no_plan_bills_founder(flask_app, monkeypatch):
    founder = app_module.PLANS["founder"]["price_id"]
    assert _checkout_price(flask_app, monkeypatch, {})[0] == founder
    assert _checkout_price(flask_app, monkeypatch, {"plan": "bogus"})[0] == founder
    price, url = _checkout_price(flask_app, monkeypatch, {"plan": "founder_classic"})
    assert price == founder and "plan=founder&" not in url and url.endswith("plan=founder")


def test_picked_plan_still_respected(flask_app, monkeypatch):
    assert _checkout_price(flask_app, monkeypatch, {"plan": "solo"})[0] == app_module.PLANS["solo"]["price_id"]


def test_signup_page_button_sends_the_shown_plan(flask_app, monkeypatch):
    monkeypatch.setattr(app_module, "_stripe_ready", lambda: True)
    monkeypatch.setattr(app_module, "_founder_seats_remaining", lambda: 50)
    page = flask_app.test_client().get("/register").get_data(as_text=True)
    if "startStripeCheckout" in page:
        assert "|| 'solo'" not in page and "|| \"founder\"" in page


def test_existing_founders_keep_original_limits(monkeypatch):
    seats = {"seats": {"A": {"claimed_by": "oldf", "plan": "founder", "created_at": "2026-08-01T00:00:00Z", "status": "active"},
                       "B": {"claimed_by": "newf", "plan": "founder", "created_at": "2026-11-02T00:00:00Z", "status": "active"}}}
    monkeypatch.setattr(app_module, "_load_seats", lambda: seats)
    monkeypatch.setattr(app_module, "load_users", lambda: {"users": {"x": {"is_admin": True}, "oldf": {}, "newf": {}}})
    with app_module.app.test_request_context():
        assert app_module._get_user_plan("oldf") == "founder_classic"
        assert app_module._get_user_plan("newf") == "founder"
    P = app_module.PLANS
    assert P["founder_classic"]["crm_contacts"] == 2500 and app_module.MSG_LIMITS["founder_classic"] == 150
    assert P["founder"]["crm_contacts"] == P["solo"]["crm_contacts"]
    assert app_module.MSG_LIMITS["founder"] < app_module.MSG_LIMITS["solo"]   # 85% margin at $27
    assert {P[k]["custom_teammates"] for k in ("founder", "solo", "teams", "founder_classic")} == {7}


def test_pricing_page_hides_original_founder_plan(flask_app):
    page = flask_app.test_client().get("/pricing").get_data(as_text=True)
    assert "toolkit" in page and "2 team seats" not in page
