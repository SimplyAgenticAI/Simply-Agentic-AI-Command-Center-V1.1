"""V18.8: a trial with no plan picked bills Founder (while seats remain), not Solo.
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
    return sent.get("line_items[0][price]")


def test_no_plan_bills_founder(flask_app, monkeypatch):
    assert _checkout_price(flask_app, monkeypatch, {}) == app_module.PLANS["founder"]["price_id"]
    assert _checkout_price(flask_app, monkeypatch, {"plan": "bogus"}) == app_module.PLANS["founder"]["price_id"]


def test_picked_plan_still_respected(flask_app, monkeypatch):
    assert _checkout_price(flask_app, monkeypatch, {"plan": "solo"}) == app_module.PLANS["solo"]["price_id"]


def test_signup_page_button_sends_the_shown_plan(flask_app, monkeypatch):
    monkeypatch.setattr(app_module, "_founder_seats_remaining", lambda: 50)
    page = flask_app.test_client().get("/register").get_data(as_text=True)
    if "startStripeCheckout" in page:
        assert "|| 'solo'" not in page and "|| \"founder\"" in page
