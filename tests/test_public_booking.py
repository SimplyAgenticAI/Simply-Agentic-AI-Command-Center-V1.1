"""Public Booking Link — the only routes in the app a stranger can reach
without a session, so the exemptions that make them reachable are exactly
what needs a regression test.

/book/ and /api/public/booking/ are deliberately exempt from BOTH the auth
guard and CSRF (a visitor has no session and no token). That means two
whole classes of bug are one-line-away at all times:
  - a tightened auth guard silently 302s the public page to /login
    (this is what happened to the extension API), and
  - visitor-supplied text reaching HTML unescaped, since this is the app's
    only anonymous write path.
Both are asserted below, alongside the anti-abuse controls that stand in
for auth here (rate limit + honeypot) and the server-side slot re-validation
that stops a client claiming any time it likes.

Google is stubbed throughout — these tests cover our logic, not Google's.
"""
import re
from datetime import timedelta

import pytest

import app as app_module


SLUG = "testbook"
MEETING_TYPE = {
    "id": "mt1",
    "name": "Strategy Call",
    "duration_min": 30,
    "active": True,
    "description": "",
    "location": "",
    "use_meet": False,
}


@pytest.fixture(autouse=True)
def _clear_rate_limits():
    """Rate limits are in-memory and keyed by IP; every test client shares
    127.0.0.1, so without this the 5-per-window submit cap leaks across tests."""
    with app_module._RATE_LIMITS_LOCK:
        app_module._RL_MEM.clear()
    yield


@pytest.fixture()
def booking_user(flask_app, monkeypatch):
    """A registered user with an enabled booking page and Google stubbed out.

    Returns a dict with the sent-email list and the created-event list so
    tests can assert on side effects.
    """
    # Build the user record directly rather than going through /register:
    # these routes need no session, and registration throttles per-IP once
    # the full suite has run, which made this fixture pass alone but error
    # in the suite.
    users = app_module.load_users()
    rec = users.setdefault("users", {}).setdefault("bookhost", {
        "username": "bookhost",
        "email": "host@example.com",
        "created_at": app_module.now_iso(),
    })
    rec["email"] = "host@example.com"
    rec.setdefault("settings", {})["booking"] = {
        "enabled": True,
        "slug": SLUG,
        "timezone": "UTC",
        "meeting_types": [MEETING_TYPE],
        # Open every day so the test never depends on which weekday it runs.
        "working_hours": {k: [{"start": "00:00", "end": "23:59"}]
                          for k in app_module._BOOKING_WEEKDAY_KEYS},
        "buffer_min": 0,
        "min_notice_hours": 1,
        "max_horizon_days": 30,
        "slot_step_min": 30,
        "custom_message": "",
    }
    app_module.save_users(users)

    created_events = []
    sent_emails = []

    def _fake_create(access_token, title, start_iso, end_iso, timezone,
                     attendees=None, description="", location="", use_meet=False):
        created_events.append({"title": title, "start": start_iso,
                               "attendees": attendees, "description": description})
        return {"id": "evt_stub_1"}

    monkeypatch.setattr(app_module, "_calendar_creds_for_user",
                        lambda u: ("stub-access-token", ""))
    monkeypatch.setattr(app_module, "_calendar_check_conflicts",
                        lambda *a, **k: [])
    monkeypatch.setattr(app_module, "_calendar_create_event", _fake_create)
    monkeypatch.setattr(app_module, "_calendar_delete_event",
                        lambda *a, **k: (True, ""))
    monkeypatch.setattr(app_module, "_send_booking_email_for_user",
                        lambda u, to, subj, body: sent_emails.append(
                            {"to": to, "subject": subj, "body": body}) or (True, ""))

    return {"events": created_events, "emails": sent_emails}


def _future_date_str(days=2):
    return (app_module._utcnow() + timedelta(days=days)).strftime("%Y-%m-%d")


def _first_slot(client, days=2):
    """Book against a slot the server itself offered, so the test exercises
    the real contract between /slots and /book instead of a guessed format."""
    resp = client.get(f"/api/public/booking/{SLUG}/slots",
                      query_string={"date": _future_date_str(days),
                                    "meeting_type": "mt1", "tz": "UTC"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body.get("ok") is True, body
    assert body["slots"], "expected bookable slots on a fully-open day"
    return body["slots"][0]


# ── Reachability: the exemptions that make this feature work at all ──────────

def test_public_page_is_reachable_without_a_session(client, booking_user):
    """The auth guard must let /book/ through. A redirect here means the
    booking page is dead for every visitor."""
    resp = client.get(f"/book/{SLUG}")
    assert resp.status_code == 200
    assert "/login" not in (resp.headers.get("Location") or "")
    assert b"Strategy Call" in resp.data


def test_public_api_is_reachable_without_a_session(client, booking_user):
    resp = client.get(f"/api/public/booking/{SLUG}/meta")
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True


def test_submit_works_without_a_csrf_token(client, booking_user):
    """A visitor has no CSRF token. If CSRF starts applying here, every
    booking 400s."""
    start = _first_slot(client)
    resp = client.post(f"/api/public/booking/{SLUG}/book", json={
        "meeting_type": "mt1", "start": start,
        "visitor_name": "Casey Jones", "visitor_email": "casey@example.com",
        "visitor_notes": "Looking forward to it.",
    })
    assert resp.status_code == 200, resp.data
    assert resp.get_json()["ok"] is True
    assert len(booking_user["events"]) == 1


def test_unknown_slug_404s(client, booking_user):
    assert client.get("/book/nope-not-a-real-slug").status_code == 404
    assert client.get("/api/public/booking/nope/meta").status_code == 404


# ── Anti-abuse: what stands in for auth on an anonymous write path ──────────

def test_honeypot_fakes_success_and_writes_nothing(client, booking_user):
    start = _first_slot(client)
    # DATA_DIR is session-scoped, so compare against the store as it is now
    # rather than assuming it is empty.
    before = set((app_module._bookings_load("bookhost").get("bookings") or {}))
    resp = client.post(f"/api/public/booking/{SLUG}/book", json={
        "meeting_type": "mt1", "start": start,
        "visitor_name": "Spam Bot", "visitor_email": "spam@example.com",
        "hp_website": "http://spam.example",
    })
    # Looks like success to the bot...
    assert resp.get_json()["ok"] is True
    # ...but nothing real happened.
    assert booking_user["events"] == []
    assert booking_user["emails"] == []
    after = set((app_module._bookings_load("bookhost").get("bookings") or {}))
    assert after == before


def test_submit_is_rate_limited(client, booking_user):
    start = _first_slot(client)
    payload = {"meeting_type": "mt1", "start": start,
               "visitor_name": "Flooder", "visitor_email": "f@example.com"}
    codes = [client.post(f"/api/public/booking/{SLUG}/book", json=payload).status_code
             for _ in range(7)]
    assert 429 in codes, f"submit should throttle a flood, got {codes}"


# ── Server-side validation: never trust a client-claimed slot ───────────────

def test_slot_inside_min_notice_is_rejected(client, booking_user):
    """min_notice_hours is 1 in the fixture — a slot 5 minutes out must fail
    even though the client asked for it politely."""
    too_soon = (app_module._utcnow() + timedelta(minutes=5)).isoformat() + "Z"
    resp = client.post(f"/api/public/booking/{SLUG}/book", json={
        "meeting_type": "mt1", "start": too_soon,
        "visitor_name": "Eager", "visitor_email": "eager@example.com",
    })
    assert resp.status_code == 400
    assert booking_user["events"] == []


def test_slot_beyond_horizon_is_rejected(client, booking_user):
    too_far = (app_module._utcnow() + timedelta(days=400)).isoformat() + "Z"
    resp = client.post(f"/api/public/booking/{SLUG}/book", json={
        "meeting_type": "mt1", "start": too_far,
        "visitor_name": "Patient", "visitor_email": "patient@example.com",
    })
    assert resp.status_code == 400
    assert booking_user["events"] == []


def test_invalid_email_is_rejected(client, booking_user):
    start = _first_slot(client)
    resp = client.post(f"/api/public/booking/{SLUG}/book", json={
        "meeting_type": "mt1", "start": start,
        "visitor_name": "No Email", "visitor_email": "not-an-email",
    })
    assert resp.status_code == 400
    assert booking_user["events"] == []


def test_double_booking_returns_conflict(client, booking_user, monkeypatch):
    start = _first_slot(client)
    monkeypatch.setattr(app_module, "_calendar_check_conflicts",
                        lambda *a, **k: [{"summary": "already busy"}])
    resp = client.post(f"/api/public/booking/{SLUG}/book", json={
        "meeting_type": "mt1", "start": start,
        "visitor_name": "Late", "visitor_email": "late@example.com",
    })
    assert resp.status_code == 409
    assert resp.get_json().get("conflict") is True
    assert booking_user["events"] == []


# ── Escaping: this is the app's only anonymous text-into-HTML path ──────────

XSS = '<script>alert("xss")</script>'


def test_visitor_name_is_escaped_on_the_cancel_page(client, booking_user):
    """visitor_name is rendered on the cancel page. It comes from an
    anonymous stranger, so it must never reach the DOM as markup."""
    start = _first_slot(client)
    resp = client.post(f"/api/public/booking/{SLUG}/book", json={
        "meeting_type": "mt1", "start": start,
        "visitor_name": XSS, "visitor_email": "xss@example.com",
        "visitor_notes": XSS,
    })
    assert resp.get_json()["ok"] is True
    cancel_url = resp.get_json()["booking"]["cancel_url"]
    path = re.sub(r"^https?://[^/]+", "", cancel_url)

    page = client.get(path)
    assert page.status_code == 200
    body = page.data.decode()
    assert "<script>alert" not in body, "visitor name rendered as live markup"
    assert "&lt;script&gt;" in body, "expected the payload escaped, not stripped"


def test_cancel_flow_marks_booking_cancelled(client, booking_user):
    start = _first_slot(client)
    resp = client.post(f"/api/public/booking/{SLUG}/book", json={
        "meeting_type": "mt1", "start": start,
        "visitor_name": "Casey Jones", "visitor_email": "casey@example.com",
    })
    booking_id = resp.get_json()["booking"]["id"]
    path = re.sub(r"^https?://[^/]+", "",
                  resp.get_json()["booking"]["cancel_url"])

    assert client.post(path).status_code == 200
    stored = app_module._bookings_load("bookhost")["bookings"][booking_id]
    assert stored["status"] == "cancelled"


def test_cancel_token_is_unguessable_and_scoped(client, booking_user):
    """The cancel token is the only credential protecting someone else's
    booking — a wrong one must not cancel anything."""
    start = _first_slot(client)
    resp = client.post(f"/api/public/booking/{SLUG}/book", json={
        "meeting_type": "mt1", "start": start,
        "visitor_name": "Casey Jones", "visitor_email": "casey@example.com",
    })
    token = resp.get_json()["booking"]["cancel_url"].rsplit("/", 1)[-1]
    assert len(token) >= 32

    booking_id = resp.get_json()["booking"]["id"]
    assert client.post(f"/book/{SLUG}/cancel/{'0' * 64}").status_code == 404
    stored = app_module._bookings_load("bookhost")["bookings"][booking_id]
    assert stored["status"] == "confirmed", "a bogus token cancelled a real booking"


def test_booking_confirmation_emails_both_parties(client, booking_user):
    start = _first_slot(client)
    client.post(f"/api/public/booking/{SLUG}/book", json={
        "meeting_type": "mt1", "start": start,
        "visitor_name": "Casey Jones", "visitor_email": "casey@example.com",
    })
    recipients = [e["to"] for e in booking_user["emails"]]
    assert "casey@example.com" in recipients
    assert "host@example.com" in recipients
