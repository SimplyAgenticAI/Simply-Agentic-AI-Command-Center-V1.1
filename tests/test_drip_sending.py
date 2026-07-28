"""Regression tests for automated drip (check-in) email sending (V9.2).

The engine, enrollment, and 60s scheduler were all built, but _drip_tick sent
via crm settings.gmail_access_token — a key never written anywhere — so no drip
email ever sent, and it advanced the step even on failure. Now it sends through
the unified _crm_send_email_to (Gmail w/ refresh OR SMTP) and only advances on a
confirmed send.
"""
import app as app_module


def _setup_campaign(uname, status="active", interval_days=30):
    app_module.save_users({"users": {uname: {
        "username": uname, "is_admin": True,
        "settings": {"smtp": {"from_name": "Jeff"}}}}})
    app_module._crm_save(uname, {
        "clients": {"c1": {"id": "c1", "name": "Dana Lee",
                           "email": "dana@client.com", "tags": ["vip"]}},
        "settings": {"from_name": "Jeff"}})
    camps = {"drip_x": {
        "id": "drip_x", "name": "Monthly check-in", "status": status,
        "audience": "all", "interval_days": interval_days, "send_time": "09:00",
        "start_date": "2020-01-01",
        "steps": [{"subject": "Checking in, [First Name]!",
                   "body": "Hi [First Name], how are things? — [Your Name]"},
                  {"subject": "Following up",
                   "body": "Circling back, [First Name]. — [Your Name]"}],
        "enrollments": {}, "created_at": "2020-01-01T00:00:00"}}
    app_module._drip_save(uname, camps)
    camps = app_module._drip_load(uname)
    app_module._drip_enroll_contacts(uname, "drip_x", camps)
    app_module._drip_save(uname, camps)


def test_due_email_sends_and_fills_placeholders(monkeypatch):
    uname = "drip_ok"
    _setup_campaign(uname)
    sent = []
    monkeypatch.setattr(app_module, "_crm_send_email_to",
                        lambda u, to, subj, body, from_name="": (
                            sent.append({"to": to, "subj": subj, "body": body}) or (True, "gmail", "")))
    app_module._drip_tick(uname)
    assert len(sent) == 1
    assert sent[0]["to"] == "dana@client.com"
    assert sent[0]["subj"] == "Checking in, Dana!"          # [First Name] filled
    assert sent[0]["body"] == "Hi Dana, how are things? — Jeff"  # [Your Name] filled too
    # Step advanced past the first message
    enr = app_module._drip_load(uname)["drip_x"]["enrollments"]["c1"]
    assert enr["step_idx"] == 1


def test_not_resent_before_interval(monkeypatch):
    uname = "drip_once"
    _setup_campaign(uname)
    sent = []
    monkeypatch.setattr(app_module, "_crm_send_email_to",
                        lambda *a, **k: (sent.append(1) or (True, "gmail", "")))
    app_module._drip_tick(uname)
    app_module._drip_tick(uname)  # immediate re-tick
    assert len(sent) == 1, "must not resend before the interval elapses"


def test_failed_send_does_not_advance(monkeypatch):
    uname = "drip_fail"
    _setup_campaign(uname)
    monkeypatch.setattr(app_module, "_crm_send_email_to",
                        lambda *a, **k: (False, "smtp", "SMTP not connected."))
    app_module._drip_tick(uname)
    enr = app_module._drip_load(uname)["drip_x"]["enrollments"]["c1"]
    assert enr["step_idx"] == 0, "a failed send must not skip the step"
    assert enr.get("done") is not True


def test_paused_campaign_does_not_send(monkeypatch):
    uname = "drip_paused"
    _setup_campaign(uname, status="paused")
    sent = []
    monkeypatch.setattr(app_module, "_crm_send_email_to",
                        lambda *a, **k: (sent.append(1) or (True, "gmail", "")))
    app_module._drip_tick(uname)
    assert sent == []


def test_contact_without_email_is_retired(monkeypatch):
    uname = "drip_noemail"
    app_module.save_users({"users": {uname: {"username": uname, "is_admin": True, "settings": {}}}})
    app_module._crm_save(uname, {"clients": {"c1": {"id": "c1", "name": "No Email"}},
                                 "settings": {}})
    camps = {"drip_y": {"id": "drip_y", "name": "x", "status": "active", "audience": "all",
                        "interval_days": 30, "send_time": "09:00", "start_date": "2020-01-01",
                        "steps": [{"subject": "hi", "body": "hi"}], "enrollments": {},
                        "created_at": "2020-01-01T00:00:00"}}
    app_module._drip_save(uname, camps)
    camps = app_module._drip_load(uname)
    app_module._drip_enroll_contacts(uname, "drip_y", camps)
    app_module._drip_save(uname, camps)
    sent = []
    monkeypatch.setattr(app_module, "_crm_send_email_to",
                        lambda *a, **k: (sent.append(1) or (True, "gmail", "")))
    app_module._drip_tick(uname)
    assert sent == []  # nothing to send
    enr = app_module._drip_load(uname)["drip_y"]["enrollments"].get("c1")
    if enr:  # enrolled by id even without email
        assert enr.get("done") is True
