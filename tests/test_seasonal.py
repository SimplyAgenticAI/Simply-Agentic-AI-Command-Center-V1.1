"""Seasonal windows and the public-page theme switch.

Dates are America/New_York. 2026 Cyber Monday is Nov 30, so winter starts
Dec 1. 2027 Cyber Monday is Nov 29, so winter starts Nov 30.
"""

from datetime import date, datetime, timezone

import pytest

import seasonal


@pytest.mark.parametrize(
    "day,expected",
    [
        (date(2026, 10, 14), "default"),
        (date(2026, 10, 15), "halloween"),
        (date(2026, 10, 31), "halloween"),
        (date(2026, 11, 1), "thanksgiving"),
        (date(2026, 11, 24), "thanksgiving"),
        (date(2026, 11, 26), "thanksgiving"),
        (date(2026, 11, 30), "thanksgiving"),
        (date(2026, 12, 1), "winter"),
        (date(2026, 12, 25), "winter"),
        (date(2026, 12, 31), "winter"),
        (date(2026, 1, 1), "winter"),
        (date(2026, 1, 2), "default"),
        (date(2026, 6, 15), "default"),
        (date(2027, 1, 1), "winter"),
        (date(2027, 1, 2), "default"),
        (date(2027, 10, 14), "default"),
        (date(2027, 10, 15), "halloween"),
        (date(2027, 11, 1), "thanksgiving"),
        (date(2027, 11, 29), "thanksgiving"),
        (date(2027, 11, 30), "winter"),
        (date(2027, 12, 31), "winter"),
        # Cyber Monday can land in December (2024-12-02, 2025-12-01).
        (date(2024, 11, 28), "thanksgiving"),
        (date(2024, 12, 2), "thanksgiving"),
        (date(2024, 12, 3), "winter"),
        (date(2025, 11, 27), "thanksgiving"),
        (date(2025, 12, 1), "thanksgiving"),
        (date(2025, 12, 2), "winter"),
    ],
)
def test_theme_for_date(day, expected):
    assert seasonal.theme_for_date(day) == expected
    assert seasonal.current_theme(today=day, env="auto") == expected


def test_et_date_not_utc():
    # 04:30 UTC on Dec 1 2026 is still Nov 30 evening in New York.
    still_nov = datetime(2026, 12, 1, 4, 30, tzinfo=timezone.utc)
    assert seasonal._today_et(still_nov) == date(2026, 11, 30)
    assert seasonal.theme_for_date(seasonal._today_et(still_nov)) == "thanksgiving"
    new_day = datetime(2026, 12, 1, 5, 30, tzinfo=timezone.utc)
    assert seasonal._today_et(new_day) == date(2026, 12, 1)
    assert seasonal.theme_for_date(seasonal._today_et(new_day)) == "winter"


def test_env_and_query_overrides():
    halloween = date(2026, 10, 31)
    quiet = date(2026, 1, 2)
    assert seasonal.current_theme(today=halloween, env="off") == "default"
    assert seasonal.current_theme(today=halloween, env="OFF") == "default"
    assert seasonal.current_theme(today=quiet, env="halloween") == "halloween"
    assert seasonal.current_theme(today=quiet, env=" thanksgiving ") == "thanksgiving"
    assert seasonal.current_theme(today=quiet, env="winter") == "winter"
    assert seasonal.current_theme(today=quiet, env="default") == "default"
    assert seasonal.current_theme(today=halloween, env="mystery") == "halloween"
    assert seasonal.current_theme(today=quiet, env="") == "default"
    # Query previews that request only; it beats the env force and the kill switch.
    assert seasonal.current_theme(today=halloween, query="winter", env="off") == "winter"
    assert seasonal.current_theme(today=halloween, query="default", env="halloween") == "default"
    assert seasonal.current_theme(today=quiet, query="Halloween", env="off") == "halloween"
    assert seasonal.current_theme(today=halloween, query="nope", env="off") == "default"
    assert seasonal.current_theme(today=halloween, query="off", env="auto") == "halloween"
    assert seasonal.current_theme(today=quiet, query="", env="auto") == "default"


def test_current_theme_reads_env_and_clock(monkeypatch):
    monkeypatch.setenv("SEASONAL_THEME", "off")
    monkeypatch.setattr(seasonal, "_today_et", lambda now=None: date(2026, 10, 31))
    assert seasonal.current_theme() == "default"
    monkeypatch.setenv("SEASONAL_THEME", "auto")
    assert seasonal.current_theme() == "halloween"
    monkeypatch.delenv("SEASONAL_THEME", raising=False)
    monkeypatch.setattr(seasonal, "_today_et", lambda now=None: date(2026, 12, 1))
    assert seasonal.current_theme() == "winter"


def test_marks_only_for_seasonal_themes():
    assert seasonal.mark_svg("default") == ""
    assert seasonal.mark_svg("off") == ""
    assert seasonal.mark_svg("") == ""
    pumpkin = seasonal.mark_svg("halloween")
    leaf = seasonal.mark_svg("thanksgiving")
    flake = seasonal.mark_svg("winter")
    assert 'class="season-symbol"' in pumpkin
    assert "#f97316" in pumpkin
    assert "#f59e0b" in leaf and "#b45309" in leaf
    assert "#e2e8f0" in flake
    for mark in (pumpkin, leaf, flake):
        assert "<svg" in mark and "aria-hidden" in mark
        assert "Happy" not in mark
    css = seasonal.public_theme_css()
    assert 'id="seasonal-theme"' in css
    assert "--start-edge:#f97316" in css
    assert "--start-edge:#f59e0b" in css
    assert "--start-edge:#67e8f9" in css
    assert "rgba(249,115,22,.62)" in css
    assert "rgba(245,158,11,.62)" in css
    assert "rgba(180,83,9,.68)" in css
    assert "rgba(103,232,249,.62)" in css
    assert "#f8fafc" in css
    # The everyday page sets none of these tokens.
    assert '[data-theme="default"]' not in css


def _ensure_an_account():
    """/ sends logged-out visitors to setup until the install has a user."""
    import app as app_module

    data = app_module.load_users()
    users = data.setdefault("users", {})
    if users:
        return
    users["publicseed"] = {"username": "publicseed", "password_hash": "x", "is_admin": True}
    app_module.save_users(data)
    app_module._invalidate_users_cache()


def _theme_attr(html: str) -> str:
    marker = 'data-theme="'
    start = html.find(marker)
    assert start != -1
    start += len(marker)
    end = html.find('"', start)
    return html[start:end]


def test_public_pages_follow_query_and_leave_other_pages_alone(client, monkeypatch):
    _ensure_an_account()
    monkeypatch.setenv("SEASONAL_THEME", "off")
    monkeypatch.setenv("ALLOW_SIGNUP", "1")

    everyday = client.get("/")
    assert everyday.status_code == 200
    html = everyday.get_data(as_text=True)
    assert _theme_attr(html) == "default"
    assert 'class="season-symbol"' not in html
    assert 'id="seasonal-theme"' in html
    assert "7 Specialists" in html
    assert "linear-gradient(140deg,#f3e8ff 0%,var(--pl) 40%,#818cf8 100%)" in html
    # Fallbacks keep the original nebula and logo colors on the everyday page.
    assert "var(--nebula-cyan-1,rgba(14,165,233,.62))" in html
    assert "var(--logo-dot,#7c3aed)" in html
    assert "var(--logo-dot-2,#4f46e5)" in html

    preview = client.get("/?theme=halloween")
    themed = preview.get_data(as_text=True)
    assert _theme_attr(themed) == "halloween"
    assert 'class="season-symbol"' in themed
    assert "#f97316" in themed
    assert "Halloween" not in themed
    assert "7 Specialists" in themed

    # The query does not stick to the next request.
    assert _theme_attr(client.get("/").get_data(as_text=True)) == "default"

    login = client.get("/login?theme=Winter")
    login_html = login.get_data(as_text=True)
    assert login.status_code == 200
    assert _theme_attr(login_html) == "winter"
    assert 'class="season-symbol"' in login_html
    assert 'class="dot"' in login_html

    monkeypatch.setenv("SEASONAL_THEME", "thanksgiving")
    forced = client.get("/showcase")
    assert _theme_attr(forced.get_data(as_text=True)) == "thanksgiving"
    assert _theme_attr(client.get("/showcase?theme=default").get_data(as_text=True)) == "default"

    for path in ("/pricing", "/register", "/terms"):
        page = client.get(path).get_data(as_text=True)
        assert "data-theme" not in page, path
        assert "seasonal-theme" not in page, path
        assert "season-symbol" not in page, path


def test_logged_in_app_ignores_seasonal_theme(client, monkeypatch):
    import app as app_module

    monkeypatch.setenv("SEASONAL_THEME", "halloween")
    data = app_module.load_users()
    data.setdefault("users", {})["seasonuser"] = {
        "username": "seasonuser",
        "password_hash": "x",
        "is_admin": False,
    }
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    with client.session_transaction() as sess:
        sess["user"] = "seasonuser"
    resp = client.get("/?theme=thanksgiving")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert 'id="tableWrap"' in html
    assert "data-theme" not in html
    assert "seasonal-theme" not in html
    assert "season-symbol" not in html
    assert "7 Specialists" not in html
