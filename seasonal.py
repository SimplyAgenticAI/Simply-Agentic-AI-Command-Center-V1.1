"""Seasonal accents for the public landing and login pages.

The clock is America/New_York, recomputed on each call. Windows repeat every
year: Halloween Oct 15–31, Thanksgiving Nov 1 through Cyber Monday (the fourth
Thursday of November plus four days), then winter through Jan 1. Winter is
snow and frost only. Every other day stays the default deep-space look.

SEASONAL_THEME: auto (default) | off (kill switch) | halloween | thanksgiving
| winter | default. A ?theme= query previews one request and does not stick.
"""

from __future__ import annotations

import os
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

ET = ZoneInfo("America/New_York")

THEMES = ("halloween", "thanksgiving", "winter", "default")
_QUERY_THEMES = frozenset(THEMES)
_FORCE_THEMES = frozenset(("halloween", "thanksgiving", "winter", "default"))


def fourth_thursday_of_november(year: int) -> date:
    nov1 = date(year, 11, 1)
    # Monday is 0 … Thursday is 3.
    days_until_thu = (3 - nov1.weekday()) % 7
    return nov1 + timedelta(days=days_until_thu + 21)


def cyber_monday(year: int) -> date:
    """Monday four days after the fourth Thursday in November."""
    return fourth_thursday_of_november(year) + timedelta(days=4)


def theme_for_date(day: date) -> str:
    if day.month == 10 and day.day >= 15:
        return "halloween"
    # Jan 1 closes the winter window that began after the previous Cyber Monday.
    if day.month == 1 and day.day == 1:
        return "winter"
    # Thanksgiving is Nov 1 through Cyber Monday. Cyber Monday can fall on
    # Dec 1 or Dec 2, and the next day starts winter through the new year.
    if day.month in (11, 12):
        monday = cyber_monday(day.year)
        if date(day.year, 11, 1) <= day <= monday:
            return "thanksgiving"
        if day > monday:
            return "winter"
    return "default"


def _today_et(now: datetime | None = None) -> date:
    if now is None:
        now = datetime.now(ET)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=ET)
    else:
        now = now.astimezone(ET)
    return now.date()


def current_theme(
    today: date | None = None,
    query: str | None = None,
    env: str | None = None,
) -> str:
    """Theme for a single request.

    A recognized query value wins for that request only. Otherwise
    SEASONAL_THEME=auto follows the ET date, off forces the everyday look,
    and a theme name forces that theme. Unrecognized values behave as auto.
    """
    q = (query or "").strip().lower()
    if q in _QUERY_THEMES:
        return q
    if env is None:
        env = os.getenv("SEASONAL_THEME")
    mode = (env or "auto").strip().lower()
    if mode == "off":
        return "default"
    if mode in _FORCE_THEMES:
        return mode
    day = today if today is not None else _today_et()
    return theme_for_date(day)


_MARKS = {
    "halloween": (
        '<svg class="season-symbol" viewBox="0 0 16 16" aria-hidden="true" focusable="false">'
        '<path fill="#15803d" d="M7.2 1.6c.4 1 .2 1.8-.2 2.3h1.8c-.3-.7-.2-1.5.3-2.4-.6.1-1.3.1-1.9.1z"/>'
        '<ellipse cx="8" cy="9.5" rx="4.7" ry="4.7" fill="#f97316"/>'
        '<path stroke="#9a3412" stroke-width=".7" fill="none" d="M8 5.2v8.4M5.6 6.4c.5 2.2.5 4.6 0 6.6M10.4 6.4c-.5 2.2-.5 4.6 0 6.6"/>'
        "</svg>"
    ),
    "thanksgiving": (
        '<svg class="season-symbol" viewBox="0 0 16 16" aria-hidden="true" focusable="false">'
        '<path fill="#b45309" d="M3.1 13.4C6.6 12.2 13.2 8.6 13.6 2.4 8.2 3.4 3.8 8 3.1 13.4z"/>'
        '<path fill="#f59e0b" d="M4.3 12.2C7.2 10.8 11.8 7.6 12.4 3.6 8.4 4.6 5.2 8.2 4.3 12.2z"/>'
        '<path stroke="#7c2d12" stroke-width=".65" fill="none" d="M4.6 12.4C7.4 9.4 9.8 6.2 12.2 3.6"/>'
        "</svg>"
    ),
    "winter": (
        '<svg class="season-symbol" viewBox="0 0 16 16" aria-hidden="true" focusable="false">'
        '<path fill="#e2e8f0" d="M7.25 1.1h1.5v4.55l3.9-2.3.78 1.3-3.95 2.3 3.95 2.3-.78 1.3-3.9-2.3v4.55h-1.5V8.25l-3.9 2.3-.78-1.3 3.95-2.3-3.95-2.3.78-1.3 3.9 2.3V1.1z"/>'
        "</svg>"
    ),
}


def mark_svg(theme: str) -> str:
    """Tiny inline symbol for the logo. Empty outside a seasonal window."""
    return _MARKS.get(theme, "")


def public_theme_css() -> str:
    """Token overrides for nebula glow, the Start-button edge, and the logo dot.

    Default pages set no tokens, so the fallbacks in the page CSS stay put.
    """
    return """<style id="seasonal-theme">
:root[data-theme="halloween"]{
  --nebula-cyan-1:rgba(249,115,22,.62);
  --nebula-cyan-2:rgba(249,115,22,.26);
  --nebula-cyan-3:rgba(249,115,22,.20);
  --logo-dot:#f97316;
  --logo-dot-2:#c2410c;
  --logo-dot-soft:rgba(249,115,22,.45);
  --logo-dot-glow:rgba(249,115,22,.70);
  --logo-mid:#fdba74;
  --start-edge:#f97316;
  --nebula-h-cyan:24;
}
:root[data-theme="thanksgiving"]{
  --nebula-cyan-1:rgba(245,158,11,.62);
  --nebula-cyan-2:rgba(245,158,11,.26);
  --nebula-cyan-3:rgba(180,83,9,.20);
  --nebula-violet-1:rgba(180,83,9,.68);
  --nebula-violet-2:rgba(180,83,9,.30);
  --nebula-violet-3:rgba(245,158,11,.18);
  --nebula-violet-4:rgba(180,83,9,.24);
  --logo-dot:#f59e0b;
  --logo-dot-2:#b45309;
  --logo-dot-soft:rgba(245,158,11,.45);
  --logo-dot-glow:rgba(245,158,11,.70);
  --logo-mid:#fcd34d;
  --start-edge:#f59e0b;
  --nebula-h-cyan:38;
  --nebula-h-violet:26;
}
:root[data-theme="winter"]{
  --nebula-cyan-1:rgba(103,232,249,.62);
  --nebula-cyan-2:rgba(226,232,240,.26);
  --nebula-cyan-3:rgba(103,232,249,.20);
  --logo-dot:#f8fafc;
  --logo-dot-2:#e2e8f0;
  --logo-dot-soft:rgba(103,232,249,.55);
  --logo-dot-glow:rgba(226,232,240,.85);
  --logo-mid:#e2e8f0;
  --start-edge:#67e8f9;
  --nebula-h-cyan:189;
}
:root[data-theme="halloween"] .bp,
:root[data-theme="thanksgiving"] .bp,
:root[data-theme="winter"] .bp{
  box-shadow:0 8px 28px rgba(124,58,237,.45),0 0 0 1px var(--start-edge);
}
:root[data-theme="halloween"] .bp:hover,
:root[data-theme="thanksgiving"] .bp:hover,
:root[data-theme="winter"] .bp:hover{
  box-shadow:0 12px 36px rgba(124,58,237,.62),0 0 0 1px var(--start-edge);
}
:root[data-theme="halloween"] .nav-cta,
:root[data-theme="thanksgiving"] .nav-cta,
:root[data-theme="winter"] .nav-cta{
  box-shadow:0 4px 18px rgba(124,58,237,.4),0 0 0 1px var(--start-edge);
}
:root[data-theme="halloween"] .logo-dot,
:root[data-theme="thanksgiving"] .logo-dot,
:root[data-theme="winter"] .logo-dot,
:root[data-theme="halloween"] .dot,
:root[data-theme="thanksgiving"] .dot,
:root[data-theme="winter"] .dot{position:relative;}
.season-symbol{position:absolute;width:11px;height:11px;left:4px;top:-8px;pointer-events:none;overflow:visible;}
</style>"""
