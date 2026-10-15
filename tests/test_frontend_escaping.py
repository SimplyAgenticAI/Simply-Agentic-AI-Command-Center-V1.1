"""Guards for the V12.1 front-end XSS sweep: outside text (calendar invites,
booking notes, imported contacts, web leads) must be escaped where it is put
into HTML. These check the template source so the holes can't creep back."""
import re
from pathlib import Path

SRC = (Path(__file__).resolve().parent.parent / "templates" / "index.html").read_text(encoding="utf-8")


def test_calendar_descriptions_are_escaped_inside_textareas():
    # wcalCleanDescription strips tags and DECODES &lt; → <, so it must be re-escaped
    assert not re.search(r">\$\{wcalCleanDescription\(", SRC)
    assert SRC.count("${escapeHtml(wcalCleanDescription(") >= 3


def test_calendar_event_titles_fully_escaped():
    assert "const title=(ev.summary||'Task').replace(/</g,'&lt;');" not in SRC
    assert "const title=(ev.summary||'Event').replace(/</g,'&lt;');" not in SRC


def test_event_key_never_raw_in_inline_onclick():
    assert "var evKey=&quot;'+(ev.id||ev.summary||'')+'&quot;" not in SRC
    assert SRC.count("decodeURIComponent(&quot;'+encodeURIComponent(ev.id||ev.summary||'')") == 2


def test_other_patched_spots():
    assert "${inv.email}" not in SRC and "${escapeHtml(inv.email)}" in SRC
    assert "'+ (pb.title||'Untitled') +'" not in SRC
    assert '<img src="${att.url}"' not in SRC
