"""Regression tests for _sanitize_svg (V8.6).

Teammate avatar glyphs are LLM-generated from a user-supplied description and
rendered into the DOM via innerHTML. The sanitizer allowlists tags and strips
on*= handlers, but its handler regex only matched QUOTED values, so an
unquoted handler on a whitelisted element (`<circle onclick=alert(1)>`)
survived and stayed live.
"""
import app as app_module

s = app_module._sanitize_svg


def _clean(out):
    low = out.lower()
    return "onclick" not in low and "onload" not in low and "onerror" not in low and "<script" not in low


def test_quoted_handler_stripped():
    assert _clean(s('<svg viewBox="0 0 40 40"><circle onclick="alert(1)" r="5"/></svg>'))


def test_unquoted_handler_stripped():
    # The bug: unquoted value skipped the old regex.
    out = s('<svg viewBox="0 0 40 40"><circle onclick=alert(1) r=5 /></svg>')
    assert _clean(out)
    assert "<circle" in out  # the element itself is still allowed, just de-fanged


def test_onload_on_root_svg_stripped():
    assert _clean(s('<svg onload=alert(1) viewBox="0 0 40 40"><path d="M0 0"/></svg>'))


def test_script_tag_removed():
    out = s('<svg viewBox="0 0 40 40"><script>alert(1)</script><circle r="5"/></svg>')
    assert "<script" not in out.lower()


def test_javascript_uri_stripped():
    out = s('<svg viewBox="0 0 40 40"><path fill="url(javascript:alert(1))" d="M0 0"/></svg>')
    assert "javascript:" not in out.lower()


def test_disallowed_tags_removed():
    out = s('<svg viewBox="0 0 40 40"><foreignObject><body>x</body></foreignObject><circle r="5"/></svg>')
    assert "foreignobject" not in out.lower()
    assert "<body" not in out.lower()


def test_legit_glyph_preserved():
    good = '<svg viewBox="0 0 40 40"><circle cx="20" cy="20" r="10" stroke="white"/><path d="M5 5"/></svg>'
    out = s(good)
    assert "<circle" in out and "<path" in out and 'viewBox="0 0 40 40"' in out


def test_non_svg_input_rejected():
    assert s("not an svg at all") == ""
