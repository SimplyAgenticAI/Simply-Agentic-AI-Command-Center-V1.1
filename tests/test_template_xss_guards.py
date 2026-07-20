"""Template-invariant guards for the CRM/notification stored-XSS fixes (V8.5).

CRM contact data (name/company/email) can be bulk-imported from Facebook via
the extension, so a contact's name is attacker-controlled and could carry
markup. The main CRM card render already escaped it, but the Create Task and
Draft Outreach dialogs, a Messenger href, and the notification feed
interpolated it into innerHTML raw.

Unit tests can't execute the client JS, so these string-level checks fail if
anyone drops the escapeHtml wrap from a known sink. Each asserts the RAW
(unescaped) interpolation is gone — the fix must keep the escaped form.
"""
import pathlib

import pytest

_TEMPLATE = (pathlib.Path(__file__).resolve().parent.parent / "templates" / "index.html").read_text(encoding="utf-8")


@pytest.mark.parametrize("raw_sink", [
    "Create Task for ${client.name||'Contact'}",          # dialog title
    "value=\"Follow up with ${client.name||'contact'}\"",  # input value attr
    "Draft Outreach for ${c.name||'Contact'}",             # dialog title
    "'<option value=\"email\">Email — '+c.email+'",        # option text
    "href=\"${msgrUrl}\"",                                  # messenger href attr
    ">${n.title}<",                                          # notification title
    ">${n.body}<",                                           # notification body
])
def test_known_xss_sink_is_not_left_raw(raw_sink):
    assert raw_sink not in _TEMPLATE, (
        f"Unescaped interpolation reintroduced — wrap it in escapeHtml(): {raw_sink!r}"
    )


@pytest.mark.parametrize("escaped_sink", [
    "Create Task for ${escapeHtml(client.name||'Contact')}",
    "Draft Outreach for ${escapeHtml(c.name||'Contact')}",
    "'+escapeHtml(c.email)+'",
    "href=\"${escapeHtml(msgrUrl)}\"",
    ">${escapeHtml(n.title)}<",
    ">${escapeHtml(n.body)}<",
])
def test_escaped_form_is_present(escaped_sink):
    assert escaped_sink in _TEMPLATE, f"Expected escaped sink missing: {escaped_sink!r}"
