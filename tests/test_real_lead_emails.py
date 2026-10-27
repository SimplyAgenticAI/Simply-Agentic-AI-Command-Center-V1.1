"""V19.8: lead emails must be real. AI-written contact details are checked against the
business's actual website; no guessed addresses; no web-less AI fallback.
(File must sort after test_client_crud.)"""
import json
import app as app_module


class _Resp:
    def __init__(self, rows):
        self.output_text = json.dumps(rows)


class _Client:
    def __init__(self, rows=None, fail=False):
        self.calls = []
        outer = self

        class _R:
            def create(self, **kw):
                outer.calls.append(kw)
                if fail:
                    raise RuntimeError("search unavailable")
                return _Resp(rows or [])

        class _Chat:
            class completions:
                @staticmethod
                def create(**kw):
                    raise AssertionError("must not fall back to a model without web search")
        self.responses = _R()
        self.chat = _Chat()


def test_invented_email_dropped_real_one_kept(monkeypatch):
    rows = [
        {"name": "Jane Doe", "company": "Doe Real Estate", "website": "https://doerealestate.com",
         "email": "jane@doerealestate.com", "phone": "555-111-2222"},
        {"name": "Ann Ortiz", "company": "Ortiz HVAC", "website": "https://ortizhvac.com",
         "email": "ann@ortizhvac.com", "phone": ""},
        {"name": "Bo", "company": "Real Co", "website": "https://realco.com", "email": "guess@realco.com", "phone": ""},
    ]
    monkeypatch.setattr(app_module, "get_openai_client", lambda: _Client(rows))
    sites = {
        "doerealestate.com": [],                                          # site doesn't load
        "ortizhvac.com": [("<p>Email ann@ortizhvac.com</p>", "https://ortizhvac.com")],
        "realco.com": [("<a href='mailto:office@realco.com'>Mail</a>", "https://realco.com/contact")],
    }
    monkeypatch.setattr(app_module, "_crm_fetch_contact_pages", lambda d, timeout=8: sites.get(d, []))
    out = app_module._crm_openai_web_search("hvac austin", "hvac", "Austin")
    by = {r["domain"]: r for r in out}
    assert "doerealestate.com" not in by                                  # invented business dropped
    assert by["ortizhvac.com"]["email_hint"] == "ann@ortizhvac.com"       # confirmed on the site
    assert by["realco.com"]["email_hint"] == "office@realco.com"          # AI guess replaced by the real one


def test_failed_web_search_returns_nothing_instead_of_inventing(monkeypatch):
    c = _Client(fail=True)
    monkeypatch.setattr(app_module, "get_openai_client", lambda: c)
    assert app_module._crm_openai_web_search("realtors nj", "realtors", "NJ") == []
    assert c.calls and all(k["tools"][0]["type"].startswith("web_search") for k in c.calls)


def test_no_guessed_addresses():
    cands = app_module._crm_merge_email_candidates([], "John Smith", "smithrealty.com")
    assert cands == []
    lead = app_module._crm_fallback_candidate_from_result(
        {"url": "https://smithrealty.com", "title": "Smith Realty", "domain": "smithrealty.com"}, "realtors", "NJ", "q")
    assert lead and lead["email"] == "" and lead["email_candidates"] == []
