"""Dev tool: render the authenticated index page, extract every inline <script>
block, and run `node --check` on each to catch JS syntax errors that ast.parse
and the pytest smoke tests cannot see. Exits non-zero if any block fails.
"""
import os, re, sys, tempfile, subprocess

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="saai_jsval_"))
os.environ.setdefault("APP_SECRET", "jsval-secret")
os.environ.setdefault("WTF_CSRF_ENABLED", "false")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import app as app_module
app_module.app.config.update(TESTING=True)


def _scripts(html):
    out = []
    for m in re.finditer(r"<script\b([^>]*)>(.*?)</script>", html, re.DOTALL | re.IGNORECASE):
        attrs, body = m.group(1), m.group(2)
        if "src=" in attrs.lower():
            continue
        if body.strip():
            out.append(body)
    return out


blocks = []
# 1) Authenticated app page (the bulk of the inline JS lives here).
with app_module.app.test_client() as c:
    c.post("/register", data={
        "username": "jsval", "email": "", "password": "TestPass123!",
        "password2": "TestPass123!", "tos_accepted": "on",
    }, follow_redirects=True)
    blocks += _scripts(c.get("/").get_data(as_text=True))

# 2) Unauthenticated pages (landing/login + a couple public routes) — their own scripts.
with app_module.app.test_client() as c2:
    for _route in ("/login", "/getting-started", "/pricing"):
        try:
            r = c2.get(_route, follow_redirects=True)
            if r.status_code == 200:
                blocks += _scripts(r.get_data(as_text=True))
        except Exception:
            pass

print(f"Found {len(blocks)} inline <script> blocks; checking with node --check...")
failures = 0
for i, body in enumerate(blocks):
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(body)
        path = f.name
    res = subprocess.run(["node", "--check", path], capture_output=True, text=True)
    os.unlink(path)
    if res.returncode != 0:
        failures += 1
        print(f"\n=== BLOCK {i} FAILED ({len(body)} chars) ===")
        print(res.stderr.strip()[:2000])

if failures:
    print(f"\n{failures} block(s) FAILED JS syntax check.")
    sys.exit(1)
print("All inline script blocks pass node --check.")
