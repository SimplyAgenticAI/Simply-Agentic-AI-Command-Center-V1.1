import os
import json
import re
import smtplib
import uuid
import base64
import secrets
import hashlib
import hmac
import threading
import shutil
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, List, Tuple, Optional, Union
from urllib.parse import urlparse, urljoin, unquote, quote_plus
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, request, render_template_string, jsonify, session, redirect, url_for, make_response, g, send_from_directory, abort
from dotenv import load_dotenv
from openai import OpenAI
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None

# Optional Gmail OAuth (Option C). These imports are optional so the app doesn't crash if deps aren't installed.
# If these libs are missing, Gmail connect/send will return a clear error message instead of taking the whole server down.
try:
    from google.oauth2.credentials import Credentials as GoogleCredentials
    from google_auth_oauthlib.flow import Flow as GoogleOAuthFlow
    from googleapiclient.discovery import build as google_build
    from googleapiclient.errors import HttpError as GoogleHttpError
except Exception:
    GoogleCredentials = None
    GoogleOAuthFlow = None
    google_build = None
    GoogleHttpError = Exception

load_dotenv()

APP_TITLE = os.getenv("APP_TITLE", " Simply Agentic AI Round Table V1.12")
MODEL = os.getenv("MODEL", "gpt-4o")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
PORT = int(os.getenv("PORT", "5000"))

# Uploads
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "12"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
MAX_INLINE_TEXT_BYTES = int(os.getenv("MAX_INLINE_TEXT_BYTES", "60000"))  # only inline small text files

# Vision (screen capture / images)
MAX_INLINE_IMAGE_BYTES = int(os.getenv("MAX_INLINE_IMAGE_BYTES", str(1_500_000)))  # 1.5MB
MAX_INLINE_IMAGES = int(os.getenv("MAX_INLINE_IMAGES", "2"))

# SMTP
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "Round Table Command Center")

# Gmail OAuth (recommended for Gmail accounts; avoids SMTP 535 BadCredentials)
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
# Public base URL for OAuth redirect, e.g. https://your-app.onrender.com
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.send", "https://www.googleapis.com/auth/gmail.readonly"]
CALENDAR_SCOPES = ["https://www.googleapis.com/auth/calendar.events"]
GOOGLE_ALL_SCOPES = list(dict.fromkeys(GMAIL_SCOPES + CALENDAR_SCOPES))

# =========================
# MANUAL GOOGLE OAUTH (no extra deps)
# =========================

GOOGLE_AUTH_URI = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"

def _now_epoch() -> int:
    try:
        return int(datetime.utcnow().timestamp())
    except Exception:
        return 0

def _oauth_auth_url(scopes: List[str], redirect_path: str, state: str) -> str:
    redirect_uri = f"{PUBLIC_BASE_URL}{redirect_path}"
    scope_str = " ".join(scopes)
    # Manual URL build (avoid extra deps)
    from urllib.parse import urlencode
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": scope_str,
        "access_type": "offline",
        "include_granted_scopes": "true",
        "prompt": "consent",
        "state": state,
    }
    return f"{GOOGLE_AUTH_URI}?{urlencode(params)}"

def _oauth_exchange_code(code: str, redirect_path: str) -> Tuple[Optional[Dict[str, Any]], str]:
    ok, reason = _google_oauth_ready()
    if not ok:
        return None, reason
    redirect_uri = f"{PUBLIC_BASE_URL}{redirect_path}"
    try:
        import requests
        r = requests.post(
            GOOGLE_TOKEN_URI,
            data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
            timeout=20,
        )
        data = r.json() if r.content else {}
        if r.status_code >= 400:
            return None, f"Token exchange failed: {data}"
        # Normalize expiry
        expires_in = int(data.get("expires_in") or 0)
        if expires_in:
            data["expires_at"] = _now_epoch() + max(0, expires_in - 30)
        return data, ""
    except Exception as e:
        return None, f"Token exchange error: {e}"

def _oauth_refresh_token(refresh_token: str, scopes: List[str]) -> Tuple[Optional[Dict[str, Any]], str]:
    ok, reason = _google_oauth_ready()
    if not ok:
        return None, reason
    try:
        import requests
        r = requests.post(
            GOOGLE_TOKEN_URI,
            data={
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            },
            timeout=20,
        )
        data = r.json() if r.content else {}
        if r.status_code >= 400:
            return None, f"Token refresh failed: {data}"
        expires_in = int(data.get("expires_in") or 0)
        if expires_in:
            data["expires_at"] = _now_epoch() + max(0, expires_in - 30)
        # refresh response often doesn't include refresh_token; keep the old one
        data.setdefault("refresh_token", refresh_token)
        return data, ""
    except Exception as e:
        return None, f"Token refresh error: {e}"

def _token_expired(token_info: Dict[str, Any]) -> bool:
    try:
        exp = int(token_info.get("expires_at") or 0)
        if exp <= 0:
            return False
        return _now_epoch() >= exp
    except Exception:
        return False

def _get_access_token_from_store(token_info: Dict[str, Any], scopes: List[str]) -> Tuple[Optional[str], Optional[Dict[str, Any]], str]:
    if not token_info:
        return None, None, "Not connected."
    # refresh if needed
    if _token_expired(token_info) and token_info.get("refresh_token"):
        refreshed, err = _oauth_refresh_token(token_info.get("refresh_token"), scopes)
        if not refreshed:
            return None, None, err or "Token refresh failed."
        return refreshed.get("access_token"), refreshed, ""
    return token_info.get("access_token"), None, ""



# Global OPENAI_API_KEY optional; users will provide their own keys

client = None  # lazy init to avoid import time crashes

def _get_global_openai_client():
    global client
    if client is None:
        client = OpenAI(api_key=(OPENAI_API_KEY or ""))
    return client

app = Flask(__name__)

# -----------------------------
# Uploads static serving (additive)
# -----------------------------
@app.get("/uploads/<path:relpath>")
def serve_upload(relpath):
    """Serve files saved under DATA/uploads. Required for teammate image links."""
    try:
        # Prevent path traversal
        relpath = relpath.replace("\\", "/")
        if relpath.startswith("../") or "/../" in relpath:
            return abort(400)
        fp = UPLOADS_DIR / relpath
        if not fp.exists():
            return abort(404)
        return send_from_directory(str(UPLOADS_DIR), relpath)
    except Exception:
        return abort(404)


# =========================
# OAuth state helpers (additive)
# =========================
def _push_oauth_state(key: str, val: str, keep: int = 5) -> None:
    try:
        lst = session.get(key) or []
        if not isinstance(lst, list):
            lst = []
        lst = [val] + [x for x in lst if x != val]
        session[key] = lst[:keep]
    except Exception:
        pass

def _oauth_state_matches(key: str, incoming: str) -> bool:
    try:
        if not incoming:
            return False
        lst = session.get(key) or []
        if isinstance(lst, list) and incoming in lst:
            return True
        single = session.get(key + "_single")
        if isinstance(single, str) and single == incoming:
            return True
    except Exception:
        pass
    return False


# Quiet noisy request logs (especially the stack tick poll)
import logging
logging.getLogger("werkzeug").setLevel(logging.ERROR)

app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

BASE = Path(__file__).parent

# ===== NEW: Persistent data directory support (additive) =====
# Use DATA_DIR env var if provided. Otherwise prefer /var/data when present (common persistent mount),
# falling back to local ./data next to app.py.
_DATA_ENV = (os.getenv("DATA_DIR") or "").strip()
_DEFAULT_PERSIST = Path("/var/data")
_OLD_DATA = BASE / "data"
if _DATA_ENV:
    DATA = Path(_DATA_ENV)
elif _DEFAULT_PERSIST.exists():
    DATA = _DEFAULT_PERSIST
else:
    DATA = _OLD_DATA

# One-time best-effort migration from old local data folder if the new DATA dir is different and empty-ish.
try:
    DATA.mkdir(parents=True, exist_ok=True)
    if DATA.resolve() != _OLD_DATA.resolve():
        # migrate key json files if they exist in old dir and not in new
        for fname in ["users.json", "registry.json", "memory.json", "secrets.json", "audit.json"]:
            srcf = _OLD_DATA / fname
            dstf = DATA / fname
            if srcf.exists() and (not dstf.exists()):
                shutil.copy2(srcf, dstf)
except Exception:
    pass

DATA_DIR = str(DATA)
REGISTRY_PATH = DATA / "teammates.json"
THREADS_DIR = DATA / "threads"
LOGS_DIR = DATA / "logs"
UPLOADS_DIR = DATA / "uploads"
UPLOAD_INDEX_PATH = UPLOADS_DIR / "_index.json"
IMAGE_STATE_DIR = DATA / "image_state"
FRAMEWORK_PATH = DATA / "core_framework.txt"

DATA.mkdir(exist_ok=True)
THREADS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)
UPLOADS_DIR.mkdir(exist_ok=True)
IMAGE_STATE_DIR.mkdir(exist_ok=True)

# =========================
# IMAGE JOBS (non-blocking)
# =========================
# Hosting platforms often kill long-running requests. Image generation can exceed request timeouts.
# So we run image generation in a background thread and let the UI poll for completion.
IMAGE_JOBS: Dict[str, Dict[str, Any]] = {}
IMAGE_JOBS_LOCK = threading.Lock()

def _image_job_set(job_id: str, patch: Dict[str, Any]) -> None:
    with IMAGE_JOBS_LOCK:
        cur = IMAGE_JOBS.get(job_id) or {}
        cur.update(patch or {})
        IMAGE_JOBS[job_id] = cur

def _image_job_get(job_id: str) -> Dict[str, Any]:
    with IMAGE_JOBS_LOCK:
        return dict(IMAGE_JOBS.get(job_id) or {})

def _thread_replace_or_append_image_note(teammate: str, job_id: str, final_note: str) -> None:
    try:
        thread = load_thread(teammate)
        replaced = False
        for i in range(len(thread)-1, -1, -1):
            msg = thread[i] or {}
            if (msg.get("role") == "assistant") and (f"job:{job_id}" in (msg.get("content") or "")):
                thread[i] = {"role": "assistant", "content": final_note}
                replaced = True
                break
        if not replaced:
            thread.append({"role": "assistant", "content": final_note})
        save_thread(teammate, thread)
    except Exception:
        pass

def _run_image_job(job_id: str, raw_prompt: str, teammate: str, username: str, lighting_mode: bool, mode: str = "new", source_file_id: str = "") -> None:
    _image_job_set(job_id, {"status": "running"})
    try:
        # Background thread needs an application context for any Flask helpers used during image creation
        with app.app_context():
            rec, url, err = generate_image_for_teammate(raw_prompt, teammate=teammate, username=username, lighting_mode=lighting_mode, mode=mode, source_file_id=source_file_id)
        if err or not url:
            _image_job_set(job_id, {"status": "error", "error": err or "Image generation failed"})
            _thread_replace_or_append_image_note(teammate, job_id, f"[Image failed] {err or 'Image generation failed'}")
            return
        _image_job_set(job_id, {"status": "done", "url": url, "image": rec})
        _thread_replace_or_append_image_note(teammate, job_id, f"[Image generated] {url}")
    except Exception as e:
        _image_job_set(job_id, {"status": "error", "error": str(e) or "Image generation failed"})
        _thread_replace_or_append_image_note(teammate, job_id, f"[Image failed] {str(e) or 'Image generation failed'}")

def create_image_job(raw_prompt: str, teammate: str, username: str, lighting_mode: bool, mode: str = "new", source_file_id: str = "") -> str:
    job_id = uuid.uuid4().hex
    _image_job_set(job_id, {"status": "queued", "created_at": now_iso(), "teammate": teammate, "mode": mode, "source_file_id": source_file_id})
    t = threading.Thread(target=_run_image_job, args=(job_id, raw_prompt, teammate, username, lighting_mode, mode, source_file_id), daemon=True)
    t.start()
    return job_id

# =========================
# AUTH + PER-USER SETTINGS
# =========================

USERS_PATH = DATA / "users.json"
SECRET_PATH = DATA / "session_secret.key"

def _load_or_create_secret() -> str:
    try:
        if SECRET_PATH.exists():
            s = SECRET_PATH.read_text(encoding="utf-8").strip()
            if s:
                return s
    except Exception:
        pass
    s = secrets.token_hex(32)
    try:
        SECRET_PATH.write_text(s, encoding="utf-8")
    except Exception:
        pass
    return s

app.secret_key = os.getenv("APP_SECRET", "") or _load_or_create_secret()
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Set Secure cookie flag when running behind HTTPS (detected via PUBLIC_BASE_URL)
app.config["SESSION_COOKIE_SECURE"] = PUBLIC_BASE_URL.startswith("https://")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)

def load_users() -> Dict[str, Any]:
    data = load_json(USERS_PATH, {"users": {}, "updated_at": None})
    if not isinstance(data, dict):
        data = {"users": {}, "updated_at": None}
    data.setdefault("users", {})
    return data

def save_users(data: Dict[str, Any]) -> None:
    data["updated_at"] = now_iso()
    save_json(USERS_PATH, data)

def has_any_user() -> bool:
    data = load_users()
    return bool((data.get("users") or {}))

def _clean_username(u: str) -> str:
    u = (u or "").strip().lower()
    u = re.sub(r"[^a-z0-9_\.\-]+", "", u)
    return u

def _find_user_by_login(identifier: str) -> Optional[Dict[str, Any]]:
    """Look up a user by username. The email field is no longer used for registration,
    but this stays in case old accounts have emails stored."""
    identifier = (identifier or "").strip().lower()
    if not identifier:
        return None
    data = load_users()
    users = data.get("users") or {}
    # Direct username match first
    clean = re.sub(r"[^a-z0-9_\.\-]+", "", identifier)
    if clean in users:
        return users[clean]
    return None

def _new_user(username: str, password: str, email: str = "") -> Dict[str, Any]:
    return {
        "username": username,
        "password_hash": generate_password_hash(password),
        "email": (email or "").strip(),
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "settings": {
            "openai_key": "",
            "smtp": {
                "host": "",
                "port": 587,
                "user": "",
                "pass": "",
                "from_name": ""
            }
        },
        "reset": {"token_hash": "", "created_at": None}
    }

def current_user() -> Optional[Dict[str, Any]]:
    uname = session.get("user")
    # Historically we stored the username string in session["user"].
    # Some earlier builds accidentally stored a dict here; support both.
    if isinstance(uname, dict):
        uname = uname.get("username")
    if not uname:
        return None
    data = load_users()
    return (data.get("users") or {}).get(uname)

def ensure_local_owner_user() -> str:
    """Ensure a local owner user exists for first-run / setup-less deployments.

    Returns the username to place in session["user"].
    """
    data = load_users()
    users = data.get("users") or {}
    if "local" not in users:
        # Create a deterministic local owner user.
        # Password is irrelevant for this bootstrap flow; the UI can still
        # support full login/reset if you later enable it.
        users["local"] = _new_user("local", password=str(uuid.uuid4()), email="")
        data["users"] = users
        save_users(data)
    return "local"

def login_required_api() -> bool:
    p = request.path or ""
    if p.startswith("/api/") and p not in ("/api/login", "/api/logout", "/api/reset_request", "/api/reset_password", "/api/me"):
        return True
    return False

@app.before_request
def _auth_guard():
    if request.path in ("/login", "/setup", "/reset", "/reset_password", "/register", "/static"):
        return None
    if request.path.startswith("/static/"):
        return None

    # allow setup if no users exist
    if request.path.startswith("/setup") and not has_any_user():
        return None

    public_api = {"/api/login", "/api/logout", "/api/reset_request", "/api/reset_password", "/api/me"}
    if request.path.startswith("/api/") and request.path in public_api:
        return None

    # Clear stale sessions so the login gate shows cleanly instead of half-auth states.
    if session.get("user") and not current_user():
        try:
            session.pop("user", None)
        except Exception:
            pass
        session.modified = True

    if request.path.startswith("/api/") and not current_user():
        resp = jsonify({"ok": False, "error": "Not authenticated"})
        resp.headers["Cache-Control"] = "no-store"
        return resp, 401

    if request.path == "/" and not current_user():
        if not has_any_user():
            return redirect(url_for("setup"))
        return redirect(url_for("login"))

    # attach per-user OpenAI client for this request
    u = current_user()
    user_key = ""
    if u:
        user_key = (((u.get("settings") or {}).get("openai_key")) or "").strip()
    g.openai_client = OpenAI(api_key=(user_key or OPENAI_API_KEY))

    return None

def get_openai_client():
    c = getattr(g, "openai_client", None)
    return c or _get_global_openai_client()

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
EMAIL_DRAFT_BLOCK_RE = re.compile(r"```email\s*([\s\S]*?)```", re.IGNORECASE)
EMAIL_HEADER_RE = re.compile(r"^\s*(to|subject|body)\s*:\s*(.*)\s*$", re.IGNORECASE)


def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def save_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def append_log(name: str, payload: Dict[str, Any]) -> None:
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_-]+", "_", name)
    save_json(LOGS_DIR / f"{safe}_{stamp}.json", payload)

# =========================
# TASK LOG (APPEND-ONLY)
# =========================

TASK_LOG_DIR = DATA / "task_logs"

def _safe_name(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]+", "_", (s or "anon"))[:80] or "anon"

# ---------------- Client Memory Profiles (additive) ----------------
def _clients_path_for_user(username: str) -> str:
    base = os.path.join(DATA_DIR, "clients")
    os.makedirs(base, exist_ok=True)
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", username or "anon")
    return os.path.join(base, f"{safe}.json")

def _load_clients(username: str) -> Dict[str, Any]:
    path = _clients_path_for_user(username)
    if not os.path.exists(path):
        return {"active_client_id": "", "clients": {}}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {"active_client_id": "", "clients": {}}
        data.setdefault("active_client_id", "")
        data.setdefault("clients", {})
        if not isinstance(data["clients"], dict):
            data["clients"] = {}
        return data
    except Exception:
        return {"active_client_id": "", "clients": {}}

def _save_clients(username: str, data: Dict[str, Any]) -> None:
    path = _clients_path_for_user(username)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

def _get_active_client(username: str) -> Dict[str, Any]:
    data = _load_clients(username)
    cid = (data.get("active_client_id") or "").strip()
    clients = data.get("clients") or {}
    if cid and cid in clients and isinstance(clients[cid], dict):
        c = clients[cid]
        c.setdefault("id", cid)
        return c
    return {}

def _get_session_username() -> str:
    u = session.get("user")
    return (u.get("username") if isinstance(u, dict) else None) or (u if isinstance(u, str) else None) or "anon"

def _new_client_id() -> str:
    return "c_" + uuid.uuid4().hex[:10]

def _task_log_path_for_user(username: Optional[str]) -> Path:
    TASK_LOG_DIR.mkdir(parents=True, exist_ok=True)
    return TASK_LOG_DIR / f"{_safe_name(username or 'anon')}.jsonl"

def append_task_log(action: str, record: Dict[str, Any], teammate: str = "", status: str = "success") -> None:
    """Append-only task log. One JSON object per line (JSONL)."""
    try:
        u = session.get("user")
        username = (u.get("username") if isinstance(u, dict) else None) or (u if isinstance(u, str) else None) or "anon"
        path = _task_log_path_for_user(username)
        entry = {
            "id": str(uuid.uuid4()),
            "ts": now_iso(),
            "user": username,
            "teammate": teammate or record.get("name") or record.get("from_teammate") or "",
            "action": action,
            "status": status,
            "record": record,
        }
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        # Task logging must never break core flows
        pass

def read_task_log(limit: int = 200, teammate: str = "", status: str = "") -> List[Dict[str, Any]]:
    username = session.get("user") or "anon"
    path = _task_log_path_for_user(username)
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        # take the most recent N lines (small, safe default)
        lines = lines[-max(1, min(2000, limit * 3)):]
        out: List[Dict[str, Any]] = []
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if teammate and (obj.get("teammate") or "") != teammate:
                continue
            if status and (obj.get("status") or "") != status:
                continue
            out.append(obj)
            if len(out) >= limit:
                break
        return list(reversed(out))
    except Exception:
        return []


# =========================
# TEAMMATE ACTION STACKS (Sequence Runner)
# =========================
#
# Per-teammate stacks that run steps sequentially.
# Scheduling is safe: no background threads at import.
# Schedules run via /api/action_stack_schedules/tick which the UI pings.

ACTION_STACKS_DIR = DATA / "action_stacks"
ACTION_STACK_RUNS_DIR = DATA / "action_stack_runs"
ACTION_STACK_MEMORY_DIR = DATA / "action_stack_memory"
OPERATOR_PROFILE_DIR = DATA / "operator_profile"



# =========================
# GUIDED ONBOARDING (additive)
# =========================
ONBOARDING_DIR = DATA / "onboarding"
ONBOARDING_DIR.mkdir(parents=True, exist_ok=True)

ONBOARDING_STEPS: List[Dict[str, str]] = [
    {"key": "preferred_ai", "title": "Connect Chat GPT or Claude"},
    {"key": "full_team", "title": "Install full team"},
    {"key": "email_connected", "title": "Connect Email"},
    {"key": "calendar_connected", "title": "Connect Calendar"},
    {"key": "first_prompt", "title": "Send first prompt"},
]

def _onboarding_path_for_user(username: str) -> Path:
    u = _safe_name(username or "anon")
    d = ONBOARDING_DIR / u
    d.mkdir(parents=True, exist_ok=True)
    return d / "state.json"

def _load_onboarding(username: str) -> Dict[str, Any]:
    path = _onboarding_path_for_user(username)
    data = load_json(path, {})
    if not isinstance(data, dict):
        data = {}
    data.setdefault("dismissed", False)
    data.setdefault("seen_auto", False)
    data.setdefault("steps", {})
    if not isinstance(data.get("steps"), dict):
        data["steps"] = {}
    for s in ONBOARDING_STEPS:
        data["steps"].setdefault(s["key"], {"done": False, "at": None})
    return data

def _save_onboarding(username: str, data: Dict[str, Any]) -> None:
    path = _onboarding_path_for_user(username)
    data = data or {}
    data["updated_at"] = now_iso()
    save_json(path, data)

def _mark_onboarding_step(username: str, key: str, done: bool = True) -> None:
    try:
        st = _load_onboarding(username)
        st.setdefault("steps", {})
        st["steps"].setdefault(key, {"done": False, "at": None})
        st["steps"][key]["done"] = bool(done)
        if done:
            st["steps"][key]["at"] = now_iso()
        _save_onboarding(username, st)
    except Exception:
        pass

def _dismiss_onboarding(username: str, dismissed: bool = True) -> None:
    try:
        st = _load_onboarding(username)
        st["dismissed"] = bool(dismissed)
        _save_onboarding(username, st)
    except Exception:
        pass

def _reconcile_onboarding_from_truth(u: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    username = (u.get("username") if isinstance(u, dict) else None) or _get_session_username()
    _ = _load_onboarding(username)

    # Step 1: Preferred AI connected (OpenAI or Claude)
    try:
        settings = ((u or {}).get("settings") or {})
        openai_key = (settings.get("openai_key") or "").strip()
        claude_key = (settings.get("claude_key") or settings.get("anthropic_key") or "").strip()
        provider = (settings.get("ai_provider") or settings.get("provider") or "").strip().lower()
        if openai_key or claude_key or provider in ("openai", "claude"):
            _mark_onboarding_step(username, "preferred_ai", True)
    except Exception:
        pass

    # Step 2: Full team installed
    try:
        reg = load_registry()
        installed = reg.get("installed") or {}
        if isinstance(installed, dict):
            all_present = True
            for n in DEFAULT_ORDER:
                if n not in installed:
                    all_present = False
                    break
            if all_present:
                _mark_onboarding_step(username, "full_team", True)
    except Exception:
        pass

    # Step 3: Email connected (Gmail OAuth OR SMTP)
    try:
        settings = ((u or {}).get("settings") or {})
        smtp = (settings.get("smtp") or {})
        smtp_ready = bool((smtp.get("user") or "").strip() and (smtp.get("pass") or "").strip())
        gmail_ready = bool(_user_gmail_oauth(u))
        if smtp_ready or gmail_ready:
            _mark_onboarding_step(username, "email_connected", True)
    except Exception:
        pass

    # Step 4: Calendar connected
    try:
        if _user_calendar_oauth(u):
            _mark_onboarding_step(username, "calendar_connected", True)
    except Exception:
        pass

    return _load_onboarding(username)

def _onboarding_status_payload(u: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    username = (u.get("username") if isinstance(u, dict) else None) or _get_session_username()
    st = _reconcile_onboarding_from_truth(u)
    steps = st.get("steps") or {}

    out_steps: List[Dict[str, Any]] = []
    done_count = 0
    for s in ONBOARDING_STEPS:
        k = s["key"]
        done = bool((steps.get(k) or {}).get("done"))
        if done:
            done_count += 1
        out_steps.append({"key": k, "title": s["title"], "done": done})

    next_key = ""
    for s in out_steps:
        if not s["done"]:
            next_key = s["key"]
            break

    all_done = done_count == len(ONBOARDING_STEPS)
    pct = int(round((done_count / max(1, len(ONBOARDING_STEPS))) * 100))

    return {
        "ok": True,
        "dismissed": bool(st.get("dismissed")),
        "steps": out_steps,
        "done_count": done_count,
        "total": len(ONBOARDING_STEPS),
        "progress_pct": pct,
        "next_key": next_key,
        "all_done": all_done,
        "username": username,
    }
ACTION_STACK_SCHEDULES_DIR = DATA / "action_stack_schedules"

ACTION_STACKS_DIR.mkdir(exist_ok=True)
ACTION_STACK_RUNS_DIR.mkdir(exist_ok=True)
ACTION_STACK_MEMORY_DIR.mkdir(exist_ok=True)
ACTION_STACK_SCHEDULES_DIR.mkdir(exist_ok=True)

def _action_user_dir(root: Path, username: str) -> Path:
    d = root / _safe_name(username or "anon")
    d.mkdir(parents=True, exist_ok=True)
    return d

def _stacks_path(u: str, teammate: str) -> Path:
    d = _action_user_dir(ACTION_STACKS_DIR, u)
    return d / f"{_safe_name(teammate)}.json"

def _runs_path(u: str) -> Path:
    d = _action_user_dir(ACTION_STACK_RUNS_DIR, u)
    return d / "runs.json"

def _memory_path(u: str) -> Path:
    d = _action_user_dir(ACTION_STACK_MEMORY_DIR, u)
    return d / "memory.json"

def _schedules_path(u: str) -> Path:
    d = _action_user_dir(ACTION_STACK_SCHEDULES_DIR, u)
    return d / "schedules.json"

def _load_saved_stacks(u: str, teammate: str) -> Dict[str, Any]:
    return load_json(_stacks_path(u, teammate), {"stacks": {}, "updated_at": None}) or {"stacks": {}, "updated_at": None}

def _save_saved_stacks(u: str, teammate: str, data: Dict[str, Any]) -> None:
    data["updated_at"] = now_iso()
    save_json(_stacks_path(u, teammate), data)

def _load_runs(u: str) -> Dict[str, Any]:
    return load_json(_runs_path(u), {"runs": {}, "updated_at": None}) or {"runs": {}, "updated_at": None}

def _save_runs(u: str, data: Dict[str, Any]) -> None:
    data["updated_at"] = now_iso()
    save_json(_runs_path(u), data)

def _load_action_memory(u: str) -> Dict[str, Any]:
    return load_json(_memory_path(u), {"memory": {}, "updated_at": None}) or {"memory": {}, "updated_at": None}

def _save_action_memory(u: str, data: Dict[str, Any]) -> None:
    data["updated_at"] = now_iso()
    save_json(_memory_path(u), data)

def _load_schedules(u: str) -> List[Dict[str, Any]]:
    data = load_json(_schedules_path(u), {"schedules": [], "updated_at": None}) or {"schedules": [], "updated_at": None}
    return data.get("schedules") or []

def _save_schedules(u: str, schedules: List[Dict[str, Any]]) -> None:
    save_json(_schedules_path(u), {"schedules": schedules, "updated_at": now_iso()})

def _parse_local_dt(dt_local: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(dt_local)
    except Exception:
        return None

def _safe_render(template: str, ctx: Dict[str, Any]) -> str:
    out = template or ""
    for k, v in (ctx or {}).items():
        out = out.replace("{{" + k + "}}", str(v))
    return out

def _call_teammate_prompt_for_user(u: str, teammate: str, prompt: str, file_ids: Optional[List[str]] = None) -> str:
    file_ids = file_ids or []
    # Use existing followup core if available
    try:
        if "_execute_followup_core" in globals():
            try:
                res = _execute_followup_core(teammate, prompt, file_ids=file_ids, user_override=u)  # type: ignore[name-defined]
            except TypeError:
                res = _execute_followup_core(teammate, prompt, file_ids=file_ids)  # type: ignore[name-defined]
            return (res or {}).get("reply", "") or ""
    except Exception:
        pass

    reg = load_registry()
    defn = (reg.get("installed") or {}).get(teammate)
    if not defn:
        return ""
    # lighting_mode is not available in this context — use False (safe default)
    sys_prompt = teammate_system_prompt(defn, lighting_mode=False)
    msg2, _, vision_images = build_prompt_with_attachments(prompt, file_ids)
    user_content = _build_user_content(msg2, vision_images)
    preferred_model = (defn.get("preferred_model") or "").strip() or None
    return call_llm(sys_prompt, [{"role": "user", "content": user_content}], temperature=0.65, model=preferred_model)

def _init_run(u: str, teammate: str, stack_name: str, steps: List[Dict[str, Any]], user_input: str) -> Dict[str, Any]:
    run_id = uuid.uuid4().hex
    return {
        "id": run_id,
        "user": u,
        "teammate": teammate,
        "stack_name": stack_name,
        "created_at": now_iso(),
        "status": "running",
        "cursor": 0,
        "error": "",
        "input": user_input or "",
        "steps": steps,
        "outputs": {},
        "log": [],
    }

def _persist_run(run: Dict[str, Any]) -> None:
    u = run.get("user") or "anon"
    runs = _load_runs(u)
    runs.setdefault("runs", {})
    runs["runs"][run["id"]] = run
    _save_runs(u, runs)

def _append_run_log(run: Dict[str, Any], event: str, data: Dict[str, Any]) -> None:
    run.setdefault("log", [])
    run["log"].append({"ts": now_iso(), "event": event, "data": data})

def _run_due_schedules_once() -> None:
    if not ACTION_STACK_SCHEDULES_DIR.exists():
        return
    now_local = datetime.now()
    for user_dir in ACTION_STACK_SCHEDULES_DIR.iterdir():
        if not user_dir.is_dir():
            continue
        u = user_dir.name
        schedules = _load_schedules(u)
        if not schedules:
            continue
        changed = False
        for s in schedules:
            try:
                teammate = s.get("teammate") or ""
                stack_name = s.get("stack_name") or ""
                mode = s.get("mode") or ""
                last_run = s.get("last_run")
                due = False

                if mode == "once":
                    dt = _parse_local_dt(s.get("run_at") or "")
                    if dt and now_local >= dt and not last_run:
                        due = True
                elif mode == "daily":
                    t = s.get("time") or ""
                    if re.match(r"^\d{2}:\d{2}$", t):
                        hh, mm = t.split(":")
                        target = now_local.replace(hour=int(hh), minute=int(mm), second=0, microsecond=0)
                        if abs((now_local - target).total_seconds()) <= 45:
                            if last_run:
                                try:
                                    lr = datetime.fromisoformat(str(last_run).replace("Z",""))
                                    due = (lr.date() != now_local.date())
                                except Exception:
                                    due = True
                            else:
                                due = True

                if not due:
                    continue

                data = _load_saved_stacks(u, teammate)
                stack = (data.get("stacks") or {}).get(stack_name)
                if not stack:
                    continue
                steps = _normalize_steps(stack.get("steps"))
                run = _init_run(u=u, teammate=teammate, stack_name=stack_name, steps=steps, user_input="")
                _persist_run(run)
                _run_action_stack_engine(run)

                s["last_run"] = now_iso()
                changed = True
            except Exception:
                continue
        if changed:
            _save_schedules(u, schedules)

def _resume_due_runs_once() -> None:
    """Resume any waiting runs that are due."""
    if not ACTION_STACK_RUNS_DIR.exists():
        return
    now_utc = datetime.utcnow()
    for user_dir in ACTION_STACK_RUNS_DIR.iterdir():
        if not user_dir.is_dir():
            continue
        u = user_dir.name
        runs_data = _load_runs(u)
        runs = runs_data.get("runs") or {}
        changed = False
        for rid, run in list(runs.items()):
            try:
                if not isinstance(run, dict):
                    continue
                if run.get("status") != "waiting":
                    continue
                w = run.get("wait_until")
                if not w:
                    continue
                try:
                    w_dt = datetime.fromisoformat(str(w).replace("Z", ""))
                except Exception:
                    w_dt = None
                if w_dt and now_utc >= w_dt:
                    run["status"] = "running"
                    run.pop("wait_until", None)
                    runs[rid] = _run_action_stack_engine(run)
                    changed = True
            except Exception:
                continue
        if changed:
            runs_data["runs"] = runs
            _save_runs(u, runs_data)


# =========================
# CORE FRAMEWORK (ENFORCED)
# =========================

DEFAULT_CORE_FRAMEWORK_TEXT = """
CORE OPERATING PILLARS (NON NEGOTIABLE)

Autonomy
Think before acting. Do not blindly comply. If unclear, unsafe, or conflicts with role or constraints, pause and surface the issue. Violation: Executing actions without understanding intent, scope, or boundaries.

Adaptability
Adjust behavior based on context, feedback, and evolving goals. Do not repeat patterns when conditions change. Violation: Static responses despite new information or correction.

Alignment
Act in service of the creator's stated goals, rules, values, and system constraints. If conflict exists, highlight the conflict before proceeding. Violation: Optimizing a single task while breaking overall intent or direction.

Collaboration
Treat the creator as a thinking partner, not a command source. Ask a clarifying question when decisions affect structure, memory, versioning, or long term behavior. Violation: Silent execution where consultation was required.

Memory
Never assume persistence. Never overwrite, alter, or delete memory silently. No role drift or memory bleed. Violation: Unapproved memory changes or forgetting locked rules.

Integrity
Prioritize truth, clarity, and system health over agreement. State uncertainty plainly. Violation: Hallucination, false certainty, or concealed uncertainty.

CORE PROCESS RULES (NON NEGOTIABLE)

Ask one question at a time when needed.
Wait for the user's response before continuing.
Do not summarize the user's answers.
Do not design ahead.
Do not assume intent.
If something matters and is unclear, ask. If uncertain, say so and propose how to clarify.

DEFAULT ON SILENCE OR AMBIGUITY
Pause immediately. Do not infer intent. Silence is not consent.

GROUP ACTIVATION & TEAM ASSEMBLY RULE (NON NEGOTIABLE)
When user says "All teammates to the round table" or similar:
- Assemble all installed teammates
- Each announces Name, Job Title, Version
- No execution during assembly
- Wait for next instruction
""".strip()


def load_core_framework() -> str:
    try:
        if FRAMEWORK_PATH.exists():
            txt = FRAMEWORK_PATH.read_text(encoding="utf-8", errors="replace").strip()
            return txt if txt else DEFAULT_CORE_FRAMEWORK_TEXT
    except Exception:
        pass
    return DEFAULT_CORE_FRAMEWORK_TEXT


def save_core_framework(text: str) -> None:
    cleaned = (text or "").strip()
    if not cleaned:
        cleaned = DEFAULT_CORE_FRAMEWORK_TEXT
    FRAMEWORK_PATH.write_text(cleaned, encoding="utf-8")

# Ensure the framework file always exists with the default framework for local-first users.
try:
    if (not FRAMEWORK_PATH.exists()) or (not FRAMEWORK_PATH.read_text(encoding="utf-8", errors="replace").strip()):
        FRAMEWORK_PATH.write_text(DEFAULT_CORE_FRAMEWORK_TEXT, encoding="utf-8")
except Exception:
    pass


# =========================
# LOCKED PREBUILT TEAMMATES
# =========================

PREBUILT_LOCKED: Dict[str, Dict[str, Any]] = {
    "Alex": {
        "name": "Alex",
        "job_title": "Chief Marketing Officer (CMO)",
        "version": "v1.0",
        "mission": "Architect marketing strategy, positioning, offer architecture, and long term growth systems.",
        "responsibilities": [
            "Strategic positioning and differentiation",
            "Offer architecture and value proposition design",
            "Messaging systems and brand narrative",
            "Growth leverage identification",
            "Campaign and channel planning",
            "Long term marketing infrastructure",
        ],
        "thinking_style": (
            "Strategy first. Diagnosis before prescription. Systems before execution. Focuses on designing the marketing plan, not executing tactics. "
            "Determines what to do and why before anything is implemented. Checks whether the market actually wants something before recommending growth. "
            "Turns thinking into repeatable strategy, not one off advice."
        ),
        "will_not_do": [
            "Manipulative marketing tactics",
            "Deceptive positioning",
            "Execution without strategy",
            "Trend chasing without validation",
            "Pure execution work",
        ],
        "goal": "Strategy before tactics. Systems over hacks.",
        "avatar": {"bg": "#1e3a8a", "fg": "#e6edff", "sigil": "A"},
    },
    "Willow": {
        "name": "Willow",
        "job_title": "Language Specialist & NLP Master",
        "version": "v1.2",
        "mission": "Architect, refine, and safeguard language with clarity, ethics, and meaning preservation.",
        "responsibilities": [
            "Tone and voice architecture",
            "Clarity and precision optimization",
            "Ethical persuasion and framing",
            "Meaning preservation across edits",
            "Language system design",
            "Communication audits",
            "Flags language that could be misunderstood or misused.",
        ],
        "thinking_style": (
            "Architect first. Precision over cleverness. Meaning before momentum. Protects the original meaning and intent of language above making it persuasive."
        ),
        "will_not_do": [
            "Manipulation or deceptive framing",
            "Artificial urgency",
            "Misrepresentation",
            "Sales strategy or hype writing",
            "Role drift",
            "Improve wording if it changes what is meant",
            "Write sales, hype, or persuasive language",
        ],
        "goal": "Architect language. Preserve meaning. Optimize clarity.",
        "avatar": {"bg": "#4c1d95", "fg": "#e6edff", "sigil": "W"},
    },
    "Ava": {
        "name": "Ava",
        "job_title": "Research & Knowledge Curator",
        "version": "v1.0",
        "mission": "Gather, validate, synthesize, and distill knowledge. Truth over certainty.",
        "responsibilities": [
            "Research and synthesis",
            "Evidence based insight delivery",
            "Assumption validation",
            "Knowledge gap identification",
            "Context building",
            "Provides information only, not advice, unless explicitly asked.",
        ],
        "thinking_style": (
            "Research first. Labels uncertainty explicitly. Separates fact from inference. Clearly separates what is known, what is assumed, and what is unknown. "
            "Allowed to say there is not enough evidence. Does not guess or fill gaps to be helpful."
        ),
        "will_not_do": [
            "Fabricate information or sources",
            "Present false certainty",
            "Speculate without labeling",
            "Drift into persuasion or strategy",
        ],
        "goal": "Signal over noise. Evidence over assumption.",
        "avatar": {"bg": "#0f766e", "fg": "#e6edff", "sigil": "A"},
    },
    "Luna": {
        "name": "Luna",
        "job_title": "Graphic Designer & Creative Engineer",
        "version": "v1.0",
        "mission": "Architect cinematic, consistent, emotionally resonant visual systems.",
        "responsibilities": [
            "Visual hierarchy and composition",
            "Brand consistency enforcement",
            "Cinematic enhancement",
            "Design system architecture",
            "Asset creation and optimization",
            "Visual storytelling",
            "Keeps designs consistent over time",
            "Enhances visuals without changing the meaning of the message",
        ],
        "thinking_style": (
            "Hierarchy before effects. Systems before one offs. Prioritizes clear message and visual order before style or effects. "
            "Calls out visual inconsistency instead of hiding it with polish."
        ),
        "will_not_do": [
            "Break brand rules",
            "Ignore enhancement instructions",
            "Generic aesthetic drift",
            "Effects over substance",
        ],
        "goal": "Enhancement without distortion.",
        "avatar": {"bg": "#7c2d12", "fg": "#e6edff", "sigil": "L"},
    },
    "Orion": {
        "name": "Orion",
        "job_title": "Systems Automation & Scale Engineer",
        "version": "v1.0",
        "mission": "Architect automation systems for reliable scale.",
        "responsibilities": [
            "Automation system architecture",
            "Workflow mapping",
            "Bottleneck identification",
            "Failure prevention planning",
            "Scale engineering",
            "System audits",
        ],
        "thinking_style": (
            "Architecture before execution. Reliability over speed. Will not automate processes that are unstable or unclear. "
            "Requires the process to work manually before scaling. Thinks about what breaks if automation fails."
        ),
        "will_not_do": [
            "Execute without approval",
            "Over automate unproven processes",
            "Drift into marketing or sales",
            "Prioritize speed over reliability",
        ],
        "goal": "Failure prevention first.",
        "avatar": {"bg": "#374151", "fg": "#e6edff", "sigil": "O"},
    },
    "Sunshine": {
        "name": "Sunshine",
        "job_title": "Sales Specialist & Relationship Strategist",
        "version": "v1.0",
        "mission": "Ethical, high trust sales conversations and long term relationship strategy.",
        "responsibilities": [
            "Lead qualification and readiness detection",
            "Buying signal identification",
            "Objection discovery",
            "Ethical closing and clean handoffs",
            "Relationship preservation",
        ],
        "thinking_style": (
            "Signal first. Listen before pitching. Diagnose before proposing. Values trust and timing over closing a sale. "
            "Determines readiness before discussing offers. Treats no sale as a successful outcome when appropriate."
        ),
        "will_not_do": [
            "Manipulate",
            "Pressure",
            "Create false urgency",
            "Misrepresent",
            "Force a close",
        ],
        "goal": "Right offer. Right time. Right tone.",
        "avatar": {"bg": "#9a3412", "fg": "#e6edff", "sigil": "S"},
    },
    "Atlis": {
        "name": "Atlis",
        "job_title": "System Integrity Architect",
        "version": "v1.0",
        "mission": "Safeguard role integrity, memory hygiene, and system coherence.",
        "responsibilities": [
            "Role boundary enforcement",
            "Memory conflict detection",
            "System coherence monitoring",
            "Alignment verification",
            "Identity protection",
            "Steps in when rules, roles, or memory are at risk of being bent",
        ],
        "thinking_style": (
            "Monitor first. Intervene only when integrity is threatened. Never performs tasks or execution. Explains why something is a problem when intervening. "
            "Acts as a referee, not a contributor."
        ),
        "will_not_do": [
            "Execute tasks",
            "Blend roles",
            "Allow silent rule changes",
            "Override ethical constraints",
        ],
        "goal": "Protect integrity. Preserve trust.",
        "avatar": {"bg": "#111827", "fg": "#e6edff", "sigil": "I"},
    },
}

DEFAULT_ORDER = ["Alex", "Willow", "Ava", "Orion", "Sunshine", "Luna", "Atlis"]


# =========================
# REGISTRY + THREADS
# =========================

def _registry_defaults() -> Dict[str, Any]:
    return {"installed": {}, "installed_order": [], "active_order": [], "updated_at": None}


def load_registry() -> Dict[str, Any]:
    reg = load_json(REGISTRY_PATH, _registry_defaults())
    if not isinstance(reg, dict):
        reg = _registry_defaults()

    reg.setdefault("installed", {})
    reg.setdefault("installed_order", [])
    reg.setdefault("active_order", [])

    if (not isinstance(reg.get("active_order"), list)) or (len(reg.get("active_order") or []) == 0):
        reg["active_order"] = list(reg.get("installed_order") or [])

    installed = reg.get("installed") or {}

    # NEW: Registry self-heal for older/corrupted states where teammates exist but ordering lists are empty.
    # This is additive and prevents "No active teammates" when installed entries are present.
    installed_order = reg.get("installed_order") or []
    if installed and (not isinstance(installed_order, list) or len(installed_order) == 0):
        # Prefer DEFAULT_ORDER for stable UX, then include any additional installed keys.
        rebuilt: List[str] = []
        try:
            for n in DEFAULT_ORDER:
                if n in installed and n not in rebuilt:
                    rebuilt.append(n)
        except Exception:
            pass
        for n in installed.keys():
            if n not in rebuilt:
                rebuilt.append(n)
        reg["installed_order"] = rebuilt

    # If active_order is empty after filtering, default to installed_order.
    if not (reg.get("active_order") or []):
        reg["active_order"] = list(reg.get("installed_order") or [])
    reg["active_order"] = [n for n in (reg.get("active_order") or []) if n in installed]

    return reg


def save_registry(reg: Dict[str, Any]) -> None:
    reg["updated_at"] = now_iso()
    save_json(REGISTRY_PATH, reg)


def install_full_team() -> Dict[str, Any]:
    reg = load_registry()
    installed = reg["installed"]
    order = reg["installed_order"]

    for name in DEFAULT_ORDER:
        installed[name] = PREBUILT_LOCKED[name]
        if name not in order:
            order.append(name)

    reg["installed"] = installed
    reg["installed_order"] = order

    active = reg.get("active_order") or []
    for name in order:
        if name not in active:
            active.append(name)
    reg["active_order"] = active

    save_registry(reg)
    return reg


def thread_path(teammate_name: str) -> Path:
    safe = re.sub(r"[^a-zA-Z0-9_-]+", "_", teammate_name)
    return THREADS_DIR / f"{safe}.json"


def load_thread(teammate_name: str) -> List[Dict[str, str]]:
    return load_json(thread_path(teammate_name), [])


def save_thread(teammate_name: str, msgs: List[Dict[str, str]]) -> None:
    save_json(thread_path(teammate_name), msgs)


def _normalize_lines_to_list(val: Any) -> List[str]:
    if val is None:
        return []
    if isinstance(val, list):
        out = []
        for x in val:
            if x is None:
                continue
            s = str(x).strip()
            if s:
                out.append(s)
        return out
    s = str(val)
    lines = [ln.strip() for ln in s.splitlines()]
    return [ln for ln in lines if ln]


def _sanitize_teammate_update(payload: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    allowed_str_fields = ["job_title", "version", "mission", "thinking_style", "goal", "preferred_model", "tts_voice"]
    allowed_list_fields = ["responsibilities", "will_not_do"]

    updated: Dict[str, Any] = {}

    for k in allowed_str_fields:
        if k in payload:
            v = payload.get(k)
            if v is None:
                continue
            updated[k] = str(v).strip()

    for k in allowed_list_fields:
        if k in payload:
            updated[k] = _normalize_lines_to_list(payload.get(k))

    updated["name"] = current.get("name", "")
    updated["avatar"] = current.get("avatar", current.get("avatar", {}))

    for k, v in current.items():
        if k not in updated:
            updated[k] = v

    if not isinstance(updated.get("responsibilities"), list):
        updated["responsibilities"] = _normalize_lines_to_list(updated.get("responsibilities"))
    if not isinstance(updated.get("will_not_do"), list):
        updated["will_not_do"] = _normalize_lines_to_list(updated.get("will_not_do"))

    return updated


def _clean_teammate_name(name: str) -> str:
    n = (name or "").strip()
    n = re.sub(r"\s+", " ", n)
    return n


def _make_avatar_for(name: str) -> Dict[str, str]:
    palette = [
        ("#1e3a8a", "#e6edff"),
        ("#4c1d95", "#e6edff"),
        ("#0f766e", "#e6edff"),
        ("#7c2d12", "#e6edff"),
        ("#374151", "#e6edff"),
        ("#9a3412", "#e6edff"),
        ("#111827", "#e6edff"),
        ("#155e75", "#e6edff"),
        ("#3f6212", "#e6edff"),
        ("#7f1d1d", "#e6edff"),
    ]
    idx = abs(hash(name)) % len(palette)
    bg, fg = palette[idx]
    sigil = (name[:1] or "T").upper()
    return {"bg": bg, "fg": fg, "sigil": sigil}


def create_teammate(payload: Dict[str, Any]) -> Dict[str, Any]:
    name = _clean_teammate_name(payload.get("name", ""))
    if not name:
        raise ValueError("Missing teammate name")

    if len(name) > 32:
        raise ValueError("Teammate name must be 32 characters or less")

    reg = load_registry()
    installed = reg.get("installed") or {}

    if name in installed:
        raise ValueError("Teammate name already exists")

    job_title = str(payload.get("job_title", "")).strip()
    version = str(payload.get("version", "v1.0")).strip() or "v1.0"
    mission = str(payload.get("mission", "")).strip()
    thinking_style = str(payload.get("thinking_style", "")).strip()
    goal = str(payload.get("goal", "")).strip()
    responsibilities = _normalize_lines_to_list(payload.get("responsibilities"))
    will_not_do = _normalize_lines_to_list(payload.get("will_not_do"))

    t = {
        "name": name,
        "job_title": job_title,
        "version": version,
        "mission": mission,
        "responsibilities": responsibilities,
        "thinking_style": thinking_style,
        "will_not_do": will_not_do,
        "goal": goal,
        "avatar": _make_avatar_for(name),
    }

    installed[name] = t
    reg["installed"] = installed

    order = reg.get("installed_order") or []
    order.append(name)
    reg["installed_order"] = order

    active = reg.get("active_order") or []
    active.append(name)
    reg["active_order"] = active

    save_registry(reg)
    return t


def set_active_order(active_order: List[str]) -> List[str]:
    reg = load_registry()
    installed = reg.get("installed") or {}
    installed_order = reg.get("installed_order") or []

    seen = set()
    cleaned: List[str] = []
    for n in active_order or []:
        if not isinstance(n, str):
            continue
        n2 = n.strip()
        if not n2:
            continue
        if n2 not in installed:
            continue
        if n2 in seen:
            continue
        seen.add(n2)
        cleaned.append(n2)

    final = [n for n in installed_order if n in cleaned]

    reg["active_order"] = final
    save_registry(reg)
    return final


# =========================
# UPLOADS
# =========================

def load_upload_index() -> Dict[str, Any]:
    return load_json(UPLOAD_INDEX_PATH, {"files": {}, "updated_at": None})


def save_upload_index(idx: Dict[str, Any]) -> None:
    idx["updated_at"] = now_iso()
    save_json(UPLOAD_INDEX_PATH, idx)


def add_upload_record(file_id: str, rec: Dict[str, Any]) -> None:
    idx = load_upload_index()
    idx.setdefault("files", {})
    idx["files"][file_id] = rec
    save_upload_index(idx)


def get_upload_record(file_id: str) -> Optional[Dict[str, Any]]:
    idx = load_upload_index()
    rec = (idx.get("files") or {}).get(file_id)
    return rec if isinstance(rec, dict) else None


def image_state_path(teammate_name: str) -> Path:
    safe = re.sub(r"[^a-zA-Z0-9_-]+", "_", teammate_name)
    return IMAGE_STATE_DIR / f"{safe}.json"

def load_image_state(teammate_name: str) -> Dict[str, Any]:
    data = load_json(image_state_path(teammate_name), {
        "current_image_id": "",
        "current_image_url": "",
        "approved_image_id": "",
        "approved_image_url": "",
        "last_uploaded_image_id": "",
        "last_uploaded_image_url": "",
        "last_prompt": "",
        "last_mode": "",
        "history": [],
        "updated_at": None,
    })
    if not isinstance(data, dict):
        data = {}
    data.setdefault("current_image_id", "")
    data.setdefault("current_image_url", "")
    data.setdefault("approved_image_id", "")
    data.setdefault("approved_image_url", "")
    data.setdefault("last_uploaded_image_id", "")
    data.setdefault("last_uploaded_image_url", "")
    data.setdefault("last_prompt", "")
    data.setdefault("last_mode", "")
    data.setdefault("history", [])
    return data

def save_image_state(teammate_name: str, payload: Dict[str, Any]) -> None:
    payload = dict(payload or {})
    payload["updated_at"] = now_iso()
    save_json(image_state_path(teammate_name), payload)

def _image_url_for_record(rec: Optional[Dict[str, Any]]) -> str:
    if not rec:
        return ""
    relpath = (rec.get("relpath") or "").strip()
    if not relpath:
        return ""
    return f"/uploads/{relpath}"

def _is_image_record(rec: Optional[Dict[str, Any]]) -> bool:
    if not isinstance(rec, dict):
        return False
    mt = (rec.get("mimetype") or "").lower()
    fn = (rec.get("filename") or "").lower()
    return mt.startswith("image/") or fn.endswith((".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg"))

def _append_image_history(state: Dict[str, Any], rec: Dict[str, Any], mode: str, prompt: str, source: str = "generated") -> Dict[str, Any]:
    state = dict(state or {})
    hist = list(state.get("history") or [])
    item = {
        "id": rec.get("id", ""),
        "url": _image_url_for_record(rec),
        "filename": rec.get("filename", ""),
        "uploaded_at": rec.get("uploaded_at") or now_iso(),
        "mode": mode or "",
        "source": source or "generated",
        "prompt": (prompt or "")[:2000],
        "teammate": rec.get("teammate") or "",
    }
    hist = [x for x in hist if isinstance(x, dict) and x.get("id") != item["id"]]
    hist.insert(0, item)
    state["history"] = hist[:50]
    return state

def set_current_image_for_teammate(teammate_name: str, rec: Dict[str, Any], source: str = "generated", prompt: str = "", mode: str = "") -> Dict[str, Any]:
    state = load_image_state(teammate_name)
    url = _image_url_for_record(rec)
    state["current_image_id"] = rec.get("id", "")
    state["current_image_url"] = url
    if source == "uploaded":
        state["last_uploaded_image_id"] = rec.get("id", "")
        state["last_uploaded_image_url"] = url
    if prompt:
        state["last_prompt"] = (prompt or "")[:4000]
    if mode:
        state["last_mode"] = mode
    state = _append_image_history(state, rec, mode=mode, prompt=prompt, source=source)
    save_image_state(teammate_name, state)
    return state

def approve_current_image_for_teammate(teammate_name: str) -> Dict[str, Any]:
    state = load_image_state(teammate_name)
    state["approved_image_id"] = state.get("current_image_id", "")
    state["approved_image_url"] = state.get("current_image_url", "")
    save_image_state(teammate_name, state)
    return state

def _latest_image_record_from_state(teammate_name: str) -> Optional[Dict[str, Any]]:
    state = load_image_state(teammate_name)
    fid = (state.get("current_image_id") or state.get("approved_image_id") or state.get("last_uploaded_image_id") or "").strip()
    return get_upload_record(fid) if fid else None

def bind_uploaded_images_to_teammate(teammate_name: str, file_ids: List[str]) -> Optional[Dict[str, Any]]:
    latest = None
    for fid in file_ids or []:
        rec = get_upload_record(fid)
        if _is_image_record(rec):
            latest = rec
            set_current_image_for_teammate(teammate_name, rec, source="uploaded", prompt="", mode="reference")
    return latest

_EDIT_HINTS = [
    "edit", "change", "revise", "adjust", "tweak", "make it", "make the", "move", "replace",
    "add", "remove", "fix", "clean up", "enhance", "use this", "try again", "based on this",
    "same graphic", "same image", "this one", "that one", "keep", "preserve", "redo", "update"
]

_VARIATION_HINTS = [
    "variation", "alternate", "another version", "different version", "same idea", "similar", "remix", "branch"
]

_START_OVER_HINTS = [
    "start over", "from scratch", "completely different", "brand new", "new graphic", "new image"
]

def classify_image_request_mode(prompt: str, teammate_name: str, has_reference_image: bool = False) -> str:
    p = (prompt or "").strip().lower()
    state = load_image_state(teammate_name)
    has_current = bool((state.get("current_image_id") or "").strip())
    has_context = has_reference_image or has_current
    if any(x in p for x in _START_OVER_HINTS):
        return "new"
    if any(x in p for x in _VARIATION_HINTS):
        return "variation"
    if has_context and any(x in p for x in _EDIT_HINTS):
        return "edit"
    if has_reference_image:
        return "edit"
    if has_current and not any(x in p for x in ["create", "generate", "new", "from scratch"]):
        return "edit"
    return "new"

def build_image_request_prompt(raw_prompt: str, teammate_name: str, mode: str, source_rec: Optional[Dict[str, Any]] = None) -> str:
    state = load_image_state(teammate_name)
    current_url = (state.get("current_image_url") or "").strip()
    approved_url = (state.get("approved_image_url") or "").strip()
    base = (raw_prompt or "").strip()
    extras: List[str] = []
    if mode == "edit":
        extras.append("Edit the existing image instead of inventing a new concept.")
        extras.append("Preserve the main subject, composition, identity, and overall layout unless the user clearly asks to change them.")
        extras.append("Only apply the requested changes.")
    elif mode == "variation":
        extras.append("Create a close variation of the current image, not a completely different concept.")
        extras.append("Keep the same subject and core visual identity while changing only the requested elements.")
    else:
        extras.append("Create a fresh image that directly follows the user's request.")
    if current_url:
        extras.append(f"Current thread image reference: {current_url}")
    if approved_url:
        extras.append(f"Approved reference image: {approved_url}")
    if source_rec and _is_image_record(source_rec):
        extras.append(f"Uploaded image reference: {_image_url_for_record(source_rec)}")
        extras.append("Use the uploaded image as the primary visual reference.")
    return (base + "\n\n" + "\n".join(extras)).strip()

def _read_upload_bytes(rec: Optional[Dict[str, Any]]) -> Tuple[Optional[bytes], str]:
    if not _is_image_record(rec):
        return None, ""
    relpath = (rec.get("relpath") or "").strip()
    if not relpath:
        return None, ""
    path = UPLOADS_DIR / relpath
    raw = safe_read_binary_file(path, max_bytes=20 * 1024 * 1024)
    return raw, (rec.get("mimetype") or "image/png")

def _extract_b64_from_image_resp(resp: Any) -> Optional[str]:
    try:
        if hasattr(resp, "data") and resp.data:
            first = resp.data[0]
            return getattr(first, "b64_json", None) or (first.get("b64_json") if isinstance(first, dict) else None)
    except Exception:
        return None
    return None


def safe_read_text_file(path: Path, max_bytes: int = MAX_INLINE_TEXT_BYTES) -> Optional[str]:
    try:
        if not path.exists():
            return None
        if path.stat().st_size > max_bytes:
            return None
        raw = path.read_bytes()
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


def safe_read_binary_file(path: Path, max_bytes: int) -> Optional[bytes]:
    try:
        if not path.exists():
            return None
        if path.stat().st_size > max_bytes:
            return None
        return path.read_bytes()
    except Exception:
        return None


def _guess_data_url(mimetype: str, raw: bytes) -> Optional[str]:
    mt = (mimetype or "").lower().strip()
    if not mt.startswith("image/"):
        return None
    b64 = base64.b64encode(raw).decode("ascii")
    return f"data:{mt};base64,{b64}"


def summarize_attachments_for_prompt(file_ids: List[str]) -> Tuple[str, List[Dict[str, Any]], List[Dict[str, Any]]]:
    meta_list: List[Dict[str, Any]] = []
    lines: List[str] = []
    vision_images: List[Dict[str, Any]] = []

    for fid in file_ids or []:
        rec = get_upload_record(fid)
        if not rec:
            continue

        meta = {
            "id": fid,
            "filename": rec.get("filename", ""),
            "mimetype": rec.get("mimetype", ""),
            "size_bytes": rec.get("size_bytes", 0),
        }
        meta_list.append(meta)

        filename = meta["filename"]
        mimetype = (meta["mimetype"] or "").lower()
        relpath = rec.get("relpath", "")
        fpath = UPLOADS_DIR / relpath if relpath else None

        if fpath and (mimetype.startswith("text/") or filename.lower().endswith((".txt", ".md", ".csv", ".json"))):
            txt = safe_read_text_file(fpath)
            if txt is not None:
                lines.append(f"[Attachment: {filename}]")
                lines.append(txt.strip())
                lines.append("")
            else:
                lines.append(f"[Attachment: {filename}] (text file too large to inline)")
            continue

        if fpath and mimetype.startswith("image/") and len(vision_images) < MAX_INLINE_IMAGES:
            raw = safe_read_binary_file(fpath, MAX_INLINE_IMAGE_BYTES)
            if raw is not None:
                data_url = _guess_data_url(mimetype, raw)
                if data_url:
                    vision_images.append({
                        "filename": filename,
                        "mimetype": mimetype,
                        "data_url": data_url
                    })
                    lines.append(f"[Attachment: {filename}] (image included for vision models when supported)")
                    continue

        lines.append(f"[Attachment: {filename}] (non text file, included as reference)")

    context = ""
    if lines:
        context = "ATTACHMENTS (user provided)\n" + "\n".join(lines).strip() + "\n"
    return context, meta_list, vision_images


# =========================
# EMAIL
# =========================

def _user_smtp_settings(u: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    smtp = (((u or {}).get("settings") or {}).get("smtp") or {})
    if not isinstance(smtp, dict):
        smtp = {}
    return {
        "host": (smtp.get("host") or "").strip() or SMTP_HOST,
        "port": int(smtp.get("port") or SMTP_PORT),
        "user": (smtp.get("user") or "").strip(),
        "pass": (smtp.get("pass") or "").strip(),
        "from_name": (smtp.get("from_name") or "").strip() or SMTP_FROM_NAME
    }

def smtp_ready_for_user(u: Optional[Dict[str, Any]]) -> Tuple[bool, str]:
    s = _user_smtp_settings(u)
    if s["user"] and s["pass"]:
        return True, ""
    # Disabled global SMTP fallback
    return False, "No SMTP connected. Add your email in Settings."
    return False, "No SMTP connected. Add your email in Settings."



def _google_oauth_ready() -> Tuple[bool, str]:
    # Manual OAuth flow (no google-auth libraries required).
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET or not PUBLIC_BASE_URL:
        return False, "Google OAuth is not configured. Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and PUBLIC_BASE_URL in your server environment."
    return True, ""

def _gmail_libs_ready() -> Tuple[bool, str]:
    # Backward-compatible name used by older code paths.
    return _google_oauth_ready()

def _user_gmail_oauth(u: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not u:
        return {}
    settings = (u.get("settings") or {})
    return (settings.get("gmail_oauth") or {})

def _save_user_gmail_oauth(u: Dict[str, Any], token_info: Optional[Dict[str, Any]]) -> None:
    users = load_users()
    uname = u.get("username")
    rec = (users.get("users") or {}).get(uname) or u
    rec.setdefault("settings", {})
    if token_info:
        rec["settings"]["gmail_oauth"] = token_info
    else:
        # disconnect
        if "gmail_oauth" in rec.get("settings", {}):
            rec["settings"].pop("gmail_oauth", None)
    rec["updated_at"] = now_iso()
    users["users"][uname] = rec
    save_users(users)

# =========================
# GOOGLE CALENDAR OAUTH
# =========================


def _calendar_libs_ready() -> Tuple[bool, str]:
    # Backward-compatible name used by older code paths.
    return _google_oauth_ready()

def _user_calendar_oauth(u: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not u:
        return {}
    settings = (u.get("settings") or {})
    return (settings.get("calendar_oauth") or {})

def _save_user_calendar_oauth(u: Dict[str, Any], token_info: Optional[Dict[str, Any]]) -> None:
    users = load_users()
    uname = u.get("username")
    rec = (users.get("users") or {}).get(uname) or u
    rec.setdefault("settings", {})
    if token_info:
        rec["settings"]["calendar_oauth"] = token_info
    else:
        if "calendar_oauth" in rec.get("settings", {}):
            rec["settings"].pop("calendar_oauth", None)
    rec["updated_at"] = now_iso()
    users["users"][uname] = rec
    save_users(users)


def _calendar_creds_for_user(u: Optional[Dict[str, Any]]) -> Tuple[Optional[str], str]:
    ok, reason = _calendar_libs_ready()
    if not ok:
        return None, reason
    token_info = _user_calendar_oauth(u)
    if not token_info:
        return None, "Calendar not connected. Go to Settings and connect Google Calendar."
    access_token, refreshed, err = _get_access_token_from_store(token_info, CALENDAR_SCOPES)
    if not access_token:
        return None, err or "Calendar session expired. Disconnect and reconnect Google Calendar."
    if refreshed:
        try:
            _save_user_calendar_oauth(u, refreshed)
        except Exception:
            pass
    return access_token, ""

def _calendar_create_event(access_token: str, title: str, start_iso: str, end_iso: str, timezone: str, attendees: Optional[List[str]] = None, description: str = "", location: str = "", use_meet: bool = False) -> Dict[str, Any]:
    import requests, uuid as _uuid
    url = "https://www.googleapis.com/calendar/v3/calendars/primary/events"
    event: Dict[str, Any] = {
        "summary": title,
        "description": description or "",
        "location": location or "",
        "start": {"dateTime": start_iso, "timeZone": timezone},
        "end": {"dateTime": end_iso, "timeZone": timezone},
    }
    if attendees:
        clean = [{"email": a.strip()} for a in attendees if (a or "").strip()]
        if clean:
            event["attendees"] = clean
            event["sendUpdates"] = "all"
    if use_meet:
        event["conferenceData"] = {
            "createRequest": {
                "requestId": str(_uuid.uuid4()),
                "conferenceSolutionKey": {"type": "hangoutsMeet"}
            }
        }
    params = {"conferenceDataVersion": "1"} if use_meet else {}
    r = requests.post(url, headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}, json=event, params=params, timeout=20)
    data = r.json() if r.content else {}
    if r.status_code >= 400:
        raise Exception(f"Calendar API error: {data}")
    return data

def _calendar_move_event(access_token: str, event_id: str, new_start_iso: str, new_end_iso: str, timezone: str, send_updates: str = "none") -> Dict[str, Any]:
    """PATCH an existing Google Calendar event to a new time — does NOT create a duplicate."""
    import requests
    url = f"https://www.googleapis.com/calendar/v3/calendars/primary/events/{event_id}"
    body = {
        "start": {"dateTime": new_start_iso, "timeZone": timezone},
        "end":   {"dateTime": new_end_iso,   "timeZone": timezone},
    }
    params = {"sendUpdates": send_updates}
    r = requests.patch(url, headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
                       json=body, params=params, timeout=20)
    data = r.json() if r.content else {}
    if r.status_code >= 400:
        raise Exception(f"Calendar PATCH error: {data}")
    return data


def _calendar_list_events(access_token: str, time_min: str, time_max: str, timezone: str, max_results: int = 250) -> List[Dict[str, Any]]:
    import requests
    url = "https://www.googleapis.com/calendar/v3/calendars/primary/events"
    params = {
        "timeMin": time_min,
        "timeMax": time_max,
        "singleEvents": "true",
        "orderBy": "startTime",
        "maxResults": str(max_results),
        "timeZone": timezone,
    }
    r = requests.get(url, headers={"Authorization": f"Bearer {access_token}"}, params=params, timeout=20)
    data = r.json() if r.content else {}
    if r.status_code >= 400:
        raise Exception(f"Calendar API error: {data}")
    items = data.get("items") or []
    out: List[Dict[str, Any]] = []
    for it in items:
        start = (it.get("start") or {}).get("dateTime") or (it.get("start") or {}).get("date") or ""
        end = (it.get("end") or {}).get("dateTime") or (it.get("end") or {}).get("date") or ""
        raw_attendees = it.get("attendees") or []
        attendee_emails = [a.get("email","") for a in raw_attendees if a.get("email") and a.get("self") is not True]
        out.append({
            "id": it.get("id",""),
            "summary": it.get("summary",""),
            "start": start,
            "end": end,
            "htmlLink": it.get("htmlLink",""),
            "hangoutLink": it.get("hangoutLink",""),
            "recurringEventId": it.get("recurringEventId",""),
            "description": it.get("description",""),
            "location": it.get("location",""),
            "attendees": attendee_emails,
        })
    return out


def _gmail_creds_for_user(u: Optional[Dict[str, Any]]) -> Tuple[Optional[str], str]:
    ok, reason = _gmail_libs_ready()
    if not ok:
        return None, reason
    token_info = _user_gmail_oauth(u)
    if not token_info:
        return None, "Gmail not connected. Go to Settings and connect Gmail."
    access_token, refreshed, err = _get_access_token_from_store(token_info, GMAIL_SCOPES)
    if not access_token:
        return None, err or "Gmail session expired. Disconnect and reconnect Gmail."
    if refreshed:
        try:
            _save_user_gmail_oauth(u, refreshed)
        except Exception:
            pass
    return access_token, ""

def _gmail_send_message(access_token: str, to_addr: str, subject: str, body: str, from_name: str = "") -> None:
    import requests
    # Build RFC 2822 message
    from_header = "me"
    if from_name:
        from_header = f"{from_name} <me>"
    msg = MIMEMultipart()
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["From"] = from_header
    msg.attach(MIMEText(body, "plain", "utf-8"))

    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")
    url = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
    r = requests.post(url, headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}, json={"raw": raw}, timeout=20)
    if r.status_code >= 400:
        data = r.json() if r.content else {}
        raise Exception(f"Gmail API error: {data}")


def _email_capability_for_user(u: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    # Returns what can be used right now
    gmail_connected = bool(_user_gmail_oauth(u))
    smtp_ok, _ = smtp_ready_for_user(u)
    return {"gmail_connected": gmail_connected, "smtp_ready": smtp_ok}

def send_email_smtp_with_creds(to_addr: str, subject: str, body: str, host: str, port: int, user: str, password: str, from_name: str) -> None:
    msg = MIMEMultipart()
    msg["From"] = f"{from_name} <{user}>"
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))

    with smtplib.SMTP(host, port) as server:
        server.starttls()
        server.login(user, password)
        server.send_message(msg)

def smtp_ready() -> Tuple[bool, str]:
    # Backward compatible, used in a few places
    return smtp_ready_for_user(current_user())
def send_email_smtp(to_addr: str, subject: str, body: str, from_name: str, from_addr: str) -> None:
    msg = MIMEMultipart()
    msg["From"] = f"{from_name} <{from_addr}>"
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)


def extract_email_draft(text: str) -> Optional[Dict[str, str]]:
    if not text:
        return None

    content = text.strip()

    block = None
    m = EMAIL_DRAFT_BLOCK_RE.search(content)
    if m:
        block = (m.group(1) or "").strip()
    else:
        block = content

    lines = block.splitlines()
    to_val = ""
    subject_val = ""
    body_lines: List[str] = []
    in_body = False

    for raw in lines:
        line = raw.rstrip("\n")
        if not in_body:
            hm = EMAIL_HEADER_RE.match(line)
            if hm:
                key = hm.group(1).lower().strip()
                val = (hm.group(2) or "").strip()
                if key == "to":
                    to_val = val
                    continue
                if key == "subject":
                    subject_val = val
                    continue
                if key == "body":
                    in_body = True
                    if val:
                        body_lines.append(val)
                    continue
        else:
            body_lines.append(line)

    body_val = "\n".join(body_lines).strip()

    if not subject_val and not body_val:
        return None

    return {"to": to_val, "subject": subject_val, "body": body_val}


# =========================
# PROMPTS + LLM
# =========================

def teammate_system_prompt(defn: Dict[str, Any], lighting_mode: bool = False,
                           rag_context: str = "") -> str:
    role_block = {
        "name": defn.get("name", ""),
        "job_title": defn.get("job_title", ""),
        "version": defn.get("version", ""),
        "mission": defn.get("mission", ""),
        "responsibilities": defn.get("responsibilities", []),
        "thinking_style": defn.get("thinking_style", ""),
        "will_not_do": defn.get("will_not_do", []),
        "goal": defn.get("goal", ""),
    }

    image_rules = (
        "IMAGE GENERATION CAPABILITY\n"
        "You CAN generate images. When the user asks for an image, graphic, logo, poster, "
        "illustration, or visual — respond with a brief confirmation and a clear DALL-E style prompt. "
        "The system will automatically detect image requests and generate the image for you. "
        "Do NOT say you cannot generate images. Do NOT say you lack image capabilities. "
        "Simply acknowledge the request enthusiastically and describe what you will create.\n"
    )

    email_rules = (
        "EMAIL CAPABILITY\n"
        "You can draft emails, but you cannot send emails.\n"
        "If the user asks you to send an email, output a structured email draft so the UI can auto fill fields.\n"
        "Use this exact format when an email draft is appropriate:\n"
        "```email\n"
        "To: recipient@email.com\n"
        "Subject: subject line\n"
        "Body: first line of body\n"
        "rest of body.\n"
        "```\n"
        "Do not claim the email was sent.\n"
        "No em dashes.\n"
    )

    # Operator profile (shared business context)
    try:
        _op_user = _get_session_username()
    except Exception:
        _op_user = "anon"

    _op = _load_operator_profile(_op_user or "anon")
    operator_block = (
        "\n\nOPERATOR PROFILE (shared context)\n"
        f"Operator: {_op.get('display_name','Operator')}\n"
        f"Business: {(_op.get('business','') or '').strip()}\n"
        f"Offers: {(_op.get('offers','') or '').strip()}\n"
        f"Audience: {(_op.get('audience','') or '').strip()}\n"
        f"Goals: {(_op.get('goals','') or '').strip()}\n"
        f"Constraints: {(_op.get('constraints','') or '').strip()}\n"
        f"Tone rules: {(_op.get('tone_rules','') or '').strip()}\n"
        f"Notes: {(_op.get('notes','') or '').strip()}\n"
    )

    # Active client (memory profiles) if available
    client_block = ""
    try:
        _active = _get_active_client(_op_user or "anon") or {}
        if isinstance(_active, dict) and _active:
            client_block = (
                "\n\nACTIVE CLIENT (memory profile)\n"
                f"Client name: {(_active.get('name') or '').strip()}\n"
                f"Email: {(_active.get('email') or '').strip()}\n"
                f"Phone: {(_active.get('phone') or '').strip()}\n"
                f"Company: {(_active.get('company') or '').strip()}\n"
                f"Notes: {(_active.get('notes') or '').strip()}\n"
            )
    except Exception:
        client_block = ""

    # Shared team memory — facts extracted from recent group convenes
    shared_memory_block = ""
    try:
        osd = _os_load(_op_user or "anon")
        smem = osd.get("shared_team_memory") or {}
        facts = smem.get("facts") or []
        decisions = smem.get("decisions") or []
        open_loops = smem.get("open_loops") or []
        if facts or decisions or open_loops:
            lines = ["\n\nSHARED TEAM MEMORY (extracted from recent group sessions — treat as established context)"]
            if facts:
                lines.append("Key facts: " + " | ".join(str(f) for f in facts[:8]))
            if decisions:
                lines.append("Decisions made: " + " | ".join(str(d) for d in decisions[:6]))
            if open_loops:
                lines.append("Open loops: " + " | ".join(str(o) for o in open_loops[:6]))
            shared_memory_block = "\n".join(lines) + "\n"
    except Exception:
        shared_memory_block = ""

    framework = load_core_framework()

    lighting_block = ""
    if lighting_mode:
        lighting_block = (
            "LIGHTING MODE (USER REQUESTED)\n"
            "Do not ask clarifying questions.\n"
            "Do not push back or debate.\n"
            "Deliver exactly what the user asked for, directly and completely.\n"
            "If a request is disallowed or unsafe, refuse briefly and offer a safe alternative.\n\n"
        )

    return (
        "You are a persistent, helpful AI teammate inside a multi teammate command center.\n"
        "Follow the core framework and role block.\n"
        "Be accurate. If you are unsure, say so.\n"
        "No em dashes.\n\n"
        f"{image_rules}\n"
        f"{email_rules}\n"
        f"{lighting_block}"
        f"CORE FRAMEWORK:\n{framework}\n"
        f"{operator_block}"
        f"{client_block}"
        f"{shared_memory_block}\n"
        f"{rag_context}"
        f"ROLE BLOCK (locked):\n{json.dumps(role_block, indent=2)}\n"
    )


ContentType = Union[str, List[Dict[str, Any]]]


def _build_user_content(text: str, vision_images: List[Dict[str, Any]]) -> ContentType:
    if not vision_images:
        return text

    parts: List[Dict[str, Any]] = [{"type": "text", "text": text}]
    for img in vision_images[:MAX_INLINE_IMAGES]:
        parts.append({
            "type": "image_url",
            "image_url": {"url": img["data_url"]}
        })
    return parts



def _classify_openai_error(e: Exception) -> Tuple[int, str]:
    """
    Returns (http_status, user_message)
    """
    s = (str(e) or "").lower()
    if "incorrect api key" in s or "authentication" in s or ("401" in s and "api" in s and "key" in s):
        return 401, "Invalid OpenAI API key. Open Settings and paste a valid key (sk-, sk-proj-, etc.)."
    if "model" in s and ("not found" in s or "does not exist" in s):
        return 400, f"Model error. Your MODEL setting may be invalid. Current MODEL='{MODEL}'. Try setting MODEL to a known available model."
    if "rate limit" in s or "429" in s:
        return 429, "Rate limit hit. Try again in a moment."
    return 500, "AI request failed. Check server logs for details."

def call_llm(system: str, messages: List[Dict[str, Any]], temperature: float = 0.6, model: Optional[str] = None) -> str:
    """Robust OpenAI call with 45s timeout and image-content fallback.
    Pass model= to override the global MODEL for per-teammate routing."""
    def _text_only(msgs):
        out = []
        for m in msgs:
            c = m.get("content", "")
            if isinstance(c, list):
                parts = [p.get("text", "") for p in c if isinstance(p, dict) and p.get("type") == "text"]
                c = " ".join(parts).strip()
            out.append({"role": m.get("role", "user"), "content": str(c)})
        return out
    use_model = (model or "").strip() or MODEL
    client = get_openai_client()
    timeout = int(os.getenv("OPENAI_REQUEST_TIMEOUT_SECONDS", "45"))
    sys_msg = [{"role": "system", "content": system}]
    try:
        resp = client.chat.completions.create(
            model=use_model,
            messages=sys_msg + messages,
            temperature=temperature,
            timeout=timeout,
        )
        return (resp.choices[0].message.content or "").strip()
    except Exception as e:
        err = str(e).lower()
        if any(x in err for x in ["image", "vision", "invalid_image", "content"]):
            try:
                resp2 = client.chat.completions.create(
                    model=use_model,
                    messages=sys_msg + _text_only(messages),
                    temperature=temperature,
                    timeout=timeout,
                )
                return (resp2.choices[0].message.content or "").strip()
            except Exception as e2:
                raise e2
        raise e

# =========================
# IMAGE GENERATION (additive)
# =========================
# Enables teammates to return real images (stored in Uploads) when the user asks for a graphic/image.
# Uses OpenAI Images API via the installed OpenAI python client.
#
# Front-end expects optional fields returned by /api/followup:
#   { image_url: "/uploads/<relpath>", image_file: {upload record} }

IMAGE_MODELS_FALLBACK = ["gpt-image-1", "gpt-image-1.5", "gpt-image-1-mini"]

_IMAGE_TRIGGERS = [
    "generate an image", "generate image", "create an image", "create image",
    "make an image", "make image",
    "create a graphic", "make a graphic", "generate a graphic",
    "give me the graphic", "give me a graphic",
    "render", "illustration", "logo", "poster",
    "image of", "picture of",
]

def is_image_request(prompt: str) -> bool:
    p = (prompt or "").strip().lower()
    if not p:
        return False
    # Strong triggers
    for t in _IMAGE_TRIGGERS:
        if t in p:
            return True
    # Heuristic: user explicitly asks for a "graphic" or "image"
    if ("graphic" in p or "image" in p or "picture" in p) and ("prompt" not in p):
        return True
    return False

def _pick_image_model() -> str:
    # Allow override via env, otherwise pick a safe default.
    m = (os.getenv("IMAGE_MODEL") or "").strip()
    if m:
        return m
    return "gpt-image-1"

def _image_prompt_refine(raw: str, lighting_mode: bool = False) -> str:
    # Refine prompt using the text model for better image outputs.
    # Keep it short, tool-friendly.
    sys = (
        "You are an expert image prompt engineer. "
        "Rewrite the user's request into a single, concise image prompt. "
        "Include composition, subject, style, and any key text (if requested). "
        "Do NOT mention policies, limitations, or tools. "
        "Output ONLY the rewritten image prompt."
    )
    user = (raw or "").strip()
    if not user:
        return ""
    # Lighting mode can bias toward higher contrast / cinematic looks.
    if lighting_mode:
        user = user + "\n\nStyle: cinematic, high contrast, rich shadows, glowing highlights."
    try:
        refined = call_llm(sys, [{"role": "user", "content": user}], temperature=0.25)
        refined = (refined or "").strip()
        # guard against multi-line chatter
        refined = refined.split("\n\n")[0].strip()
        return refined or user
    except Exception:
        return user

def _save_generated_image_bytes(image_bytes: bytes, teammate: str, username: str) -> Dict[str, Any]:
    # Save into uploads like any other file and index it.
    file_id = uuid.uuid4().hex
    subdir = datetime.utcnow().strftime("%Y%m%d")
    (UPLOADS_DIR / subdir).mkdir(parents=True, exist_ok=True)
    filename = f"{_safe_name(teammate or 'teammate')}_image.png"
    out_path = UPLOADS_DIR / subdir / f"{file_id}_{filename}"
    with open(out_path, "wb") as f:
        f.write(image_bytes or b"")
    size_bytes = out_path.stat().st_size if out_path.exists() else 0
    rec = {
        "id": file_id,
        "filename": filename,
        "relpath": str(Path(subdir) / f"{file_id}_{filename}"),
        "mimetype": "image/png",
        "size_bytes": size_bytes,
        "uploaded_at": now_iso(),
        # additive metadata for image library
        "kind": "ai_image",
        "teammate": teammate,
        "owner": username,
    }
    add_upload_record(file_id, rec)
    append_log("ai_image", {"teammate": teammate, "owner": username, "file": rec})
    return rec


def _get_openai_client_for_username(username: str):
    """
    Background jobs cannot rely on Flask request/g context.
    Build an OpenAI client directly from the user's saved settings, with a global-key fallback.
    """
    key = ""
    try:
        users = load_users()
        rec = ((users.get("users") or {}).get((username or "").strip().lower()) or {})
        settings = rec.get("settings") or {}
        key = (settings.get("openai_key") or "").strip()
    except Exception:
        key = ""
    key = key or (OPENAI_API_KEY or "")
    if not key:
        raise RuntimeError("No OpenAI API key found. Add your OpenAI key in Settings.")
    return OpenAI(api_key=key)

def generate_image_for_teammate(raw_prompt: str, teammate: str, username: str, lighting_mode: bool = False, mode: str = "new", source_file_id: str = "") -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[str]]:
    """
    Returns (upload_record, image_url, error_message)
    """
    prompt = (raw_prompt or "").strip()
    if not prompt:
        return None, None, "Missing image prompt"

    source_rec = get_upload_record(source_file_id) if source_file_id else None

    prompt2 = _image_prompt_refine(prompt, lighting_mode=lighting_mode) or prompt

    model = _pick_image_model()
    try:
        client = _get_openai_client_for_username(username)
    except Exception as e:
        return None, None, str(e)

    tried = []
    last_err = ""
    ref_bytes, ref_mimetype = _read_upload_bytes(source_rec)
    can_edit = bool(ref_bytes) and mode in ("edit", "variation")

    for m in [model] + [x for x in IMAGE_MODELS_FALLBACK if x != model]:
        tried.append(m)
        try:
            resp = None
            if can_edit and hasattr(client.images, "edit"):
                suffix = ".png"
                if "jpeg" in (ref_mimetype or "") or "jpg" in (ref_mimetype or ""):
                    suffix = ".jpg"
                tmp_name = ""
                try:
                    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                        tmp.write(ref_bytes or b"")
                        tmp.flush()
                        tmp_name = tmp.name
                    with open(tmp_name, "rb") as imgf:
                        resp = client.images.edit(
                            model=m,
                            image=imgf,
                            prompt=prompt2,
                            size=os.getenv("IMAGE_SIZE", "1024x1024"),
                        )
                finally:
                    try:
                        if tmp_name and os.path.exists(tmp_name):
                            os.unlink(tmp_name)
                    except Exception:
                        pass
            if resp is None:
                resp = client.images.generate(
                    model=m,
                    prompt=prompt2,
                    size=os.getenv("IMAGE_SIZE", "1024x1024"),
                )
            b64 = _extract_b64_from_image_resp(resp)
            if not b64:
                last_err = "Image generation returned no data"
                continue
            image_bytes = base64.b64decode(b64)
            rec = _save_generated_image_bytes(image_bytes, teammate=teammate, username=username)
            url = f"/uploads/{rec['relpath']}"
            set_current_image_for_teammate(teammate, rec, source="generated", prompt=prompt, mode=mode)
            return rec, url, None
        except Exception as e:
            last_err = str(e) or "Image generation failed"
            continue

    detail = (last_err or "").strip()
    if detail:
        return None, None, f"Image generation failed (tried: {', '.join(tried)}). {detail}"
    return None, None, f"Image generation failed (tried: {', '.join(tried)})."

def is_assembly(prompt: str) -> bool:
    p = (prompt or "").strip().lower()
    triggers = [
        "all teammates to the round table",
        "all teammates to round table",
        "assemble the round table",
        "round table roll call",
        "roll call",
    ]
    return any(t in p for t in triggers)


def build_prompt_with_attachments(user_prompt: str, file_ids: List[str]) -> Tuple[str, List[Dict[str, Any]], List[Dict[str, Any]]]:
    attach_text, meta, vision_images = summarize_attachments_for_prompt(file_ids or [])
    if attach_text:
        combined = (user_prompt.strip() + "\n\n" + attach_text).strip()
        return combined, meta, vision_images
    return user_prompt.strip(), meta, vision_images


# =========================
# API
# =========================

@app.get("/api/state")
def api_state():
    reg = load_registry()
    installed = reg["installed"]
    installed_order = reg["installed_order"]
    active_order = reg.get("active_order") or []
    u = current_user()
    ready, reason = smtp_ready_for_user(u)
    return jsonify({
        "ok": True,
        "app_title": APP_TITLE,
        "model": MODEL,
        "installed_order": installed_order,
        "active_order": active_order,
        "installed": {k: {
            "name": v["name"],
            "job_title": v.get("job_title", ""),
            "version": v.get("version", ""),
            "mission": v.get("mission", ""),
            "responsibilities": v.get("responsibilities", []),
            "thinking_style": v.get("thinking_style", ""),
            "will_not_do": v.get("will_not_do", []),
            "goal": v.get("goal", ""),
            "avatar": v.get("avatar", {"bg": "#1f2a44", "fg": "#e6edff", "sigil": v["name"][:1].upper()}),
        } for k, v in installed.items()},
        "prebuilt_names": DEFAULT_ORDER,
        "email": {
            "smtp_ready": ready,
            "smtp_reason": reason,
            "smtp_user": SMTP_USER or "",
            "from_name": SMTP_FROM_NAME,
        },
        "uploads": {
            "max_upload_mb": MAX_UPLOAD_MB,
            "max_inline_text_bytes": MAX_INLINE_TEXT_BYTES,
            "max_inline_image_bytes": MAX_INLINE_IMAGE_BYTES,
            "max_inline_images": MAX_INLINE_IMAGES
        },
        "framework": {
            "has_custom": FRAMEWORK_PATH.exists(),
            "length": len(load_core_framework() or "")
        }
    })



@app.get("/api/diagnostics")
def api_diagnostics():
    """Lightweight, read-only diagnostics for debugging UI state.
    Additive endpoint: does not change behavior of any existing flows.
    """
    reg = load_registry()
    u = current_user()
    # Email capability
    email_cap = _email_capability_for_user(u) if u else {"gmail_connected": False, "smtp_ready": False}
    # Calendar capability (best-effort)
    cal_connected = False
    cal_reason = ""
    try:
        if u:
            cal_token, cal_reason = _calendar_creds_for_user(u)
            cal_connected = bool(cal_token)
    except Exception as e:
        cal_connected = False
        cal_reason = str(e)

    # Basic session flags (safe)
    sess = {
        "authenticated": bool(u),
        "user": (u or ""),
    }

    return jsonify({
        "ok": True,
        "app_title": APP_TITLE,
        "model": MODEL,
        "session": sess,
        "registry": {
            "installed_order": reg.get("installed_order") or [],
            "active_order": reg.get("active_order") or [],
            "installed_keys": sorted(list((reg.get("installed") or {}).keys())),
        },
        "capabilities": {
            "email": email_cap,
            "calendar": {
                "calendar_connected": cal_connected,
                "reason": cal_reason,
            }
        }
    })


@app.get("/api/task_log")
def api_task_log():
    # Optional query params: teammate, status, limit
    try:
        limit = int(request.args.get("limit", "200"))
    except Exception:
        limit = 200
    limit = max(1, min(500, limit))
    teammate = (request.args.get("teammate") or "").strip()
    status = (request.args.get("status") or "").strip()
    return jsonify({"ok": True, "entries": read_task_log(limit=limit, teammate=teammate, status=status)})
# -------------------------
# Action Stack API
# -------------------------

@app.get("/api/teammates/<teammate>/stacks")
def api_action_stacks_list(teammate: str):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    data = _load_saved_stacks(uname, teammate)
    names = list((data.get("stacks") or {}).keys())
    names.sort(key=lambda x: x.lower())
    return jsonify({"ok": True, "stacks": names})

@app.get("/api/teammates/<teammate>/stacks/<stack_name>")
def api_action_stacks_get(teammate: str, stack_name: str):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    data = _load_saved_stacks(uname, teammate)
    stack = (data.get("stacks") or {}).get(stack_name)
    if not stack:
        return jsonify({"ok": False, "error": "Stack not found"}), 404
    return jsonify({"ok": True, "stack": stack})

@app.post("/api/teammates/<teammate>/stacks/<stack_name>")
def api_action_stacks_save(teammate: str, stack_name: str):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(force=True) or {}
    steps = _normalize_steps(payload.get("steps"))
    data = _load_saved_stacks(uname, teammate)
    data.setdefault("stacks", {})
    data["stacks"][stack_name] = {"name": stack_name, "teammate": teammate, "steps": steps, "updated_at": now_iso()}
    _save_saved_stacks(uname, teammate, data)
    return jsonify({"ok": True})

@app.post("/api/teammates/<teammate>/stacks/<stack_name>/run")
def api_action_stacks_run(teammate: str, stack_name: str):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(force=True) or {}
    user_input = (payload.get("input") or "").strip()
    data = _load_saved_stacks(uname, teammate)
    stack = (data.get("stacks") or {}).get(stack_name)
    if not stack:
        return jsonify({"ok": False, "error": "Stack not found"}), 404
    steps = _normalize_steps(stack.get("steps"))
    run = _init_run(u=uname, teammate=teammate, stack_name=stack_name, steps=steps, user_input=user_input)
    _persist_run(run)
    run2 = _run_action_stack_engine(run)
    return jsonify({"ok": True, "run": run2})

@app.post("/api/action_stack_runs/<run_id>/resume")
def api_action_stack_run_resume(run_id: str):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(force=True) or {}
    user_input = (payload.get("input") or "").strip()

    runs_data = _load_runs(uname)
    runs = runs_data.get("runs") or {}
    run = runs.get(run_id)
    if not run:
        return jsonify({"ok": False, "error": "Run not found"}), 404
    if run.get("status") != "needs_input":
        return jsonify({"ok": False, "error": f"Run not waiting for input (status={run.get('status')})"}), 400

    run["input"] = user_input
    run["status"] = "running"
    runs[run_id] = run
    runs_data["runs"] = runs
    _save_runs(uname, runs_data)

    run2 = _run_action_stack_engine(run)
    return jsonify({"ok": True, "run": run2})


@app.get("/api/teammates/<teammate>/stacks/schedules")
def api_action_stacks_schedules_list(teammate: str):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    schedules = [s for s in _load_schedules(uname) if (s.get("teammate") == teammate)]
    return jsonify({"ok": True, "schedules": schedules})

@app.post("/api/teammates/<teammate>/stacks/schedule")
def api_action_stacks_schedules_create(teammate: str):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(force=True) or {}
    mode = (payload.get("mode") or "").strip().lower()
    stack_name = (payload.get("stack_name") or "").strip()
    if not stack_name:
        return jsonify({"ok": False, "error": "Missing stack_name"}), 400
    data = _load_saved_stacks(uname, teammate)
    if stack_name not in (data.get("stacks") or {}):
        return jsonify({"ok": False, "error": "Stack not found"}), 404
    schedules = _load_schedules(uname)
    sid = uuid.uuid4().hex
    if mode == "once":
        run_at = (payload.get("run_at") or "").strip()
        if not _parse_local_dt(run_at):
            return jsonify({"ok": False, "error": "Invalid run_at"}), 400
        schedules.append({"id": sid, "teammate": teammate, "stack_name": stack_name, "mode": "once", "run_at": run_at, "last_run": None, "created_at": now_iso()})
    elif mode == "daily":
        t = (payload.get("time") or "").strip()
        if not re.match(r"^\\d{2}:\\d{2}$", t):
            return jsonify({"ok": False, "error": "Invalid time"}), 400
        schedules.append({"id": sid, "teammate": teammate, "stack_name": stack_name, "mode": "daily", "time": t, "last_run": None, "created_at": now_iso()})
    else:
        return jsonify({"ok": False, "error": "Invalid mode"}), 400
    _save_schedules(uname, schedules)
    return jsonify({"ok": True, "schedule_id": sid})

@app.post("/api/teammates/<teammate>/stacks/schedule/delete")
def api_action_stacks_schedules_delete(teammate: str):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(force=True) or {}
    sid = (payload.get("schedule_id") or "").strip()
    if not sid:
        return jsonify({"ok": False, "error": "Missing schedule_id"}), 400
    schedules = [s for s in _load_schedules(uname) if s.get("id") != sid]
    _save_schedules(uname, schedules)
    return jsonify({"ok": True})

@app.post("/api/action_stack_schedules/tick")
def api_action_stack_schedules_tick():
    try:
        # Action Stacks schedules
        _run_due_schedules_once()
        # Resume Action Stack runs that are due (additive fix)
        try:
            _resume_due_runs_once()
        except Exception:
            pass
        # CRM automations (sequences, reminders) - additive
        try:
            _crm_tick_once()
        except Exception:
            pass
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500




@app.get("/api/me")
def api_me():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    settings = (u.get("settings") or {})
    smtp = (settings.get("smtp") or {})
    return jsonify({
        "ok": True,
        "user": {
            "username": u.get("username", ""),
            "email": u.get("email", "")
        },
        "has_openai_key": bool((settings.get("openai_key") or "").strip()),
        "has_smtp": bool((smtp.get("user") or "").strip() and (smtp.get("pass") or "").strip()),
        "has_gmail_oauth": bool((settings.get("gmail_oauth") or {}))
    })


@app.get("/api/onboarding/status")
def api_onboarding_status():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    return jsonify(_onboarding_status_payload(u))

@app.post("/api/onboarding/dismiss")
def api_onboarding_dismiss():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    username = (u.get("username") if isinstance(u, dict) else None) or _get_session_username()
    data = request.get_json(silent=True) or {}
    dismissed = bool(data.get("dismissed", True))
    _dismiss_onboarding(username, dismissed)
    return jsonify({"ok": True, "dismissed": dismissed})

@app.get("/api/user/settings")
def api_get_user_settings():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    settings = (u.get("settings") or {})
    smtp = (settings.get("smtp") or {})

    key = (settings.get("openai_key") or "").strip()
    key_hint = ""
    if key:
        # show only last 4 chars to confirm something is saved, never return the key
        key_hint = "••••" + key[-4:] if len(key) >= 4 else "••••"

    # do not leak password
    safe_smtp = {
        "host": smtp.get("host", ""),
        "port": smtp.get("port", 587),
        "user": smtp.get("user", ""),
        "from_name": smtp.get("from_name", "")
    }
    return jsonify({
        "ok": True,
        "settings": {
            "has_openai_key": bool(key),
            "openai_key_hint": key_hint,
            "gmail_oauth_connected": bool((settings.get("gmail_oauth") or {})),
            "smtp": safe_smtp
        }
    })



@app.post("/api/user/settings")
def api_set_user_settings():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401

    # onboarding_openai_key: mark OpenAI key step when a non-empty key is saved
    try:
        uname = (u.get("username") if isinstance(u, dict) else None) or _get_session_username()
        new_key = (((u.get("settings") or {}).get("openai_key")) or "").strip() if u else ""
        if new_key:
            _mark_onboarding_step(uname, "openai_key", True)
    except Exception:
        pass


    data = request.get_json(force=True) or {}
    openai_key_in = (data.get("openai_key") or "")
    openai_key = openai_key_in.strip()

    smtp_in = data.get("smtp") or {}
    if not isinstance(smtp_in, dict):
        smtp_in = {}

    smtp_host = (smtp_in.get("host") or "").strip()
    smtp_port = int(smtp_in.get("port") or 587)
    smtp_user = (smtp_in.get("user") or "").strip()
    smtp_pass = (smtp_in.get("pass") or "").strip()
    smtp_from_name = (smtp_in.get("from_name") or "").strip()

    users = load_users()
    uname = u.get("username")
    rec = (users.get("users") or {}).get(uname) or u

    rec.setdefault("settings", {})
    if openai_key and len(openai_key) >= 20:
        rec["settings"]["openai_key"] = openai_key
    # if user leaves it blank, do NOT overwrite the saved key

    rec["settings"].setdefault("smtp", {})
    if smtp_host != "":
        rec["settings"]["smtp"]["host"] = smtp_host
    rec["settings"]["smtp"]["port"] = smtp_port
    if smtp_user != "":
        rec["settings"]["smtp"]["user"] = smtp_user
    if smtp_pass != "":
        rec["settings"]["smtp"]["pass"] = smtp_pass
    if smtp_from_name != "":
        rec["settings"]["smtp"]["from_name"] = smtp_from_name

    rec["updated_at"] = now_iso()
    users["users"][uname] = rec
    save_users(users)

    append_log("user_settings_updated", {"user": uname, "updated_at": now_iso(), "fields": list(data.keys())})
    return jsonify({"ok": True})


@app.get("/api/framework")
def api_get_framework():
    return jsonify({"ok": True, "framework": load_core_framework()})


@app.post("/api/framework")
def api_set_framework():
    data = request.get_json(force=True) or {}
    fw = (data.get("framework") or "").strip()
    save_core_framework(fw)
    append_log("framework_updated", {"updated_at": now_iso(), "length": len(load_core_framework())})
    return jsonify({"ok": True, "length": len(load_core_framework())})


@app.post("/api/install/full")
def api_install_full():
    reg = install_full_team()
    # onboarding_full_team: mark Full Team step after successful install
    try:
        uname = _get_session_username()
        _mark_onboarding_step(uname, "full_team", True)
    except Exception:
        pass


    return jsonify({"ok": True, "installed_order": reg["installed_order"], "active_order": reg.get("active_order") or []})


@app.post("/api/active_order")
def api_set_active_order():
    data = request.get_json(force=True) or {}
    order = data.get("active_order")
    if not isinstance(order, list):
        return jsonify({"ok": False, "error": "active_order must be a list"}), 400
    final = set_active_order(order)
    append_log("active_order_set", {"active_order": final, "updated_at": now_iso()})
    return jsonify({"ok": True, "active_order": final})


@app.post("/api/teammate/create")
def api_create_teammate():
    data = request.get_json(force=True) or {}
    try:
        t = create_teammate(data)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    append_log("teammate_created", {
        "name": t.get("name"),
        "job_title": t.get("job_title"),
        "version": t.get("version"),
        "created_at": now_iso()
    })
    return jsonify({"ok": True, "teammate": t})


@app.get("/api/teammate/<name>")
def api_get_teammate(name: str):
    reg = load_registry()
    installed = reg.get("installed", {})
    if name not in installed:
        return jsonify({"ok": False, "error": "Teammate not installed"}), 404
    t = installed[name]
    return jsonify({
        "ok": True,
        "teammate": {
            "name": t.get("name", name),
            "job_title": t.get("job_title", ""),
            "version": t.get("version", ""),
            "mission": t.get("mission", ""),
            "responsibilities": t.get("responsibilities", []),
            "thinking_style": t.get("thinking_style", ""),
            "will_not_do": t.get("will_not_do", []),
            "goal": t.get("goal", ""),
            "preferred_model": t.get("preferred_model", ""),
            "tts_voice": t.get("tts_voice", "alloy"),
        }
    })


@app.post("/api/teammate/<name>")
def api_update_teammate(name: str):
    reg = load_registry()
    installed = reg.get("installed", {})
    if name not in installed:
        return jsonify({"ok": False, "error": "Teammate not installed"}), 404

    payload = request.get_json(force=True) or {}
    current = installed[name]
    updated = _sanitize_teammate_update(payload, current)

    installed[name] = updated
    reg["installed"] = installed
    save_registry(reg)

    append_log("teammate_updated", {
        "name": name,
        "updated_at": now_iso(),
        "updated_fields": list(payload.keys()),
        "snapshot": {
            "name": updated.get("name", ""),
            "job_title": updated.get("job_title", ""),
            "version": updated.get("version", ""),
            "mission": updated.get("mission", ""),
            "responsibilities_count": len(updated.get("responsibilities", []) or []),
            "will_not_do_count": len(updated.get("will_not_do", []) or []),
            "goal": updated.get("goal", ""),
        }
    })

    return jsonify({"ok": True})


@app.post("/api/upload")
def api_upload():
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "Missing file field"}), 400

    f = request.files["file"]
    if not f or not f.filename:
        return jsonify({"ok": False, "error": "Empty upload"}), 400

    filename = secure_filename(f.filename)
    if not filename:
        return jsonify({"ok": False, "error": "Invalid filename"}), 400

    file_id = uuid.uuid4().hex
    subdir = datetime.utcnow().strftime("%Y%m%d")
    (UPLOADS_DIR / subdir).mkdir(parents=True, exist_ok=True)

    out_path = UPLOADS_DIR / subdir / f"{file_id}_{filename}"
    f.save(out_path)

    size_bytes = out_path.stat().st_size if out_path.exists() else 0
    mimetype = (f.mimetype or "").strip()

    owner = ""
    try:
        u = current_user()
        owner = (u.get("username") if isinstance(u, dict) else None) or ""
    except Exception:
        owner = ""
    rec = {
        "id": file_id,
        "filename": filename,
        "relpath": str(Path(subdir) / f"{file_id}_{filename}"),
        "mimetype": mimetype,
        "size_bytes": size_bytes,
        "uploaded_at": now_iso(),
        "owner": owner,
    }
    add_upload_record(file_id, rec)

    append_log("upload", rec)
    return jsonify({"ok": True, "file": rec})

@app.get("/api/images")
def api_images_list():
    """List stored images (includes AI-generated images and uploaded images)."""
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401

    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    only_ai = (request.args.get("only_ai") or "").strip().lower() in ("1","true","yes","y","on")

    idx = load_upload_index()
    files = list((idx.get("files") or {}).values())

    def _is_image(rec: Dict[str, Any]) -> bool:
        mt = (rec.get("mimetype") or "").lower()
        fn = (rec.get("filename") or "").lower()
        if mt.startswith("image/"):
            return True
        if fn.endswith((".png",".jpg",".jpeg",".webp",".gif",".svg")):
            return True
        return False

    out = []
    for rec in files:
        if not isinstance(rec, dict):
            continue
        if not _is_image(rec):
            continue
        if only_ai and (rec.get("kind") != "ai_image"):
            continue
        # If record has owner, enforce per-user privacy; otherwise show.
        owner = (rec.get("owner") or "").strip()
        if owner and owner != uname:
            continue
        r = dict(rec)
        r["url"] = f"/uploads/{r.get('relpath','')}"
        out.append(r)

    # newest first
    out.sort(key=lambda r: (r.get("uploaded_at") or ""), reverse=True)
    return jsonify({"ok": True, "images": out})


@app.get("/api/images/job/<job_id>")
def api_image_job_status(job_id: str):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    st = _image_job_get(job_id)
    if not st:
        return jsonify({"ok": False, "error": "Job not found"}), 404
    return jsonify({"ok": True, "job": st})


@app.post("/api/convene")
def api_convene():
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        data = {}
    try:
        return _api_convene_impl(data)
    except Exception as e:
        try:
            append_log("convene_crash", {"error": str(e)})
        except Exception:
            pass
        r = jsonify({"ok": False, "error": str(e)})
        r.headers["Content-Type"] = "application/json"
        return r, 500

def _api_convene_impl(data):
    prompt = (data.get("prompt") or "").strip()
    file_ids = data.get("file_ids") or []
    lighting_mode = bool(data.get("lighting_mode"))

    if not prompt:
        return jsonify({"ok": False, "error": "Missing prompt"}), 400

    reg = load_registry()
    installed = reg["installed"]
    order = reg.get("active_order") or reg.get("installed_order") or []

    if not installed:
        return jsonify({"ok": False, "error": "No teammates installed"}), 400
    if not order:
        return jsonify({"ok": False, "error": "No active teammates in the round table"}), 400

    if is_assembly(prompt):
        roll = []
        for name in order:
            d = installed.get(name)
            if not d:
                continue
            roll.append({"name": d["name"], "job_title": d.get("job_title", ""), "version": d.get("version", "")})
        append_log("assembly", {"prompt": prompt, "roll": roll})
        return jsonify({"ok": True, "mode": "assembly", "roll": roll})

    prompt2, attach_meta, vision_images = build_prompt_with_attachments(prompt, file_ids)
    user_content = _build_user_content(prompt2, vision_images)

    atlis = installed.get("Atlis") or PREBUILT_LOCKED["Atlis"]
    atlis_sys = teammate_system_prompt(atlis, lighting_mode=lighting_mode)
    try:
        atlis_report = call_llm(
            atlis_sys,
        [{"role": "user", "content": json.dumps({
            "task": "Integrity preflight check",
            "rules": [
                "No execution. Report only.",
                "If unclear, recommend asking exactly one clarifying question.",
                "No em dashes."
            ],
            "user_prompt": prompt2
        }, indent=2)}],
        temperature=0.2
        )
    except Exception as e:
        status, msg = _classify_openai_error(e)
        append_log("convene_error", {"where":"atlis_preflight","error": str(e)})
        return jsonify({"ok": False, "error": msg}), status

    # Task log: Atlis preflight (append-only)
    append_task_log(
        "atlis_preflight",
        {
            "prompt": prompt,
            "prompt_with_attachments": prompt2,
            "attachment_meta": attach_meta,
            "vision_images_count": len(vision_images),
            "report_preview": (atlis_report[:800] + ("..." if len(atlis_report) > 800 else "")),
        },
        teammate="Atlis",
        status="success"
    )

    outputs: Dict[str, str] = {}
    email_drafts: Dict[str, Dict[str, str]] = {}

    for name in order:
        defn = installed.get(name)
        if not defn:
            continue

        sys = teammate_system_prompt(defn, lighting_mode=lighting_mode)

        thread = load_thread(name)
        thread = thread[-12:] if len(thread) > 12 else thread

        msgs: List[Dict[str, Any]] = []
        msgs.extend(thread)
        msgs.append({"role": "user", "content": user_content})

        try:
            text = call_llm(sys, msgs, temperature=0.65)
        except Exception as e:
            status, msg = _classify_openai_error(e)
            append_log("convene_error", {"where": name, "error": str(e)})
            return jsonify({"ok": False, "error": msg}), status

        new_thread = thread + [{"role": "user", "content": prompt2}, {"role": "assistant", "content": text}]
        save_thread(name, new_thread)

        outputs[name] = text

        # Task log per teammate response (append-only)
        append_task_log(
            "teammate_convene",
            {
                "prompt": prompt,
                "prompt_with_attachments": prompt2,
                "attachment_meta": attach_meta,
                "vision_images_count": len(vision_images),
                "response_preview": (text[:800] + ("..." if len(text) > 800 else "")),
            },
            teammate=name,
            status="success"
        )

        d = extract_email_draft(text)
        if d:
            email_drafts[name] = d

    append_log("convene", {
        "prompt": prompt,
        "prompt_with_attachments": prompt2,
        "attachment_meta": attach_meta,
        "vision_images_count": len(vision_images),
        "order": order,
        "atlis_report": atlis_report,
        "framework_length": len(load_core_framework()),
        "outputs": outputs,
        "email_drafts": email_drafts,
    })

    # Extract shared team memory from this round's outputs (non-blocking background thread)
    try:
        uname_for_mem = _get_session_username()
        _extract_shared_memory_async(uname_for_mem, prompt, outputs)
    except Exception:
        pass

    return jsonify({
        "ok": True,
        "mode": "execute",
        "atlis_report": atlis_report,
        "outputs": outputs,
        "email_drafts": email_drafts,
        "attachment_meta": attach_meta
    })


@app.post("/api/followup")
def api_followup():
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        data = {}
    try:
        return _api_followup_impl(data)
    except Exception as e:
        try:
            append_log("followup_crash", {"error": str(e)})
        except Exception:
            pass
        r = jsonify({"ok": False, "error": str(e)})
        r.headers["Content-Type"] = "application/json"
        return r, 500

def _api_followup_impl(data):
    name = (data.get("name") or "").strip()
    msg = (data.get("message") or "").strip()
    file_ids = data.get("file_ids") or []
    lighting_mode = bool(data.get("lighting_mode"))

    if not name or not msg:
        return jsonify({"ok": False, "error": "Missing name or message"}), 400

    reg = load_registry()
    installed = reg["installed"]
    if name not in installed:
        return jsonify({"ok": False, "error": "Teammate not installed"}), 400

    msg2, attach_meta, vision_images = build_prompt_with_attachments(msg, file_ids)
    user_content = _build_user_content(msg2, vision_images)

    defn = installed[name]

    thread = load_thread(name)
    thread = thread[-14:] if len(thread) > 14 else thread

    latest_uploaded_image = bind_uploaded_images_to_teammate(name, file_ids)

    try:
        uname = _get_session_username()
    except Exception:
        uname = "anon"

    # RAG: retrieve relevant chunks from indexed knowledge base (non-blocking, safe)
    rag_context = ""
    try:
        rag_context = _rag_retrieve(uname, msg, top_k=4)
    except Exception:
        rag_context = ""

    sys = teammate_system_prompt(defn, lighting_mode=lighting_mode, rag_context=rag_context)

    if is_image_request(msg2):
        source_rec = latest_uploaded_image or _latest_image_record_from_state(name)
        mode = classify_image_request_mode(msg2, name, has_reference_image=bool(source_rec))
        source_file_id = (source_rec.get("id") if isinstance(source_rec, dict) else "") or ""
        job_prompt = build_image_request_prompt(msg, name, mode=mode, source_rec=source_rec)
        job_id = create_image_job(job_prompt, teammate=name, username=uname, lighting_mode=lighting_mode, mode=mode, source_file_id=source_file_id)

        mode_label = {"edit": "Editing image", "variation": "Generating variation", "new": "Generating image"}.get(mode, "Generating image")
        placeholder = f"[{mode_label}] job:{job_id}"
        thread2 = load_thread(name)
        thread2 = thread2[-14:] if len(thread2) > 14 else thread2
        new_thread = thread2 + [{"role": "user", "content": msg2}, {"role": "assistant", "content": placeholder}]
        save_thread(name, new_thread)

        st0 = load_image_state(name)
        st0["last_prompt"] = msg
        st0["last_mode"] = mode
        save_image_state(name, st0)

        append_log("followup_image_job", {"name": name, "prompt": msg2, "job_prompt": job_prompt, "job_id": job_id, "mode": mode, "source_file_id": source_file_id})
        append_task_log("teammate_followup_image_job", {"name": name, "prompt": msg2, "job_prompt": job_prompt, "job_id": job_id, "mode": mode, "source_file_id": source_file_id}, teammate=name, status="queued")

        return jsonify({"ok": True, "name": name, "response": placeholder, "job_id": job_id, "mode": mode, "email_draft": None, "attachment_meta": attach_meta, "image_state": load_image_state(name)})



    msgs: List[Dict[str, Any]] = []
    msgs.extend(thread)
    msgs.append({"role": "user", "content": user_content})

    preferred_model = (defn.get("preferred_model") or "").strip() or None
    _pm = preferred_model or MODEL
    _tool_log: List[Dict[str, Any]] = []

    # Tool calling: skip for o1/o3 series (they don't support the tools param)
    _supports_tools = not any(_pm.startswith(p) for p in ("o1", "o3", "o4"))
    if _supports_tools:
        try:
            text, _tool_log = call_llm_with_tools(
                sys, msgs, temperature=0.65, model=preferred_model,
                username=uname, u=current_user() or {}
            )
        except Exception:
            text = call_llm(sys, msgs, temperature=0.65, model=preferred_model)
    else:
        text = call_llm(sys, msgs, temperature=0.65, model=preferred_model)

    new_thread = thread + [{"role": "user", "content": msg2}, {"role": "assistant", "content": text}]
    save_thread(name, new_thread)

    draft = extract_email_draft(text)

    append_log("followup", {
        "name": name,
        "message": msg,
        "message_with_attachments": msg2,
        "attachment_meta": attach_meta,
        "vision_images_count": len(vision_images),
        "framework_length": len(load_core_framework()),
        "response": text,
        "email_draft": draft,
        "tool_calls": _tool_log,
    })

    # Task log (append-only)
    append_task_log(
        "teammate_followup",
        {
            "name": name,
            "message": msg,
            "message_with_attachments": msg2,
            "attachment_meta": attach_meta,
            "vision_images_count": len(vision_images),
            "email_draft": draft,
            "tool_calls_count": len(_tool_log),
            "response_preview": (text[:800] + ("..." if len(text) > 800 else "")),
        },
        teammate=name,
        status="success"
    )
    # onboarding_first_prompt: mark after the first successful prompt is sent
    try:
        uname = _get_session_username()
        _mark_onboarding_step(uname, "first_prompt", True)
    except Exception:
        pass

    return jsonify({"ok": True, "name": name, "response": text, "email_draft": draft,
                    "attachment_meta": attach_meta, "tool_calls": _tool_log})


@app.get("/api/thread/<name>")
def api_thread(name: str):
    reg = load_registry()
    installed = reg["installed"]
    if name not in installed:
        return jsonify({"ok": False, "error": "Teammate not installed"}), 400
    return jsonify({"ok": True, "thread": load_thread(name), "image_state": load_image_state(name)})

@app.get("/api/teammates/<name>/image_state")
def api_teammate_image_state(name: str):
    reg = load_registry()
    installed = reg["installed"]
    if name not in installed:
        return jsonify({"ok": False, "error": "Teammate not installed"}), 400
    return jsonify({"ok": True, "image_state": load_image_state(name)})

@app.post("/api/teammates/<name>/current_image")
def api_teammate_set_current_image(name: str):
    reg = load_registry()
    installed = reg["installed"]
    if name not in installed:
        return jsonify({"ok": False, "error": "Teammate not installed"}), 400
    data = request.get_json(force=True) or {}
    file_id = (data.get("file_id") or "").strip()
    approve = bool(data.get("approve"))
    if not file_id:
        return jsonify({"ok": False, "error": "Missing file_id"}), 400
    rec = get_upload_record(file_id)
    if not _is_image_record(rec):
        return jsonify({"ok": False, "error": "Image not found"}), 404
    st = set_current_image_for_teammate(name, rec, source="selected", prompt="", mode="selected")
    if approve:
        st = approve_current_image_for_teammate(name)
    return jsonify({"ok": True, "image_state": st, "file": rec, "url": _image_url_for_record(rec)})

@app.post("/api/teammates/<name>/approve_current_image")
def api_teammate_approve_current_image(name: str):
    reg = load_registry()
    installed = reg["installed"]
    if name not in installed:
        return jsonify({"ok": False, "error": "Teammate not installed"}), 400
    st = approve_current_image_for_teammate(name)
    return jsonify({"ok": True, "image_state": st})


@app.post("/api/send_email")
def api_send_email():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401

    data = request.get_json(force=True) or {}
    to_addr = (data.get("to") or "").strip()
    subject = (data.get("subject") or "").strip()
    body = (data.get("body") or "").strip()
    from_teammate = (data.get("from_teammate") or "").strip()

    if not to_addr or not subject or not body:
        return jsonify({"ok": False, "error": "Missing to, subject, or body"}), 400
    if not EMAIL_RE.match(to_addr):
        return jsonify({"ok": False, "error": "Invalid recipient email"}), 400

    # Prefer Gmail OAuth (Option C). If not connected, fall back to SMTP if configured.
    cap = _email_capability_for_user(u)

    try:
        if cap["gmail_connected"]:
            access_token, reason = _gmail_creds_for_user(u)
            if not access_token:
                return jsonify({"ok": False, "error": reason}), 400
            _gmail_send_message(access_token, to_addr=to_addr, subject=subject, body=body, from_name=_user_smtp_settings(u).get("from_name", ""))
            provider = "gmail_oauth"
        else:
            ready, reason = smtp_ready_for_user(u)
            if not ready:
                return jsonify({
                    "ok": False,
                    "error": reason,
                    "hint": "Connect Gmail (recommended) or add SMTP credentials in Settings. For Gmail SMTP you must use an App Password."
                }), 400

            s = _user_smtp_settings(u)
            host = s["host"]
            port = s["port"]
            user = s["user"] or SMTP_USER
            password = s["pass"] or SMTP_PASS
            from_name = s["from_name"]
            if not user or not password:
                return jsonify({"ok": False, "error": "Missing SMTP credentials"}), 400
            send_email_smtp_with_creds(
                to_addr=to_addr,
                subject=subject,
                body=body,
                host=host,
                port=port,
                user=user,
                password=password,
                from_name=from_name
            )
            provider = "smtp"
    except Exception as e:
        append_log("email_error", {"to": to_addr, "subject": subject, "from_teammate": from_teammate, "error": str(e)})

        append_task_log(
            "send_email",
            {
                "to": to_addr,
                "subject": subject,
                "from_teammate": from_teammate,
                "provider": cap,
                "error": str(e),
            },
            teammate=from_teammate or "",
            status="failed"
        )

        return jsonify({"ok": False, "error": f"Email send failed: {e}"}), 500

    append_log("email_sent", {"to": to_addr, "subject": subject, "from_teammate": from_teammate, "provider": provider, "sent_at": now_iso()})

    append_task_log(
        "send_email",
        {
            "to": to_addr,
            "subject": subject,
            "from_teammate": from_teammate,
            "provider": provider,
            "sent_at": now_iso(),
        },
        teammate=from_teammate or "",
        status="success"
    )

    return jsonify({"ok": True, "provider": provider})


@app.post("/api/send_sms")
def api_send_sms():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    to_phone = (data.get("to") or "").strip()
    body = (data.get("body") or "").strip()
    from_teammate = (data.get("from_teammate") or "").strip()

    if not to_phone or not body:
        return jsonify({"ok": False, "error": "Missing to or body"}), 400

    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    ok_send, err = _crm_try_send_sms(uname, to_phone, body)
    if not ok_send:
        return jsonify({"ok": False, "error": err or "SMS send failed"}), 400

    try:
        _crm_log_message(uname, {"type": "single_sms", "to": to_phone, "from_teammate": from_teammate, "sent": 1, "failed": 0})
    except Exception:
        pass

    return jsonify({"ok": True, "provider": "twilio"})



# =========================
# GMAIL OAUTH ROUTES (Option C)
# =========================

@app.get("/api/gmail/status")
def api_gmail_status():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    connected = bool(_user_gmail_oauth(u))
    return jsonify({"ok": True, "connected": connected})

@app.post("/api/gmail/disconnect")
def api_gmail_disconnect():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    _save_user_gmail_oauth(u, None)
    append_log("gmail_disconnected", {"user": u.get("username", ""), "at": now_iso()})
    return jsonify({"ok": True})


@app.get("/gmail/connect")
def gmail_connect():
    u = current_user()
    if not u:
        return redirect("/login")
    ok, reason = _google_oauth_ready()
    if not ok:
        return make_response(f"Gmail OAuth not ready: {reason}", 400)

    state = secrets.token_urlsafe(24)
    session["gmail_oauth_states_single"] = state
    _push_oauth_state("gmail_oauth_states", state)
    auth_url = _oauth_auth_url(GMAIL_SCOPES, "/gmail/callback", state)
    return redirect(auth_url)


@app.get("/gmail/callback")
def gmail_callback():
    u = current_user()
    if not u:
        return redirect("/login")
    ok, reason = _google_oauth_ready()
    if not ok:
        return make_response(f"Gmail OAuth not ready: {reason}", 400)

    state = request.args.get("state", "")
    if not _oauth_state_matches("gmail_oauth_states", state):
        return make_response("OAuth state mismatch. Please retry Gmail connect.", 400)
    code = request.args.get("code", "")
    if not code:
        return make_response("Missing authorization code from Google.", 400)

    token_info, err = _oauth_exchange_code(code, "/gmail/callback")
    if not token_info:
        append_log("gmail_connect_error", {"user": u.get("username", ""), "error": err, "at": now_iso()})
        return make_response(f"Failed to connect Gmail: {err}", 400)

    # Keep refresh_token if Google didn't re-send it
    old = _user_gmail_oauth(u) or {}
    if old.get("refresh_token") and not token_info.get("refresh_token"):
        token_info["refresh_token"] = old.get("refresh_token")

    _save_user_gmail_oauth(u, token_info)
    append_log("gmail_connected", {"user": u.get("username", ""), "at": now_iso()})
    # onboarding_gmail_connected: mark Gmail step after successful connect
    try:
        uname = (u.get("username") if isinstance(u, dict) else None) or _get_session_username()
        _mark_onboarding_step(uname, "gmail_connected", True)
    except Exception:
        pass


    return redirect("/#settings")



# =========================
# GOOGLE CALENDAR OAUTH ROUTES
# =========================

@app.get("/api/calendar/status")
def api_calendar_status():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    connected = bool(_user_calendar_oauth(u))
    return jsonify({"ok": True, "connected": connected})

@app.post("/api/calendar/disconnect")
def api_calendar_disconnect():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    _save_user_calendar_oauth(u, None)
    append_log("calendar_disconnected", {"user": u.get("username", ""), "at": now_iso()})
    return jsonify({"ok": True})


@app.get("/calendar/connect")
def calendar_connect():
    u = current_user()
    if not u:
        return redirect("/login")
    ok, reason = _google_oauth_ready()
    if not ok:
        return make_response(f"Google Calendar OAuth not ready: {reason}", 400)

    state = secrets.token_urlsafe(24)
    session["calendar_oauth_state"] = state
    auth_url = _oauth_auth_url(CALENDAR_SCOPES, "/calendar/callback", state)
    return redirect(auth_url)


@app.get("/calendar/callback")
def calendar_callback():
    u = current_user()
    if not u:
        return redirect("/login")
    ok, reason = _google_oauth_ready()
    if not ok:
        return make_response(f"Google Calendar OAuth not ready: {reason}", 400)

    state = request.args.get("state", "")
    expected = session.get("calendar_oauth_state", "")
    if not state or not expected or state != expected:
        return make_response("OAuth state mismatch. Please retry Google Calendar connect.", 400)

    code = request.args.get("code", "")
    if not code:
        return make_response("Missing authorization code from Google.", 400)

    token_info, err = _oauth_exchange_code(code, "/calendar/callback")
    if not token_info:
        append_log("calendar_connect_error", {"user": u.get("username", ""), "error": err, "at": now_iso()})
        return make_response(f"Failed to connect Google Calendar: {err}", 400)

    old = _user_calendar_oauth(u) or {}
    if old.get("refresh_token") and not token_info.get("refresh_token"):
        token_info["refresh_token"] = old.get("refresh_token")

    _save_user_calendar_oauth(u, token_info)
    append_log("calendar_connected", {"user": u.get("username", ""), "at": now_iso()})
    return redirect("/#settings")

@app.post("/api/calendar/create_event")
def api_calendar_create_event():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    access_token, reason = _calendar_creds_for_user(u)
    if not access_token:
        return jsonify({"ok": False, "error": reason}), 400
    payload = request.get_json(force=True, silent=True) or {}
    title = (payload.get("title") or payload.get("summary") or "Call").strip()
    start = (payload.get("start") or "").strip()
    end = (payload.get("end") or "").strip()
    timezone = (payload.get("timezone") or "America/New_York").strip()
    attendees = payload.get("attendees") or []
    if isinstance(attendees, str):
        attendees = [a.strip() for a in attendees.split(',') if a.strip()]
    description = (payload.get("description") or "").strip()
    location = (payload.get("location") or "").strip()
    use_meet = bool(payload.get("use_meet"))

    if not start or not end:
        return jsonify({"ok": False, "error": "Missing start/end. Provide ISO datetime strings."}), 400
    try:
        created = _calendar_create_event(access_token, title=title, start_iso=start, end_iso=end, timezone=timezone, attendees=attendees, description=description, location=location, use_meet=use_meet)
        append_log("calendar_event_created", {"user": u.get("username", ""), "title": title, "start": start, "end": end, "at": now_iso()})
        return jsonify({"ok": True, "event": created})
    except Exception as e:
        append_log("calendar_event_error", {"user": u.get("username", ""), "error": str(e), "at": now_iso()})
        return jsonify({"ok": False, "error": str(e)}), 500
@app.post("/api/calendar/move_event")
def api_calendar_move_event():
    """Move an existing Google Calendar event to a new time/date without creating a duplicate."""
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    access_token, reason = _calendar_creds_for_user(u)
    if not access_token:
        return jsonify({"ok": False, "error": reason}), 400
    payload = request.get_json(force=True, silent=True) or {}
    event_id = (payload.get("event_id") or "").strip()
    start     = (payload.get("start") or "").strip()
    end       = (payload.get("end")   or "").strip()
    timezone  = (payload.get("timezone") or "America/New_York").strip()
    send_upd  = "all" if payload.get("resend") else "none"
    if not event_id or not start or not end:
        return jsonify({"ok": False, "error": "Missing event_id, start, or end"}), 400
    try:
        updated = _calendar_move_event(access_token, event_id=event_id,
                                       new_start_iso=start, new_end_iso=end,
                                       timezone=timezone, send_updates=send_upd)
        append_log("calendar_event_moved", {"user": u.get("username",""), "event_id": event_id,
                                             "start": start, "at": now_iso()})
        return jsonify({"ok": True, "event": updated})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.get("/api/calendar/events")
def api_calendar_events():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    access_token, reason = _calendar_creds_for_user(u)
    if not access_token:
        return jsonify({"ok": False, "error": reason}), 400

    time_min = (request.args.get("time_min") or "").strip()
    time_max = (request.args.get("time_max") or "").strip()
    timezone = (request.args.get("timezone") or "America/New_York").strip()
    max_results = int((request.args.get("max_results") or "250").strip() or "250")
    max_results = max(1, min(max_results, 1200))

    if not time_min or not time_max:
        return jsonify({"ok": False, "error": "Missing time_min/time_max"}), 400
    try:
        events = _calendar_list_events(access_token, time_min=time_min, time_max=time_max, timezone=timezone, max_results=max_results)
        return jsonify({"ok": True, "events": events})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# =========================
# LOCAL CALENDAR TASKS (stored per-user in DATA)
# =========================

def _cal_tasks_path(username: str) -> Path:
    return DATA / f"cal_tasks_{username}.json"

def _load_cal_tasks(username: str) -> List[Dict[str, Any]]:
    p = _cal_tasks_path(username)
    try:
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        pass
    return []

def _save_cal_tasks(username: str, tasks: List[Dict[str, Any]]) -> None:
    p = _cal_tasks_path(username)
    p.write_text(json.dumps(tasks, ensure_ascii=False), encoding="utf-8")

@app.get("/api/cal/tasks")
def api_cal_tasks_get():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    tasks = _load_cal_tasks(u.get("username", ""))
    return jsonify({"ok": True, "tasks": tasks})

@app.post("/api/cal/tasks")
def api_cal_tasks_create():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    payload = request.get_json(force=True, silent=True) or {}
    task: Dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "title": (payload.get("title") or "Untitled task").strip(),
        "date": (payload.get("date") or "").strip(),
        "start": (payload.get("start") or "09:00").strip(),
        "duration": int(payload.get("duration") or 30),
        "priority": (payload.get("priority") or "medium").strip(),
        "description": (payload.get("description") or "").strip(),
        "recurring": (payload.get("recurring") or "none").strip(),
        "on_complete_teammate": (payload.get("on_complete_teammate") or "").strip(),
        "on_complete_client_email": (payload.get("on_complete_client_email") or "").strip(),
        "done": False,
        "completed_at": None,
        "created_at": now_iso(),
    }
    tasks = _load_cal_tasks(u.get("username", ""))
    tasks.append(task)
    _save_cal_tasks(u.get("username", ""), tasks)
    return jsonify({"ok": True, "task": task})

@app.post("/api/cal/tasks/<task_id>")
def api_cal_tasks_update(task_id: str):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    payload = request.get_json(force=True, silent=True) or {}
    tasks = _load_cal_tasks(u.get("username", ""))
    for t in tasks:
        if t.get("id") == task_id:
            for field in ("title", "date", "start", "priority", "description", "recurring", "on_complete_teammate", "on_complete_client_email"):
                if field in payload:
                    t[field] = (payload[field] or "").strip()
            if "duration" in payload:
                t["duration"] = int(payload["duration"] or 30)
            if "done" in payload:
                was_done = t.get("done", False)
                t["done"] = bool(payload["done"])
                if t["done"] and not was_done:
                    t["completed_at"] = now_iso()
                elif not t["done"]:
                    t["completed_at"] = None
            _save_cal_tasks(u.get("username", ""), tasks)
            return jsonify({"ok": True, "task": t})
    return jsonify({"ok": False, "error": "Task not found"}), 404


@app.post("/api/cal/tasks/<task_id>/complete_action")
def api_cal_task_complete_action(task_id: str):
    """When a task is marked done, use the assigned teammate to draft and send a completion email to the client."""
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401

    tasks = _load_cal_tasks(u.get("username", ""))
    task = next((t for t in tasks if t.get("id") == task_id), None)
    if not task:
        return jsonify({"ok": False, "error": "Task not found"}), 404

    teammate_name = (task.get("on_complete_teammate") or "").strip()
    client_email  = (task.get("on_complete_client_email") or "").strip()
    if not teammate_name or not client_email:
        return jsonify({"ok": False, "error": "No teammate or client email configured on this task"}), 400

    reg = load_registry()
    defn = (reg.get("installed") or {}).get(teammate_name)
    if not defn:
        return jsonify({"ok": False, "error": f"Teammate '{teammate_name}' not found"}), 404

    # Build prompt for the teammate to draft a completion email
    task_title = task.get("title","Untitled task")
    task_desc  = task.get("description","")
    task_date  = task.get("date","")
    prompt = (
        f"The task '{task_title}' has just been marked complete"
        + (f" (scheduled {task_date})" if task_date else "")
        + ". "
        + (f"Task notes: {task_desc}. " if task_desc else "")
        + f"Please draft a professional, warm, concise email to the client at {client_email} "
        + "letting them know this task is complete. Include a subject line on the first line in the format 'Subject: ...' "
        + "followed by the email body. Keep it brief and friendly."
    )

    try:
        oai = _get_openai_client_for_username(u.get("username",""))
        sys_prompt = teammate_system_prompt(defn)
        resp = oai.chat.completions.create(
            model=(defn.get("preferred_model") or MODEL),
            messages=[
                {"role": "system", "content": sys_prompt},
                {"role": "user",   "content": prompt},
            ],
            temperature=0.65,
            max_tokens=600,
            timeout=45,
        )
        raw = (resp.choices[0].message.content or "").strip()
    except Exception as e:
        return jsonify({"ok": False, "error": f"Teammate AI error: {e}"}), 500

    # Parse subject + body
    lines = raw.splitlines()
    subject = f"Task Complete: {task_title}"
    body_lines = []
    found_subject = False
    for ln in lines:
        if not found_subject and ln.lower().startswith("subject:"):
            subject = ln[8:].strip()
            found_subject = True
        else:
            body_lines.append(ln)
    body = "\n".join(body_lines).strip()
    if not body:
        body = raw

    # Send the email
    cap = _email_capability_for_user(u)
    try:
        if cap.get("gmail_connected"):
            access_token, reason = _gmail_creds_for_user(u)
            if not access_token:
                return jsonify({"ok": False, "error": f"Gmail not ready: {reason}", "draft_subject": subject, "draft_body": body}), 400
            smtp_s = _user_smtp_settings(u)
            _gmail_send_message(access_token, to_addr=client_email, subject=subject, body=body, from_name=smtp_s.get("from_name",""))
            provider = "gmail_oauth"
        else:
            ready, reason = smtp_ready_for_user(u)
            if not ready:
                return jsonify({"ok": False, "error": reason, "draft_subject": subject, "draft_body": body}), 400
            s = _user_smtp_settings(u)
            send_email_smtp_with_creds(to_addr=client_email, subject=subject, body=body,
                host=s["host"], port=s["port"],
                user=s["user"] or SMTP_USER, password=s["pass"] or SMTP_PASS,
                from_name=s["from_name"])
            provider = "smtp"
    except Exception as e:
        return jsonify({"ok": False, "error": f"Email send failed: {e}", "draft_subject": subject, "draft_body": body}), 500

    append_log("task_complete_email_sent", {
        "task_id": task_id, "task_title": task_title,
        "teammate": teammate_name, "to": client_email,
        "provider": provider, "at": now_iso()
    })
    return jsonify({"ok": True, "subject": subject, "body": body, "provider": provider})

@app.delete("/api/cal/tasks/<task_id>")
def api_cal_tasks_delete(task_id: str):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    tasks = _load_cal_tasks(u.get("username", ""))
    tasks = [t for t in tasks if t.get("id") != task_id]
    _save_cal_tasks(u.get("username", ""), tasks)
    return jsonify({"ok": True})

# =========================
# AUTH ROUTES
# =========================

AUTH_BASE_CSS = r"""
<style>
  :root{ --text:#e6edff; --muted:#b8c4ffcc; --gold:#f7d36a; --gold2:#d7a93a; --blue:#3b82f6; --purple:#7c3aed; }
  *{box-sizing:border-box}
  body{
    margin:0;
    font-family: Arial, sans-serif;
    background:
      radial-gradient(1200px 820px at 50% 22%, rgba(247,211,106,.18), transparent 56%),
      radial-gradient(1200px 900px at 50% 38%, rgba(124,58,237,.28), transparent 58%),
      radial-gradient(1000px 760px at 50% 46%, rgba(59,130,246,.16), transparent 56%),
      linear-gradient(180deg, #090d19 0%, #0a1022 38%, #0b1226 100%);
    color:var(--text);
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    padding: 28px 18px;
  }
  .card{
    width: min(680px, calc(100vw - 36px));
    min-height: auto;
    max-width: calc(100vw - 36px);
    background:
      linear-gradient(180deg, rgba(19,28,59,.94), rgba(10,15,33,.96)),
      radial-gradient(900px 520px at 50% 0%, rgba(124,58,237,.14), transparent 62%);
    border:1px solid rgba(76,92,148,.72);
    border-radius: 26px;
    padding: 34px 34px 30px;
    box-shadow: 0 24px 90px rgba(0,0,0,.58), 0 0 34px rgba(124,58,237,.12);
    backdrop-filter: blur(14px);
    position: relative;
    overflow: hidden;
  }
  .card::before{
    content:"";
    position:absolute;
    inset:0;
    padding:2px;
    border-radius:26px;
    background: linear-gradient(135deg, rgba(247,211,106,.95), rgba(226,181,73,.65) 26%, rgba(124,58,237,.78) 58%, rgba(59,130,246,.52) 100%);
    -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
    -webkit-mask-composite: xor;
    mask-composite: exclude;
    pointer-events:none;
  }
  .card::after{
    content:"";
    position:absolute;
    inset:16px;
    border-radius:20px;
    border:1px solid rgba(247,211,106,.12);
    pointer-events:none;
    box-shadow: inset 0 0 24px rgba(247,211,106,.04);
  }
  .brand{ display:flex; gap:12px; align-items:center; font-weight:800; letter-spacing:.2px; margin-bottom: 14px; font-size: 28px; }
  .dot{
    width:16px;height:16px;border-radius:999px;
    background: radial-gradient(circle at 30% 30%, #fff, #c4b5fd 28%, #7c3aed 72%);
    box-shadow: 0 0 18px rgba(124,58,237,.62), 0 0 28px rgba(247,211,106,.18);
    flex: 0 0 auto;
  }
  .muted{ color: var(--muted); font-size: 15px; line-height: 1.5; }
  label{ display:block; font-size: 14px; color: #d8defd; margin: 14px 0 8px 0; font-weight: 800; letter-spacing:.2px; }
  input{
    width:100%;
    border-radius: 16px;
    border:1px solid rgba(82,98,156,.92);
    background: rgba(12,18,38,.94);
    color: var(--text);
    padding:16px 18px;
    outline:none;
    font-size:16px;
    line-height:1.4;
    min-height: 54px;
    box-shadow: inset 0 0 0 1px rgba(247,211,106,.04);
  }
  input:focus{ border-color: rgba(167,139,250,.85); box-shadow: 0 0 0 3px rgba(124,58,237,.18), 0 0 18px rgba(124,58,237,.14); outline:none; }
  .row{ display:flex; gap:14px; align-items:center; justify-content:space-between; margin-top: 18px; flex-wrap:wrap; }
  .btn{
    border:1px solid rgba(82,98,156,.9);
    background: rgba(11,16,36,.92);
    color:var(--text);
    padding:14px 18px;
    border-radius:16px;
    cursor:pointer;
    font-size:16px;
    font-weight:700;
    min-height: 52px;
  }
  .btn:hover{ background: rgba(20,28,60,.96); }
  .card form{ max-width: 640px; }
  .btnPrimary{
    border:1px solid rgba(247,211,106,.72);
    background: linear-gradient(180deg, rgba(124,58,237,.46), rgba(59,130,246,.18));
    box-shadow: 0 0 24px rgba(124,58,237,.22), 0 0 24px rgba(247,211,106,.16), inset 0 0 0 1px rgba(247,211,106,.22);
  }
  a{ color: #ddd6fe; text-decoration:none; font-size: 15px; }
  a:hover{ text-decoration: underline; }
  .err{ margin-top: 14px; color: #ffb4b4; font-size: 14px; white-space: pre-wrap; }
  .ok{ margin-top: 14px; color: #9effc2; font-size: 14px; white-space: pre-wrap; }

    /* ===== NEW: Coach marks (first-run guidance) ===== */
    .coachGlow{
      position: relative;
      z-index: 90;
      border-color: rgba(124,58,237,.95) !important;
      box-shadow: 0 0 0 3px rgba(124,58,237,.22), 0 0 26px rgba(59,130,246,.22);
      animation: coachPulse 1.8s ease-in-out infinite;
    }
    @keyframes coachPulse{
      0%{ box-shadow: 0 0 0 3px rgba(124,58,237,.18), 0 0 18px rgba(59,130,246,.16); }
      50%{ box-shadow: 0 0 0 4px rgba(124,58,237,.26), 0 0 30px rgba(59,130,246,.22); }
      100%{ box-shadow: 0 0 0 3px rgba(124,58,237,.18), 0 0 18px rgba(59,130,246,.16); }
    }
    .coachBubble{
      position: fixed;
      z-index: 140;
      width: min(360px, calc(100vw - 24px));
      background: rgba(10,14,30,.94);
      border:1px solid rgba(42,58,106,.8);
      border-radius:16px;
      padding:12px 12px 10px 12px;
      box-shadow: 0 10px 40px rgba(0,0,0,.45), 0 0 24px rgba(124,58,237,.12);
      backdrop-filter: blur(10px);
    }
    .coachTitle{ font-weight: 800; font-size: 13px; margin-bottom: 6px; }
    .coachBody{ font-size: 12px; color: var(--muted); line-height: 1.4; }
    .coachActions{ display:flex; gap:8px; justify-content:flex-end; margin-top:10px; }

  /* Mobile responsiveness */
@media (max-width: 640px){
  body{ overflow-x:hidden; padding: 16px 10px; }
  .container{ padding: 12px; padding-bottom: 40px; }
  .row{ flex-wrap: wrap; gap: 10px; }
  .btn, .seatToolBtn{ padding: 12px 14px; border-radius: 14px; }
  .seatToolBtn{ font-size: 13px; }
  .actions{ flex-wrap: wrap; }
  .grid{ grid-template-columns: 1fr !important; gap: 10px; }
  #modalWin{ width: calc(100vw - 16px) !important; left: 8px !important; right: 8px !important; top: 8px !important; height: calc(100vh - 16px) !important; max-height: calc(100vh - 16px) !important; }
  #modalScroll{ max-height: calc(100vh - 120px) !important; }
  .seatTools{ flex-wrap: wrap; gap: 8px; }
  .seat{ min-width: 160px; }
  textarea, input, select{ font-size: 16px; } /* prevents iOS zoom */
  .card{ width: calc(100vw - 18px) !important; min-height: auto !important; padding: 22px 18px !important; border-radius: 20px !important; }
  .brand{ font-size: 22px !important; }
  .muted{ font-size: 14px !important; }
}


/* UI polish */
.seat{ box-shadow: 0 10px 24px rgba(0,0,0,.25); }
.modalWin{ box-shadow: 0 18px 50px rgba(0,0,0,.45); }
.btnPrimary{ filter: saturate(1.05); }
.pill{ max-width: 100%; overflow:hidden; text-overflow: ellipsis; }


/* ===== FINAL: Mobile Layout Lock v2 (no clipping, true centering, horizontal pan allowed) ===== */
@media (max-width: 640px){
  /* Allow horizontal pan if anything still overflows */
  html, body{ overflow-x: auto !important; }
  .container{ overflow-x: auto !important; }

  /* Force the round table region to behave like a centered block */
  .tableWrap{
    width: 100% !important;
    max-width: 100% !important;
    height: auto !important;
    min-height: unset !important;
    margin-left: auto !important;
    margin-right: auto !important;
    display: flex !important;
    justify-content: center !important;
    overflow-x: auto !important;
    overflow-y: visible !important;
    -webkit-overflow-scrolling: touch;
  }

  /* Lock the table itself: no absolute centering math on mobile */
  .table{
    position: relative !important;
    inset: auto !important;
    left: auto !important;
    top: auto !important;
    margin-left: auto !important;
    margin-right: auto !important;

    width: min(92vw, 520px) !important;
    max-width: min(92vw, 520px) !important;
    height: auto !important;
    aspect-ratio: 1 / 1;

    /* Zoom + nudge, without translate(-50%,-50%) */
    transform: translateX(var(--tableShiftX)) scale(var(--tableScale)) !important;
    transform-origin: center center !important;
  }
}


/* ===== NEW: Mobile Round Table Viewport Lock v3 (no clipping, true center, pinch zoom enabled) ===== */
@media (max-width: 700px){
  /* Create a dedicated viewport for the round table that can pan if needed */
  #tableViewport{
    width: 100% !important;
    max-width: 100% !important;
    overflow-x: auto !important;
    overflow-y: visible !important;
    -webkit-overflow-scrolling: touch;
    display: flex !important;
    justify-content: center !important;
    align-items: flex-start !important;
    padding-left: max(8px, env(safe-area-inset-left)) !important;
    padding-right: max(8px, env(safe-area-inset-right)) !important;
    box-sizing: border-box !important;
    scroll-snap-type: x mandatory;
  }
  #tableViewport::-webkit-scrollbar{ display:none; }

  /* Force the table to behave like a normal centered block on mobile */
  .table{
    position: relative !important;
    inset: auto !important;
    left: auto !important;
    top: auto !important;
    margin: 0 auto !important;
    transform: translateX(var(--tableShiftX, 0px)) !important; /* no centering math here */
    transform-origin: center top !important;
    zoom: var(--tableZoom, 0.72) !important; /* zoom affects layout, so centering + scrolling works */
    scroll-snap-align: center;
  }

  /* If any earlier rules hid horizontal overflow, undo it (user asked to pan if needed) */
  html, body{ overflow-x: auto !important; }
}


/* ===== ADDITIVE UPGRADE: Mobile Round Table Stage v4 (true center, no cut-off, seats visible, pinch zoom) ===== */
@media (max-width: 700px){
  /* Keep the tableWrap square on mobile (prevents half-table cut-off from height:auto overrides) */
  .tableWrap#tableWrap{
    width: min(96vw, 620px) !important;
    height: min(96vw, 620px) !important;
    min-height: min(96vw, 620px) !important;
    margin-left: auto !important;
    margin-right: auto !important;
    overflow: hidden !important;
    position: relative !important;
    touch-action: none !important; /* required for custom pinch/pan */
  }

  /* Stage that pans/zooms the table + seats */
  #rtStage{
    position:absolute !important;
    inset:0 !important;
    transform-origin: 0 0 !important;
    will-change: transform;
  }

  /* Preserve original desktop-style table centering on mobile */
  #rtStage .table{
    position:absolute !important;
    inset: 50% 50% !important;
    transform: translate(-50%,-50%) !important;
  }

  /* Prevent text clipping inside seat cards */
  .seatMeta{ min-width: 0 !important; }
  .seatName, .seatRole{
    max-width: 100% !important;
    overflow: hidden !important;
    text-overflow: ellipsis !important;
    white-space: nowrap !important;
  }
}
</style>
"""

LOGIN_HTML = r"""
<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=5,user-scalable=yes"/>
<title>{{app_title}} | Login</title>
""" + AUTH_BASE_CSS + r"""

/* ===== MOBILE FIT FIX v2: stop right-lean / clipped controls ===== */
<style>
@media (max-width: 900px){
  html, body{
    width:100% !important;
    max-width:100% !important;
    overflow-x:hidden !important;
  }

  *, *::before, *::after{
    box-sizing:border-box !important;
  }

  .container,
  .stage,
  .arena,
  .underTable,
  .side,
  .sideCard,
  .groupCard{
    width:100% !important;
    max-width:100% !important;
  }

  .stage{
    display:flex !important;
    flex-direction:column !important;
    align-items:stretch !important;
    min-height:auto !important;
  }

  .arena{
    padding-left:0 !important;
    padding-right:0 !important;
    overflow:visible !important;
  }

  .underTable{
    margin:0 auto 18px auto !important;
    padding-left:0 !important;
    padding-right:0 !important;
  }

  .side{
    position:relative !important;
    top:auto !important;
    height:auto !important;
    overflow:visible !important;
    border-left:none !important;
    padding:0 !important;
    background:transparent !important;
    backdrop-filter:none !important;
  }

  .sideCard,
  .groupCard{
    margin-left:0 !important;
    margin-right:0 !important;
  }

  .sideHead{
    flex-wrap:wrap !important;
    align-items:flex-start !important;
    justify-content:space-between !important;
  }

  .sideTitle{
    min-width:0 !important;
    flex:1 1 180px !important;
  }

  .sideHead .btn{
    flex:0 0 auto !important;
    max-width:100% !important;
  }

  .passRow,
  .pillRow{
    width:100% !important;
    max-width:100% !important;
    overflow:visible !important;
  }

  .passRow .btn,
  .pillRow .btn{
    max-width:100% !important;
  }

  textarea, input, select{
    max-width:100% !important;
  }
}

@media (max-width: 700px){
  .container{
    padding-left:12px !important;
    padding-right:12px !important;
    padding-bottom:88px !important;
  }

  .groupCard,
  .sideCard{
    padding:10px !important;
    border-radius:14px !important;
  }

  .sideHead{
    gap:8px !important;
  }

  .sideHead .btn{
    align-self:flex-start !important;
  }

  .h1, #seatTitle{
    max-width:100% !important;
    word-break:break-word !important;
  }

  #refreshThread{
    margin-left:auto !important;
  }

  .tableWrap#tableWrap{
    width:min(94vw, 620px) !important;
    height:min(94vw, 620px) !important;
    min-height:min(94vw, 620px) !important;
  }

  #tableViewport{
    padding-left:0 !important;
    padding-right:0 !important;
    overflow-x:hidden !important;
  }

  .table{
    transform:translateX(0) !important;
    zoom:var(--tableZoom, 0.70) !important;
    margin-left:auto !important;
    margin-right:auto !important;
  }
}

/* ===== MUSHROOM + DRAGONFLY ANIMATION ===== */
.loginScene{
  position:relative;
  width:100%;
  height:160px;
  margin-top:28px;
  overflow:hidden;
  pointer-events:none;
  user-select:none;
}

/* Mushroom grows from bottom center */
@keyframes mushroomGrow{
  0%  { transform: scaleY(0) translateX(-50%); opacity:0; }
  15% { opacity:1; }
  60% { transform: scaleY(1.08) translateX(-50%); }
  75% { transform: scaleY(0.96) translateX(-50%); }
  100%{ transform: scaleY(1)    translateX(-50%); opacity:1; }
}
.mushroomSvg{
  position:absolute;
  bottom:0;
  left:50%;
  transform-origin: bottom center;
  animation: mushroomGrow 1.2s cubic-bezier(.34,1.56,.64,1) 0.3s both;
  width:110px;
  height:130px;
}

/* Dragonfly: fly in from right, land, pause, fly off left */
@keyframes dragonflyFlight{
  0%   { transform: translate(220px, 60px) rotate(-20deg) scaleX(1);  opacity:0; }
  8%   { opacity:1; }
  38%  { transform: translate(0px,   0px) rotate(5deg)  scaleX(1);  opacity:1; }
  55%  { transform: translate(0px,   0px) rotate(0deg)  scaleX(1);  opacity:1; }
  56%  { transform: translate(0px,   0px) rotate(0deg)  scaleX(-1); opacity:1; }
  88%  { transform: translate(-260px, 55px) rotate(15deg) scaleX(-1); opacity:1; }
  95%  { opacity:0.3; }
  100% { transform: translate(-320px, 80px) rotate(15deg) scaleX(-1); opacity:0; }
}
@keyframes wingBeat{
  0%,100%{ transform: scaleY(1);   }
  50%    { transform: scaleY(0.35);}
}
.dragonflySvg{
  position:absolute;
  bottom:92px;
  left:calc(50% + 6px);
  width:54px;
  height:28px;
  transform-origin: center center;
  animation: dragonflyFlight 5.8s ease-in-out 1.2s both;
}
.dfWing{
  animation: wingBeat 0.18s linear infinite;
  transform-origin: center center;
}
/* Pause wing beat during landing phase (38%-55% = ~2.3s-3.2s into 5.8s) */
.dragonflySvg:hover .dfWing{ animation-play-state:paused; }
</style>

</head><body>
  <div class="card">
    <div class="brand"><div class="dot"></div><div>{{app_title}}</div></div>
    <div class="muted">Sign in to your command center.</div>

    <form method="post" action="/login">
      <label>Username</label>
      <input name="username" placeholder="Username" autocomplete="username" required/>
      <label>Password</label>
      <input name="password" type="password" autocomplete="current-password" required/>
      <div class="row">
        <label style="margin:0; display:flex; gap:8px; align-items:center;">
          <input type="checkbox" name="remember" value="1" style="width:auto; margin:0;"> Remember me
        </label>
        <button class="btn btnPrimary" type="submit">Login</button>
      </div>
    </form>

    <div class="row">
      <div class="muted"><a href="/reset">Reset password</a></div>
      {% if allow_signup %}
        <div class="muted"><a href="/register">Create account</a></div>
      {% endif %}
      {% if allow_setup %}
        <div class="muted"><a href="/setup">First time setup</a></div>
      {% endif %}
    </div>

    {% if error %}<div class="err">{{error}}</div>{% endif %}

    <!-- ===== MUSHROOM + DRAGONFLY SCENE ===== -->
    <div class="loginScene" aria-hidden="true">
      <!-- Mushroom SVG -->
      <svg class="mushroomSvg" viewBox="0 0 110 130" xmlns="http://www.w3.org/2000/svg">
        <!-- stem -->
        <rect x="36" y="72" width="38" height="58" rx="10" fill="rgba(230,220,200,0.88)"/>
        <!-- stem shading -->
        <rect x="36" y="72" width="14" height="58" rx="7" fill="rgba(200,185,165,0.45)"/>
        <!-- gill underside -->
        <ellipse cx="55" cy="74" rx="34" ry="10" fill="rgba(220,200,175,0.75)"/>
        <!-- cap -->
        <ellipse cx="55" cy="55" rx="52" ry="32" fill="#c0392b"/>
        <!-- cap highlight gradient dome -->
        <ellipse cx="55" cy="44" rx="44" ry="25" fill="rgba(220,80,60,0.55)"/>
        <!-- white spots -->
        <circle cx="55" cy="38" r="11" fill="rgba(255,255,255,0.88)"/>
        <circle cx="28" cy="52" r="7"  fill="rgba(255,255,255,0.82)"/>
        <circle cx="82" cy="50" r="7"  fill="rgba(255,255,255,0.82)"/>
        <circle cx="43" cy="62" r="4"  fill="rgba(255,255,255,0.72)"/>
        <circle cx="70" cy="60" r="5"  fill="rgba(255,255,255,0.72)"/>
        <!-- shimmer -->
        <ellipse cx="40" cy="38" rx="14" ry="6" fill="rgba(255,255,255,0.18)" transform="rotate(-18 40 38)"/>
        <!-- ground ring -->
        <ellipse cx="55" cy="128" rx="30" ry="5" fill="rgba(100,180,80,0.35)"/>
        <ellipse cx="55" cy="128" rx="22" ry="3.5" fill="rgba(80,160,60,0.25)"/>
      </svg>

      <!-- Dragonfly SVG -->
      <svg class="dragonflySvg" viewBox="0 0 54 28" xmlns="http://www.w3.org/2000/svg">
        <!-- body -->
        <ellipse cx="27" cy="16" rx="13" ry="4" fill="#2d7a4f"/>
        <ellipse cx="27" cy="16" rx="5"  ry="3.5" fill="#1a5c37"/>
        <!-- abdomen segments -->
        <ellipse cx="36" cy="17" rx="4" ry="2.5" fill="#3a9e65"/>
        <ellipse cx="42" cy="18" rx="3" ry="2"   fill="#2d7a4f"/>
        <ellipse cx="47" cy="19" rx="2" ry="1.5" fill="#1a5c37"/>
        <!-- head -->
        <circle cx="18" cy="15" r="4.5" fill="#1a5c37"/>
        <circle cx="16" cy="13" r="1.5" fill="#80ffcc" opacity="0.7"/>
        <circle cx="20" cy="13" r="1.5" fill="#80ffcc" opacity="0.7"/>
        <!-- wings (upper pair) -->
        <g class="dfWing">
          <ellipse cx="27" cy="9"  rx="18" ry="7" fill="rgba(160,220,255,0.55)" stroke="rgba(80,180,220,0.6)" stroke-width="0.5" transform="rotate(-8 27 9)"/>
          <ellipse cx="27" cy="23" rx="16" ry="6" fill="rgba(160,220,255,0.45)" stroke="rgba(80,180,220,0.5)" stroke-width="0.5" transform="rotate(10 27 23)"/>
        </g>
        <!-- wing veins -->
        <line x1="18" y1="9"  x2="44" y2="6"  stroke="rgba(80,180,220,0.4)" stroke-width="0.4"/>
        <line x1="18" y1="23" x2="42" y2="27" stroke="rgba(80,180,220,0.4)" stroke-width="0.4"/>
      </svg>
    </div>
    <!-- ===== END SCENE ===== -->

  </div>
</body></html>
"""


REGISTER_HTML = r"""
<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=5,user-scalable=yes"/>
<title>{{app_title}} | Create Account</title>
""" + AUTH_BASE_CSS + r"""
<style>
/* ===== MUSHROOM + DRAGONFLY ANIMATION (register gate) ===== */
.loginScene{
  position:relative;
  width:100%;
  height:160px;
  margin-top:28px;
  overflow:hidden;
  pointer-events:none;
  user-select:none;
}
@keyframes mushroomGrow{
  0%  { transform: scaleY(0) translateX(-50%); opacity:0; }
  15% { opacity:1; }
  60% { transform: scaleY(1.08) translateX(-50%); }
  75% { transform: scaleY(0.96) translateX(-50%); }
  100%{ transform: scaleY(1)    translateX(-50%); opacity:1; }
}
.mushroomSvg{
  position:absolute;
  bottom:0;
  left:50%;
  transform-origin: bottom center;
  animation: mushroomGrow 1.2s cubic-bezier(.34,1.56,.64,1) 0.3s both;
  width:110px;
  height:130px;
}
@keyframes dragonflyFlight{
  0%   { transform: translate(220px, 60px) rotate(-20deg) scaleX(1);  opacity:0; }
  8%   { opacity:1; }
  38%  { transform: translate(0px,   0px) rotate(5deg)  scaleX(1);  opacity:1; }
  55%  { transform: translate(0px,   0px) rotate(0deg)  scaleX(1);  opacity:1; }
  56%  { transform: translate(0px,   0px) rotate(0deg)  scaleX(-1); opacity:1; }
  88%  { transform: translate(-260px, 55px) rotate(15deg) scaleX(-1); opacity:1; }
  95%  { opacity:0.3; }
  100% { transform: translate(-320px, 80px) rotate(15deg) scaleX(-1); opacity:0; }
}
@keyframes wingBeat{
  0%,100%{ transform: scaleY(1);   }
  50%    { transform: scaleY(0.35);}
}
.dragonflySvg{
  position:absolute;
  bottom:92px;
  left:calc(50% + 6px);
  width:54px;
  height:28px;
  transform-origin: center center;
  animation: dragonflyFlight 5.8s ease-in-out 1.2s both;
}
.dfWing{
  animation: wingBeat 0.18s linear infinite;
  transform-origin: center center;
}
</style>
</head><body>
  <div class="card">
    <div class="brand"><div class="dot"></div><div>{{app_title}}</div></div>
    <div class="muted">Create your account to get started.</div>

    <form method="post" action="/register">
      <label>Username</label>
      <input name="username" placeholder="Choose a username" autocomplete="username" required/>
      <label>Password</label>
      <input name="password" type="password" autocomplete="new-password" required/>
      <label>Confirm password</label>
      <input name="password2" type="password" autocomplete="new-password" required/>
      {% if require_code %}
        <label>Invite code</label>
        <input name="invite_code" autocomplete="one-time-code" required/>
        <div class="tiny">Ask the owner for an invite code.</div>
      {% endif %}
      <div class="row">
        <button class="btn btnPrimary" type="submit">Create account</button>
        <a class="muted" href="/login">Back to login</a>
      </div>
    </form>

    {% if error %}<div class="err">{{error}}</div>{% endif %}
    {% if ok %}<div class="ok">{{ok}}</div>{% endif %}

    <!-- ===== MUSHROOM + DRAGONFLY SCENE ===== -->
    <div class="loginScene" aria-hidden="true">
      <svg class="mushroomSvg" viewBox="0 0 110 130" xmlns="http://www.w3.org/2000/svg">
        <rect x="36" y="72" width="38" height="58" rx="10" fill="rgba(230,220,200,0.88)"/>
        <rect x="36" y="72" width="14" height="58" rx="7" fill="rgba(200,185,165,0.45)"/>
        <ellipse cx="55" cy="74" rx="34" ry="10" fill="rgba(220,200,175,0.75)"/>
        <ellipse cx="55" cy="55" rx="52" ry="32" fill="#c0392b"/>
        <ellipse cx="55" cy="44" rx="44" ry="25" fill="rgba(220,80,60,0.55)"/>
        <circle cx="55" cy="38" r="11" fill="rgba(255,255,255,0.88)"/>
        <circle cx="28" cy="52" r="7"  fill="rgba(255,255,255,0.82)"/>
        <circle cx="82" cy="50" r="7"  fill="rgba(255,255,255,0.82)"/>
        <circle cx="43" cy="62" r="4"  fill="rgba(255,255,255,0.72)"/>
        <circle cx="70" cy="60" r="5"  fill="rgba(255,255,255,0.72)"/>
        <ellipse cx="40" cy="38" rx="14" ry="6" fill="rgba(255,255,255,0.18)" transform="rotate(-18 40 38)"/>
        <ellipse cx="55" cy="128" rx="30" ry="5" fill="rgba(100,180,80,0.35)"/>
        <ellipse cx="55" cy="128" rx="22" ry="3.5" fill="rgba(80,160,60,0.25)"/>
      </svg>
      <svg class="dragonflySvg" viewBox="0 0 54 28" xmlns="http://www.w3.org/2000/svg">
        <ellipse cx="27" cy="16" rx="13" ry="4" fill="#2d7a4f"/>
        <ellipse cx="27" cy="16" rx="5"  ry="3.5" fill="#1a5c37"/>
        <ellipse cx="36" cy="17" rx="4" ry="2.5" fill="#3a9e65"/>
        <ellipse cx="42" cy="18" rx="3" ry="2"   fill="#2d7a4f"/>
        <ellipse cx="47" cy="19" rx="2" ry="1.5" fill="#1a5c37"/>
        <circle cx="18" cy="15" r="4.5" fill="#1a5c37"/>
        <circle cx="16" cy="13" r="1.5" fill="#80ffcc" opacity="0.7"/>
        <circle cx="20" cy="13" r="1.5" fill="#80ffcc" opacity="0.7"/>
        <g class="dfWing">
          <ellipse cx="27" cy="9"  rx="18" ry="7" fill="rgba(160,220,255,0.55)" stroke="rgba(80,180,220,0.6)" stroke-width="0.5" transform="rotate(-8 27 9)"/>
          <ellipse cx="27" cy="23" rx="16" ry="6" fill="rgba(160,220,255,0.45)" stroke="rgba(80,180,220,0.5)" stroke-width="0.5" transform="rotate(10 27 23)"/>
        </g>
        <line x1="18" y1="9"  x2="44" y2="6"  stroke="rgba(80,180,220,0.4)" stroke-width="0.4"/>
        <line x1="18" y1="23" x2="42" y2="27" stroke="rgba(80,180,220,0.4)" stroke-width="0.4"/>
      </svg>
    </div>
    <!-- ===== END SCENE ===== -->

  </div>
</body></html>
"""

SETUP_HTML = r"""
<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=5,user-scalable=yes"/>
<title>{{app_title}} | Setup</title>
""" + AUTH_BASE_CSS + r"""
</head><body>
  <div class="card">
    <div class="brand"><div class="dot"></div><div>{{app_title}}</div></div>
    <div class="muted">Welcome! Create the admin account to get started.</div>

    <form method="post" action="/setup">
      <label>Username</label>
      <input name="username" placeholder="Choose a username" autocomplete="username" required/>
      <label>Password</label>
      <input name="password" type="password" autocomplete="new-password" required/>
      <div class="row">
        <button class="btn btnPrimary" type="submit">Create account</button>
        <a class="muted" href="/login">Back to login</a>
      </div>
    </form>

    {% if error %}<div class="err">{{error}}</div>{% endif %}
  </div>
</body></html>
"""

RESET_HTML = r"""
<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=5,user-scalable=yes"/>
<title>{{app_title}} | Reset Password</title>
""" + AUTH_BASE_CSS + r"""
</head><body>
  <div class="card">
    <div class="brand"><div class="dot"></div><div>{{app_title}}</div></div>
    <div class="muted">Request a reset token, then set a new password.</div>

    <form method="post" action="/reset">
      <label>Username</label>
      <input name="username" autocomplete="username" required/>
      <div class="row">
        <button class="btn btnPrimary" type="submit">Generate reset token</button>
        <a class="muted" href="/login">Back to login</a>
      </div>
    </form>

    {% if token %}<div class="ok">Reset token (copy this): {{token}}</div>{% endif %}
    {% if error %}<div class="err">{{error}}</div>{% endif %}

    <div style="height:14px"></div>

    <form method="post" action="/reset_password">
      <label>Username</label>
      <input name="username" autocomplete="username" required/>
      <label>Reset token</label>
      <input name="token" required/>
      <label>New password</label>
      <input name="new_password" type="password" autocomplete="new-password" required/>
      <div class="row">
        <button class="btn btnPrimary" type="submit">Set new password</button>
      </div>
    </form>

    {% if ok %}<div class="ok">{{ok}}</div>{% endif %}
  </div>
</body></html>
"""

def _make_token() -> str:
    return secrets.token_urlsafe(18)

def _hash_token(token: str) -> str:
    if not token:
        return ""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

@app.get("/setup")
def setup():
    if has_any_user():
        return redirect(url_for("login"))
    return render_template_string(SETUP_HTML, app_title=APP_TITLE, error=None)

@app.post("/setup")
def setup_post():
    if has_any_user():
        return redirect(url_for("login"))
    username = _clean_username(request.form.get("username", ""))
    email = (request.form.get("email") or "").strip()
    password = (request.form.get("password") or "").strip()

    if not username or not password:
        return render_template_string(SETUP_HTML, app_title=APP_TITLE, error="Missing username or password")

    if len(username) < 3:
        return render_template_string(SETUP_HTML, app_title=APP_TITLE, error="Username must be at least 3 characters")
    if len(password) < 8:
        return render_template_string(SETUP_HTML, app_title=APP_TITLE, error="Password must be at least 8 characters")

    data = load_users()
    data["users"][username] = _new_user(username=username, password=password, email=email)
    save_users(data)

    session["user"] = username
    session.permanent = True
    return redirect(url_for("index"))

@app.get("/login")
def login():
    allow_setup = not has_any_user()
    resp = make_response(render_template_string(LOGIN_HTML, app_title=APP_TITLE, error=None, allow_setup=allow_setup, allow_signup=_signup_enabled()))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

@app.post("/login")
def login_post():
    username = _clean_username(request.form.get("username", ""))
    password = (request.form.get("password") or "").strip()
    remember = (request.form.get("remember") or "").strip()

    data = load_users()
    u = (data.get("users") or {}).get(username)
    if not u or not check_password_hash(u.get("password_hash",""), password):
        return render_template_string(LOGIN_HTML, app_title=APP_TITLE, error="Invalid username or password.", allow_setup=(not has_any_user()), allow_signup=_signup_enabled())

    session["user"] = username
    session.permanent = bool(remember)
    # if remember is checked, keep for 30 days
    if remember:
        app.permanent_session_lifetime = timedelta(days=30)

    return redirect(url_for("index"))



# ===== NEW: Account registration (additive) =====
def _signup_enabled() -> bool:
    # Allow signups if explicitly enabled, or if there are no users yet (first run).
    v = (os.getenv("ALLOW_SIGNUP") or "").strip().lower()
    if v in ("1","true","yes","y","on"):
        return True
    if v in ("0","false","no","n","off"):
        return False
    return (not has_any_user())

def _require_invite_code() -> bool:
    v = (os.getenv("REQUIRE_INVITE_CODE") or "").strip().lower()
    return v in ("1","true","yes","y","on")

def _invite_code_value() -> str:
    return (os.getenv("INVITE_CODE") or "").strip()

@app.get("/register")
def register_get():
    allow = _signup_enabled()
    if not allow:
        return redirect(url_for("login"))
    return render_template_string(REGISTER_HTML, app_title=APP_TITLE, error=None, ok=None, require_code=_require_invite_code())

@app.post("/register")
def register_post():
    if not _signup_enabled():
        return render_template_string(LOGIN_HTML, app_title=APP_TITLE, error="Account creation is disabled.", allow_setup=(not has_any_user()), allow_signup=False)
    username = _clean_username(request.form.get("username",""))
    email = (request.form.get("email","") or "").strip()
    pw = (request.form.get("password","") or "").strip()
    pw2 = (request.form.get("password2","") or "").strip()

    if not username or len(username) < 3:
        return render_template_string(REGISTER_HTML, app_title=APP_TITLE, error="Username must be at least 3 characters.", ok=None, require_code=_require_invite_code())
    if len(pw) < 8:
        return render_template_string(REGISTER_HTML, app_title=APP_TITLE, error="Password must be at least 8 characters.", ok=None, require_code=_require_invite_code())
    if pw != pw2:
        return render_template_string(REGISTER_HTML, app_title=APP_TITLE, error="Passwords do not match.", ok=None, require_code=_require_invite_code())

    if _require_invite_code():
        got = (request.form.get("invite_code") or "").strip()
        want = _invite_code_value()
        if not want:
            return render_template_string(REGISTER_HTML, app_title=APP_TITLE, error="Invite code is not configured on the server.", ok=None, require_code=True)
        if got != want:
            return render_template_string(REGISTER_HTML, app_title=APP_TITLE, error="Invalid invite code.", ok=None, require_code=True)

    data = load_users()
    users = data.get("users") or {}
    if username in users:
        return render_template_string(REGISTER_HTML, app_title=APP_TITLE, error="That username is already taken.", ok=None, require_code=_require_invite_code())

    users[username] = _new_user(username, pw, email=email)
    data["users"] = users
    save_users(data)

    session["user"] = username
    session.permanent = True
    return redirect(url_for("index"))
@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.get("/reset")
def reset():
    return render_template_string(RESET_HTML, app_title=APP_TITLE, error=None, token=None, ok=None)

@app.post("/reset")
def reset_post():
    username = _clean_username(request.form.get("username", ""))
    data = load_users()
    u = (data.get("users") or {}).get(username)
    if not u:
        return render_template_string(RESET_HTML, app_title=APP_TITLE, error="Unknown username", token=None, ok=None)

    token = _make_token()
    u.setdefault("reset", {})
    u["reset"]["token_hash"] = _hash_token(token)
    u["reset"]["created_at"] = now_iso()
    u["updated_at"] = now_iso()

    data["users"][username] = u
    save_users(data)

    # Token is shown once on screen (copy it). In production you'd email this.
    return render_template_string(RESET_HTML, app_title=APP_TITLE, error=None, token=token, ok=None)

@app.post("/reset_password")
def reset_password_post():
    username = _clean_username(request.form.get("username", ""))
    token = (request.form.get("token") or "").strip()
    new_password = (request.form.get("new_password") or "").strip()

    if len(new_password) < 8:
        return render_template_string(RESET_HTML, app_title=APP_TITLE, error="New password must be at least 8 characters", token=None, ok=None)

    data = load_users()
    u = (data.get("users") or {}).get(username)
    if not u:
        return render_template_string(RESET_HTML, app_title=APP_TITLE, error="Unknown username", token=None, ok=None)

    th = ((u.get("reset") or {}).get("token_hash")) or ""
    if not th or _hash_token(token) != th:
        return render_template_string(RESET_HTML, app_title=APP_TITLE, error="Invalid reset token", token=None, ok=None)

    u["password_hash"] = generate_password_hash(new_password)
    u["reset"]["token_hash"] = ""
    u["reset"]["created_at"] = None
    u["updated_at"] = now_iso()
    data["users"][username] = u
    save_users(data)

    return render_template_string(RESET_HTML, app_title=APP_TITLE, error=None, token=None, ok="Password updated. You can log in now.")


# =========================
# Operator Profile (shared context)
# =========================

@app.get("/api/operator_profile")
def api_operator_profile_get():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    prof = _load_operator_profile(uname)
    return jsonify({"ok": True, "profile": prof})

@app.post("/api/operator_profile")
def api_operator_profile_set():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(silent=True) or {}
    prof = _load_operator_profile(uname)
    # only update known keys (additive safety)
    for k in ["display_name","business","offers","audience","goals","constraints","tone_rules","notes"]:
        if k in payload:
            prof[k] = (payload.get(k) or "")
    _save_operator_profile(uname, prof)
    # onboarding_operator_profile: mark Operator Profile step when profile is saved with any meaningful content
    try:
        uname = (u.get("username") if isinstance(u, dict) else None) or _get_session_username()
        op = _load_operator_profile(uname) or {}
        meaningful = ["business", "offers", "audience", "goals", "constraints", "tone_rules", "notes"]
        ok = False
        for k in meaningful:
            if (op.get(k) or "").strip():
                ok = True
                break
        if ok:
            _mark_onboarding_step(uname, "operator_profile", True)
    except Exception:
        pass


    return jsonify({"ok": True, "profile": prof})



# =========================
# UI
# =========================

HTML = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=5,user-scalable=yes"/>
  <title>{{app_title}}</title>
  <style>
    :root{ --text:#eef2ff; --muted:#d4dcffee; --surface:#1a2040; --card:#1e2548; --border:rgba(80,110,200,.35); }
    *{box-sizing:border-box}
    html, body{ height:auto; min-height:100%; overflow-y:auto; }
    body{
      margin:0;
      font-family: Arial, sans-serif;
      background:
        radial-gradient(900px 600px at 50% 30%, rgba(124,58,237,.18), transparent 55%),
        radial-gradient(800px 600px at 70% 60%, rgba(59,130,246,.14), transparent 55%),
        linear-gradient(160deg, #111827 0%, #0f1629 40%, #121c38 100%);
      color:var(--text);
    }

    .topbar{
      position: relative;
      z-index: 20;
      padding: 14px 16px 12px 16px;
      background: linear-gradient(180deg, rgba(20,30,65,.97), rgba(18,26,56,.92));
      border-bottom:1px solid rgba(34,49,90,.8);
      backdrop-filter: blur(10px);
    }
    .topbarMain{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:14px;
      flex-wrap:wrap;
    }
    .brand{ display:flex; gap:10px; align-items:center; font-weight:700; letter-spacing:.2px; }
    .dot{
      width:10px;height:10px;border-radius:999px;
      background: radial-gradient(circle at 30% 30%, #fff, #7c3aed);
      box-shadow: 0 0 14px rgba(124,58,237,.55);
    }
    .rightmeta{ display:flex; gap:10px; align-items:center; font-size:12px; color:var(--muted); flex-wrap:wrap; justify-content:flex-end; }
    .commandHeader{
      margin-top: 14px;
      display:flex;
      flex-direction:column;
      gap:10px;
    }
    .commandRow{
      display:grid;
      grid-template-columns: repeat(4, minmax(160px, 1fr));
      gap:10px;
      align-items:stretch;
    }
    .commandRow.secondary{
      grid-template-columns: repeat(4, minmax(180px, 1fr));
      max-width: 980px;
    }
    .commandRow .btn, .commandRow a.btn{
      width:100%;
      min-height:46px;
      display:flex;
      align-items:center;
      justify-content:center;
      text-align:center;
      white-space:normal;
      line-height:1.2;
      font-size:14px;
      font-weight:700;
    }
    .btn{
      border:1px solid rgba(42,58,106,.9);
      background: rgba(11,16,36,.9);
      color:var(--text);
      padding:10px 12px;
      border-radius:12px;
      cursor:pointer;
      font-size:13px;
    }
    .btn:hover{ background: rgba(20,28,60,.96); }
  .card form{ max-width: 640px; }
    .btnPrimary{
      border:1px solid rgba(124,58,237,.75);
      background: linear-gradient(180deg, rgba(124,58,237,.35), rgba(59,130,246,.12));
      box-shadow: 0 0 24px rgba(124,58,237,.18);
    }
    .btnMini{
      padding:8px 10px;
      font-size:12px;
      border-radius:10px;
    }
    .btnTiny{
      padding:6px 8px;
      font-size:11px;
      border-radius:10px;
    }

    .stage{
      min-height: calc(100vh - 24px);
      display:grid;
      grid-template-columns: minmax(0, 1fr) 500px;
      align-items:start;
    }

    .arena{
      position:relative;
      display:flex;
      align-items:flex-start;
      justify-content:center;
      padding: 18px 0 18px 0;
    }

    .tableWrap{
      position:relative;
      width:min(860px, 92vw);
      height:min(860px, 92vw);
      min-height: 860px;
      margin-bottom: 0;
    }

    .table{
      position:absolute;
      inset: 50% 50%;
      transform: translate(-50%,-50%);
      width: 62%;
      height: 62%;
      border-radius: 999px;
      background:
        radial-gradient(circle at 50% 50%, rgba(124,58,237,.22), rgba(11,16,36,.88) 52%, rgba(7,10,20,.96) 76%);
      border: 1px solid rgba(42,58,106,.85);
      box-shadow:
        0 0 0 1px rgba(17,24,39,.35) inset,
        0 0 70px rgba(124,58,237,.18);
      overflow:hidden;
    }
    .table:before{
      content:"";
      position:absolute;
      inset:14%;
      border-radius:999px;
      border: 1px dashed rgba(124,58,237,.35);
      opacity:.8;
    }
    .runes{
      position:absolute;
      inset: 6%;
      border-radius:999px;
      border: 1px solid rgba(124,58,237,.18);
      box-shadow: 0 0 40px rgba(124,58,237,.10) inset;
    }

    .operator{
      position:absolute;
      left:50%; top:50%;
      transform: translate(-50%,-50%);
      width: 44%;
      min-width: 340px;
      max-width: 520px;
      background: rgba(22,34,72,.82);
      border:1px solid rgba(42,58,106,.9);
      border-radius: 18px;
      padding: 12px;
      box-shadow: 0 0 28px rgba(0,0,0,.38);
      backdrop-filter: blur(10px);
      z-index: 20;
    }

    .opHead{
      display:flex; align-items:center; justify-content:space-between; gap:10px;
      margin-bottom:8px;
    }
    .opTitle{ display:flex; flex-direction:column; gap:2px; }
    .opTitle .t1{ font-weight:700; font-size:13px; }
    .opTitle .t2{ font-size:12px; color:var(--muted); }

    .opText{
      width:100%;
      height: 118px;
      resize:none;
      border-radius: 14px;
      border:1px solid rgba(42,58,106,.9);
      background: rgba(11,16,36,.92);
      color: var(--text);
      padding:10px;
      outline:none;
      font-size:13px;
      line-height:1.3;
    }

    .opRow{
      display:flex; gap:10px; margin-top:10px; align-items:center; justify-content:space-between;
    }

    .tablePulseEnergy{
      animation: tablePulseEnergy 1.85s ease-in-out infinite;
      border-color: rgba(124,58,237,.92) !important;
    }
    @keyframes tablePulseEnergy{
      0%{
        box-shadow:
          0 0 0 1px rgba(17,24,39,.35) inset,
          0 0 70px rgba(124,58,237,.18),
          0 0 120px rgba(59,130,246,.10),
          0 0 0 0 rgba(124,58,237,.22);
      }
      55%{
        box-shadow:
          0 0 0 1px rgba(17,24,39,.35) inset,
          0 0 95px rgba(124,58,237,.34),
          0 0 160px rgba(59,130,246,.16),
          0 0 0 26px rgba(124,58,237,0);
      }
      100%{
        box-shadow:
          0 0 0 1px rgba(17,24,39,.35) inset,
          0 0 70px rgba(124,58,237,.18),
          0 0 120px rgba(59,130,246,.10),
          0 0 0 0 rgba(124,58,237,0);
      }
    }

    .tablePulseAll{
      animation: tablePulseAll 1.35s ease-in-out infinite;
      border-color: rgba(255,215,105,.85) !important;
    }
    @keyframes tablePulseAll{
      0%{
        box-shadow:
          0 0 0 1px rgba(17,24,39,.35) inset,
          0 0 88px rgba(124,58,237,.28),
          0 0 150px rgba(255,215,105,.12),
          0 0 0 0 rgba(255,215,105,.18);
      }
      55%{
        box-shadow:
          0 0 0 1px rgba(17,24,39,.35) inset,
          0 0 120px rgba(124,58,237,.40),
          0 0 200px rgba(255,215,105,.18),
          0 0 0 28px rgba(255,215,105,0);
      }
      100%{
        box-shadow:
          0 0 0 1px rgba(17,24,39,.35) inset,
          0 0 88px rgba(124,58,237,.28),
          0 0 150px rgba(255,215,105,.12),
          0 0 0 0 rgba(255,215,105,0);
      }
    }

    
    .seatOperator{
      border-color: rgba(34,211,238,.55) !important;
      box-shadow:
        0 0 0 1px rgba(17,24,39,.35) inset,
        0 0 16px rgba(34,211,238,.24);
    }
    .seatOperatorPulse{
      animation: operatorPulse 2.4s ease-in-out infinite;
      border-color: rgba(34,211,238,.90) !important;
      box-shadow:
        0 0 0 1px rgba(17,24,39,.35) inset,
        0 0 34px rgba(34,211,238,.38),
        0 0 52px rgba(124,58,237,.18);
    }
    @keyframes operatorPulse{
      0%{ transform: translate(-50%,0) scale(1); }
      50%{ transform: translate(-50%,0) scale(1.03); }
      100%{ transform: translate(-50%,0) scale(1); }
    }

.seatPulse{
      animation: seatPulse 1.9s ease-in-out infinite;
      border-color: rgba(124,58,237,.92) !important;
      box-shadow:
        0 0 0 1px rgba(17,24,39,.35) inset,
        0 0 22px rgba(124,58,237,.30),
        0 0 38px rgba(255,215,105,.18);
    }
    @keyframes seatPulse{
      0%{
        box-shadow:
          0 0 0 0 rgba(124,58,237,.25),
          0 0 0 0 rgba(255,215,105,.18);
      }
      55%{
        box-shadow:
          0 0 0 16px rgba(124,58,237,0),
          0 0 0 22px rgba(255,215,105,0);
      }
      100%{
        box-shadow:
          0 0 0 0 rgba(124,58,237,0),
          0 0 0 0 rgba(255,215,105,0);
      }
    }

    .seat{
      position:absolute;
      width: 190px;
      height: 124px;
      background: rgba(14,22,48,.78);
      border: 1px solid rgba(42,58,106,.85);
      border-radius: 16px;
      padding: 10px;
      cursor: grab;
      display:flex;
      gap:10px;
      align-items:flex-start;
      transition: transform .12s ease, border-color .12s ease, background .12s ease;
      backdrop-filter: blur(10px);
      box-shadow: 0 0 22px rgba(0,0,0,.28);
      user-select:none;
      touch-action: manipulation;
      z-index: 12;
    }
    .seat:active{ cursor: grabbing; }
    .seat:hover{
      transform: translateY(-2px);
      border-color: rgba(124,58,237,.55);
      background: rgba(16,26,58,.84);
    }
    .seat.dragging{
      transform: none;
      z-index: 30;
      border-color: rgba(124,58,237,.85);
      box-shadow: 0 0 30px rgba(124,58,237,.22), 0 0 22px rgba(0,0,0,.28);
    }

    .avatar{
      width:44px;height:44px;border-radius:14px;
      display:flex;align-items:center;justify-content:center;
      font-weight:800;
      box-shadow: 0 0 18px rgba(0,0,0,.30);
      border: 1px solid rgba(255,255,255,.08);
      flex: 0 0 auto;
      position:relative;
      pointer-events:none;
    }

    .liveDot{
      position:absolute;
      right:-4px;
      bottom:-4px;
      width:12px;height:12px;border-radius:999px;
      border:1px solid rgba(0,0,0,.35);
      background: rgba(184,196,255,.35);
      box-shadow: 0 0 12px rgba(184,196,255,.22);
      pointer-events:none;
    }
    .liveDot.idle{ background: rgba(184,196,255,.28); }
    .liveDot.thinking{ background: rgba(255,207,112,.55); box-shadow: 0 0 14px rgba(255,207,112,.25); }
    .liveDot.done{ background: rgba(141,255,179,.60); box-shadow: 0 0 14px rgba(141,255,179,.25); }
    .liveDot.waiting{ background: rgba(255,123,123,.55); box-shadow: 0 0 14px rgba(255,123,123,.22); }

    .seatMeta{ display:flex; flex-direction:column; gap:4px; min-width:0; flex: 1 1 auto; pointer-events:none; }
    .seatName{ font-weight:800; font-size:13px; }
    .seatRole{ font-size:12px; color:var(--muted); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
    .seatStatus{ font-size:12px; color:var(--muted); opacity:.95; }

    .seatTools{
      position:absolute;
      bottom:8px;
      right:8px;
      display:flex;
      gap:10px;
      pointer-events:auto;
      z-index: 40;
    }
    .seatToolBtn{
      border:1px solid rgba(42,58,106,.85);
      background: rgba(20,30,60,.65);
      color: var(--text);
      padding: 6px 8px;
      border-radius: 10px;
      font-size: 11px;
      cursor:pointer;
      pointer-events:auto;
    }
    .seatToolBtn:hover{
      background: rgba(22,34,72,.78);
      border-color: rgba(124,58,237,.55);
    }

    .side{
      position: sticky;
      top: 0;
      align-self:start;
      height: 100vh;
      overflow:hidden;
      border-left:1px solid rgba(34,49,90,.8);
      background: linear-gradient(180deg, rgba(14,22,48,.92), rgba(10,14,30,.92));
      backdrop-filter: blur(10px);
      padding: 12px;
      display:flex;
      flex-direction:column;
      gap: 12px;
    }

    .sideCard{
      background: rgba(11,16,36,.92);
      border:1px solid rgba(42,58,106,.9);
      border-radius: 16px;
      padding: 12px;
      box-shadow: 0 0 24px rgba(0,0,0,.24);
      display: flex;
      flex-direction: column;
      height: calc(100vh - 48px);
      overflow: hidden;
    }

    .sideHead{
      display:flex; align-items:center; justify-content:space-between; gap:10px;
      margin-bottom:10px;
    }
    .sideTitle{ display:flex; flex-direction:column; gap:2px; min-width:0; }
    .sideTitle .h1{ font-weight:800; }
    .sideTitle .h2{ font-size:12px; color:var(--muted); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }


    /* ===== REDESIGNED NAV BAR ===== */
    .saNavBar{display:flex;align-items:center;gap:12px;padding:10px 16px;background:rgba(18,26,56,.97);border-bottom:1px solid rgba(80,110,200,.3);flex-wrap:wrap;position:sticky;top:0;z-index:900;backdrop-filter:blur(12px);}
    .saNavLeft{display:flex;gap:6px;align-items:center;flex-shrink:0;}
    .saNavCenter{flex:1;display:flex;flex-direction:column;gap:4px;align-items:center;}
    .saNavRight{flex-shrink:0;}
    .saModelTag{font-size:12px;color:rgba(148,163,184,.6);white-space:nowrap;}
    .saDropWrap{position:relative;}
    .saNavBtn{display:flex;align-items:center;gap:5px;padding:7px 14px;background:rgba(28,40,80,.85);border:1px solid rgba(80,110,200,.45);border-radius:10px;color:rgba(210,220,255,.95);font-size:13px;font-weight:600;cursor:pointer;white-space:nowrap;}
    .saNavBtn:hover{background:rgba(30,40,80,.9);border-color:rgba(124,58,237,.5);}
    .saChevron{font-size:9px;opacity:.7;}
    .saDrop{display:none;position:absolute;top:calc(100% + 6px);left:0;min-width:200px;background:rgba(18,28,60,.99);border:1px solid rgba(80,110,200,.5);border-radius:12px;padding:6px;z-index:9999;box-shadow:0 16px 48px rgba(0,0,0,.6);}
    .saDrop.open{display:block;}
    .saDropItem{display:block;width:100%;text-align:left;padding:9px 12px;background:transparent;border:none;border-radius:8px;color:rgba(226,232,240,.85);font-size:13px;cursor:pointer;}
    .saDropItem:hover{background:rgba(124,58,237,.15);color:#c4b5fd;}


    .saObjectivePill{font-size:12px;color:rgba(148,163,184,.5);padding:2px 0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
    .commandHeader,.commandRow{display:none !important;}
    /* ===== END NAV BAR CSS ===== */

    .thread{
      height: 40vh;
      overflow:auto;
      background: rgba(20,30,60,.65);
      border:1px solid rgba(42,58,106,.6);
      border-radius: 14px;
      padding: 10px;
      font-size: 13px;
      line-height: 1.35;
      white-space: pre-wrap;
    }

    .msg{
      margin-bottom: 10px;
      padding: 10px;
      border-radius: 14px;
      border:1px solid rgba(42,58,106,.55);
      background: rgba(14,22,48,.55);
    }
    .msg.user{ border-color: rgba(59,130,246,.35); background: rgba(59,130,246,.08); }
    .msg.assistant{ border-color: rgba(124,58,237,.35); background: rgba(124,58,237,.08); }
    .msg .who{
      font-size: 11px;
      color: var(--muted);
      margin-bottom: 6px;
      font-weight: 700;
      letter-spacing: .2px;
    }

    .followBox, .field{
      width:100%;
      resize:none;
      border-radius: 14px;
      border:1px solid rgba(42,58,106,.9);
      background: rgba(7,10,20,.75);
      color: var(--text);
      padding:10px;
      outline:none;
      font-size:13px;
      line-height:1.3;
    }
    .followBox{ height: 92px; }

    .underTable{
      width: min(860px, 92vw);
      margin: 0 auto 42px auto;
      padding: 0 0 18px 0;
    }

    .groupCard{
      background: rgba(11,16,36,.92);
      border:1px solid rgba(42,58,106,.9);
      border-radius: 16px;
      padding: 12px;
      box-shadow: 0 0 24px rgba(0,0,0,.24);
      margin-top: 16px;
    }

    .groupReplies{
      max-height: 52vh;
      overflow:auto;
      background: rgba(20,30,60,.65);
      border:1px solid rgba(42,58,106,.6);
      border-radius: 14px;
      padding: 10px;
    }

    .replyItem{
      border:1px solid rgba(42,58,106,.55);
      background: rgba(14,22,48,.55);
      border-radius: 14px;
      padding:10px;
      margin-bottom:10px;
    }
    .replyTop{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:10px;
      margin-bottom:8px;
    }
    .replyName{
      font-weight:800;
      font-size:13px;
    }
    .replyBtns{ display:flex; gap:8px; flex-wrap:wrap; }
    .replyBody{
      white-space: pre-wrap;
      font-size:13px;
      line-height:1.35;
      color: var(--text);
    }

    .row2{
      display:grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
    }

    .tiny{ font-size: 12px; color:var(--muted); }

    .overlay{
      position:fixed; inset:0; display:none;
      align-items:flex-start; justify-content:center;
      padding-top: 68px;
      background: rgba(20,30,60,.65);
      backdrop-filter: blur(8px);
      z-index: 80;
    }
    .overlay.show{ display:flex; }

    .modal{
      position: fixed;
      left: 50%;
      top: 64px;
      transform: translateX(-50%);
      width: 860px;
      max-width: calc(100vw - 22px);
      height: 680px;
      max-height: calc(100vh - 90px);
      background: rgba(14,22,48,.92);
      border: 1px solid rgba(42,58,106,.9);
      border-radius: 18px;
      padding: 12px;
      box-shadow: 0 0 60px rgba(0,0,0,.45);
      display: flex;
      flex-direction: column;
      resize: both;
      overflow: hidden;
      min-width: 560px;
      min-height: 420px;
      z-index: 90;
    }

    .modalBar{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:10px;
      padding: 8px 10px;
      border-radius: 14px;
      border: 1px solid rgba(42,58,106,.7);
      background: rgba(18,28,56,.5);
      cursor: move;
      user-select:none;
    }

    .modalBarTitle{
      font-size: 13px;
      font-weight: 800;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      max-width: 360px;
    }

    .modalBarBtns{
      display:flex;
      gap:8px;
      align-items:center;
      flex-wrap:wrap;
    }

    .modalBodyWrap{
      margin-top: 10px;
      flex: 1 1 auto;
      overflow: auto;
      border-radius: 14px;
      border: 1px solid rgba(42,58,106,.6);
      background: rgba(18,28,56,.5);
      padding: 10px;
    }

    .modal pre{
      margin:0;
      white-space: pre-wrap;
      color: var(--text);
      background: transparent;
      border: 0;
      padding: 0;
      font-size: 13px;
      line-height: 1.35;
    }

    .modalForm{ display:none; background: transparent; border:0; border-radius:0; padding:0; }
    .modalForm .grid{ display:grid; grid-template-columns: 1fr 1fr; gap:10px; }
    .modalForm label{
      display:block;
      font-size: 11px;
      color: var(--muted);
      margin: 0 0 6px 0;
      font-weight: 700;
      letter-spacing: .2px;
    }
    .modalForm input, .modalForm textarea{
      width:100%;
      border-radius: 12px;
      border:1px solid rgba(42,58,106,.9);
      background: rgba(11,16,36,.92);
      color: var(--text);
      padding:10px;
      outline:none;
      font-size:13px;
      line-height:1.3;
    }
    .modalForm textarea{ height: 96px; resize: vertical; }
    .modalForm .actions{ display:flex; gap:10px; flex-wrap:wrap; margin-top:10px; align-items:center; justify-content:flex-end; }

    .imgPreview{
      width:100%;
      border-radius: 14px;
      border:1px solid rgba(42,58,106,.7);
      margin-top: 10px;
      display:none;
    }

    .modal.minimized{ height: auto !important; resize: none !important; overflow: hidden !important; }
    .modal.minimized .modalBodyWrap{ display:none; }
    .modalResizeGrip{
      position:absolute;
      right:10px;
      bottom:10px;
      width:18px;
      height:18px;
      cursor:nwse-resize;
      z-index:3;
      border-radius:8px;
      background:linear-gradient(135deg, rgba(255,255,255,.06), rgba(255,255,255,.18));
      border:1px solid rgba(255,255,255,.14);
      box-shadow: inset 0 0 0 1px rgba(255,255,255,.04);
      touch-action:none;
    }
    .modalResizeGrip::before{
      content:"";
      position:absolute;
      right:3px;
      bottom:3px;
      width:10px;
      height:10px;
      border-right:2px solid rgba(255,255,255,.75);
      border-bottom:2px solid rgba(255,255,255,.75);
      opacity:.9;
    }

    .pillRow{ display:flex; gap:8px; flex-wrap:wrap; margin-top:10px; }

    .passRow{ display:flex; gap:8px; flex-wrap:wrap; margin-top:10px; align-items:center; }
    .passRow .tiny{ margin-left: 2px; }
    .passBtn{ padding:7px 10px; border-radius: 999px; font-weight:800; font-size:12px; }
    .pill{
      display:inline-flex;
      gap:8px;
      align-items:center;
      border:1px solid rgba(42,58,106,.7);
      background: rgba(14,22,48,.45);
      padding:8px 10px;
      border-radius:999px;
      font-size:12px;
      color: var(--text);
    }
    .pill button{
      border:0;
      background: transparent;
      color: var(--muted);
      cursor:pointer;
      font-size:12px;
    }
    .pill button:hover{ color: var(--text); }


    @media (max-width: 1280px){
      .stage{ grid-template-columns: minmax(0,1fr) 340px; }
      .commandRow{ grid-template-columns: repeat(3, minmax(150px, 1fr)); }
      .commandRow.secondary{ grid-template-columns: repeat(2, minmax(180px, 1fr)); max-width:none; }
    }

    @media (max-width: 980px){
      .stage{ grid-template-columns: 1fr; }
      .side{ position:relative; top:0; height:auto; overflow:visible; border-left:0; }
      .tableWrap{ min-height: 860px; }
      .row2{ grid-template-columns: 1fr; }
      .underTable{ width: min(860px, 92vw); }
      .modalForm .grid{ grid-template-columns: 1fr; }
      .modal{ width: calc(100vw - 22px); }
      .modalBarTitle{ max-width: 240px; }
    }
  

    /* Mobile responsiveness */
    @media (max-width: 720px){
      body{ overflow-x:hidden; }
      .topbar{ height:auto; }
      .topbarMain{ gap:10px; }
      .rightmeta{ justify-content:flex-start; }
      .commandRow, .commandRow.secondary{ grid-template-columns: repeat(2, minmax(0, 1fr)); max-width:none; }
      .stage{ grid-template-columns: 1fr !important; }
      .side{ padding: 0 12px 22px 12px; }
      .sideCard{ position: relative; top:auto; max-height:none; }
      .arena{ padding: 12px 0 12px 0; }

      /* Round table becomes a clean vertical list to prevent overlap */
      .tableWrap{
        width: calc(100vw - 24px);
        height: auto !important;
        min-height: 0 !important;
        display:flex;
        flex-direction:column;
        align-items:center;
        gap: 10px;
        padding-bottom: 14px;
      }
      .table{
        position:relative !important;
        inset:auto !important;
        transform:none !important;
        width: min(520px, 100%);
        height: 120px;
        margin: 0 auto 6px auto;
      }
      .seat{
        position:relative !important;
        left:auto !important;
        top:auto !important;
        transform:none !important;
        width: min(520px, 100%) !important;
        max-width: 100% !important;
        height: auto !important;
        min-height: 118px;
        cursor: default;
      }
      .seatTools{ flex-wrap:wrap; gap:8px; }
      .seatToolBtn{ flex: 1 1 auto; }

      /* Prevent any long labels from forcing overlap */
      .pill, .seatRole, .seatStatus{ max-width:100%; overflow:hidden; text-overflow:ellipsis; }


/* Mobile: make modal truly full-screen so it never covers seats awkwardly */
.overlay{ align-items: flex-start; padding-top: 10px; background: rgba(2,6,16,.72); backdrop-filter: blur(6px); }
#modalWin{
  position: fixed !important;
  left: 10px !important;
  right: 10px !important;
  top: 10px !important;
  bottom: 10px !important;
  width: auto !important;
  height: auto !important;
  max-height: none !important;
}
#modalScroll{ max-height: calc(100vh - 170px) !important; }
      /* iOS: prevent zoom on focus */
      textarea, input, select{ font-size: 16px; }
    }


/* ===== NEW: Mobile Vertical UI v2 (additive, safe-area aware) ===== */

/* ===== NEW: Mobile Layout Cleanup v1 (operator on top, teammates below) ===== */

/* ===== NEW: Mobile Fit & Modal Fix v1 (no cutoffs, no drag, full-screen popups) ===== */

/* ===== NEW: Mobile + Desktop Responsive Fit v1 (portrait + landscape, no cutoffs) ===== */

/* ===== NEW: Mobile Centering & Symmetry Fix v1 (true centered, no right-lean) ===== */

/* ===== NEW: Mobile Auto-Center v1 (measured centering to eliminate browser quirks) ===== */

/* ===== NEW: Mobile Table Zoom Controls v1 ===== */
@media (max-width: 640px){
  :root{ --tableScale: 0.68; --tableShiftX: 0px; }
  .table{ transform: translate(-50%,-50%) translateX(var(--tableShiftX)) scale(var(--tableScale)) !important; transform-origin: center top !important; }
  #tableZoomFab{
    position: fixed;
    right: 12px;
    bottom: calc(86px + env(safe-area-inset-bottom));
    z-index: 255;
    display:flex;
    gap:8px;
    align-items:center;
  }
  #tableZoomFab .zbtn{
    border:1px solid rgba(255,255,255,.14);
    box-shadow: 0 0 14px rgba(247,211,106,.10), inset 0 0 0 1px rgba(247,211,106,.14);
    background: rgba(9,14,28,.78);
    color: var(--text);
    padding:10px 12px;
    border-radius: 999px;
    font-weight:800;
    cursor:pointer;
    backdrop-filter: blur(8px);
  }

  /* ===== ADDITIVE: Gold Trim for Controls v1 ===== */
  #tableZoomFab .zbtn{ border-color: rgba(247,211,106,.22); }
  #tableZoomFab .zbtn:hover{ border-color: rgba(247,211,106,.40); }
  #tableZoomFab .zbtn.isLocked{ border-color: rgba(247,211,106,.55); box-shadow: 0 0 18px rgba(247,211,106,.16), inset 0 0 0 1px rgba(247,211,106,.22); }

  #tableZoomFab .zbtn:active{ transform: translateY(1px); }
}

@media (max-width: 640px){
  :root{ --tableShiftX: 0px; --tableScale: 0.68; }
  .table{
    /* allow JS to nudge horizontally to true center */
    transform: translateX(var(--tableShiftX)) scale(var(--tableScale)) !important;
    transform-origin: center top !important;
  }
}
@media (max-width: 900px) and (orientation: landscape){
  :root{ --tableShiftX: 0px; --tableScale: 0.68; }
  .table{ transform: translate(-50%,-50%) translateX(var(--tableShiftX)) scale(var(--tableScale)) !important; transform-origin: center top !important; }
}

@media (max-width: 900px){
  /* Use symmetric inline padding accounting for safe areas */
  .container{
    box-sizing: border-box !important;
    width: 100% !important;
    max-width: 100% !important;
    margin-left: auto !important;
    margin-right: auto !important;
    padding-left: calc(var(--mobile-pad) + env(safe-area-inset-left)) !important;
    padding-right: calc(var(--mobile-pad) + env(safe-area-inset-right)) !important;
  }
  .tableWrap{
    box-sizing: border-box !important;
    width: 100% !important;
    margin-left: auto !important;
    margin-right: auto !important;
  }
}

/* Place diagnostics button bottom-left above the mobile bar to avoid any overlap */
@media (max-width: 640px){
  #diagFab{
    left: 12px !important;
    right: auto !important;
    bottom: calc(86px + env(safe-area-inset-bottom)) !important;
  }
}
@media (max-width: 900px) and (orientation: landscape){
  #diagFab{
    left: 12px !important;
    right: auto !important;
    bottom: calc(86px + env(safe-area-inset-bottom)) !important;
  }
}


/* ===== NEW: Mobile Table Fit Tuning v1 (reduce edge clipping) ===== */
@media (max-width: 640px) and (orientation: portrait){
  .table{
    transform: scale(0.90) !important;
    transform-origin: center top !important;
  }
}

:root{
  --mobile-pad: 12px;
}

/* Safe-area aware page padding */
@media (max-width: 900px){
  .container{
    padding-left: max(var(--mobile-pad), env(safe-area-inset-left)) !important;
    padding-right: max(var(--mobile-pad), env(safe-area-inset-right)) !important;
  }
}

/* Portrait phones: ensure table + seats fit without clipping */
@media (max-width: 640px) and (orientation: portrait){
  .table{
    width: min(calc(100vw - 24px), 520px) !important;
    max-width: min(calc(100vw - 24px), 520px) !important;
    margin-left: auto !important;
    margin-right: auto !important;
    transform: scale(0.94) !important;
    transform-origin: center top !important;
  }
}

/* Landscape phones: side-by-side layout */
@media (max-width: 900px) and (orientation: landscape){
  html, body{ overflow-x:hidden !important; }
  .tableWrap{
    display:flex !important;
    flex-direction: row !important;
    align-items: flex-start !important;
    gap: 12px !important;
  }

  .operator{
    order: 0 !important;
    width: min(420px, 44vw) !important;
    flex: 0 0 auto !important;
  }

  .table{
    order: 1 !important;
    flex: 1 1 auto !important;
    width: min(calc(56vw - 24px), 520px) !important;
    max-width: min(calc(56vw - 24px), 520px) !important;
    transform: scale(0.88) !important;
    transform-origin: center top !important;
    margin: 0 auto !important;
  }

  .container{ padding-bottom: calc(92px + env(safe-area-inset-bottom)) !important; }
}

@media (max-width: 640px){

  /* Prevent sideways drag/scroll and keep everything centered */
  html, body{
    overflow-x: hidden !important;
    overscroll-behavior-x: none;
  }
  body{ touch-action: manipulation; }

  /* Ensure the main content can't exceed viewport width */
  .container, .tableWrap{
    max-width: 100vw !important;
  }
  .tableWrap{
    padding-left: 12px !important;
    padding-right: 12px !important;
  }

  /* Round table always fits within viewport */
  .table{
    width: min(calc(100vw - 24px), 560px) !important;
    max-width: min(calc(100vw - 24px), 560px) !important;
    margin-left: auto !important;
    margin-right: auto !important;
  }

  /* Seats never push layout wider than the screen */
  .seat{
    max-width: calc(100vw - 24px) !important;
  }

  /* Overlays and popups must be fully visible on mobile */
  .overlay{
    padding-top: calc(env(safe-area-inset-top) + 10px) !important;
    padding-left: 10px !important;
    padding-right: 10px !important;
    align-items: flex-start !important;
  }

  /* Generic modal: full-screen, scrollable body, no resize/drag */
  .modal{
    position: fixed !important;
    inset: 0 !important;
    left: 0 !important;
    top: 0 !important;
    transform: none !important;
    width: 100vw !important;
    height: 100vh !important;
    max-width: 100vw !important;
    max-height: 100vh !important;
    border-radius: 0 !important;
    resize: none !important;
    min-width: 0 !important;
    min-height: 0 !important;
  }
  .modalBar{
    cursor: default !important;
  }
  .modalBodyWrap{
    overflow: auto !important;
    -webkit-overflow-scrolling: touch;
  }

  /* If your implementation uses these ids, force full-screen too */
  #modalWin{
    width: 100vw !important;
    height: 100vh !important;
    left: 0 !important;
    right: 0 !important;
    top: 0 !important;
    max-height: 100vh !important;
    border-radius: 0 !important;
  }
  #modalScroll{
    max-height: calc(100vh - 140px) !important;
    overflow: auto !important;
    -webkit-overflow-scrolling: touch;
  }
}

@media (max-width: 640px){
  /* Use normal document flow on mobile so panels never overlap */
  .tableWrap{
    display:flex !important;
    flex-direction: column !important;
    align-items: stretch !important;
    gap: 10px !important;
  }

  /* Move the group prompt console to the top, full width */
  .operator{
    position: relative !important;
    left: auto !important;
    top: auto !important;
    transform: none !important;
    width: 100% !important;
    min-width: 0 !important;
    max-width: none !important;
    margin: 0 !important;
    order: -10 !important;
  }

  /* Keep the table circle visible but non-overlapping */
  .table{
    position: relative !important;
    inset: auto !important;
    transform: none !important;
    width: 100% !important;
    height: auto !important;
    aspect-ratio: 1 / 1;
    max-width: 560px;
    margin: 0 auto !important;
    order: -5 !important;
  }

  /* Ensure any absolutely-positioned children can anchor correctly */
  #tableCore{ position: relative !important; }

  /* Give the prompt textarea breathing room */
  .opText{ min-height: 108px; }

  /* Avoid the bottom mobile bar covering content */
  .container{ padding-bottom: calc(96px + env(safe-area-inset-bottom)) !important; }
}

.mobileBar{ display:none; }
.mobileDrawerOverlay{ display:none; }
.mobileDrawer{
  position:absolute;
  left:10px;
  right:10px;
  bottom: calc(66px + env(safe-area-inset-bottom));
  background: rgba(10,14,30,96);
  border:1px solid rgba(42,58,106,8);
  border-radius:18px;
  box-shadow: 0 18px 60px rgba(0,0,0,55), 0 0 26px rgba(124,58,237,12);
  backdrop-filter: blur(10px);
  overflow:hidden;
}
.mobileDrawerHead{
  display:flex;
  align-items:flex-start;
  justify-content:space-between;
  gap:12px;
  padding:12px 12px 10px 12px;
  border-bottom:1px solid rgba(42,58,106,7);
}
.mobileDrawerTitle{ font-weight:900; font-size: 13px; }
.mobileDrawerSub{ font-size:12px; color: var(--muted); margin-top: 2px; }
.mobileDrawerGrid{
  display:grid;
  grid-template-columns: 1fr 1fr;
  gap:10px;
  padding:12px;
}
.mobileDrawerGrid .btn{ width:100%; justify-content:center; }
.mobileDrawerFoot{
  display:flex;
  gap:10px;
  padding: 0 12px 12px 12px;
}
.mobileDrawerFoot .btn{ flex: 1 1 auto; }

@media (max-width: 720px){
  /* keep top brand, move actions to bottom bar + drawer */
  .rightmeta{ display:none !important; }
  .mobileBar{
    display:flex;
    position:fixed;
    left:0; right:0; bottom:0;
    padding: 10px 12px calc(10px + env(safe-area-inset-bottom));
    background: rgba(7,10,20,86);
    border-top:1px solid rgba(42,58,106,7);
    z-index: 120;
    gap:10px;
    justify-content: space-between;
    backdrop-filter: blur(10px);
  }
  .mobileBar .btn{ flex: 1 1 auto; padding: 10px 10px; }
  body{ padding-bottom: calc(76px + env(safe-area-inset-bottom)); }
  .mobileDrawerOverlay.show{
    display:block;
    position:fixed;
    inset:0;
    background: rgba(2,6,16,62);
    z-index: 130;
  }
}

/* NEW: Diagnostics Panel v1 (additive) */

/* ===== NEW: Mobile Diag Placement v2 (no overlays) ===== */
@media (max-width: 640px){
  #diagFab{ display:none !important; }
}

#diagFab{
  position:fixed;
  right:14px;
  bottom:14px;
  z-index: 260;
  display:flex;
  gap:8px;
  align-items:center;
}
#diagFab button{
  border:1px solid rgba(255,255,255,.14);
  background: rgba(9,14,28,.78);
  color: var(--text);
  padding:10px 12px;
  border-radius: 999px;
  cursor:pointer;
  font-weight:700;
  letter-spacing:.2px;
  backdrop-filter: blur(8px);
}
#diagFab button:active{ transform: translateY(1px); }


/* ===== NEW: Mobile Diagnostics Button Placement v1 (avoid overlap with bottom bar) ===== */
@media (max-width: 640px){
  #diagFab{
    right: 12px !important;
    bottom: calc(86px + env(safe-area-inset-bottom)) !important; /* sits above mobile action bar */
  }
}
@media (max-width: 900px) and (orientation: landscape){
  #diagFab{
    bottom: calc(86px + env(safe-area-inset-bottom)) !important;
  }
}
#diagOverlay{
  display:none;
  position:fixed;
  inset:0;
  z-index: 270;
  background: rgba(2,6,16,.62);
}
#diagOverlay.show{ display:block; }
#diagPanel{
  position:fixed;
  left: 50%;
  transform: translateX(-50%);
  bottom: 14px;
  width: min(980px, calc(100% - 18px));
  max-height: min(72vh, 720px);
  z-index: 280;
  display:none;
  border:1px solid rgba(255,255,255,.12);
  border-radius: 16px;
  overflow:hidden;
  background: rgba(7,10,22,.92);
  backdrop-filter: blur(10px);
  box-shadow: 0 18px 50px rgba(0,0,0,.55);
}
#diagPanel.show{ display:block; }
#diagHeader{
  display:flex;
  align-items:center;
  justify-content:space-between;
  padding:10px 12px;
  gap:10px;
  border-bottom:1px solid rgba(255,255,255,.10);
}
#diagHeader .title{
  font-weight:800;
  font-size: 14px;
  color: var(--text);
  opacity:.95;
}
#diagHeader .actions{
  display:flex;
  gap:8px;
  align-items:center;
}
.diagBtn{
  border:1px solid rgba(255,255,255,.14);
  background: rgba(255,255,255,.06);
  color: var(--text);
  padding:8px 10px;
  border-radius: 10px;
  cursor:pointer;
  font-weight:700;
  font-size:12px;
}
.diagBtn:active{ transform: translateY(1px); }
#diagBody{
  padding: 10px 12px 12px 12px;
}
#diagGrid{
  display:grid;
  grid-template-columns: 1fr 1fr;
  gap:10px;
  margin-bottom:10px;
}
.diagCard{
  border:1px solid rgba(255,255,255,.10);
  border-radius: 14px;
  background: rgba(255,255,255,.04);
  padding:10px;
  min-height: 72px;
}
.diagLabel{ font-size:12px; color: var(--muted); margin-bottom:6px; }
.diagValue{ font-size:13px; color: var(--text); line-height:1.35; word-break:break-word; }
#diagPre{
  border:1px solid rgba(255,255,255,.10);
  border-radius: 14px;
  background: rgba(0,0,0,.25);
  padding:10px;
  color: var(--text);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  font-size: 12px;
  line-height:1.35;
  overflow:auto;
  max-height: 42vh;
  white-space: pre-wrap;
}
@media (max-width: 820px){
  #diagGrid{ grid-template-columns: 1fr; }
  #diagPanel{
    bottom: calc(14px + env(safe-area-inset-bottom));
    width: calc(100% - 18px);
  }
  #diagFab{
    bottom: calc(14px + env(safe-area-inset-bottom));
  }
}


/* === V5: RIGHT-EDGE + BUTTON TRIM FIX (ADDITIVE) === */
/* Stop any tiny horizontal overflow that causes right-side clipping in mobile webviews (Messenger, etc.) */
*, *::before, *::after{ box-sizing:border-box; }
html, body{ max-width:100%; overflow-x:hidden !important; }

/* Ensure primary layout wrappers never exceed viewport width */
.container, .card, .sideCard, .grid, .row{ max-width:100% !important; }

/* Headers with right-side action buttons: prevent "leaning" and text clipping */
.sideHead, .cardHead, .panelHead{ max-width:100%; }
.sideHead{ flex-wrap:wrap; }
.sideHead .btn{ flex: 0 0 auto; white-space:nowrap; max-width:100%; }

/* Common culprit: elements using vw inside padded containers. Prefer 100% on mobile. */
@media (max-width: 640px){
  .card{ width:100% !important; max-width:100% !important; }
  .side{ width:100% !important; max-width:100% !important; }
  #modalWin{ max-width: calc(100% - 16px) !important; }
}

/* Restore + enhance gold trim on console buttons (login gate already has it) */
.btn{
  box-shadow:
    inset 0 0 0 1px rgba(247,211,106,.22),
    0 0 18px rgba(247,211,106,.07);
}
.btnPrimary{
  border-color: rgba(247,211,106,.55) !important;
  box-shadow:
    inset 0 0 0 1px rgba(247,211,106,.36),
    0 0 26px rgba(124,58,237,.16),
    0 0 18px rgba(247,211,106,.10);
}
/* Slightly stronger trim on the bottom mobile bar buttons */
.mobileBar .btn{
  border-color: rgba(247,211,106,.35) !important;
}

/* === Calendar modal (additive, minimal) === */
.calWeekdays{
  display:grid;
  grid-template-columns: repeat(7, 1fr);
  gap:6px;
  margin-bottom:6px;
}
.calWeekdays .calWd{
  font-size:11px;
  color: var(--muted);
  text-align:center;
  padding:6px 0;
  opacity:.9;
}
.calGrid{
  display:grid;
  grid-template-columns: repeat(7, 1fr);
  gap:6px;
}
.calCell{
  border:1px solid rgba(255,255,255,.10);
  border-radius:12px;
  padding:8px;
  background: rgba(0,0,0,.18);
  min-height:72px;
  cursor:pointer;
  position:relative;
  overflow:hidden;
}
.calCell:hover{
  border-color: rgba(247,211,106,.35);
}
.calCell.muted{
  opacity:.45;
}
.calCell.selected{
  border-color: rgba(247,211,106,.65);
  box-shadow: 0 0 18px rgba(247,211,106,.10);
}
.calNum{
  font-weight:800;
  font-size:12px;
}
.calDots{
  margin-top:6px;
  display:flex;
  gap:4px;
  flex-wrap:wrap;
}
.calDot{
  width:6px; height:6px; border-radius:999px;
  background: rgba(59,130,246,.75);
  box-shadow: 0 0 10px rgba(59,130,246,.22);
}


/* ===== FINAL ADDITIVE: Mobile Seat Flow Lock v1 =====
   Goal: the command center prompt box stays first, and teammate cards begin below it.
   This only affects mobile and does not remove any existing features. */
@media (max-width: 720px){
  #tableWrap{
    display: flex !important;
    flex-direction: column !important;
    align-items: stretch !important;
    justify-content: flex-start !important;
    gap: 12px !important;
    height: auto !important;
    min-height: 0 !important;
    padding-bottom: 18px !important;
  }

  #tableWrap > .operator{
    position: relative !important;
    left: auto !important;
    top: auto !important;
    transform: none !important;
    width: 100% !important;
    min-width: 0 !important;
    max-width: none !important;
    margin: 0 0 4px 0 !important;
    order: 1 !important;
    z-index: 6 !important;
  }

  #tableWrap > .table{
    position: relative !important;
    inset: auto !important;
    left: auto !important;
    top: auto !important;
    transform: none !important;
    width: 100% !important;
    max-width: min(560px, 100%) !important;
    height: 92px !important;
    aspect-ratio: auto !important;
    margin: 0 auto !important;
    order: 2 !important;
    overflow: hidden !important;
  }

  #tableWrap > .seat{
    position: relative !important;
    left: auto !important;
    top: auto !important;
    right: auto !important;
    bottom: auto !important;
    transform: none !important;
    width: 100% !important;
    max-width: none !important;
    min-height: 118px !important;
    height: auto !important;
    margin: 0 !important;
    order: 3 !important;
    z-index: 2 !important;
  }

  #tableWrap > .seat:hover,
  #tableWrap > .seat.dragging,
  #tableWrap > .seat:active{
    transform: none !important;
  }

  #tableWrap > .seat .seatTools{
    position: absolute !important;
    right: 8px !important;
    bottom: 8px !important;
  }

  #tableWrap > .operator .opText{
    min-height: 124px !important;
  }
}


/* ===== Full-workspace app windows ===== */
#overlay{ align-items:stretch !important; justify-content:stretch !important; padding:0 !important; }
#modalWin{
  width:100% !important;
  height:100% !important;
  max-width:none !important;
  max-height:none !important;
  inset:0 !important;
  left:0 !important;
  top:0 !important;
  right:0 !important;
  bottom:0 !important;
  transform:none !important;
  border-radius:0 !important;
  resize:none !important;
}
#modalScroll{ height:calc(100vh - 64px) !important; max-height:none !important; }

/* ─────────────────────────────────────────────────────────────
   FONT SIZE OVERRIDES — bumped for readability
   ───────────────────────────────────────────────────────────── */

/* Base body text */
body { font-size: 15px; }

/* Thread / message text */
.thread       { font-size: 15px !important; line-height: 1.6 !important; }
.msg          { padding: 12px 14px !important; }
.msg .who     { font-size: 13px !important; margin-bottom: 8px !important; }
.replyBody    { font-size: 15px !important; line-height: 1.6 !important; }
.replyName    { font-size: 14px !important; }

/* Buttons */
.btn          { font-size: 14px !important; }
.btnMini      { font-size: 13px !important; padding: 8px 11px !important; }
.btnTiny      { font-size: 12px !important; }
.passBtn      { font-size: 13px !important; }

/* Input fields */
.followBox, .field, .opText, textarea, input[type="text"], input:not([type]), select {
  font-size: 15px !important;
  line-height: 1.55 !important;
}

/* Seat cards */
.seatName     { font-size: 15px !important; }
.seatRole     { font-size: 13px !important; }
.seatStatus   { font-size: 12px !important; }

/* Sidebar headers */
.sideTitle .h1 { font-size: 16px !important; }
.sideTitle .h2 { font-size: 13px !important; }
.opTitle .t1   { font-size: 15px !important; }
.opTitle .t2   { font-size: 13px !important; }

/* Nav bar */
.saNavBtn     { font-size: 14px !important; }
.saDropItem   { font-size: 14px !important; padding: 10px 14px !important; }

.saObjectivePill { font-size: 12px !important; }
.saModelTag   { font-size: 12px !important; }

/* Labels and tiny text */
.tiny         { font-size: 13px !important; }
label         { font-size: 14px !important; }
.pill         { font-size: 13px !important; }
.pillRow .tiny { font-size: 12px !important; }

/* Modal forms */
.modalForm label { font-size: 14px !important; }
.card label      { font-size: 14px !important; }

/* Group reply section */
.groupReplies    { font-size: 15px !important; }

/* Command row primary buttons */
.commandRow .btn { font-size: 15px !important; }

</style>
</head>
<body>
  <div class="topbar">
    <div class="topbarMain">
      <div class="brand">
        <div class="dot"></div>
        <div>{{app_title}}</div>
      </div>
      <div class="rightmeta">
        <div id="modelTag">Model: {{model}}</div>
      </div>
    </div>
    <!-- ===== REDESIGNED NAV BAR ===== -->
    <div class="saNavBar" id="saNavBar">

      <!-- Left: 3 dropdown groups -->
      <div class="saNavLeft">

        <div class="saDropWrap">
          <button class="saNavBtn" id="saTeamDropBtn" onclick="saToggleDrop('saTeamDrop')">
            <span>Team</span><span class="saChevron">&#9660;</span>
          </button>
          <div class="saDrop" id="saTeamDrop">
            <button class="saDropItem" id="frameworkBtn">Core framework</button>
            <button class="saDropItem" id="manageTeamBtn">Add / dismiss teammates</button>
            <button class="saDropItem" id="createTeamBtn">Create teammate</button>
            <button class="saDropItem" id="installFullBtn">Install full team</button>
            <button class="saDropItem" id="onboardingBtn">Onboarding checklist</button>
            <button class="saDropItem" id="openApiKeyHelpBtn">Get OpenAI key</button>
          </div>
        </div>

        <div class="saDropWrap">
          <button class="saNavBtn" id="saToolsDropBtn" onclick="saToggleDrop('saToolsDrop')">
            <span>Tools</span><span class="saChevron">&#9660;</span>
          </button>
          <div class="saDrop" id="saToolsDrop">
            <button class="saDropItem" id="leadLabBtn">Lead Lab</button>
            <button class="saDropItem" id="crmBtn">CRM</button>
            <button class="saDropItem" id="growthPlaybookBtn">Growth Playbook</button>
            <button class="saDropItem" id="socialStudioBtn">Social Studio</button>
            <button class="saDropItem" id="offerBuilderBtn">Offer Builder</button>
            <button class="saDropItem" id="imageLibBtn">Image Library</button>
            <button class="saDropItem" id="emailConsoleBtn">Email Console</button>
            <button class="saDropItem" id="calendarBtn">Calendar</button>
          </div>
        </div>

        <div class="saDropWrap">
          <button class="saNavBtn" id="saSettingsDropBtn" onclick="saToggleDrop('saSettingsDrop')">
            <span>Settings</span><span class="saChevron">&#9660;</span>
          </button>
          <div class="saDrop" id="saSettingsDrop">
            <button class="saDropItem" id="settingsBtn">User settings</button>
            <button class="saDropItem" id="operatorProfileBtn">Operator profile</button>
            <button class="saDropItem" id="sessionObjectiveBtn">Session objective</button>
            <a class="saDropItem" href="/logout" style="text-decoration:none;color:inherit;">Logout</a>
          </div>
        </div>

        <button class="saNavBtn" id="dashboardNavBtn" onclick="saOpenDashboard()" style="padding:7px 14px;">
          📊 Dashboard
        </button>

      </div>

      <!-- Center: Session objective pill only -->
      <div class="saNavCenter">
        <div class="saObjectivePill" id="sessionObjectivePill" title="Current session objective">No objective set</div>
      </div>

      <!-- Right: model tag + logout -->
      <div class="saNavRight">
        <div class="saModelTag" id="modelTag">Model: {{model}}</div>
        <a class="saNavBtn" href="/logout" title="Sign out" style="text-decoration:none;padding:6px 13px;font-size:13px;opacity:0.85;">🚪 Logout</a>
      </div>

    </div>
    <!-- ===== END REDESIGNED NAV BAR ===== -->
  </div>

  <!-- ===== NEW: Mobile Vertical UI v2 (bottom bar + drawer) ===== -->
  <div class="mobileBar" id="mobileBar">
    <button class="btn" id="mobileMenuBtn">Menu</button>
    <button class="btn" id="mobileManageBtn">Team</button>
    <button class="btn" id="mobileSettingsBtn">Settings</button>
  </div>

  <div class="mobileDrawerOverlay" id="mobileDrawerOverlay" aria-hidden="true">
    <div class="mobileDrawer" id="mobileDrawer" role="dialog" aria-modal="true" aria-label="Mobile menu">
      <div class="mobileDrawerHead">
        <div>
          <div class="mobileDrawerTitle">{{app_title}}</div>
          <div class="mobileDrawerSub">Model: {{model}}</div>
        </div>
        <button class="btn btnMini" id="mobileCloseMenuBtn">Close</button>
      </div>

      <div class="mobileDrawerGrid">
        <button class="btn" data-click="frameworkBtn">Core framework</button>
        <button class="btn" data-click="manageTeamBtn">Add or dismiss</button>
        <button class="btn" data-click="createTeamBtn">Create teammate</button>
        <button class="btn" data-click="installFullBtn">Install full team</button>
        <button class="btn" data-click="settingsBtn">Settings</button>
                <button class="btn" data-click="calendarBtn">Calendar</button>
<button class="btn" data-click="crmBtn">Client Center</button>
        <button class="btn" data-click="growthPlaybookBtn">Growth Playbook</button>
        <button class="btn" data-click="leadLabBtn">Lead Lab</button>
        <button class="btn" data-click="socialStudioBtn">Social Studio</button>
        <button class="btn" data-click="offerBuilderBtn">Offer Builder</button>
        <button class="btn" data-click="imageLibBtn">Image Library</button>
        <button class="btn" data-click="emailConsoleBtn">Email Console</button>
        <button class="btn" id="mobileOnboardingBtn">Next step</button>
        <button class="btn" data-click="openApiKeyHelpBtn">Get OpenAI key</button>
        <a class="btn" href="/logout" style="text-decoration:none; display:inline-block; text-align:center;">Logout</a>
      </div>

      <div class="mobileDrawerFoot">
        <button class="btn" id="mobileScrollTopBtn">Top</button>
        <button class="btn btnPrimary" id="mobileCloseMenuBtn2">Done</button>
      </div>
    </div>
  </div>


  <div class="stage">
    <div>
      <div class="arena">
        <div class="overlay" id="overlay">
          <div class="modal" id="modalWin">
            <div class="modalBar" id="modalBar">
              <div class="modalBarTitle" id="modalTitle">Round Table</div>
              <div class="modalBarBtns">
                <button class="btn btnTiny" id="minModal">Minimize</button>
                <button class="btn btnTiny" id="restoreModal" style="display:none">Restore</button>
                <button class="btn btnTiny" id="closeModal">Close</button>
              </div>
            </div>

            <div class="modalBodyWrap" id="modalScroll">
              <pre id="modalBody"></pre>





              <div class="modalForm" id="modalForm">
                <div class="tiny" id="editHint" style="margin-bottom:10px;">
                  Update responsibilities, rules, and goals for this teammate. Name stays locked.
                </div>

                <div style="margin-bottom:10px;">
                  <label>Name</label>
                  <input id="editName" placeholder="Teammate name" readonly />
                </div>

                <div class="grid">
                  <div>
                    <label>Job Title</label>
                    <input id="editJobTitle" placeholder="Job title"/>
                  </div>
                  <div>
                    <label>Version</label>
                    <input id="editVersion" placeholder="v1.0"/>
                  </div>
                </div>

                <div style="height:10px"></div>

                <label>Mission</label>
                <textarea id="editMission" placeholder="Mission"></textarea>

                <div style="height:10px"></div>

                <label>Goal</label>
                <textarea id="editGoal" placeholder="Goal"></textarea>

                <div style="height:10px"></div>

                <label>Thinking Style</label>
                <textarea id="editThinking" placeholder="Thinking style"></textarea>

                <div style="height:10px"></div>

                <label>Responsibilities (one per line)</label>
                <textarea id="editResponsibilities" placeholder="One responsibility per line"></textarea>

                <div style="height:10px"></div>

                <label>Will Not Do (one per line)</label>
                <textarea id="editWillNotDo" placeholder="One rule per line"></textarea>

                <div style="height:10px"></div>

                <div class="grid">
                  <div>
                    <label>AI Model <span class="tiny" style="opacity:.6;">(leave blank for global default)</span></label>
                    <select id="editPreferredModel" style="width:100%;background:rgba(11,16,36,.92);color:var(--text);border:1px solid rgba(42,58,106,.9);border-radius:10px;padding:8px 10px;font-size:13px;">
                      <option value="">Default (global model)</option>
                      <option value="gpt-4o">gpt-4o — balanced</option>
                      <option value="gpt-4o-mini">gpt-4o-mini — fast &amp; cheap</option>
                      <option value="gpt-4-turbo">gpt-4-turbo — high quality</option>
                      <option value="o1-mini">o1-mini — deep reasoning</option>
                      <option value="o3-mini">o3-mini — advanced reasoning</option>
                      <option value="gpt-4.5-preview">gpt-4.5-preview</option>
                    </select>
                  </div>
                  <div>
                    <label>TTS Voice <span class="tiny" style="opacity:.6;">(speak responses aloud)</span></label>
                    <select id="editTtsVoice" style="width:100%;background:rgba(11,16,36,.92);color:var(--text);border:1px solid rgba(42,58,106,.9);border-radius:10px;padding:8px 10px;font-size:13px;">
                      <option value="alloy">Alloy — neutral</option>
                      <option value="echo">Echo — male, clear</option>
                      <option value="fable">Fable — storytelling</option>
                      <option value="onyx">Onyx — deep male</option>
                      <option value="nova">Nova — female, bright</option>
                      <option value="shimmer">Shimmer — soft female</option>
                    </select>
                  </div>
                </div>

                <div class="actions">
                  <button class="btn" id="cancelEdit">Cancel</button>
                  <button class="btn btnPrimary" id="saveEdit">Save changes</button>
                  <button class="btn btnPrimary" id="saveEditExit">Save &amp; Exit</button>
                </div>

                <div class="tiny" id="editStatus" style="margin-top:10px;"></div>
              </div>

<div id="apiKeyHelpForm" class="modalForm" style="display:none;">
  <div class="tiny" style="margin-bottom:10px;">Quick setup: create an OpenAI API key, then paste it into Settings.</div>
  <div class="pill" style="margin:8px 0;">Steps</div>
  <ol style="margin: 8px 0 0 18px; line-height:1.5;">
    <li>Open the OpenAI API Keys page</li>
    <li>Click <b>Create new secret key</b> and copy it (you only see it once)</li>
    <li>Back here: click <b>Settings</b> and paste the key into <b>OpenAI API Key</b></li>
    <li>Click <b>Save</b>, then run a test prompt</li>
  </ol>
  <div style="margin-top:12px;">
    <a class="btn btnPrimary" href="https://platform.openai.com/api-keys" target="_blank" rel="noopener">Open API Keys page</a>
    <button class="btn" id="closeApiKeyHelpBtn" style="margin-left:8px;">Close</button>
  </div>
  <div class="tiny" style="margin-top:12px; opacity:.85;">
    Tip: Never share your key publicly. If it leaks, revoke it and create a new one.
  </div>
</div>

              <div class="modalForm" id="manageForm">
                <div class="tiny" style="margin-bottom:10px;">
                  Toggle who is present at the table. Installed teammates stay installed.
                </div>
                <div id="manageList"></div>
                <div class="actions">
                  <button class="btn" id="cancelManage">Cancel</button>
                  <button class="btn" id="assembleInManageBtn">Assemble All</button>
                  <button class="btn btnPrimary" id="saveManage">Save</button>
                  <button class="btn btnPrimary" id="saveManageExit">Save &amp; Exit</button>
                </div>
                <div class="tiny" id="manageStatus" style="margin-top:10px;"></div>
              </div>

              <div class="modalForm" id="createForm">
                <div class="tiny" style="margin-bottom:10px;">
                  Create a new teammate (name is locked after creation).
                </div>

                <div class="grid">
                  <div>
                    <label>Name</label>
                    <input id="newName" placeholder="Teammate name"/>
                  </div>
                  <div>
                    <label>Version</label>
                    <input id="newVersion" placeholder="v1.0" value="v1.0"/>
                  </div>
                </div>

                <div style="height:10px"></div>

                <label>Job Title</label>
                <input id="newJobTitle" placeholder="Job title"/>

                <div style="height:10px"></div>

                <label>Mission</label>
                <textarea id="newMission" placeholder="Mission"></textarea>

                <div style="height:10px"></div>

                <label>Goal</label>
                <textarea id="newGoal" placeholder="Goal"></textarea>

                <div style="height:10px"></div>

                <label>Thinking Style</label>
                <textarea id="newThinking" placeholder="Thinking style"></textarea>

                <div style="height:10px"></div>

                <label>Responsibilities (one per line)</label>
                <textarea id="newResponsibilities" placeholder="One responsibility per line"></textarea>

                <div style="height:10px"></div>

                <label>Will Not Do (one per line)</label>
                <textarea id="newWillNotDo" placeholder="One rule per line"></textarea>

                <div class="actions">
                  <button class="btn" id="cancelCreate">Cancel</button>
                  <button class="btn btnPrimary" id="saveCreate">Create</button>
                  <button class="btn btnPrimary" id="saveCreateExit">Create &amp; Exit</button>
                </div>
                <div class="tiny" id="createStatus" style="margin-top:10px;"></div>
              </div>

              <div class="modalForm" id="frameworkForm">
                <div class="tiny" style="margin-bottom:10px;">
                  This is injected into every teammate system prompt. Changes affect all teammates immediately.
                </div>

                <label>Core framework (pillars and rules)</label>
                <textarea id="frameworkText" style="height:260px" placeholder="Paste the full core framework here"></textarea>

                <div class="actions">
                  <button class="btn" id="cancelFramework">Cancel</button>
                  <button class="btn" id="resetFramework">Reset to default</button>
                  <button class="btn btnPrimary" id="saveFramework">Save framework</button>
                  <button class="btn btnPrimary" id="saveFrameworkExit">Save &amp; Exit</button>
                </div>
                <div class="tiny" id="frameworkStatus" style="margin-top:10px;"></div>
              </div>


              <div class="modalForm" id="settingsForm">
                <div class="tiny" style="margin-bottom:10px;">
                  Personal settings for this account. OpenAI key affects only your sessions. Email settings are used when you send email so you do not send from the owner's inbox.
                </div>

                <label>OpenAI API Key</label>
                <input id="openaiKey" type="text" placeholder="sk-..." autocomplete="off" autocapitalize="off" spellcheck="false" inputmode="verbatim" name="openai_api_key_field" data-lpignore="true" data-1p-ignore="true" />

                <div class="tiny" style="margin-top:10px;">Google Connections (easy connect)</div>

                <div class="row2">
                  <div>
                    <div class="tiny" id="gmailOAuthStatus">Gmail: checking...</div>
                    <div style="display:flex; gap:8px; flex-wrap:wrap; margin-top:6px;">
                      <button class="btn btnMini" id="gmailConnectBtn">Connect Gmail</button>
                      <button class="btn btnMini" id="gmailDisconnectBtn">Disconnect Gmail</button>
                    </div>
                  </div>
                  <div>
                    <div class="tiny" id="calendarOAuthStatus">Calendar: checking...</div>
                    <div style="display:flex; gap:8px; flex-wrap:wrap; margin-top:6px;">
                      <button class="btn btnMini" id="calendarConnectBtn">Connect Calendar</button>
                      <button class="btn btnMini" id="calendarDisconnectBtn">Disconnect Calendar</button>
                    </div>
                  </div>
                </div>

                <div class="tiny" style="margin-top:6px;">Tip: set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and PUBLIC_BASE_URL on your server to enable Google connect.</div>


                <div class="tiny" style="margin-top:8px;">Email (SMTP) connection</div>

                <label>SMTP Host</label>
                <input id="smtpHost" placeholder="smtp.gmail.com" />

                <label>SMTP Port</label>
                <input id="smtpPort" type="number" placeholder="587" />

                <label>SMTP Username (from address)</label>
                <input id="smtpUser" placeholder="you@example.com" />

                <label>SMTP Password (app password recommended)</label>
                <input id="smtpPass" type="password" placeholder="••••••••" />

                <label>From Name</label>
                <input id="smtpFromName" placeholder="Your Name" />


                <details style="margin-top:12px;">
                  <summary style="cursor:pointer; user-select:none;">Twilio Connection (SMS)</summary>
                  <div class="tiny" style="margin-top:8px; opacity:.9;">
                    Used for Broadcast SMS in the Client Center. This is stored in your personal settings.
                  </div>

                  <label>Twilio Account SID</label>
                  <input id="twilioSid" placeholder="ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" />

                  <label>Twilio Auth Token</label>
                  <input id="twilioToken" type="password" placeholder="••••••••" />

                  <label>Twilio From Number</label>
                  <input id="twilioFrom" placeholder="+15551234567" />

                  <div class="actions" style="justify-content:flex-start; gap:8px;">
                    <button class="btn btnMini" id="twilioLoadBtn">Load</button>
                    <button class="btn btnMini" id="twilioSaveBtn">Save</button>
                  </div>
                  <div class="tiny" id="twilioStatus" style="margin-top:8px;"></div>
                </details>

                <div class="actions">
                  <button class="btn" id="cancelSettings">Cancel</button>
                  <button class="btn btnPrimary" id="saveSettings">Save settings</button>
                  <button class="btn btnPrimary" id="saveSettingsExit">Save &amp; Exit</button>
                </div>
                <div class="tiny" id="settingsStatus" style="margin-top:10px;"></div>
              </div>

              

<div class="modalForm" id="emailConsoleForm" style="display:none;">
  <div class="tiny" style="margin-bottom:10px;">When a teammate drafts an email, fields auto fill here. You approve before sending.</div>
  <div class="tiny" id="smtpStatus">SMTP: checking...</div>
  <div style="height:10px"></div>
  <div class="row2">
    <input class="field" id="emailFrom" placeholder="From" readonly/>
    <input class="field" id="emailTo" placeholder="To: name@email.com"/>
  </div>
  <div style="height:10px"></div>
  <input class="field" id="emailSubject" placeholder="Subject"/>
  <div style="height:10px"></div>
  <textarea class="field" id="emailBody" style="height:280px" placeholder="Email body"></textarea>
  <div style="display:flex; gap:10px; flex-wrap:wrap; margin-top:10px;">
    <button class="btn" id="draftWithSelected">Draft with selected</button>
    <button class="btn btnPrimary" id="sendEmailBtn">Approve and send</button>
  </div>
  <div class="tiny" style="margin-top:8px;">Sending is always manual. The teammate drafts. You approve.</div>
</div>

<div class="modalForm" id="smsConsoleForm" style="display:none;">
  <div class="tiny" style="margin-bottom:10px;">When a teammate drafts a text message, fields auto fill here. You approve before sending.</div>
  <div class="row2">
    <input class="field" id="smsFrom" placeholder="From" readonly/>
    <input class="field" id="smsTo" placeholder="To: +1..."/>
  </div>
  <div style="height:10px"></div>
  <textarea class="field" id="smsBody" style="height:220px" placeholder="Text message body"></textarea>
  <div style="display:flex; gap:10px; flex-wrap:wrap; margin-top:10px;">
    <button class="btn" id="draftSmsWithSelected">Draft with selected</button>
    <button class="btn btnPrimary" id="sendSmsBtn">Approve and send text</button>
  </div>
  <div class="tiny" id="smsConsoleStatus" style="margin-top:8px;">Sending is always manual. The teammate drafts. You approve.</div>
</div>

<div class="modalForm" id="leadHandoffForm" style="display:none;">
  <div class="tiny" style="margin-bottom:10px;">Choose who should write the outreach, then the app will open the matching console with the draft loaded.</div>
  <div class="grid">
    <div>
      <label>Teammate</label>
      <select id="leadHandoffTeammate"></select>
    </div>
    <div>
      <label>Channel</label>
      <input id="leadHandoffChannel" readonly />
    </div>
    <div>
      <label>Goal</label>
      <select id="leadHandoffGoal">
        <option value="intro">Intro</option>
        <option value="follow_up">Follow up</option>
        <option value="offer">Offer</option>
        <option value="nurture">Nurture</option>
        <option value="book_call">Book call</option>
      </select>
    </div>
    <div>
      <label>Tone</label>
      <select id="leadHandoffTone">
        <option value="warm">Warm</option>
        <option value="professional">Professional</option>
        <option value="direct">Direct</option>
        <option value="casual">Casual</option>
      </select>
    </div>
  </div>
  <label style="margin-top:10px;">Lead context</label>
  <textarea id="leadHandoffContext" rows="7" readonly></textarea>
  <div class="actions" style="justify-content:flex-end;">
    <button class="btn" id="leadHandoffCancel">Cancel</button>
    <button class="btn btnPrimary" id="leadHandoffGenerate">Write draft</button>
  </div>
  <div class="tiny" id="leadHandoffStatus"></div>
</div>

<div class="modalForm" id="sessionObjectiveForm" style="display:none;">
  <div class="tiny" style="margin-bottom:10px;">Set the current session objective so the whole system can align around one goal.</div>
  <label>Objective</label>
  <input id="sessionObjectiveInput" placeholder="Example: build a clean NJ realtor lead engine and draft first outreach" />
  <label style="margin-top:10px;">Context</label>
  <textarea id="sessionObjectiveContext" rows="5" placeholder="What matters most right now, constraints, and what success looks like."></textarea>
  <div class="actions">
    <button class="btn" id="sessionObjectiveCloseBtn">Close</button>
    <button class="btn btnPrimary" id="sessionObjectiveSaveBtn">Save objective</button>
    <button class="btn btnPrimary" id="sessionObjectiveSaveExitBtn">Save &amp; Exit</button>
  </div>
  <div class="tiny" id="sessionObjectiveStatus" style="margin-top:10px;"></div>
</div>

<div class="modalForm" id="operatorProfileModalForm" style="display:none;">
  <div class="tiny" style="margin-bottom:10px;">Shared operator context that all teammates can reference.</div>
  <div class="grid">
    <div>
      <label>Display name</label>
      <input id="opm_display_name" placeholder="Operator" />
    </div>
    <div>
      <label>Audience</label>
      <input id="opm_audience" placeholder="Who you serve" />
    </div>
  </div>
  <label style="margin-top:10px;">Business</label>
  <textarea id="opm_business" rows="4" placeholder="What your business does"></textarea>
  <label style="margin-top:10px;">Offers</label>
  <textarea id="opm_offers" rows="4" placeholder="What you sell"></textarea>
  <label style="margin-top:10px;">Goals</label>
  <textarea id="opm_goals" rows="3" placeholder="Current goals"></textarea>
  <label style="margin-top:10px;">Constraints</label>
  <textarea id="opm_constraints" rows="3" placeholder="Rules and boundaries"></textarea>
  <label style="margin-top:10px;">Tone rules</label>
  <textarea id="opm_tone_rules" rows="3" placeholder="How teammates should communicate"></textarea>
  <label style="margin-top:10px;">Notes</label>
  <textarea id="opm_notes" rows="4" placeholder="Anything else teammates should know"></textarea>
  <div class="actions">
    <button class="btn" id="operatorProfileCloseBtn">Close</button>
    <button class="btn btnPrimary" id="operatorProfileSaveBtn">Save</button>
    <button class="btn btnPrimary" id="operatorProfileSaveExitBtn">Save &amp; Exit</button>
  </div>
  <div class="tiny" id="operatorProfileStatus" style="margin-top:10px;"></div>
</div>

<div class="modalForm" id="crmForm" style="display:none;">
  <div class="tiny" style="margin-bottom:10px;">Client Command Center. Clients and broadcasts without leaving the Round Table.</div>

  <div class="pillRow" id="crmNavTabs" style="justify-content:flex-start; gap:8px; flex-wrap:wrap; margin-bottom:10px;">
    <button class="btn btnMini" id="crmTabClients">Clients</button>
    <button class="btn btnMini" id="crmTabPipeline">Pipeline</button>
    <button class="btn btnMini" id="crmTabBroadcast">Email Broadcast</button>
    <button class="btn btnMini" id="crmTabBroadcastSMS">Broadcast SMS</button>
  </div>

  <div id="crmStatus" class="tiny" style="margin:6px 0 10px;"></div>

  <!-- Clients -->
  <div id="crmViewClients" style="display:none;">
    <div class="grid">
      <div>
        <label>Search</label>
        <input id="crmSearch" placeholder="Name, email, tag..." />
      </div>
      <div>
        <label>Filter</label>
        <select id="crmFilter">
          <option value="">All</option>
          <option value="status:lead">Status: Lead</option>
          <option value="status:active">Status: Active</option>
          <option value="status:vip">Status: VIP</option>
          <option value="status:past">Status: Past</option>
          <option value="stage:Lead">Stage: Lead</option>
          <option value="stage:Conversation">Stage: Conversation</option>
          <option value="stage:Interested">Stage: Interested</option>
          <option value="stage:Call booked">Stage: Call booked</option>
          <option value="stage:Client">Stage: Client</option>
          <option value="stage:VIP">Stage: VIP</option>
          <option value="stage:Past client">Stage: Past client</option>
          <option value="stage:Cold">Stage: Cold</option>
        </select>
      </div>
    </div>

    <div class="actions" style="justify-content:flex-start; margin-top:10px;">
      <button class="btn" id="crmRefreshClients">Refresh</button>
      <button class="btn btnPrimary" id="crmNewClientBtn">Add client</button>
      <input type="file" id="crmCsvFile" accept=".csv,text/csv" style="display:none" />
      <button class="btn" id="crmPickCsvBtn">Import CSV</button>
    </div>
    <div class="tiny" id="crmCsvStatus" style="margin-top:8px;">Upload a CSV to add prospects into the pipeline.</div>

    <div id="crmClientsList" style="margin-top:10px;"></div>

    <div id="crmClientEditor" style="display:none; margin-top:12px; border:1px solid rgba(255,255,255,.10); border-radius:14px; padding:10px; background: rgba(0,0,0,.18);">
      <div class="tiny" id="crmEditTitle" style="margin-bottom:8px;">Client</div>
      <div class="grid">
        <div>
          <label>Name</label>
          <input id="crmName" />
        </div>
        <div>
          <label>Email</label>
          <input id="crmEmail" />
        </div>
      </div>
      <div class="grid" style="margin-top:10px;">
        <div>
          <label>Phone</label>
          <input id="crmPhone" placeholder="+15551234567" />
        </div>
        <div>
          <label>Status</label>
          <select id="crmStatusSel">
            <option value="lead">lead</option>
            <option value="active">active</option>
            <option value="vip">vip</option>
            <option value="past">past</option>
            <option value="cold">cold</option>
          </select>
        </div>
      </div>
      <div class="grid" style="margin-top:10px;">
        <div>
          <label>Pipeline stage</label>
          <input id="crmStage" placeholder="Lead" />
        </div>
        <div>
          <label>Tags (comma separated)</label>
          <input id="crmTags" placeholder="realtor, vip" />
        </div>
      </div>
      <div style="margin-top:10px;">
        <label>Notes</label>
        <textarea id="crmNotes" rows="3" placeholder="Notes..."></textarea>
      </div>
      <div class="actions" style="justify-content:flex-end; margin-top:10px;">
        <button class="btn" id="crmCancelEdit">Cancel</button>
        <button class="btn btnPrimary" id="crmSaveClient">Save</button>
        <button class="btn btnPrimary" id="crmSaveClientExit">Save &amp; Exit</button>
      </div>
      <div class="tiny" id="crmEditStatus" style="margin-top:8px;"></div>
    </div>
  </div>

  <!-- Pipeline -->
  <div id="crmViewPipeline" style="display:none;">
    <div class="tiny" style="margin-bottom:8px;">Edit your pipeline stages and manage a visual deal board. Drag cards between stages to keep your pipeline current.</div>
    <label>Stages</label>
    <textarea id="crmStagesText" style="height:180px" placeholder="Lead\nConversation\nInterested\nCall booked\nClient\nVIP\nPast client\nCold"></textarea>
    <div class="actions" style="justify-content:flex-end; margin-top:10px;">
      <button class="btn" id="crmReloadPipeline">Reload</button>
      <button class="btn btnPrimary" id="crmSavePipeline">Save</button>
      <button class="btn btnPrimary" id="crmSavePipelineExit">Save &amp; Exit</button>
    </div>
    <div class="tiny" id="crmPipelineStatus" style="margin-top:8px;"></div>
    <div class="tiny" style="margin:12px 0 8px;">Live pipeline board</div>
    <div id="crmPipelineBoard" style="display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:10px;"></div>
  </div>

  <!-- Broadcast -->
  <div id="crmViewBroadcast" style="display:none;">
    <div class="grid">
      <div>
        <label>Audience</label>
        <select id="crmAudience">
          <option value="all">All clients</option>
          <option value="tag">Tag</option>
          <option value="stage">Pipeline stage</option>
          <option value="status">Status</option>
          <option value="selected">Selected client IDs</option>
        </select>
      </div>
      <div>
        <label>Value</label>
        <input id="crmAudienceValue" placeholder="e.g. realtor" />
      </div>
    </div>

    <div style="margin-top:10px;">
      <label>Subject</label>
      <input id="crmEmailSubject" placeholder="Quick update" />
      <label style="margin-top:10px;">Message</label>
      <textarea id="crmEmailBody" style="height:180px" placeholder="Hey {first_name},\n\n..."></textarea>
      <div class="tiny" style="margin-top:8px; opacity:.85;">Tip: You can use {name} in the body for personalization.</div>
    </div>

    <div class="actions" style="justify-content:flex-end; margin-top:10px;">
      <button class="btn" id="crmBroadcastDryRun">Dry run</button>
      <button class="btn btnPrimary" id="crmBroadcastSend">Send</button>
    </div>
    <div class="tiny" id="crmBroadcastStatus" style="margin-top:8px;"></div>
  </div>


<!-- Broadcast SMS -->
<div id="crmViewBroadcastSMS" style="display:none;">
  <div class="tiny" style="margin-bottom:8px;">Send a broadcast text message to a filtered audience.</div>

  


  <div class="grid">
    <div>
      <label>Audience</label>
      <select id="crmSmsAudience">
        <option value="all">All clients</option>
        <option value="tag">Tag</option>
        <option value="stage">Pipeline stage</option>
        <option value="status">Status</option>
        <option value="selected">Selected IDs</option>
      </select>
    </div>
    <div>
      <label>Value (tag/stage/status or comma IDs)</label>
      <input id="crmSmsAudienceValue" placeholder="vip, Lead, status, or client_123, client_456" />
    </div>
  </div>

  <label style="margin-top:10px;">Message</label>
  <textarea id="crmSmsBody" rows="6" placeholder="Write your text message..."></textarea>

  <div class="actions" style="justify-content:flex-start; margin-top:10px;">
    <button class="btn" id="crmSmsDryRun">Dry run</button>
    <button class="btn btnPrimary" id="crmSmsSend">Send SMS</button>
  </div>

  <div class="tiny" id="crmSmsStatus" style="margin-top:8px;"></div>
</div>

  <!-- Tasks -->
  <div id="crmViewTasks" style="display:none;">
    <div class="actions" style="justify-content:flex-start;">
      <button class="btn" id="crmRefreshTasks">Refresh</button>
      <button class="btn btnPrimary" id="crmNewTaskBtn">New task</button>
    </div>
    <div id="crmTasksList" style="margin-top:10px;"></div>

    <div id="crmTaskEditor" style="display:none; margin-top:12px; border:1px solid rgba(255,255,255,.10); border-radius:14px; padding:10px; background: rgba(0,0,0,.18);">
      <div class="tiny" id="crmTaskTitle" style="margin-bottom:8px;">Task</div>
      <label>Title</label>
      <input id="crmTaskText" placeholder="Follow up with..." />
      <div class="grid" style="margin-top:10px;">
        <div>
          <label>Due date</label>
          <input id="crmTaskDue" type="date" />
        </div>
        <div>
          <label>Priority</label>
          <select id="crmTaskPriority">
            <option value="normal">normal</option>
            <option value="high">high</option>
            <option value="low">low</option>
          </select>
        </div>
      </div>
      <div style="margin-top:10px;">
        <label>Client ID (optional)</label>
        <input id="crmTaskClientId" placeholder="client_..." />
      </div>
      <div class="actions" style="justify-content:flex-end; margin-top:10px;">
        <button class="btn" id="crmCancelTask">Cancel</button>
        <button class="btn btnPrimary" id="crmSaveTask">Save</button>
        <button class="btn btnPrimary" id="crmSaveTaskExit">Save &amp; Exit</button>
      </div>
      <div class="tiny" id="crmTaskStatus" style="margin-top:8px;"></div>
    </div>
  </div>

  <!-- Sequences -->
  <div id="crmViewSequences" style="display:none;">
    <div class="tiny" style="margin-bottom:8px;">Sequences are automated nurture steps that run on schedule. Add a sequence, then enroll clients.</div>

    <div class="actions" style="justify-content:flex-start;">
      <button class="btn" id="crmRefreshSeq">Refresh</button>
      <button class="btn btnPrimary" id="crmNewSeqBtn">New sequence</button>
    </div>

    <div id="crmSeqList" style="margin-top:10px;"></div>

    <div id="crmSeqEditor" style="display:none; margin-top:12px; border:1px solid rgba(255,255,255,.10); border-radius:14px; padding:10px; background: rgba(0,0,0,.18);">
      <div class="tiny" style="margin-bottom:8px;">Create sequence</div>
      <label>Name</label>
      <input id="crmSeqName" placeholder="Monthly Value Drop" />
      <label style="margin-top:10px;">Steps (JSON array)</label>
      <textarea id="crmSeqSteps" style="height:180px" placeholder='[{"after_days":0,"channel":"email","subject":"Welcome","body":"Hi {name}..."}]'></textarea>
      <div class="tiny" style="margin-top:8px; opacity:.85;">Each step: after_days, channel=email, subject, body. (This UI is minimal but fully operational.)</div>
      <div class="actions" style="justify-content:flex-end; margin-top:10px;">
        <button class="btn" id="crmCancelSeq">Cancel</button>
        <button class="btn btnPrimary" id="crmSaveSeq">Save</button>
        <button class="btn btnPrimary" id="crmSaveSeqExit">Save &amp; Exit</button>
      </div>
      <div class="tiny" id="crmSeqStatus" style="margin-top:8px;"></div>
    </div>

    <div style="margin-top:12px; border:1px solid rgba(255,255,255,.10); border-radius:14px; padding:10px; background: rgba(0,0,0,.18);">
      <div class="tiny" style="margin-bottom:8px;">Enroll client</div>
      <div class="grid">
        <div>
          <label>Client ID</label>
          <input id="crmEnrollClient" placeholder="client_..." />
        </div>
        <div>
          <label>Sequence ID</label>
          <input id="crmEnrollSeq" placeholder="seq_..." />
        </div>
      </div>
      <div class="actions" style="justify-content:flex-end; margin-top:10px;">
        <button class="btn btnPrimary" id="crmEnrollBtn">Enroll</button>
      </div>
      <div class="tiny" id="crmEnrollStatus" style="margin-top:8px;"></div>
    </div>
  </div>

  <!-- Calendar -->
  <div id="crmViewCalendar" style="display:none;">
    <div class="tiny" style="margin-bottom:8px;">Create a calendar event (uses your Google Calendar connection if enabled).</div>
    <label>Title</label>
    <input id="crmCalTitle" placeholder="Client check-in" />
    <div class="grid" style="margin-top:10px;">
      <div>
        <label>Start</label>
        <input id="crmCalStart" type="datetime-local" />
      </div>
      <div>
        <label>End</label>
        <input id="crmCalEnd" type="datetime-local" />
      </div>
    </div>
    <label style="margin-top:10px;">Description</label>
    <textarea id="crmCalDesc" rows="3" placeholder="Notes..."></textarea>
    <div class="actions" style="justify-content:flex-end; margin-top:10px;">
      <button class="btn btnPrimary" id="crmCreateEventBtn">Create event</button>
    </div>
    <div class="tiny" id="crmCalStatus" style="margin-top:8px;"></div>
  </div>

  <!-- Lead Lab -->
  <div id="crmViewLeadLab" style="display:none;">
    <div class="tiny" style="margin-bottom:8px;">Generate organized public lead lists from the web. Paste optional seed rows as: Name | Company | Domain | Title. If you leave seed rows blank, Lead Lab will discover prospects from scratch.</div>
    <div class="grid">
      <div>
        <label>Target niche</label>
        <input id="leadLabNiche" placeholder="real estate agents" />
      </div>
      <div>
        <label>Location</label>
        <input id="leadLabLocation" placeholder="New Jersey" />
      </div>
      <div>
        <label>Lead count</label>
        <select id="leadLabCount">
          <option value="10">10</option>
          <option value="25" selected>25</option>
          <option value="50">50</option>
          <option value="100">100</option>
        </select>
      </div>
      <div>
        <label>Search mode</label>
        <select id="leadLabMode">
          <option value="balanced" selected>Balanced</option>
          <option value="broad">Broad</option>
          <option value="precision">Precision</option>
        </select>
      </div>
    </div>
    <div class="grid" style="margin-top:10px;">
      <div>
        <label>Specific areas</label>
        <input id="leadLabAreas" placeholder="Newark, Jersey City, Hoboken" />
      </div>
      <div>
        <label>Contact filter</label>
        <select id="leadLabRequireContact">
          <option value="phone_or_email" selected>Phone or email preferred</option>
          <option value="phone">Phone only</option>
          <option value="email">Email only</option>
          <option value="any">Any public lead</option>
        </select>
      </div>
      <div>
        <label>Minimum score</label>
        <select id="leadLabMinScore">
          <option value="30">30</option>
          <option value="40" selected>40</option>
          <option value="50">50</option>
          <option value="60">60</option>
        </select>
      </div>
      <div>
        <label>Seed rows (optional)</label>
        <div class="tiny" style="margin-top:8px; opacity:.8;">Lead Lab can search from scratch even if this is blank.</div>
      </div>
    </div>
    <label style="margin-top:10px;">Lead source text (optional)</label>
    <textarea id="leadLabInput" style="height:180px" placeholder="Jane Doe | Acme Realty | acmerealty.com | Broker&#10;Mike Ray | rayinvestments.com | Investor"></textarea>
    <div class="actions" style="justify-content:flex-end; margin-top:10px;">
      <button class="btn" id="leadLabSampleBtn">Sample</button>
      <button class="btn btnPrimary" id="leadLabRunBtn">Build lead list</button>
    </div>
    <div class="tiny" id="leadLabStatus" style="margin-top:8px;"></div>
    <div id="leadLabResults" style="margin-top:12px;"></div>
  </div>

  <!-- Social Studio -->
  <div id="crmViewSocialStudio" style="display:none;">
    <div class="tiny" style="margin-bottom:8px;">Generate entrepreneur-ready social assets fast: posts, hooks, comments, DMs, and CTAs.</div>
    <div class="grid">
      <div>
        <label>Platform</label>
        <select id="socialStudioPlatform">
          <option value="Facebook">Facebook</option>
          <option value="LinkedIn">LinkedIn</option>
          <option value="Instagram">Instagram</option>
          <option value="X">X</option>
        </select>
      </div>
      <div>
        <label>Asset set</label>
        <select id="socialStudioAsset">
          <option value="content_pack">Content pack</option>
          <option value="dm_pack">DM pack</option>
          <option value="comment_pack">Comment pack</option>
          <option value="launch_pack">Launch pack</option>
        </select>
      </div>
    </div>
    <label style="margin-top:10px;">Audience</label>
    <input id="socialStudioAudience" placeholder="solo real estate agents" />
    <label style="margin-top:10px;">Offer / angle</label>
    <textarea id="socialStudioOffer" rows="4" placeholder="What do you sell and why should people care?"></textarea>
    <div class="actions" style="justify-content:flex-end; margin-top:10px;">
      <button class="btn btnPrimary" id="socialStudioRunBtn">Generate assets</button>
    </div>
    <div class="tiny" id="socialStudioStatus" style="margin-top:8px;"></div>
    <div id="socialStudioResults" style="margin-top:12px;"></div>
  </div>

  <!-- Offer Builder -->
  <div id="crmViewOfferBuilder" style="display:none;">
    <div class="tiny" style="margin-bottom:8px;">Build a cleaner offer, stronger positioning, and ready-to-use copy in one place.</div>
    <label>Who do you help?</label>
    <input id="offerBuilderAudience" placeholder="entrepreneurs using social media to get clients" />
    <label style="margin-top:10px;">What result do you help them get?</label>
    <input id="offerBuilderResult" placeholder="generate qualified leads and book more calls" />
    <label style="margin-top:10px;">How do you deliver it?</label>
    <textarea id="offerBuilderMethod" rows="4" placeholder="Describe your process, service, or product."></textarea>
    <div class="actions" style="justify-content:flex-end; margin-top:10px;">
      <button class="btn btnPrimary" id="offerBuilderRunBtn">Build offer</button>
    </div>
    <div class="tiny" id="offerBuilderStatus" style="margin-top:8px;"></div>
    <div id="offerBuilderResults" style="margin-top:12px;"></div>
  </div>

  <!-- Playbooks -->
  <div id="crmViewPlaybooks" style="display:none;">
    <div class="tiny" style="margin-bottom:8px;">Generate step-by-step action plans for growth goals without leaving the command center.</div>
    <div class="grid">
      <div>
        <label>Goal</label>
        <select id="playbookGoal">
          <option value="get_clients">Get clients</option>
          <option value="grow_audience">Grow audience</option>
          <option value="launch_offer">Launch an offer</option>
          <option value="reactivate_leads">Reactivate old leads</option>
          <option value="book_calls">Book more calls</option>
        </select>
      </div>
      <div>
        <label>Timeline</label>
        <select id="playbookTimeline">
          <option value="7 days">7 days</option>
          <option value="14 days">14 days</option>
          <option value="30 days">30 days</option>
          <option value="90 days">90 days</option>
        </select>
      </div>
    </div>
    <label style="margin-top:10px;">Business context</label>
    <textarea id="playbookContext" rows="4" placeholder="Who you help, what you sell, and where you are stuck."></textarea>
    <div class="actions" style="justify-content:flex-end; margin-top:10px;">
      <button class="btn btnPrimary" id="playbookRunBtn">Generate playbook</button>
    </div>
    <div class="tiny" id="playbookStatus" style="margin-top:8px;"></div>
    <div id="playbookResults" style="margin-top:12px;"></div>
  </div>
</div>

              <div class="modalForm" id="calendarForm" style="display:none;padding:0;overflow:hidden;height:calc(100% - 0px);flex-direction:column;">

<style>
/* Message expand modal */
    #saMsgModal { display:none; }
    #saMsgModal.open { display:flex !important; }

/* ── Motion-style Calendar ── */
.wcal-wrap { display:flex; height:100%; min-height:640px; background:#0f1629; border-radius:12px; overflow:hidden; position:relative; }
.wcal-sidebar { width:230px; flex-shrink:0; background:#131e3a; border-right:1px solid rgba(42,58,106,.6); display:flex; flex-direction:column; padding:10px; gap:10px; overflow-y:auto; }
.wcal-main { flex:1; display:flex; flex-direction:column; min-width:0; overflow:hidden; }
.wcal-topbar { display:flex; align-items:center; gap:8px; padding:8px 12px; border-bottom:1px solid rgba(42,58,106,.5); flex-shrink:0; flex-wrap:wrap; }
.wcal-nav-btn { background:rgba(14,22,48,.8); border:1px solid rgba(42,58,106,.7); color:rgba(196,181,253,.85); border-radius:8px; padding:4px 11px; font-size:12px; cursor:pointer; }
.wcal-nav-btn:hover { background:rgba(30,40,80,.9); }
.wcal-nav-btn.today { background:rgba(124,58,237,.25); border-color:rgba(124,58,237,.5); }
.wcal-range-label { font-size:13px; font-weight:700; color:#c4b5fd; flex:1; }
.wcal-view-btns { display:flex; gap:4px; }
.wcal-view-btn { background:rgba(14,22,48,.6); border:1px solid rgba(42,58,106,.5); color:rgba(148,163,184,.7); border-radius:6px; padding:3px 9px; font-size:11px; cursor:pointer; }
.wcal-view-btn.active { background:rgba(124,58,237,.3); border-color:rgba(124,58,237,.6); color:#c4b5fd; }
.wcal-grid-wrap { flex:1; overflow:auto; position:relative; min-height:0; width:100%; }
.wcal-grid { display:flex; flex-direction:column; position:relative; min-height:1440px; width:100%; min-width:0; }
.wcal-time-col { width:54px; flex-shrink:0; position:sticky; left:0; background:#0f1629; z-index:5; }
.wcal-time-label { height:60px; display:flex; align-items:flex-start; justify-content:flex-end; padding:2px 8px 0 0; font-size:12px; color:rgba(148,168,210,.75); }
.wcal-days-area { flex:1; display:grid; position:relative; }
.wcal-day-col { border-left:1px solid rgba(80,110,180,.22); position:relative; flex:1; min-width:0; }
.wcal-hour-line { height:60px; border-bottom:1px solid rgba(80,110,180,.18); position:relative; }
.wcal-half-line { position:absolute; bottom:0; left:0; right:0; height:1px; background:rgba(42,58,106,.09); top:50%; }
.wcal-col-header { text-align:center; padding:5px 2px; border-left:1px solid rgba(80,110,180,.3); border-bottom:1px solid rgba(80,110,180,.4); background:#131e3a; position:sticky; top:0; z-index:4; }
.wcal-col-header .wd { font-size:12px; color:rgba(180,200,240,.85); text-transform:uppercase; letter-spacing:.06em; }
.wcal-col-header .dd { font-size:19px; font-weight:700; color:rgba(230,238,255,.95); line-height:1.1; }
.wcal-col-header .dd.today-num { background:rgba(124,58,237,.8); color:#fff; border-radius:50%; width:30px; height:30px; display:flex; align-items:center; justify-content:center; margin:0 auto; }
.wcal-event { position:absolute; left:3px; right:3px; border-radius:6px; padding:3px 6px 3px 22px; font-size:12px; font-weight:600; cursor:pointer; overflow:hidden; z-index:3; transition:filter 0.15s,box-shadow 0.15s; min-height:22px; box-sizing:border-box; }
.wcal-event:hover { filter:brightness(1.15); box-shadow:0 2px 12px rgba(0,0,0,.4); }
.wcal-event.is-done { opacity:.72; }
.wcal-event.is-done .wcal-event-title { text-decoration:line-through; text-decoration-color:currentColor; text-decoration-thickness:2px; }
/* Check circle — always visible, pinned top-left */
.wcal-event-check {
  position:absolute; top:4px; left:5px;
  display:flex; align-items:center; justify-content:center;
  width:13px; height:13px; border-radius:50%;
  border:1.5px solid currentColor;
  cursor:pointer; z-index:4;
  transition:background .15s;
  font-size:9px; font-weight:900; line-height:1;
  opacity:.9; flex-shrink:0;
}
.wcal-event-check:hover { opacity:1; transform:scale(1.15); }
.wcal-event-check.checked { background:currentColor; }
.wcal-event-check.checked::after { content:'✓'; color:#080c1a; }
/* Recurring badge — pinned top-right, always visible pill */
.wcal-recur-badge {
  position:absolute; top:3px; right:4px;
  width:14px; height:14px; border-radius:50%;
  background:rgba(0,0,0,.35); border:1px solid currentColor;
  display:flex; align-items:center; justify-content:center;
  font-size:9px; font-weight:900; z-index:5;
  pointer-events:none; line-height:1; opacity:.95;
  box-shadow:0 0 0 1px rgba(0,0,0,.3);
}
.wcal-event-row { display:flex; align-items:center; min-width:0; width:100%; padding-right:14px; }
.wcal-event-title { white-space:nowrap; overflow:hidden; text-overflow:ellipsis; flex:1; transition:text-decoration .18s; }
.wcal-event-time { font-size:11px; opacity:.75; padding-left:0; }
.wcal-now-line { position:absolute; left:0; right:0; height:2px; background:#ef4444; z-index:6; pointer-events:none; }
.wcal-now-dot { position:absolute; left:-4px; top:-4px; width:10px; height:10px; border-radius:50%; background:#ef4444; }
/* Sidebar mini-month */
.wcal-mini-month { font-size:11px; }
.wcal-mini-header { display:flex; align-items:center; justify-content:space-between; margin-bottom:4px; }
.wcal-mini-month-label { font-size:12px; font-weight:700; color:#c4b5fd; }
.wcal-mini-nav { background:transparent; border:none; color:rgba(148,163,184,.6); cursor:pointer; font-size:13px; padding:2px 4px; }
.wcal-mini-grid { display:grid; grid-template-columns:repeat(7,1fr); gap:1px; }
.wcal-mini-day { text-align:center; padding:3px 1px; font-size:11px; border-radius:4px; cursor:pointer; color:rgba(180,200,240,.85); }
.wcal-mini-day:hover { background:rgba(124,58,237,.2); color:#c4b5fd; }
.wcal-mini-day.today { background:rgba(124,58,237,.6); color:#fff; border-radius:50%; }
.wcal-mini-day.selected { background:rgba(59,130,246,.4); color:#93c5fd; border-radius:50%; }
.wcal-mini-day.has-events::after { content:''; display:block; width:4px; height:4px; border-radius:50%; background:#7c3aed; margin:1px auto 0; }
.wcal-mini-wd { font-size:11px; color:rgba(100,116,139,.5); text-align:center; padding:2px 0; }
/* Quick-add form in sidebar */
.wcal-add-form { background:rgba(14,22,48,.7); border:1px solid rgba(42,58,106,.6); border-radius:10px; padding:10px; }
.wcal-add-tabs { display:flex; gap:4px; margin-bottom:8px; }
.wcal-add-tab { flex:1; background:rgba(7,10,20,.5); border:1px solid rgba(42,58,106,.5); color:rgba(180,196,255,.8); border-radius:6px; padding:4px; font-size:12px; font-weight:600; cursor:pointer; text-align:center; }
.wcal-add-tab.active { background:rgba(124,58,237,.3); border-color:rgba(124,58,237,.6); color:#c4b5fd; }
.wcal-add-label { font-size:12px; font-weight:600; color:rgba(196,181,253,.8); margin-bottom:6px; }
.wcal-field { width:100%; background:rgba(20,30,60,.7); border:1px solid rgba(80,110,180,.45); border-radius:7px; padding:5px 8px; font-size:13px; color:#e2e8f0; margin-bottom:5px; outline:none; box-sizing:border-box; }
.wcal-field:focus { border-color:rgba(124,58,237,.6); }
.wcal-submit { width:100%; background:rgba(124,58,237,.4); border:1px solid rgba(124,58,237,.6); color:#c4b5fd; border-radius:7px; padding:6px; font-size:12px; font-weight:600; cursor:pointer; }
.wcal-submit:hover { background:rgba(124,58,237,.6); }
.wcal-status { font-size:12px; color:rgba(148,163,184,.6); margin-top:4px; min-height:14px; }
.wcal-section-title { font-size:11px; font-weight:700; color:rgba(160,185,240,.75); text-transform:uppercase; letter-spacing:.08em; margin-bottom:4px; }
.wcal-upcoming { font-size:11px; }
.wcal-upcoming-item { padding:4px 0; border-bottom:1px solid rgba(42,58,106,.25); cursor:pointer; }
.wcal-upcoming-item:hover { color:#c4b5fd; }
.wcal-upcoming-time { font-size:11px; color:rgba(148,168,210,.8); }
.wcal-upcoming-title { color:rgba(226,232,240,.9); font-size:12px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
/* Detail Panel (Motion-style right sidebar) */
.wcal-detail { position:absolute; top:0; right:0; bottom:0; width:300px; background:#131e3a; border-left:1px solid rgba(42,58,106,.7); display:flex; flex-direction:column; z-index:200; transform:translateX(100%); transition:transform .22s cubic-bezier(.4,0,.2,1); box-shadow:-6px 0 30px rgba(0,0,0,.5); }
.wcal-detail.open { transform:translateX(0); }
.wcal-detail-header { display:flex; align-items:center; justify-content:space-between; padding:12px 14px 8px; border-bottom:1px solid rgba(42,58,106,.5); flex-shrink:0; }
.wcal-detail-type { font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.08em; color:rgba(180,200,240,.85); }
.wcal-detail-close { background:transparent; border:none; color:rgba(148,163,184,.6); font-size:18px; cursor:pointer; padding:2px 6px; border-radius:4px; }
.wcal-detail-close:hover { background:rgba(255,255,255,.08); color:#e2e8f0; }
.wcal-detail-body { flex:1; overflow-y:auto; padding:12px 14px; display:flex; flex-direction:column; gap:10px; }
.wcal-detail-title { font-size:16px; font-weight:700; color:#e2e8f0; background:transparent; border:none; border-bottom:1px solid rgba(42,58,106,.5); padding:4px 0; width:100%; outline:none; }
.wcal-detail-title:focus { border-color:rgba(124,58,237,.7); }
.wcal-detail-label { font-size:11px; font-weight:700; color:rgba(160,185,240,.8); text-transform:uppercase; letter-spacing:.06em; margin-bottom:3px; }
.wcal-detail-value { font-size:12px; color:#e2e8f0; }
.wcal-detail-field { width:100%; background:rgba(20,30,60,.7); border:1px solid rgba(80,110,180,.45); border-radius:7px; padding:5px 8px; font-size:12px; color:#e2e8f0; outline:none; box-sizing:border-box; }
.wcal-detail-field:focus { border-color:rgba(124,58,237,.6); }
.wcal-detail-textarea { width:100%; background:rgba(7,10,20,.6); border:1px solid rgba(42,58,106,.6); border-radius:7px; padding:6px 8px; font-size:12px; color:#e2e8f0; outline:none; resize:vertical; min-height:70px; box-sizing:border-box; }
.wcal-detail-textarea:focus { border-color:rgba(124,58,237,.6); }
.wcal-detail-row { display:flex; gap:8px; align-items:center; }
.wcal-detail-status { display:flex; align-items:center; gap:8px; }
.wcal-done-toggle { display:flex; align-items:center; gap:6px; cursor:pointer; padding:5px 10px; border-radius:8px; border:1px solid rgba(42,58,106,.6); background:rgba(14,22,48,.7); font-size:12px; color:#e2e8f0; font-weight:600; user-select:none; }
.wcal-done-toggle:hover { border-color:rgba(124,58,237,.5); }
.wcal-done-toggle.done { border-color:rgba(16,185,129,.5); background:rgba(16,185,129,.1); color:#6ee7b7; }
.wcal-detail-actions { display:flex; gap:8px; margin-top:4px; flex-wrap:wrap; }
.wcal-det-btn { flex:1; padding:7px; border-radius:8px; border:1px solid rgba(42,58,106,.6); background:rgba(14,22,48,.7); color:#c4b5fd; font-size:12px; font-weight:600; cursor:pointer; }
.wcal-det-btn:hover { background:rgba(30,40,80,.9); }
.wcal-det-btn.primary { background:rgba(124,58,237,.4); border-color:rgba(124,58,237,.6); color:#f3e8ff; }
.wcal-det-btn.primary:hover { background:rgba(124,58,237,.65); }
.wcal-det-btn.danger { background:rgba(239,68,68,.15); border-color:rgba(239,68,68,.4); color:#fca5a5; }
.wcal-det-btn.danger:hover { background:rgba(239,68,68,.3); }
.wcal-meet-badge { display:inline-flex; align-items:center; gap:5px; background:rgba(59,130,246,.15); border:1px solid rgba(59,130,246,.35); border-radius:6px; padding:3px 8px; font-size:11px; color:#93c5fd; font-weight:600; cursor:pointer; text-decoration:none; }
.wcal-meet-badge:hover { background:rgba(59,130,246,.3); }
/* Video conference buttons in sidebar + detail panel */
.wcal-conf-row { display:flex; gap:6px; margin-bottom:5px; }
.wcal-conf-btn { flex:1; display:flex; align-items:center; justify-content:center; gap:5px; padding:6px 4px; border-radius:7px; border:1px solid rgba(42,58,106,.6); background:rgba(14,22,48,.7); color:rgba(196,181,253,.8); font-size:11px; font-weight:600; cursor:pointer; transition:background .15s,border-color .15s; }
.wcal-conf-btn:hover { background:rgba(30,40,80,.9); border-color:rgba(124,58,237,.5); }
.wcal-conf-btn.active-meet { background:rgba(26,115,232,.2); border-color:rgba(26,115,232,.6); color:#93c5fd; }
.wcal-conf-btn.active-zoom { background:rgba(45,140,255,.18); border-color:rgba(45,140,255,.55); color:#7dd3fc; }
.wcal-zoom-input { display:none; margin-top:4px; }
.wcal-zoom-input.show { display:block; }
.wcal-join-btn { display:inline-flex; align-items:center; gap:6px; padding:6px 12px; border-radius:8px; font-size:12px; font-weight:700; text-decoration:none; border:1px solid; cursor:pointer; }
.wcal-join-meet { background:rgba(26,115,232,.2); border-color:rgba(26,115,232,.6); color:#93c5fd; }
.wcal-join-zoom { background:rgba(45,140,255,.18); border-color:rgba(45,140,255,.55); color:#7dd3fc; }
.wcal-join-meet:hover { background:rgba(26,115,232,.4); }
.wcal-join-zoom:hover { background:rgba(45,140,255,.35); }
.wcal-autocomplete-section { background:rgba(16,185,129,.08); border:1px solid rgba(16,185,129,.25); border-radius:10px; padding:10px 12px; margin-top:4px; }
.wcal-autocomplete-title { font-size:10px; font-weight:700; color:rgba(110,231,183,.9); text-transform:uppercase; letter-spacing:.07em; margin-bottom:8px; display:flex; align-items:center; gap:6px; }
.wcal-autocomplete-title::before { content:'⚡'; font-size:12px; }
.wcal-automail-status { font-size:11px; color:rgba(110,231,183,.8); margin-top:6px; min-height:16px; font-style:italic; }
.wcal-priority-pill { display:inline-block; padding:2px 8px; border-radius:999px; font-size:10px; font-weight:700; letter-spacing:.04em; }
.wcal-priority-pill.high { background:rgba(239,68,68,.2); color:#fca5a5; border:1px solid rgba(239,68,68,.35); }
.wcal-priority-pill.medium { background:rgba(245,158,11,.18); color:#fcd34d; border:1px solid rgba(245,158,11,.3); }
.wcal-priority-pill.low { background:rgba(16,185,129,.15); color:#6ee7b7; border:1px solid rgba(16,185,129,.3); }
/* Tasks: solid left stripe + diamond shape to distinguish from events */
/* Tasks: default = purple (medium priority is yellow, default is purple = high) */
.wcal-event[data-etype="task"] {
  background: rgba(99,102,241,.75) !important;  /* purple — default */
  color: #e0e7ff !important;
  border-left: 3px solid rgba(129,140,248,.95) !important;
  border-radius: 4px 6px 6px 4px;
}
/* HIGH priority = purple (same as default, distinct via brighter stripe) */
.wcal-event[data-etype="task"].task-prio-high {
  background: rgba(109,40,217,.80) !important;  /* deep purple */
  color: #ede9fe !important;
  border-left-color: rgba(167,139,250,.95) !important;
}
/* MEDIUM priority = yellow/amber */
.wcal-event[data-etype="task"].task-prio-medium {
  background: rgba(161,98,7,.78) !important;    /* amber/gold */
  color: #fef9c3 !important;
  border-left-color: rgba(234,179,8,.95) !important;
}
/* LOW priority = green */
.wcal-event[data-etype="task"].task-prio-low {
  background: rgba(6,95,70,.78) !important;     /* green */
  color: #d1fae5 !important;
  border-left-color: rgba(16,185,129,.95) !important;
}
/* Done tasks go grey regardless of priority — but stay visible with strikethrough */
.wcal-event[data-etype="task"].is-done {
  background: rgba(30,40,70,.75) !important;
  color: rgba(160,180,220,.75) !important;
  border-left-color: rgba(100,120,180,.4) !important;
}
/* Events: rounded pill corners, no left stripe */
.wcal-event[data-etype="event"] { border-radius:7px; }
/* Dragging: the original block dims in-place (no ghost clone) */
.wcal-event[style*="cursor: grabbing"] { outline:2px solid rgba(167,139,250,.7); }
/* Detail panel: task=indigo header, event=blue header */
.wcal-detail-header.type-task  { border-bottom-color:rgba(99,102,241,.5); }
.wcal-detail-header.type-event { border-bottom-color:rgba(59,130,246,.5); }
.wcal-detail-type.type-task  { color:#a5b4fc; }
.wcal-detail-type.type-event { color:#93c5fd; }
</style>

<div class="wcal-wrap" id="wcalWrap">

  <!-- LEFT SIDEBAR -->
  <div class="wcal-sidebar">

    <!-- Mini month -->
    <div class="wcal-mini-month">
      <div class="wcal-mini-header">
        <button class="wcal-mini-nav" id="wcalMiniPrev">&#8249;</button>
        <span class="wcal-mini-month-label" id="wcalMiniLabel">April 2026</span>
        <button class="wcal-mini-nav" id="wcalMiniNext">&#8250;</button>
      </div>
      <div class="wcal-mini-grid" id="wcalMiniGrid"></div>
    </div>

    <div style="border-top:1px solid rgba(42,58,106,.4);"></div>

    <!-- Quick add -->
    <div class="wcal-add-form">
      <div class="wcal-add-tabs">
        <div class="wcal-add-tab active" id="wcalTabEvent" onclick="wcalSwitchAddTab('event')">Event</div>
        <div class="wcal-add-tab" id="wcalTabTask" onclick="wcalSwitchAddTab('task')">Task</div>
      </div>
      <!-- Event fields -->
      <div id="wcalAddEventFields">
        <input class="wcal-field" id="wcalAddTitle" placeholder="Event title" autocomplete="off" data-lpignore="true" />
        <input class="wcal-field" id="wcalAddDate" type="date" />
        <div style="display:flex;gap:5px;">
          <input class="wcal-field" id="wcalAddStart" type="time" value="09:00" style="flex:1;" />
          <select class="wcal-field" id="wcalAddDur" style="flex:1;">
            <option value="30">30m</option>
            <option value="60" selected>1h</option>
            <option value="90">1.5h</option>
            <option value="120">2h</option>
            <option value="180">3h</option>
          </select>
        </div>
        <input class="wcal-field" id="wcalAddAttendees" placeholder="Invite emails (comma sep)" autocomplete="off" />
        <div class="wcal-conf-row">
          <button class="wcal-conf-btn" id="wcalAddMeetBtn" onclick="wcalToggleConf('meet')" title="Schedule a Google Meet call — a Meet link will be added to the event">
            📹 Google Meet
          </button>
          <button class="wcal-conf-btn" id="wcalAddZoomBtn" onclick="wcalToggleConf('zoom')" title="Add a Zoom meeting link to this event">
            🔵 Zoom
          </button>
        </div>
        <input class="wcal-field wcal-zoom-input" id="wcalAddZoomUrl" placeholder="Paste Zoom meeting URL…" autocomplete="off" />
        <input type="hidden" id="wcalAddMeet" value="" />
        <button class="wcal-submit" id="wcalAddBtn">Create event</button>
      </div>
      <!-- Task fields -->
      <div id="wcalAddTaskFields" style="display:none;">
        <input class="wcal-field" id="wcalTaskTitle" placeholder="Task title" autocomplete="off" data-lpignore="true" />
        <input class="wcal-field" id="wcalTaskDate" type="date" />
        <div style="display:flex;gap:5px;">
          <input class="wcal-field" id="wcalTaskStart" type="time" value="09:00" style="flex:1;" />
          <select class="wcal-field" id="wcalTaskDur" style="flex:1;">
            <option value="15">15m</option>
            <option value="30" selected>30m</option>
            <option value="60">1h</option>
            <option value="90">1.5h</option>
          </select>
        </div>
        <select class="wcal-field" id="wcalTaskPriority">
          <option value="medium" selected>Medium priority</option>
          <option value="high">High priority</option>
          <option value="low">Low priority</option>
        </select>
        <select class="wcal-field" id="wcalTaskRecurring">
          <option value="none" selected>Does not repeat</option>
          <option value="daily">Daily</option>
          <option value="weekly">Weekly</option>
          <option value="biweekly">Every 2 weeks</option>
          <option value="monthly">Monthly</option>
        </select>
        <button class="wcal-submit" id="wcalAddTaskBtn">Add task</button>
      </div>
      <div class="wcal-status" id="wcalAddStatus"></div>
    </div>

    <div style="border-top:1px solid rgba(42,58,106,.4);"></div>

    <!-- Upcoming -->
    <div>
      <div class="wcal-section-title">Upcoming</div>
      <div class="wcal-upcoming" id="wcalUpcoming">
        <div class="wcal-upcoming-time">Loading...</div>
      </div>
    </div>

    <div class="wcal-status" id="calLoadStatus"></div>

  </div>

  <!-- MAIN CALENDAR -->
  <div class="wcal-main">

    <!-- Top nav bar -->
    <div class="wcal-topbar">
      <button class="wcal-nav-btn" id="calPrevBtn">&#8249;</button>
      <button class="wcal-nav-btn today" id="calTodayBtn">Today</button>
      <button class="wcal-nav-btn" id="calNextBtn">&#8250;</button>
      <span class="wcal-range-label" id="wcalRangeLabel">Week</span>
      <div class="wcal-view-btns">
        <button class="wcal-view-btn active" id="wcalViewWeek" onclick="wcalSetView('week')">Week</button>
        <button class="wcal-view-btn" id="wcalViewDay" onclick="wcalSetView('day')">Day</button>
      </div>
    </div>

    <!-- Week/Day grid -->
    <div class="wcal-grid-wrap" id="wcalGridWrap">
      <div class="wcal-grid" id="wcalGrid"><!-- Rendered by JS --></div>
    </div>

  </div>

  <!-- DETAIL PANEL (Motion-style) -->
  <div class="wcal-detail" id="wcalDetail">
    <div class="wcal-detail-header">
      <span class="wcal-detail-type" id="wcalDetType">EVENT</span>
      <button class="wcal-detail-close" id="wcalDetClose" title="Close">&#x2715;</button>
    </div>
    <div class="wcal-detail-body" id="wcalDetBody">
      <!-- Populated by JS -->
    </div>
  </div>

</div>

<!-- Click-to-create popover (double-click on grid) -->
<div id="wcalPopover" style="
  position:fixed;z-index:9999;display:none;
  background:#0d1120;border:1px solid rgba(124,58,237,.55);
  border-radius:14px;padding:16px;min-width:250px;
  box-shadow:0 12px 48px rgba(0,0,0,.75);
  flex-direction:column;gap:10px;
  animation:wcalPopIn .14s ease;
">
<style>
@keyframes wcalPopIn{from{opacity:0;transform:scale(.93)}to{opacity:1;transform:scale(1)}}
.wcp-tabs{display:flex;gap:5px;margin-bottom:2px;}
.wcp-tab{flex:1;padding:5px;border-radius:7px;border:1px solid rgba(42,58,106,.6);background:rgba(14,22,48,.7);color:rgba(148,163,184,.7);font-size:11px;font-weight:700;cursor:pointer;text-align:center;}
.wcp-tab.active{background:rgba(124,58,237,.3);border-color:rgba(124,58,237,.6);color:#c4b5fd;}
.wcp-field{width:100%;background:rgba(7,10,20,.7);border:1px solid rgba(42,58,106,.6);border-radius:7px;padding:7px 9px;font-size:12px;color:#e2e8f0;outline:none;box-sizing:border-box;}
.wcp-field:focus{border-color:rgba(124,58,237,.6);}
.wcp-row{display:flex;gap:6px;}
.wcp-btn{flex:1;padding:8px;border-radius:8px;background:rgba(124,58,237,.4);border:1px solid rgba(124,58,237,.6);color:#f3e8ff;font-size:12px;font-weight:700;cursor:pointer;}
.wcp-btn:hover{background:rgba(124,58,237,.65);}
.wcp-cancel{flex:0 0 auto;padding:8px 14px;border-radius:8px;background:transparent;border:1px solid rgba(42,58,106,.5);color:rgba(148,163,184,.6);font-size:12px;cursor:pointer;}
.wcp-cancel:hover{border-color:rgba(148,163,184,.4);color:#e2e8f0;}
.wcp-label{font-size:10px;font-weight:700;color:rgba(100,116,139,.6);text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px;}
.wcp-hint{font-size:10px;color:rgba(100,116,139,.45);text-align:center;}
</style>
  <div style="display:flex;align-items:center;justify-content:space-between;">
    <span style="font-size:12px;font-weight:700;color:#c4b5fd;" id="wcalPopLabel">New entry</span>
    <button onclick="wcalPopClose()" style="background:none;border:none;color:rgba(148,163,184,.5);font-size:17px;cursor:pointer;line-height:1;padding:0 2px;">&times;</button>
  </div>
  <div class="wcp-tabs">
    <div class="wcp-tab active" id="wcalPopTabEvent" onclick="wcalPopSwitch('event')">📅 Event</div>
    <div class="wcp-tab" id="wcalPopTabTask"  onclick="wcalPopSwitch('task')">☑ Task</div>
  </div>
  <div>
    <div class="wcp-label">Title</div>
    <input class="wcp-field" id="wcalPopTitle" placeholder="What's this?" autocomplete="off" />
  </div>
  <div class="wcp-row">
    <div style="flex:1;">
      <div class="wcp-label">Time</div>
      <input class="wcp-field" id="wcalPopTime" type="time" />
    </div>
    <div style="flex:1;">
      <div class="wcp-label">Duration</div>
      <select class="wcp-field" id="wcalPopDur">
        <option value="30">30 min</option>
        <option value="60" selected>1 hour</option>
        <option value="90">1.5 hrs</option>
        <option value="120">2 hours</option>
      </select>
    </div>
  </div>
  <div id="wcalPopTaskExtras" style="display:none;">
    <div class="wcp-label">Priority</div>
    <select class="wcp-field" id="wcalPopPriority">
      <option value="medium" selected>Medium</option>
      <option value="high">High</option>
      <option value="low">Low</option>
    </select>
  </div>
  <div class="wcp-row">
    <button class="wcp-btn" id="wcalPopCreate">Create</button>
    <button class="wcp-cancel" onclick="wcalPopClose()">Cancel</button>
  </div>
  <div class="wcp-hint">Double-click anywhere on the grid to create &nbsp;·&nbsp; Esc to cancel</div>
</div>

<!-- Hidden backward-compat inputs -->
<input id="calTaskTitle" type="hidden" />
<input id="calTaskTime" type="hidden" value="17:00" />
<input id="calCallTitle" type="hidden" value="Strategy call" />
<input id="calCallTime" type="hidden" value="09:00" />
<select id="calCallDur" style="display:none;"><option value="60">60</option></select>
<div id="calSelectedLabel" style="display:none;"></div>
<div id="calSelectedSub" style="display:none;"></div>
<div id="calDayEvents" style="display:none;"></div>
<div id="calMonthLabel" style="display:none;"></div>
<div id="calWeekdays" style="display:none;"></div>
<div id="calGrid_old" style="display:none;"></div>

</div>

<img id="modalImg" class="imgPreview" alt="Preview"/>
            </div>
          </div>
        </div>


        <div class="tableWrap" id="tableWrap">
          <div class="table" id="tableCore">
            <div class="runes"></div>
          </div>

          <div class="operator" id="operator">
            <div class="opHead">
              <div class="opTitle">
                <div class="t1">Group Console (All Teammates)</div>
                <div class="t2">Send one prompt here to trigger answers from everyone.</div>
              </div>
              <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
                <button class="btn btnMini" id="assembleBtn2">Assemble</button>
                <button class="btn btnMini" id="talkGroupBtn">Talk</button>
                <!-- CHANGE: Always Listening toggle (group) -->
                <button class="btn btnMini" id="alwaysListenGroupBtn">Always listen</button>
                <button class="btn btnMini" id="lightingModeBtn">Lighting mode</button>
                <button class="btn btnMini" id="screenGroupBtn">Share screen</button>
                <button class="btn btnPrimary" id="conveneAll">Send to all</button>
              </div>
            </div>

            <textarea class="opText" id="opPrompt" placeholder="Type a group prompt for the entire table. To assemble only, say: All teammates to the round table" autocomplete="off" autocapitalize="off" autocorrect="off" data-lpignore="true" data-1p-ignore="true" data-bwi-ignore="true"></textarea>

            <div class="passRow" id="groupPassRow">
              <button class="btn btnMini passBtn" id="passGroupRisk" title="Run Risk Assessment on the most recent group output">🔍 Risk</button>
              <button class="btn btnMini passBtn" id="passGroupScale" title="Run Scalability Ranking on the most recent group output">📈 Scale</button>
              <button class="btn btnMini passBtn" id="passGroupFail" title="Run Failure Simulator on the most recent group output">💥 Failure</button>              <button class="btn btnMini passBtn" id="passGroupConstr" title="Run Constraint Scan on the most recent group output">🧩 Constraints</button>
              <button class="btn btnMini passBtn" id="passGroupOpt" title="Run Optimization Pass on the most recent group output">⚡ Optimize</button>
              <div class="tiny" style="opacity:.9;">Runs on the latest group replies.</div>
            </div>

            <div class="pillRow">
              <input type="file" id="groupFiles" multiple style="display:none" />
              <button class="btn btnMini" id="pickGroupFiles">Upload files</button>
              <div class="tiny" id="uploadHint">Attach files or use Share screen to capture a screenshot.</div>
            </div>
            <div id="groupAttachList" class="pillRow"></div>

            <div class="opRow">
              <div class="tiny" id="opStatus">Ready</div>
              <div class="tiny" id="opHint">Say a teammate name while always listening to switch seats instantly.</div>
            </div>
            <div class="tiny" id="micStatusGroup" style="margin-top:8px;">Mic: idle</div>
          </div>

        </div>
      </div>

      <div class="underTable">
        <div class="groupCard">
          <div class="sideHead">
            <div class="sideTitle">
              <div class="h1">Group Replies</div>
              <div class="h2">Last round table responses in one place.</div>
            </div>
            <button class="btn" id="clearGroup">Clear</button>
          </div>
          <div class="groupReplies" id="groupReplies">
            <div class="tiny">No group replies yet. Use the center Group Console.</div>
          </div>
        </div>

        <!-- Shared Team Memory panel -->
        <div class="groupCard" id="sharedMemoryCard" style="margin-top:12px;display:none;">
          <div class="sideHead">
            <div class="sideTitle">
              <div class="h1">🧠 Shared Team Memory</div>
              <div class="h2">Facts, decisions, and open loops extracted from group sessions.</div>
            </div>
            <button class="btn btnMini" id="clearSharedMemoryBtn">Clear</button>
          </div>
          <div id="sharedMemoryBody" style="padding:8px 4px;font-size:12px;line-height:1.6;color:rgba(182,196,255,.85);">
          </div>
        </div>
      </div>
    </div>

    <div class="side">
      <div class="sideCard" style="display:flex;flex-direction:column;height:calc(100vh - 80px);overflow:hidden;">
        <!-- Header -->
        <div class="sideHead" style="flex-shrink:0;">
          <div class="sideTitle">
            <div class="h1" id="seatTitle">Select a seat</div>
            <div class="h2" id="seatSub">Click any teammate for individual chat.</div>
          </div>
          <button class="btn" id="refreshThread">Refresh</button>
        </div>
        <!-- Pass row -->
        <div class="passRow" id="seatPassRow" style="margin:6px 0;flex-shrink:0;">
          <button class="btn btnMini passBtn" id="passSeatRisk" title="Risk Assessment">🔍 Risk</button>
          <button class="btn btnMini passBtn" id="passSeatScale" title="Scalability">📈 Scale</button>
          <button class="btn btnMini passBtn" id="passSeatFail" title="Failure Simulator">💥 Failure</button>
          <button class="btn btnMini passBtn" id="passSeatConstr" title="Constraints">🧩 Constraints</button>
          <button class="btn btnMini passBtn" id="passSeatOpt" title="Optimize">⚡ Optimize</button>
        </div>
        <!-- Thread actions toolbar -->
        <div class="pillRow" id="threadActionsRow" style="flex-shrink:0;gap:6px;margin-bottom:4px;display:none;">
          <button class="btn btnMini" id="branchSnapshotBtn" title="Save a named snapshot of this conversation">🌿 Snapshot</button>
          <select id="branchSelector" title="Restore a saved snapshot" style="background:rgba(11,16,36,.9);color:var(--text);border:1px solid rgba(42,58,106,.7);border-radius:8px;padding:4px 7px;font-size:11px;max-width:130px;">
            <option value="">Snapshots…</option>
          </select>
          <button class="btn btnMini" id="exportThreadBtn" title="Export conversation as HTML">📄 Export</button>
          <button class="btn btnMini" id="shareThreadBtn" title="Create read-only share link">🔗 Share</button>
          <span id="ragIndexStatus" class="sa-rag-pill" style="display:none;" title="Knowledge base active for this conversation">🔬 RAG</span>
        </div>
        <!-- Thread scrolls -->
        <div class="thread" id="thread" style="flex:1;height:auto;min-height:80px;overflow-y:auto;"></div>
        <!-- Sticky input area -->
        <div style="flex-shrink:0;border-top:1px solid rgba(42,58,106,.5);padding-top:10px;margin-top:8px;">
          <textarea class="followBox" id="followMsg" placeholder="Message selected teammate..." style="height:70px;resize:none;" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" data-lpignore="true" data-1p-ignore="true" data-bwi-ignore="true"></textarea>
          <div class="pillRow" style="margin-top:6px;">
            <input type="file" id="dmFiles" multiple style="display:none" />
            <button class="btn btnMini" id="pickDmFiles">📎 Files</button>
            <button class="btn btnMini" id="screenDmBtn">🖥 Screen</button>
            <button class="btn btnMini" id="talkDmBtn">🎤 Talk</button>
            <button class="btn btnMini" id="alwaysListenDmBtn">👂 Listen</button>
            <button class="btn btnPrimary" id="sendFollow" style="margin-left:auto;">Send ↵</button>
            <button class="btn btnMini" id="streamToggleBtn" title="Toggle streaming mode — watch tokens arrive in real time" style="margin-left:4px;border-color:rgba(99,102,241,.5);">⚡ Stream</button>
          </div>
          <div id="dmAttachList" class="pillRow"></div>
          <div class="tiny" id="micStatusDm" style="margin-top:4px;">Mic: idle</div>
        </div>
      </div>

    </div>


  <!-- Message Expand Modal -->
  <div id="saMsgModal" style="position:fixed;inset:0;z-index:99998;background:rgba(0,0,0,.75);backdrop-filter:blur(4px);align-items:center;justify-content:center;" onclick="if(event.target===this)saCloseMsgModal()">
    <div style="background:rgba(10,14,30,.98);border:1px solid rgba(42,58,106,.9);border-radius:18px;width:min(860px,92vw);max-height:85vh;display:flex;flex-direction:column;overflow:hidden;box-shadow:0 24px 80px rgba(0,0,0,.7);">
      <div style="display:flex;align-items:center;justify-content:space-between;padding:12px 18px;border-bottom:1px solid rgba(42,58,106,.6);">
        <span id="saMsgModalTitle" style="font-weight:700;font-size:14px;color:#c4b5fd;">Response</span>
        <div style="display:flex;gap:8px;">
          <button onclick="if(typeof saCopyMsgModal==='function')saCopyMsgModal()" style="background:rgba(42,58,106,.6);border:1px solid rgba(124,58,237,.4);color:#a5b4fc;border-radius:7px;padding:4px 12px;font-size:12px;cursor:pointer;">Copy</button>
          <button onclick="if(typeof saCloseMsgModal==='function')saCloseMsgModal()" style="background:rgba(180,30,60,.3);border:1px solid rgba(239,68,68,.4);color:#fca5a5;border-radius:7px;padding:4px 12px;font-size:12px;cursor:pointer;">✕ Close</button>
        </div>
      </div>
      <div id="saMsgModalBody" style="flex:1;overflow-y:auto;padding:20px 24px;font-size:15px;line-height:1.7;white-space:pre-wrap;color:#e2e8f0;"></div>
    </div>
  </div>

  <!-- Fullscreen image viewer (additive) -->
  <div id="lightbox" style="display:none; position:fixed; inset:0; background:rgba(0,0,0,.92); z-index:99999; align-items:center; justify-content:center; padding:20px;">
    <div style="position:absolute; top:14px; right:14px;">
      <button class="btn" id="lightboxCloseBtn">Close</button>
    </div>
    <img id="lightboxImg" src="" alt="Full screen" style="max-width:96vw; max-height:92vh; border-radius:16px; box-shadow:0 20px 80px rgba(0,0,0,.6);" />
  </div>

<script>

if (typeof window.showToast !== "function") {
  window.showToast = function(msg, type) {
    try {
      const el = document.createElement("div");
      el.textContent = msg;

      el.style.position = "fixed";
      el.style.bottom = "20px";
      el.style.right = "20px";
      el.style.padding = "10px 14px";
      el.style.borderRadius = "8px";
      el.style.fontSize = "14px";
      el.style.zIndex = 999999;

      if (type === "error") {
        el.style.background = "#7f1d1d";
        el.style.color = "#fff";
      } else {
        el.style.background = "#1f2937";
        el.style.color = "#fff";
      }

      document.body.appendChild(el);

      setTimeout(() => {
        el.remove();
      }, 3000);

    } catch (e) {
      alert(msg);
    }
  };
}


    const POS = [
      {x: 50, y: 4},
      {x: 77, y: 12},
      {x: 88, y: 40},
      {x: 77, y: 68},
      {x: 50, y: 78},
      {x: 23, y: 68},
      {x: 12, y: 40},
      {x: 23, y: 12}
    ];

    const STORE_KEY = "round_table_seat_positions_v1";
    const MODAL_POS_KEY = "round_table_modal_pos_v1";
    const MODAL_SIZE_KEY = "round_table_modal_size_v1";

    let state = null;
    let selectedSeat = "";
    window.selectedSeat = "";  // expose for cross-IIFE access (streaming, branching, etc.)
    let seatStatus = {};
    let lastGroupOutputs = {};
    let lastSeatAssistantText = "";
    let lastEmailDraftBy = "";
    let lastSmsDraftBy = "";
    let leadHandoffState = null;
    let lastImageState = {};

    let groupFileIds = [];
    let dmFileIds = [];

    let assemblyPulseActive = false;

    let editingTeammate = "";
    let modalMinimized = false;
    let modalDragging = false;

    let manageDraftActive = [];

    // =========================
    // CHANGE: ALWAYS LISTENING + VOICE NAME SWITCHING
    // =========================
    let alwaysOn = false;
    let alwaysMode = "dm"; // "dm" or "group"
    let alwaysRec = null;
    let alwaysBaseText = "";
    let alwaysFinalText = "";
    let alwaysInterimText = "";
    let lastNameSwitchAt = 0;

    // UPDATE: prevent duplication by deriving a canonical final transcript from event.results
    // and only displaying the delta after a teammate name switch.
    let alwaysFinalBaseline = "";

    const $ = (id) => document.getElementById(id);

    function escapeHtml(str){
      const s = (str === null || str === undefined) ? '' : String(str);
      return s
        .replace(/&/g,'&amp;')
        .replace(/</g,'&lt;')
        .replace(/>/g,'&gt;')
        .replace(/"/g,'&quot;')
        .replace(/'/g,'&#39;');
    }


    function isAssemblyPhrase(p){
      const s = (p || "").trim().toLowerCase();
      const triggers = [
        "all teammates to the round table",
        "all teammates to round table",
        "assemble the round table",
        "round table roll call",
        "roll call"
      ];
      return triggers.some(t => s.includes(t));
    }

    function loadModalPos(){
      try{
        const raw = localStorage.getItem(MODAL_POS_KEY);
        if(!raw) return null;
        const obj = JSON.parse(raw);
        if(!obj || typeof obj !== "object") return null;
        if(typeof obj.left !== "number" || typeof obj.top !== "number") return null;
        return obj;
      }catch(e){ return null; }
    }

    function loadModalSize(){
      try{
        const raw = localStorage.getItem(MODAL_SIZE_KEY);
        if(!raw) return null;
        const obj = JSON.parse(raw);
        if(!obj || typeof obj !== "object") return null;
        if(typeof obj.width !== "number" || typeof obj.height !== "number") return null;
        return obj;
      }catch(e){ return null; }
    }

    function saveModalSize(width, height){
      try{ localStorage.setItem(MODAL_SIZE_KEY, JSON.stringify({width, height})); }catch(e){}
    }

    function saveModalPos(left, top){
      try{
        localStorage.setItem(MODAL_POS_KEY, JSON.stringify({left, top}));
      }catch(e){}
    }

    
    function ensureModalMinSize(minW, minH){
      const win = $("modalWin");
      if(!win) return;
      const curW = parseInt((win.style.width || "0").replace("px","")) || win.getBoundingClientRect().width || 0;
      const curH = parseInt((win.style.height || "0").replace("px","")) || win.getBoundingClientRect().height || 0;
      const w = Math.max(curW, minW || 0);
      const h = Math.max(curH, minH || 0);
      win.style.width = w + "px";
      win.style.height = h + "px";
      try{ saveModalSize(w, h); }catch(e){}
    }

function applyModalPos(){
      const win = $("modalWin");
      if(!win) return;

      const saved = loadModalPos();
      const savedSize = loadModalSize();

      if(savedSize){
        // Clamp saved size so windows never reopen tiny.
        const maxW = Math.max(620, (window.innerWidth || 1200) - 24);
        const maxH = Math.max(520, (window.innerHeight || 800) - 120);
        const w = Math.min(Math.max(760, savedSize.width), maxW);
        const h = Math.min(Math.max(560, savedSize.height), maxH);
        win.style.width = w + "px";
        win.style.height = h + "px";
      } else {
        // Sensible defaults (no manual resizing needed)
        const w = Math.min(860, Math.max(760, (window.innerWidth || 1200) - 24));
        const h = Math.min(680, Math.max(560, (window.innerHeight || 800) - 120));
        win.style.width = w + "px";
        win.style.height = h + "px";
      }

      // If we have a saved position, clamp it so the modal never renders off-screen.
      if(saved){
        win.style.transform = "none";

        // Use current rendered size (after applying savedSize above) to clamp.
        const mw = Math.max(360, win.offsetWidth || 520);
        const mh = Math.max(260, win.offsetHeight || 420);

        const margin = 12;
        const maxLeft = Math.max(margin, (window.innerWidth || 1200) - mw - margin);
        const maxTop  = Math.max(margin, (window.innerHeight || 800) - mh - margin);

        const left = Math.min(Math.max(saved.left, margin), maxLeft);
        const top  = Math.min(Math.max(saved.top, margin), maxTop);

        win.style.left = left + "px";
        win.style.top  = top + "px";

        // If the saved position was out-of-bounds, persist the corrected one.
        if(left !== saved.left || top !== saved.top){
          saveModalPos(left, top);
        }
        return;
      }

      // Default centered position
      win.style.left = "50%";
      win.style.top = "80px";
      win.style.transform = "translateX(-50%)";
    }

    function hideAllModalForms(){
      if($("modalBody")) $("modalBody").style.display = "block";
      if($("modalForm")) $("modalForm").style.display = "none";
      if($("manageForm")) $("manageForm").style.display = "none";
      if($("createForm")) $("createForm").style.display = "none";
      if($("frameworkForm")) $("frameworkForm").style.display = "none";
      if($("settingsForm")) $("settingsForm").style.display = "none";
            if($("apiKeyHelpForm")) $("apiKeyHelpForm").style.display = "none";
      if($("crmForm")) $("crmForm").style.display = "none";
      if($("calendarForm")) $("calendarForm").style.display = "none";
      if($("emailConsoleForm")) $("emailConsoleForm").style.display = "none";
      if($("smsConsoleForm")) $("smsConsoleForm").style.display = "none";
      if($("leadHandoffForm")) $("leadHandoffForm").style.display = "none";
      if($("operatorProfileModalForm")) $("operatorProfileModalForm").style.display = "none";
      if($("sessionObjectiveForm")) $("sessionObjectiveForm").style.display = "none";
      if($("modalImg")) $("modalImg").style.display = "none";
    }

    
    // Fullscreen image viewer (additive)
    function openLightbox(url){
      const lb = $("lightbox");
      const im = $("lightboxImg");
      if(!lb || !im) return;
      im.src = url;
      lb.style.display = "flex";
    }
    function closeLightbox(){
      const lb = $("lightbox");
      const im = $("lightboxImg");
      if(im) im.src = "";
      if(lb) lb.style.display = "none";
    }

window.showModal = function showModal(title, body, imgUrl){
      $("modalTitle").innerText = title;
      $("modalBody").innerText = body || "";
      hideAllModalForms();
      if($("calendarForm")) $("calendarForm").style.display = "none";
      $("modalBody").style.display = "block";

      $("editStatus").innerText = "";
      editingTeammate = "";

      const img = $("modalImg");
      if(imgUrl){
        img.src = imgUrl;
        img.style.display = "block";
        img.style.cursor = "zoom-in";
        img.onclick = ()=> openLightbox(imgUrl);
      }else{
        img.src = "";
        img.style.display = "none";
      }

      modalMinimized = false;
      $("modalWin").classList.remove("minimized");
      $("minModal").style.display = "inline-block";
      $("restoreModal").style.display = "none";

      $("overlay").classList.add("show");
      applyModalPos();

      const sc = $("modalScroll");
      if(sc) sc.scrollTop = 0;
    }

    function showEditModal(title){
      $("modalTitle").innerText = title || "Edit teammate";
      $("modalBody").innerText = "";
      hideAllModalForms();
      $("modalBody").style.display = "none";
      $("modalForm").style.display = "block";

      modalMinimized = false;
      $("modalWin").classList.remove("minimized");
      $("minModal").style.display = "inline-block";
      $("restoreModal").style.display = "none";

      $("overlay").classList.add("show");
      applyModalPos();

      const sc = $("modalScroll");
      if(sc) sc.scrollTop = 0;
    }

    function showManageModal(){
      $("modalTitle").innerText = "Add or dismiss teammates";
      $("modalBody").innerText = "";
      hideAllModalForms();
      $("modalBody").style.display = "none";
      $("manageForm").style.display = "block";
      $("manageStatus").innerText = "";

      modalMinimized = false;
      $("modalWin").classList.remove("minimized");
      $("minModal").style.display = "inline-block";
      $("restoreModal").style.display = "none";

      $("overlay").classList.add("show");
      applyModalPos();

      const sc = $("modalScroll");
      if(sc) sc.scrollTop = 0;
    }

    function showCreateModal(){
      $("modalTitle").innerText = "Create teammate";
      $("modalBody").innerText = "";
      hideAllModalForms();
      $("modalBody").style.display = "none";
      $("createForm").style.display = "block";
      $("createStatus").innerText = "";

      $("newName").value = "";
      $("newVersion").value = "v1.0";
      $("newJobTitle").value = "";
      $("newMission").value = "";
      $("newGoal").value = "";
      $("newThinking").value = "";
      $("newResponsibilities").value = "";
      $("newWillNotDo").value = "";

      modalMinimized = false;
      $("modalWin").classList.remove("minimized");
      $("minModal").style.display = "inline-block";
      $("restoreModal").style.display = "none";

      $("overlay").classList.add("show");
      applyModalPos();

      const sc = $("modalScroll");
      if(sc) sc.scrollTop = 0;
    }

    function showFrameworkModal(){
      $("modalTitle").innerText = "Core framework";
      $("modalBody").innerText = "";
      hideAllModalForms();
      $("modalBody").style.display = "none";
      $("frameworkForm").style.display = "block";
      $("frameworkStatus").innerText = "Loading...";

      modalMinimized = false;
      $("modalWin").classList.remove("minimized");
      $("minModal").style.display = "inline-block";
      $("restoreModal").style.display = "none";

      $("overlay").classList.add("show");
      applyModalPos();

      const sc = $("modalScroll");
      if(sc) sc.scrollTop = 0;
    }

    function hideModal(){
      try{ document.body.style.overflow = ""; }catch(_){ }

      $("overlay").classList.remove("show");
      if(assemblyPulseActive){
        assemblyPulseActive = false;
        updateTablePulseFromStatuses();
      }
    }
    $("closeModal").onclick = hideModal;
    $("overlay").addEventListener("click", (e) => {
      if(e.target.id === "overlay") hideModal();
    });

    $("minModal").onclick = () => {
      modalMinimized = true;
      $("modalWin").classList.add("minimized");
      $("minModal").style.display = "none";
      $("restoreModal").style.display = "inline-block";
    };

    $("restoreModal").onclick = () => {
      modalMinimized = false;
      $("modalWin").classList.remove("minimized");
      $("minModal").style.display = "inline-block";
      $("restoreModal").style.display = "none";
    };

    (function initModalWindowControls(){
      const bar = $("modalBar");
      const win = $("modalWin");
      const grip = $("modalResizeGrip");
      if(!bar || !win) return;

      function clamp(v, min, max){ return Math.max(min, Math.min(max, v)); }
      function normalizeWinRect(){
        const r = win.getBoundingClientRect();
        win.style.transform = "none";
        win.style.right = "auto";
        win.style.bottom = "auto";
        win.style.left = r.left + "px";
        win.style.top = r.top + "px";
        return r;
      }
      function keepModalInView(){
        const r = win.getBoundingClientRect();
        const maxLeft = Math.max(8, window.innerWidth - r.width - 8);
        const maxTop = Math.max(8, window.innerHeight - r.height - 8);
        const left = clamp(r.left, 8, maxLeft);
        const top = clamp(r.top, 8, maxTop);
        win.style.left = left + "px";
        win.style.top = top + "px";
        win.style.right = "auto";
        win.style.bottom = "auto";
        win.style.transform = "none";
        saveModalPos(left, top);
        saveModalSize(r.width, r.height);
      }

      let dragState = {active:false, startX:0, startY:0, startLeft:0, startTop:0};
      let resizeState = {active:false, startX:0, startY:0, startW:0, startH:0, startLeft:0, startTop:0};

      bar.addEventListener("pointerdown", (e) => {
        const t = e.target;
        if(t && (t.id === "closeModal" || t.id === "minModal" || t.id === "restoreModal")) return;
        if(modalMinimized) return;
        const r = normalizeWinRect();
        modalDragging = true;
        dragState.active = true;
        dragState.startX = e.clientX;
        dragState.startY = e.clientY;
        dragState.startLeft = r.left;
        dragState.startTop = r.top;
        try{ bar.setPointerCapture(e.pointerId); }catch(err){}
      });

      bar.addEventListener("pointermove", (e) => {
        if(!dragState.active) return;
        const r = win.getBoundingClientRect();
        const nextLeft = dragState.startLeft + (e.clientX - dragState.startX);
        const nextTop = dragState.startTop + (e.clientY - dragState.startY);
        const maxLeft = Math.max(8, window.innerWidth - r.width - 8);
        const maxTop = Math.max(8, window.innerHeight - r.height - 8);
        win.style.left = clamp(nextLeft, 8, maxLeft) + "px";
        win.style.top = clamp(nextTop, 8, maxTop) + "px";
        win.style.transform = "none";
      });

      function endDrag(pointerId){
        if(!dragState.active) return;
        dragState.active = false;
        modalDragging = false;
        try{ bar.releasePointerCapture(pointerId); }catch(err){}
        keepModalInView();
      }

      bar.addEventListener("pointerup", (e) => endDrag(e.pointerId));
      bar.addEventListener("pointercancel", (e) => endDrag(e.pointerId));

      if(grip){
        grip.addEventListener("pointerdown", (e) => {
          if(modalMinimized) return;
          try{ e.preventDefault(); e.stopPropagation(); }catch(_){ }
          const r = normalizeWinRect();
          resizeState.active = true;
          resizeState.startX = e.clientX;
          resizeState.startY = e.clientY;
          resizeState.startW = r.width;
          resizeState.startH = r.height;
          resizeState.startLeft = r.left;
          resizeState.startTop = r.top;
          try{ grip.setPointerCapture(e.pointerId); }catch(err){}
        });

        grip.addEventListener("pointermove", (e) => {
          if(!resizeState.active) return;
          const minW = 640;
          const minH = 440;
          const maxW = Math.max(minW, window.innerWidth - resizeState.startLeft - 8);
          const maxH = Math.max(minH, window.innerHeight - resizeState.startTop - 8);
          const nextW = clamp(resizeState.startW + (e.clientX - resizeState.startX), minW, maxW);
          const nextH = clamp(resizeState.startH + (e.clientY - resizeState.startY), minH, maxH);
          win.style.width = nextW + "px";
          win.style.height = nextH + "px";
          saveModalSize(nextW, nextH);
        });

        const endResize = (e) => {
          if(!resizeState.active) return;
          resizeState.active = false;
          try{ grip.releasePointerCapture(e.pointerId); }catch(err){}
          keepModalInView();
        };
        grip.addEventListener("pointerup", endResize);
        grip.addEventListener("pointercancel", endResize);
      }

      try{
        const ro = new ResizeObserver((entries)=>{
          for(const ent of entries){
            const cr = ent.contentRect;
            if(cr && cr.width && cr.height){
              saveModalSize(cr.width, cr.height);
            }
          }
        });
        ro.observe(win);
      }catch(e){}

      window.addEventListener("resize", ()=>{ try{ keepModalInView(); }catch(e){} }, {passive:true});
    })();

    function setOpStatus(text){
      $("opStatus").innerText = text;
    }

    function loadSeatPositions(){
      try{
        const raw = localStorage.getItem(STORE_KEY);
        if(!raw) return {};
        const obj = JSON.parse(raw);
        if(!obj || typeof obj !== "object") return {};
        return obj;
      }catch(e){
        return {};
      }
    }

    function saveSeatPositions(pos){
      try{
        localStorage.setItem(STORE_KEY, JSON.stringify(pos));
      }catch(e){}
    }

    function clamp(v, min, max){
      return Math.max(min, Math.min(max, v));
    }

    function setTablePulse(on){
      const el = $("tableCore");
      if(!el) return;
      if(on) el.classList.add("tablePulseEnergy");
      else el.classList.remove("tablePulseEnergy");
    }

    function setTablePulseAll(on){
      const el = $("tableCore");
      if(!el) return;
      if(on) el.classList.add("tablePulseAll");
      else el.classList.remove("tablePulseAll");
    }

    function activeOrder(){
      const a = (state && state.active_order) ? state.active_order : [];
      const installed = (state && state.installed) ? state.installed : {};
      return a.filter(n => installed[n]);
    }

    // RULE: If more than 3 teammates are active, keep the gold and purple pulse on persistently.
    function updateTablePulseFromStatuses(){
      const order = activeOrder();
      const activeCount = order.length;

      if(activeCount > 3){
        setTablePulse(true);
        setTablePulseAll(true);
        return;
      }

      if(!order.length){
        setTablePulse(false);
        setTablePulseAll(false);
        return;
      }

      const thinkingCount = order.filter(n => seatStatus[n] === "thinking").length;
      const anyActive = thinkingCount > 0;
      const allActive = thinkingCount === order.length;

      if(assemblyPulseActive){
        setTablePulse(true);
        setTablePulseAll(true);
        return;
      }

      setTablePulse(anyActive);
      setTablePulseAll(allActive);
    }

    function setSeatLive(name, mode){
      seatStatus[name] = mode;
      const dot = document.getElementById("live_" + name);
      const label = document.getElementById("status_" + name);
      if(dot){
        dot.className = "liveDot " + mode;
      }
      if(label){
        label.innerText =
          mode === "thinking" ? "Thinking" :
          mode === "done" ? "Responded" :
          mode === "waiting" ? "Waiting" : "Idle";
      }
      updateTablePulseFromStatuses();
    }

    function setEmailFrom(teammate){
      const smtpUser = (state && state.email && state.email.smtp_user) ? state.email.smtp_user : "";
      if(teammate){
        $("emailFrom").value = `${teammate} via ${smtpUser}`.trim();
      }else{
        $("emailFrom").value = smtpUser ? smtpUser : "SMTP not configured";
      }
    }

    function applyEmailDraft(draft, teammateName){
      if(!draft) return;

      lastEmailDraftBy = teammateName || selectedSeat || "";

      if($("emailTo") && draft.to) $("emailTo").value = draft.to;
      if($("emailSubject") && draft.subject) $("emailSubject").value = draft.subject;
      if($("emailBody") && draft.body) $("emailBody").value = draft.body;

      setEmailFrom(lastEmailDraftBy);
      showEmailConsoleModal("Email Console");
      showToast(`Email draft loaded${lastEmailDraftBy ? ' by ' + lastEmailDraftBy : ''}`);
    }

    function setSmsFrom(teammate){
      if($("smsFrom")) $("smsFrom").value = teammate ? `${teammate} via Twilio/CRM` : 'Twilio/CRM';
    }

    function applySmsDraft(draft, teammateName){
      if(!draft) return;
      lastSmsDraftBy = teammateName || selectedSeat || "";
      if($("smsTo") && draft.to) $("smsTo").value = draft.to;
      if($("smsBody") && draft.body) $("smsBody").value = draft.body;
      setSmsFrom(lastSmsDraftBy);
      showSMSConsoleModal("SMS Console");
      showToast(`Text draft loaded${lastSmsDraftBy ? ' by ' + lastSmsDraftBy : ''}`);
    }

    function getActiveTeammateOptions(){
      const installed = (state && state.installed) ? state.installed : {};
      const active = (state && state.active_order && state.active_order.length) ? state.active_order : ((state && state.installed_order) ? state.installed_order : []);
      const out = [];
      (active || []).forEach(name=>{ if(installed && installed[name]) out.push(name); });
      return out;
    }

    function buildLeadOutreachContext(item, channel){
      const email = (((item.email_candidates||[])[0]||{}).email) || item.email || '';
      const phone = item.phone || '';
      const site = item.website || item.domain || '';
      const sourceQuery = item.source_query || '';
      const parts = [
        `Channel: ${channel}`,
        `Lead name: ${item.name || ''}`,
        `Company: ${item.company || ''}`,
        `Title: ${item.title || ''}`,
        `Website: ${site}`,
        `Email: ${email}`,
        `Phone: ${phone}`,
        `Location: ${($("leadLabLocation")?.value || '').trim()}`,
        `Specific areas: ${($("leadLabAreas")?.value || '').trim()}`,
        `Search niche: ${($("leadLabNiche")?.value || '').trim()}`,
        `Source query: ${sourceQuery}`,
        `Notes: ${item.notes || ''}`
      ].filter(x=>!/:\s*$/.test(x));
      return parts.join('\n');
    }

    function openLeadHandoff(channel, item){
      const options = getActiveTeammateOptions();
      if(!options.length){
        showModal('No teammates available', 'Install or activate at least one teammate first.');
        return;
      }
      leadHandoffState = { channel, item: item || {} };
      showModal();
      try{ ensureModalMinSize(820, 680); }catch(e){}
      hideAllModalForms();
      if($("leadHandoffForm")) $("leadHandoffForm").style.display = 'block';
      if($("modalBody")) $("modalBody").style.display = 'none';
      if($("modalTitle")) $("modalTitle").innerText = channel === 'sms' ? 'Write lead text' : 'Write lead email';
      const sel = $("leadHandoffTeammate");
      if(sel){
        sel.innerHTML = options.map(name=>`<option value="${escapeHtml(name)}">${escapeHtml(name)}</option>`).join('');
        if(selectedSeat && options.includes(selectedSeat)) sel.value = selectedSeat;
      }
      if($("leadHandoffChannel")) $("leadHandoffChannel").value = channel === 'sms' ? 'Text message' : 'Email';
      if($("leadHandoffGoal")) $("leadHandoffGoal").value = 'intro';
      if($("leadHandoffTone")) $("leadHandoffTone").value = channel === 'sms' ? 'warm' : 'professional';
      if($("leadHandoffContext")) $("leadHandoffContext").value = buildLeadOutreachContext(item || {}, channel);
      if($("leadHandoffStatus")) $("leadHandoffStatus").innerText = '';
    }

    async function generateLeadOutreachDraft(){
      const cfg = leadHandoffState || {};
      const item = cfg.item || {};
      const channel = cfg.channel || 'email';
      const teammate = ($("leadHandoffTeammate")?.value || '').trim();
      const goal = ($("leadHandoffGoal")?.value || 'intro').trim();
      const tone = ($("leadHandoffTone")?.value || 'warm').trim();
      const st = $("leadHandoffStatus");
      if(!teammate){
        if(st) st.innerText = 'Choose a teammate first.';
        return;
      }
      if(st) st.innerText = 'Writing draft...';
      const email = (((item.email_candidates||[])[0]||{}).email) || item.email || '';
      const phone = item.phone || '';
      if(channel === 'email' && !email){ if(st) st.innerText = 'This lead does not have an email yet.'; return; }
      if(channel === 'sms' && !phone){ if(st) st.innerText = 'This lead does not have a phone number yet.'; return; }

      let prompt = '';
      if(channel === 'email'){
        prompt = [
          'Draft a prospecting email for this lead.',
          'Write it in a ' + tone + ' tone.',
          'Goal: ' + goal + '.',
          'Use the exact structured format below so the Email Console can auto fill:',
          '```email',
          'To: recipient@email.com',
          'Subject: subject line',
          'Body: first line',
          'rest of body...',
          '```',
          'Keep it specific, human, and ready to send.',
          '',
          buildLeadOutreachContext(item, channel)
        ].join('\n');
      }else{
        prompt = [
          'Draft a prospecting text message for this lead.',
          'Write it in a ' + tone + ' tone.',
          'Goal: ' + goal + '.',
          'Use the exact structured format below so the SMS Console can auto fill:',
          '```sms',
          'To: +15555550123',
          'Body: first line',
          'rest of body...',
          '```',
          'Keep it concise, natural, and ready to send.',
          '',
          buildLeadOutreachContext(item, channel)
        ].join('\n');
      }

      try{
        const res = await fetch('/api/followup', {
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify({name: teammate, message: prompt})
        });
        const data = await res.json();
        if(!data.ok) throw new Error(data.error || 'Draft failed');
        if(channel === 'email'){
          const draft = data.email_draft || {to: email, subject: '', body: ''};
          if(!draft.to) draft.to = email;
          if(!draft.body) draft.body = (data.response || '').trim();
          applyEmailDraft(draft, teammate);
        }else{
          const draft = {to: phone, body: (data.response || '').trim()};
          applySmsDraft(draft, teammate);
        }
        try{ await refreshThread(); }catch(e){}
      }catch(e){
        if(st) st.innerText = e && e.message ? e.message : 'Draft failed';
        return;
      }
      if(st) st.innerText = 'Draft loaded.';
    }

    async function refreshSessionObjectivePill(){
      try{
        const res = await fetch('/api/os/session_objective');
        const data = await res.json();
        if(!data.ok) return;
        const obj = data.objective || {};
        const txt = (obj.title || '').trim();
        const pill = $("sessionObjectivePill");
        if(pill) pill.innerText = txt ? txt : 'No session objective';
      }catch(e){}
    }

    async function openSessionObjectiveModal(){
      try{ document.body.style.overflow = 'hidden'; }catch(_){ }
      showModal();
      try{ ensureModalMinSize(860, 620); }catch(e){}
      hideAllModalForms();
      if($("sessionObjectiveForm")) $("sessionObjectiveForm").style.display = 'block';
      if($("modalBody")) $("modalBody").style.display = 'none';
      if($("modalTitle")) $("modalTitle").innerText = 'Session objective';
      if($("sessionObjectiveStatus")) $("sessionObjectiveStatus").innerText = 'Loading...';
      try{
        const res = await fetch('/api/os/session_objective');
        const data = await res.json();
        if(!data.ok) throw new Error(data.error || 'Load failed');
        const obj = data.objective || {};
        if($("sessionObjectiveInput")) $("sessionObjectiveInput").value = obj.title || '';
        if($("sessionObjectiveContext")) $("sessionObjectiveContext").value = obj.context || '';
        if($("sessionObjectiveStatus")) $("sessionObjectiveStatus").innerText = 'Ready';
      }catch(e){
        if($("sessionObjectiveStatus")) $("sessionObjectiveStatus").innerText = e && e.message ? e.message : 'Load failed';
      }
    }

    async function saveSessionObjectiveModal(){
      const st = $("sessionObjectiveStatus");
      if(st) st.innerText = 'Saving...';
      try{
        const payload = {
          title: (($("sessionObjectiveInput")||{}).value || '').trim(),
          context: (($("sessionObjectiveContext")||{}).value || '').trim()
        };
        const res = await fetch('/api/os/session_objective', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
        const data = await res.json();
        if(!data.ok) throw new Error(data.error || 'Save failed');
        if(st) st.innerText = 'Saved';
        try{ await refreshSessionObjectivePill(); }catch(e){}
        showToast('Session objective saved');
      }catch(e){
        if(st) st.innerText = e && e.message ? e.message : 'Save failed';
      }
    }

    async function openOperatorProfileModal(){
      try{ document.body.style.overflow = 'hidden'; }catch(_){ }
      showModal();
      try{ ensureModalMinSize(960, 760); }catch(e){}
      hideAllModalForms();
      if($("operatorProfileModalForm")) $("operatorProfileModalForm").style.display = 'block';
      if($("modalBody")) $("modalBody").style.display = 'none';
      if($("modalTitle")) $("modalTitle").innerText = 'Operator Profile';
      if($("operatorProfileStatus")) $("operatorProfileStatus").innerText = 'Loading...';
      try{
        const res = await fetch('/api/operator_profile');
        const data = await res.json();
        if(!data.ok) throw new Error(data.error || 'Load failed');
        const p = data.profile || {};
        if($("opm_display_name")) $("opm_display_name").value = p.display_name || 'Operator';
        if($("opm_audience")) $("opm_audience").value = p.audience || '';
        if($("opm_business")) $("opm_business").value = p.business || '';
        if($("opm_offers")) $("opm_offers").value = p.offers || '';
        if($("opm_goals")) $("opm_goals").value = p.goals || '';
        if($("opm_constraints")) $("opm_constraints").value = p.constraints || '';
        if($("opm_tone_rules")) $("opm_tone_rules").value = p.tone_rules || '';
        if($("opm_notes")) $("opm_notes").value = p.notes || '';
        if($("operatorProfileStatus")) $("operatorProfileStatus").innerText = 'Ready';
      }catch(e){
        if($("operatorProfileStatus")) $("operatorProfileStatus").innerText = e && e.message ? e.message : 'Load failed';
      }
    }

    async function saveOperatorProfileModal(){
      const st = $("operatorProfileStatus");
      if(st) st.innerText = 'Saving...';
      const payload = {
        display_name: ($("opm_display_name")?.value || '').trim(),
        audience: ($("opm_audience")?.value || '').trim(),
        business: ($("opm_business")?.value || '').trim(),
        offers: ($("opm_offers")?.value || '').trim(),
        goals: ($("opm_goals")?.value || '').trim(),
        constraints: ($("opm_constraints")?.value || '').trim(),
        tone_rules: ($("opm_tone_rules")?.value || '').trim(),
        notes: ($("opm_notes")?.value || '').trim()
      };
      try{
        const res = await fetch('/api/operator_profile', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
        const data = await res.json();
        if(!data.ok) throw new Error(data.error || 'Save failed');
        if(st) st.innerText = 'Saved';
        showToast('Saved Operator Profile');
        if(selectedSeat === 'Operator'){ try{ await refreshThread(); }catch(e){} }
      }catch(e){
        if(st) st.innerText = e && e.message ? e.message : 'Save failed';
      }
    }

    function showSMSConsoleModal(titleText='SMS Console'){
      showModal();
      try{ ensureModalMinSize(900, 680); }catch(e){}
      hideAllModalForms();
      if($("modalBody")) $("modalBody").style.display = 'none';
      if($("smsConsoleForm")) $("smsConsoleForm").style.display = 'block';
      if($("modalTitle")) $("modalTitle").innerText = titleText;
    }


    async function openEditForTeammate(name){
      if(!name) return;

      editingTeammate = name;
      $("editStatus").innerText = "Loading...";

      const res = await fetch("/api/teammate/" + encodeURIComponent(name));
      const data = await res.json();
      if(!data.ok){
        showModal("Error", data.error || "Could not load teammate");
        return;
      }

      const t = data.teammate || {};
      if($("editName")) $("editName").value = t.name || name || "";
      $("editJobTitle").value = t.job_title || "";
      $("editVersion").value = t.version || "";
      $("editMission").value = t.mission || "";
      $("editGoal").value = t.goal || "";
      $("editThinking").value = t.thinking_style || "";
      $("editResponsibilities").value = (t.responsibilities || []).join("\n");
      $("editWillNotDo").value = (t.will_not_do || []).join("\n");
      if($("editPreferredModel")) $("editPreferredModel").value = t.preferred_model || "";
      if($("editTtsVoice")) $("editTtsVoice").value = t.tts_voice || "alloy";

      $("editStatus").innerText = "Ready";
      showEditModal("Edit " + name);
    }

    $("cancelEdit").onclick = () => hideModal();

    $("saveEdit").onclick = async () => {
      if(!editingTeammate){
        hideModal();
        return;
      }

      $("editStatus").innerText = "Saving...";

      const payload = {
        job_title: $("editJobTitle").value || "",
        version: $("editVersion").value || "",
        mission: $("editMission").value || "",
        goal: $("editGoal").value || "",
        thinking_style: $("editThinking").value || "",
        responsibilities: $("editResponsibilities").value || "",
        will_not_do: $("editWillNotDo").value || "",
        preferred_model: ($("editPreferredModel") ? $("editPreferredModel").value : "") || "",
        tts_voice: ($("editTtsVoice") ? $("editTtsVoice").value : "") || "alloy",
      };

      const res = await fetch("/api/teammate/" + encodeURIComponent(editingTeammate), {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if(!data.ok){
        $("editStatus").innerText = data.error || "Save failed";
        return;
      }

      $("editStatus").innerText = "Saved";
      await loadState();
      hideModal();
      showModal("Saved", "Teammate framework updated.");
    };



function makeSeat(defn, idx){
      const wrap = $("tableWrap");
      const wrapRect = wrap.getBoundingClientRect();

      const seat = document.createElement("div");
      seat.className = "seat";
      seat.dataset.name = defn.name;
      seat.tabIndex = 0;

      const tools = document.createElement("div");
      tools.className = "seatTools";

      const editBtn = document.createElement("button");
      editBtn.className = "seatToolBtn";
      editBtn.innerText = "Edit";
      editBtn.title = "Edit teammate framework";

      editBtn.addEventListener("pointerdown", (e) => {
        e.preventDefault();
        e.stopPropagation();
      });
      editBtn.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        openEditForTeammate(defn.name);
      });

      tools.appendChild(editBtn);


      seat.appendChild(tools);

      const av = defn.avatar || {bg:"#1f2a44", fg:"#e6edff", sigil:defn.name.slice(0,1).toUpperCase()};
      const avatar = document.createElement("div");
      avatar.className = "avatar";
      avatar.style.background = av.bg;
      avatar.style.color = av.fg;
      avatar.innerText = av.sigil || defn.name.slice(0,1).toUpperCase();

      const liveDot = document.createElement("div");
      liveDot.className = "liveDot idle";
      liveDot.id = "live_" + defn.name;
      avatar.appendChild(liveDot);

      const meta = document.createElement("div");
      meta.className = "seatMeta";

      const nm = document.createElement("div");
      nm.className = "seatName";
      nm.innerText = defn.name;

      const rl = document.createElement("div");
      rl.className = "seatRole";
      rl.innerText = `${defn.job_title}  |  ${defn.version}`;

      const st = document.createElement("div");
      st.className = "seatStatus";
      st.id = "status_" + defn.name;
      st.innerText = "Idle";

      meta.appendChild(nm);
      meta.appendChild(rl);
      meta.appendChild(st);

      seat.appendChild(avatar);
      seat.appendChild(meta);

      const saved = loadSeatPositions();
      const w = 190, h = 104;
      if(saved[defn.name] && typeof saved[defn.name].left === "number" && typeof saved[defn.name].top === "number"){
        seat.style.left = saved[defn.name].left + "px";
        seat.style.top = saved[defn.name].top + "px";
      }else{
        const pos = POS[idx % POS.length];
        const left = (pos.x/100) * wrapRect.width - (w/2);
        const top  = (pos.y/100) * wrapRect.height - (h/2);
        seat.style.left = left + "px";
        seat.style.top = top + "px";
      }

      let dragging = false;
      let moved = false;
      let startX = 0, startY = 0;
      let offsetX = 0, offsetY = 0;

      seat.addEventListener("pointerdown", (e) => {
        if(e.button !== undefined && e.button !== 0) return;
        dragging = true;
        moved = false;
        startX = e.clientX;
        startY = e.clientY;

        const r = seat.getBoundingClientRect();
        const sc = (window.getRTScaleV4 ? window.getRTScaleV4() : 1) || 1;
        offsetX = (e.clientX - r.left) / sc;
        offsetY = (e.clientY - r.top) / sc;

        seat.classList.add("dragging");
        seat.setPointerCapture(e.pointerId);
      });

      seat.addEventListener("pointermove", (e) => {
        if(!dragging) return;

        const dx = Math.abs(e.clientX - startX);
        const dy = Math.abs(e.clientY - startY);
        if(dx > 6 || dy > 6) moved = true;

        const boundsEl = (window.getRTBoundsElV4 ? window.getRTBoundsElV4() : $("tableWrap"));
        const boundsRect = boundsEl.getBoundingClientRect();
        const sc = (window.getRTScaleV4 ? window.getRTScaleV4() : 1) || 1;

        let newLeft = ((e.clientX - boundsRect.left) / sc) - offsetX;
        let newTop  = ((e.clientY - boundsRect.top) / sc) - offsetY;

        const pad = 6;
        const maxLeft = (boundsEl.clientWidth || 0) - seat.offsetWidth - pad;
        const maxTop  = (boundsEl.clientHeight || 0) - seat.offsetHeight - pad;

        newLeft = clamp(newLeft, pad, maxLeft);
        newTop  = clamp(newTop, pad, maxTop);

        seat.style.left = newLeft + "px";
        seat.style.top = newTop + "px";
      });

      function finishDrag(pointerId){
        if(!dragging) return;
        dragging = false;
        seat.classList.remove("dragging");

        const current = loadSeatPositions();
        current[defn.name] = {
          left: parseFloat(seat.style.left) || 0,
          top: parseFloat(seat.style.top) || 0
        };
        saveSeatPositions(current);

        if(!moved){
          selectSeat(defn.name);
        }

        try{ seat.releasePointerCapture(pointerId); }catch(err){}
      }

      seat.addEventListener("pointerup", (e) => finishDrag(e.pointerId));
      seat.addEventListener("pointercancel", (e) => finishDrag(e.pointerId));

      seat.addEventListener("keydown", (e) => {
        if(e.key === "Enter" || e.key === " "){
          e.preventDefault();
          selectSeat(defn.name);
        }
      });

      return seat;
    }

    function renderTable(){
      const wrap = $("tableWrap");
      Array.from(wrap.querySelectorAll(".seat")).forEach(x => x.remove());

      // Operator seat (always available)
      try{
        wrap.appendChild(makeOperatorSeat(0));
      }catch(err){
        console.error("Operator seat failed to render:", err);
      }


      const order = activeOrder();
      const installed = state.installed || {};
      const seats = order.filter(n => installed[n]);

      if(seats.length === 0){
        // keep operator seat usable even with zero teammates
        if(selectedSeat === "Operator"){ try{ refreshThread(); }catch(_){ } }

        // FIX: soft toast instead of blocking modal — Operator seat still works
        try{ if(typeof showToast==='function') showToast('No teammates active — use Add or dismiss to add seats.'); }catch(_){}
        setTablePulse(false);
        setTablePulseAll(false);
        $("seatTitle").innerText = "Select a seat";
        $("seatSub").innerText = "No active teammate selected.";
        if(selectedSeat !== "Operator"){ selectedSeat = ""; window.selectedSeat = ""; }
        renderThread([]);
        return;
      }

      seats.forEach((name, i) => {
        const defn = installed[name];
        const seat = makeSeat(defn, i);
        wrap.appendChild(seat);
        setSeatLive(defn.name, seatStatus[defn.name] || "idle");
      });

      if(!selectedSeat || !seats.includes(selectedSeat)){
        selectSeat(seats[0]);
      }else{
        markActiveSeat();
      }

      updateTablePulseFromStatuses();
    }
    function makeOperatorSeat(idx){
      const wrap = $("tableWrap");

      const seat = document.createElement("div");
      seat.className = "seat seatOperator";
      seat.dataset.name = "Operator";
      seat.tabIndex = 0;

      const tools = document.createElement("div");
      tools.className = "seatTools";

      const profBtn = document.createElement("button");
      profBtn.className = "seatToolBtn";
      profBtn.innerText = "Profile";
      profBtn.title = "Edit Operator Profile (shared context)";
      profBtn.addEventListener("pointerdown", (e) => { e.preventDefault(); e.stopPropagation(); });
      profBtn.addEventListener("click", (e) => { e.preventDefault(); e.stopPropagation(); openOperatorProfileModal(); });
      tools.appendChild(profBtn);

      seat.appendChild(tools);

      const avatar = document.createElement("div");
      avatar.className = "avatar";
      avatar.style.background = "#0f172a";
      avatar.style.color = "#67e8f9";
      avatar.innerText = "O";
      seat.appendChild(avatar);

      const nameEl = document.createElement("div");
      nameEl.className = "seatName";
      nameEl.innerText = "Operator";
      seat.appendChild(nameEl);

      const meta = document.createElement("div");
      meta.className = "seatMeta";
      meta.innerText = "Profile";
      seat.appendChild(meta);

      // Default position like other seats (with saved drag positions)
      try{
        const saved = loadSeatPositions();
        if(saved && saved["Operator"] && typeof saved["Operator"].left === "number" && typeof saved["Operator"].top === "number"){
          seat.style.left = saved["Operator"].left + "px";
          seat.style.top = saved["Operator"].top + "px";
        }else{
          // Use the same placement math as teammate seats so it never renders off-screen.
          const r = wrap.getBoundingClientRect();
          const w = 190, h = 124; // match .seat size
          const pos = {x: 50, y: 18}; // slightly lower so it can't hide under header
          let left = (pos.x/100) * r.width - (w/2);
          let top  = (pos.y/100) * r.height - (h/2);

          // Clamp into visible bounds (mirrors drag constraints)
          const maxLeft = r.width - 110;
          const maxTop  = r.height - 110;

          // If the table area hasn't laid out yet, fall back to safe pixels.
          if(r.width < 260 || r.height < 260){
            left = 20; top = 20;
          }else{
            left = clamp(left, 10, Math.max(10, maxLeft));
            top  = clamp(top, 10, Math.max(10, maxTop));
          }

          seat.style.left = left + "px";
          seat.style.top  = top + "px";
        }
      }catch(_){
        seat.style.left = "50%";
        seat.style.top = "12%";
      }

      // Click / keyboard select
      seat.addEventListener("click", (e) => { e.preventDefault(); openOperatorProfileModal(); });
      seat.addEventListener("keydown", (e) => {
        if(e.key === "Enter" || e.key === " "){
          e.preventDefault(); openOperatorProfileModal();
        }
      });

      // Drag behavior (same as other seats)
      let dragging = false;
      let moved = false;
      let startX = 0, startY = 0;
      let offsetX = 0, offsetY = 0;

      seat.addEventListener("pointerdown", (e) => {
        if(e.button !== undefined && e.button !== 0) return;
        dragging = true;
        moved = false;
        startX = e.clientX;
        startY = e.clientY;

        const r = seat.getBoundingClientRect();
        const sc = (window.getRTScaleV4 ? window.getRTScaleV4() : 1) || 1;
        offsetX = (e.clientX - r.left) / sc;
        offsetY = (e.clientY - r.top) / sc;

        seat.classList.add("dragging");
        seat.setPointerCapture(e.pointerId);
      });

      seat.addEventListener("pointermove", (e) => {
        if(!dragging) return;
        const dx = e.clientX - startX;
        const dy = e.clientY - startY;
        if(Math.abs(dx) > 3 || Math.abs(dy) > 3) moved = true;

        const boundsEl = (window.getRTBoundsElV4 ? window.getRTBoundsElV4() : wrap);
        const boundsRect = boundsEl.getBoundingClientRect();
        const sc = (window.getRTScaleV4 ? window.getRTScaleV4() : 1) || 1;

        const left = ((e.clientX - boundsRect.left) / sc) - offsetX;
        const top = ((e.clientY - boundsRect.top) / sc) - offsetY;

        const maxLeft = (boundsEl.clientWidth || 0) - 110;
        const maxTop = (boundsEl.clientHeight || 0) - 110;

        seat.style.left = clamp(left, 10, Math.max(10, maxLeft)) + "px";
        seat.style.top = clamp(top, 10, Math.max(10, maxTop)) + "px";
      });

      seat.addEventListener("pointerup", (e) => {
        if(!dragging) return;
        dragging = false;
        seat.classList.remove("dragging");

        try{
          const saved = loadSeatPositions() || {};
          const r = seat.getBoundingClientRect();
          const wr = wrap.getBoundingClientRect();
          saved["Operator"] = {left: (r.left - wr.left), top: (r.top - wr.top)};
          saveSeatPositions(saved);
        }catch(_){}

        try{ seat.releasePointerCapture(e.pointerId); }catch(_){}

        // If user dragged, don't also "click" select (prevents accidental open)
        if(moved){
          e.preventDefault();
          e.stopPropagation();
        }
      });

      seat.addEventListener("pointercancel", () => {
        dragging = false;
        seat.classList.remove("dragging");
      });

      return seat;
    }



    async function loadState(){
      const res = await fetch("/api/state");
      state = await res.json();
      if(!state.ok){
        showModal("Error", "Failed to load /api/state");
        return;
      }

      // NEW (compat): mirror top-level teammate order into state.registry for conveneAll()
      // This is additive and prevents "No active teammates" when /api/state returns active_order at top-level.
      if(!state.registry){
        state.registry = {active_order: (state.active_order||[]), installed_order: (state.installed_order||[])};
      } else {
        if(!state.registry.active_order) state.registry.active_order = (state.active_order||[]);
        if(!state.registry.installed_order) state.registry.installed_order = (state.installed_order||[]);
      }

      const email = state.email || {};
      const ok = !!email.smtp_ready;
      $("smtpStatus").innerText = ok ? `SMTP: ready (${email.smtp_user})` : `SMTP: not ready (${email.smtp_reason || "missing"})`;

      setEmailFrom(selectedSeat || "");
      renderTable();
      updateAlwaysButtons();
      try{ await refreshSessionObjectivePill(); }catch(e){}
    }

    function markActiveSeat(){
      const all = document.querySelectorAll(".seat");
      all.forEach(el => {
        if(el.dataset.name === selectedSeat){
          el.classList.add("seatPulse"); // glow like clicking
        }else{
          el.classList.remove("seatPulse");
        }
      });
    }

    function _cssEscape(s){
      try{
        if(window.CSS && CSS.escape) return CSS.escape(s);
      }catch(_){}
      return (s || "").replace(/[^a-zA-Z0-9_\-]/g, "\\$&");
    }

    // Force the same visible "glow + switch" feedback as a click.
    // This also restarts the pulse animation if the seat was already selected.
    function forceSeatSelectUI(name){
      try{
        selectedSeat = name;
        window.selectedSeat = name;  // keep window in sync
        markActiveSeat();
        const el = document.querySelector('.seat[data-name="' + _cssEscape(name) + '"]');
        if(!el) return;
        // Restart CSS animation
        el.classList.remove("seatPulse");
        void el.offsetWidth; // reflow
        el.classList.add("seatPulse");
        // Bring into view and focus for accessibility
        try{ el.focus({preventScroll:true}); }catch(_){}
        try{ el.scrollIntoView({behavior:"smooth", block:"center", inline:"center"}); }catch(_){}
      }catch(_){}
    }

    async function selectSeat(name){
      selectedSeat = name;
      window.selectedSeat = name;  // keep window in sync
      markActiveSeat();

      const defn = state.installed[name];
      $("seatTitle").innerText = defn ? defn.name : name;
      $("seatSub").innerText = defn ? `${defn.job_title}  |  ${defn.version}` : "";

      setEmailFrom(selectedSeat);

      await refreshThread();
    }

    function renderThread(msgs, imageState){
      lastSeatAssistantText = "";
      lastImageState = imageState || lastImageState || {};
      const box = $("thread");
      box.innerHTML = "";
      if(selectedSeat && selectedSeat !== "Operator" && lastImageState && (lastImageState.current_image_url || lastImageState.approved_image_url)) {
        const stateCard = document.createElement("div");
        stateCard.className = "msg assistant";
        const who = document.createElement("div");
        who.className = "who";
        who.innerText = selectedSeat + " image context";
        const body = document.createElement("div");
        const currentUrl = lastImageState.current_image_url || lastImageState.approved_image_url || "";
        const note = document.createElement("div");
        note.className = "tiny";
        note.style.marginBottom = "8px";
        note.style.opacity = ".95";
        note.innerText = lastImageState.approved_image_id ? "Current graphic ready. Revisions will use this unless you say start over." : "Current graphic context loaded for smoother revisions.";
        body.appendChild(note);
        if(currentUrl){
          const img = document.createElement("img");
          img.src = currentUrl;
          img.alt = "Current graphic";
          img.style.maxWidth = "100%";
          img.style.maxHeight = "220px";
          img.style.borderRadius = "12px";
          img.style.cursor = "zoom-in";
          img.onclick = ()=> openLightbox(currentUrl);
          body.appendChild(img);

          const row = document.createElement("div");
          row.className = "actions";
          row.style.justifyContent = "flex-start";
          row.style.marginTop = "8px";

          const openBtn = document.createElement("button");
          openBtn.className = "btn btnMini";
          openBtn.innerText = "Open full screen";
          openBtn.onclick = ()=> openLightbox(currentUrl);

          const keepBtn = document.createElement("button");
          keepBtn.className = "btn btnMini";
          keepBtn.innerText = "Approve current";
          keepBtn.onclick = async ()=>{
            try{
              const r = await fetch('/api/teammates/' + encodeURIComponent(selectedSeat) + '/approve_current_image', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{}'});
              const d = await r.json();
              if(!d.ok) throw new Error(d.error || 'Could not approve image');
              lastImageState = d.image_state || lastImageState || {};
              await refreshThread();
            }catch(e){ showModal('Image approval failed', String(e && e.message ? e.message : e)); }
          };

          const varyBtn = document.createElement("button");
          varyBtn.className = "btn btnMini";
          varyBtn.innerText = "Make variation";
          varyBtn.onclick = ()=>{ const el = $('followMsg'); if(el){ el.value = 'Make a close variation of the current graphic. Keep the same subject and composition but explore a new version.'; el.focus(); } };

          row.appendChild(openBtn);
          row.appendChild(keepBtn);
          row.appendChild(varyBtn);
          body.appendChild(row);
        }
        stateCard.appendChild(who);
        stateCard.appendChild(body);
        box.appendChild(stateCard);
      }
      if(!msgs || msgs.length === 0){
        const empty = document.createElement("div");
        empty.className = "msg assistant";
        empty.innerHTML = `<div class="who">System</div><div>No messages yet. Use the center Group Console or send to the selected teammate.</div>`;
        box.appendChild(empty);
        return;
      }
      msgs.forEach(m => {
        const div = document.createElement("div");
        div.className = "msg " + (m.role === "user" ? "user" : "assistant");
        const who = document.createElement("div");
        who.className = "who";
        who.innerText = (m.role === "user") ? "You" : selectedSeat;
        const content = document.createElement("div");
        const raw = (m.content || "");
        const imgMatch = raw.match(/\/uploads\/[^\s]+\.(?:png|jpg|jpeg|webp|gif)/i) || raw.match(/\/api\/uploads\/[^\s]+/i);
        if(imgMatch){
          const url = imgMatch[0];
          const cap = document.createElement("div");
          cap.className = "tiny";
          cap.style.opacity = ".9";
          cap.style.marginBottom = "6px";
          cap.innerText = raw.replace(url, "").replace("[Image generated]", "").trim() || "Image generated";
          const a = document.createElement("a");
          a.href = url;
          a.target = "_blank";
          a.rel = "noopener";
          a.innerText = url;
          a.style.display = "inline-block";
          a.style.marginBottom = "8px";
          const img = document.createElement("img");
          img.src = url;
          img.alt = "Generated image";
          img.style.maxWidth = "100%";
          img.style.borderRadius = "12px";
          img.style.display = "block";
          img.style.cursor = "zoom-in";
          img.onclick = ()=> openLightbox(url);
          img.style.marginTop = "8px";
          content.appendChild(cap);
          content.appendChild(a);
          content.appendChild(img);

          const actions = document.createElement("div");
          actions.className = "actions";
          actions.style.justifyContent = "flex-start";
          actions.style.marginTop = "8px";

          const openBtn = document.createElement("button");
          openBtn.className = "btn btnMini";
          openBtn.innerText = "Open";
          openBtn.onclick = ()=> openLightbox(url);

          const useBtn = document.createElement("button");
          useBtn.className = "btn btnMini";
          useBtn.innerText = "Use for revisions";
          useBtn.onclick = async ()=>{
            try{
              const imgs = await fetch('/api/images').then(r=>r.json());
              const match = (imgs.images || []).find(x => x.url === url);
              if(!match || !match.id) throw new Error('Could not find this image in the library');
              const r = await fetch('/api/teammates/' + encodeURIComponent(selectedSeat) + '/current_image', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({file_id: match.id})});
              const d = await r.json();
              if(!d.ok) throw new Error(d.error || 'Could not set current image');
              lastImageState = d.image_state || {};
              await refreshThread();
            }catch(e){ showModal('Image selection failed', String(e && e.message ? e.message : e)); }
          };

          const editBtn = document.createElement("button");
          editBtn.className = "btn btnMini";
          editBtn.innerText = "Edit this";
          editBtn.onclick = ()=>{ const el = $('followMsg'); if(el){ el.value = 'Edit the current graphic. Keep the same overall image, but '; el.focus(); } };

          actions.appendChild(openBtn);
          actions.appendChild(useBtn);
          actions.appendChild(editBtn);
          content.appendChild(actions);
        }else{
          content.innerText = raw;
        }

        if(m.role !== "user"){ lastSeatAssistantText = (m.content || ""); }
        div.appendChild(who);
        div.appendChild(content);
        box.appendChild(div);
      });
      box.scrollTop = box.scrollHeight;
    }
    function renderOperatorProfile(p){
      const box = $("thread");
      box.innerHTML = "";
      const card = document.createElement("div");
      card.className = "msg assistant";
      const safe = (v)=> (v==null? "" : String(v));
      card.innerHTML = `
        <div class="who">Operator</div>
        <div class="tiny" style="margin-bottom:10px; opacity:.9">Teammates can reference this card for your business context, goals, and rules.</div>
        <div class="pillRow" style="gap:10px; flex-wrap:wrap">
          <div style="flex:1; min-width:240px">
            <div class="tiny">Display name</div>
            <input id="op_display_name" class="input" placeholder="Operator" value="${safe(p.display_name||"Operator")}" />
          </div>
          <div style="flex:1; min-width:240px">
            <div class="tiny">Audience</div>
            <input id="op_audience" class="input" placeholder="Who you serve" value="${safe(p.audience||"")}" />
          </div>
        </div>

        <div style="height:10px"></div>

        <div class="tiny">Business</div>
        <textarea id="op_business" class="followBox" style="min-height:90px" placeholder="What your business does...">${safe(p.business||"")}</textarea>

        <div style="height:10px"></div>

        <div class="tiny">Offers</div>
        <textarea id="op_offers" class="followBox" style="min-height:80px" placeholder="Your offers, pricing model, deliverables...">${safe(p.offers||"")}</textarea>

        <div style="height:10px"></div>

        <div class="tiny">Goals</div>
        <textarea id="op_goals" class="followBox" style="min-height:70px" placeholder="Current goals and KPIs...">${safe(p.goals||"")}</textarea>

        <div style="height:10px"></div>

        <div class="tiny">Constraints</div>
        <textarea id="op_constraints" class="followBox" style="min-height:70px" placeholder="Rules, boundaries, what not to do...">${safe(p.constraints||"")}</textarea>

        <div style="height:10px"></div>

        <div class="tiny">Tone rules</div>
        <textarea id="op_tone_rules" class="followBox" style="min-height:70px" placeholder="How teammates should speak and write...">${safe(p.tone_rules||"")}</textarea>

        <div style="height:10px"></div>

        <div class="tiny">Notes</div>
        <textarea id="op_notes" class="followBox" style="min-height:70px" placeholder="Anything else teammates should know...">${safe(p.notes||"")}</textarea>

        <div style="height:12px"></div>
        <div class="pillRow" style="justify-content:flex-end">
          <button class="btn btnMini" id="opReload">Reload</button>
          <button class="btn btnPrimary" id="opSave">Save</button>
          <button class="btn btnPrimary" id="opSaveExit">Save &amp; Exit</button>
        </div>
      `;
      box.appendChild(card);

      const bind = (id, fn)=>{ const el=$(id); if(el) el.addEventListener("click", fn); };
      bind("opReload", async()=>{ await refreshThread(); });
      bind("opSave", async()=>{
        const payload = {
          display_name: $("op_display_name").value,
          audience: $("op_audience").value,
          business: $("op_business").value,
          offers: $("op_offers").value,
          goals: $("op_goals").value,
          constraints: $("op_constraints").value,
          tone_rules: $("op_tone_rules").value,
          notes: $("op_notes").value
        };
        const res = await fetch("/api/operator_profile", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(payload)});
        const data = await res.json();
        if(data.ok){
          showToast("Saved Operator Profile");
          try{ if(window.onboardingRefresh) await window.onboardingRefresh(); }catch(e){}
        }else{
          showToast("Save failed: " + (data.error||"unknown"));
        }
      });
      bind("opSaveExit", async()=>{
        const payload = {
          display_name: $("op_display_name").value,
          audience: $("op_audience").value,
          business: $("op_business").value,
          offers: $("op_offers").value,
          goals: $("op_goals").value,
          constraints: $("op_constraints").value,
          tone_rules: $("op_tone_rules").value,
          notes: $("op_notes").value
        };
        const res = await fetch("/api/operator_profile", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(payload)});
        const data = await res.json();
        if(data.ok){
          showToast("Saved Operator Profile");
          try{ if(window.onboardingRefresh) await window.onboardingRefresh(); }catch(e){}
          selectedSeat = ""; window.selectedSeat = "";
          renderThread([]);
        }else{
          showToast("Save failed: " + (data.error||"unknown"));
        }
      });
    }



    async function refreshThread(){
      if(!selectedSeat) return;

      if(selectedSeat === "Operator"){
        const res = await fetch("/api/operator_profile");
        const data = await res.json();
        if(!data.ok){ renderThread([]); return; }
        renderOperatorProfile(data.profile || {});
        return;
      }

      const res = await fetch("/api/thread/" + encodeURIComponent(selectedSeat));
      const data = await res.json();
      if(!data.ok){
        renderThread([]);
        return;
      }
      renderThread(data.thread, data.image_state || {});
    }

    $("refreshThread").onclick = refreshThread;

    function renderGroupReplies(outputs, drafts, images){
      const box = $("groupReplies");
      box.innerHTML = "";

      const keys = Object.keys(outputs || {});
      if(keys.length === 0){
        const t = document.createElement("div");
        t.className = "tiny";
        t.innerText = "No group replies yet. Use the center Group Console.";
        box.appendChild(t);
        return;
      }

      keys.forEach((name) => {
        const item = document.createElement("div");
        item.className = "replyItem";

        const top = document.createElement("div");
        top.className = "replyTop";

        const nm = document.createElement("div");
        nm.className = "replyName";
        nm.innerText = name;

        const btns = document.createElement("div");
        btns.className = "replyBtns";

        const openBtn = document.createElement("button");
        openBtn.className = "btn";
        openBtn.innerText = "Open";
        openBtn.onclick = () => showModal(name, outputs[name], (images && images[name]) ? images[name] : null);

        const selectBtn = document.createElement("button");
        selectBtn.className = "btn";
        selectBtn.innerText = "Select";
        selectBtn.onclick = () => selectSeat(name);

        const copyBtn = document.createElement("button");
        copyBtn.className = "btn";
        copyBtn.innerText = "Copy";
        copyBtn.onclick = async () => {
          try{ await navigator.clipboard.writeText(outputs[name]); }catch(e){}
        };

        btns.appendChild(openBtn);
        btns.appendChild(selectBtn);
        btns.appendChild(copyBtn);

        const draft = drafts && drafts[name] ? drafts[name] : null;
        if(draft){
          const loadBtn = document.createElement("button");
          loadBtn.className = "btn btnPrimary";
          loadBtn.innerText = "Load email";
          loadBtn.onclick = () => applyEmailDraft(draft, name);
          btns.appendChild(loadBtn);
        }

        top.appendChild(nm);
        top.appendChild(btns);

        const body = document.createElement("div");
        body.className = "replyBody";
        if(images && images[name]){
          const im = document.createElement('img');
          im.src = images[name];
          im.style.maxWidth = '100%';
          im.style.borderRadius = '12px';
          im.style.marginBottom = '8px';
          body.appendChild(im);
        }
        const tx = document.createElement('div');
        tx.style.whiteSpace = 'pre-wrap';
        tx.innerText = outputs[name];
        body.appendChild(tx);

        item.appendChild(top);
        item.appendChild(body);
        box.appendChild(item);
      });
    }

    function renderAttachList(listElId, fileIds){
      const box = $(listElId);
      box.innerHTML = "";
      (fileIds || []).forEach((fid) => {
        const pill = document.createElement("div");
        pill.className = "pill";
        pill.innerText = fid.slice(0, 8);

        const x = document.createElement("button");
        x.innerText = "remove";
        x.onclick = () => {
          if(listElId === "groupAttachList"){
            groupFileIds = groupFileIds.filter(id => id !== fid);
            renderAttachList("groupAttachList", groupFileIds);
          }else{
            dmFileIds = dmFileIds.filter(id => id !== fid);
            renderAttachList("dmAttachList", dmFileIds);
          }
        };

        pill.appendChild(x);
        box.appendChild(pill);
      });
    }

    async function uploadOne(file){
      const fd = new FormData();
      fd.append("file", file);

      const res = await fetch("/api/upload", {
        method: "POST",
        body: fd
      });
      const data = await res.json();
      if(!data.ok){
        throw new Error(data.error || "Upload failed");
      }
      return data.file;
    }

    async function uploadFiles(files, target){
      if(!files || !files.length) return;

      let okCount = 0;

      for(const f of files){
        try{
          const rec = await uploadOne(f);
          okCount += 1;
          if(target === "group"){
            groupFileIds.push(rec.id);
            renderAttachList("groupAttachList", groupFileIds);
          }else{
            dmFileIds.push(rec.id);
            renderAttachList("dmAttachList", dmFileIds);
          }
        }catch(err){
          showModal("Upload error", String(err && err.message ? err.message : err));
        }
      }

      if(okCount){
        showModal("Uploaded", `${okCount} file(s) attached.`);
      }
    }

    $("pickGroupFiles").onclick = () => $("groupFiles").click();
    $("pickDmFiles").onclick = () => $("dmFiles").click();

    $("groupFiles").addEventListener("change", async (e) => {
      const files = Array.from(e.target.files || []);
      e.target.value = "";
      await uploadFiles(files, "group");
    });

    $("dmFiles").addEventListener("change", async (e) => {
      const files = Array.from(e.target.files || []);
      e.target.value = "";
      await uploadFiles(files, "dm");
    });

    async function captureScreenOnce(){
      if(!navigator.mediaDevices || !navigator.mediaDevices.getDisplayMedia){
        showModal("Screen share not supported", "This browser does not support screen capture. Try Chrome or Edge.");
        return null;
      }

      let stream = null;
      try{
        stream = await navigator.mediaDevices.getDisplayMedia({ video: { cursor: "always" }, audio: false });
      }catch(e){
        showModal("Screen share cancelled", "You closed the prompt or blocked permissions.");
        return null;
      }

      try{
        const track = stream.getVideoTracks()[0];
        const video = document.createElement("video");
        video.srcObject = stream;

        await new Promise((resolve) => {
          video.onloadedmetadata = () => resolve(true);
        });

        video.play();
        await new Promise(r => setTimeout(r, 120));

        const canvas = document.createElement("canvas");
        canvas.width = video.videoWidth || 1280;
        canvas.height = video.videoHeight || 720;
        const ctx = canvas.getContext("2d");
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

        const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/png", 0.92));

        try{ track.stop(); }catch(err){}
        try{ stream.getTracks().forEach(t => t.stop()); }catch(err){}

        if(!blob){
          showModal("Capture failed", "Could not capture screenshot.");
          return null;
        }

        const file = new File([blob], `screen_capture_${Date.now()}.png`, { type: "image/png" });
        const url = URL.createObjectURL(blob);

        return { file, previewUrl: url };
      }catch(e){
        try{ if(stream) stream.getTracks().forEach(t => t.stop()); }catch(err){}
        showModal("Capture failed", String(e && e.message ? e.message : e));
        return null;
      }
    }

    async function captureAndAttach(target){
      const cap = await captureScreenOnce();
      if(!cap) return;

      showModal("Screen captured", "Screenshot captured and attached.", cap.previewUrl);

      try{
        const rec = await uploadOne(cap.file);
        if(target === "group"){
          groupFileIds.push(rec.id);
          renderAttachList("groupAttachList", groupFileIds);
        }else{
          dmFileIds.push(rec.id);
          renderAttachList("dmAttachList", dmFileIds);
        }
      }catch(e){
        showModal("Upload error", String(e && e.message ? e.message : e));
      }
    }

    $("screenGroupBtn").onclick = () => captureAndAttach("group");
    $("screenDmBtn").onclick = () => captureAndAttach("dm");


    // --- Voice / Mic reliability patch (ADD v6) ---
    // Some mobile in-app browsers (Messenger/FB/IG webviews) partially support SpeechRecognition but fail to start.
    // We preflight microphone permissions via getUserMedia, and provide clearer error feedback.
    function isInAppBrowser(){
      const ua = (navigator.userAgent || "").toLowerCase();
      return ua.includes("fb_iab") || ua.includes("fban") || ua.includes("fbav") || ua.includes("instagram") || ua.includes("messenger");
    }

    async function ensureMicPermission(){
      // No-op if media devices are not available.
      try{
        if(!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) return true;
        const stream = await navigator.mediaDevices.getUserMedia({audio:true});
        // Immediately stop tracks; we just want to prompt permission.
        try{ stream.getTracks().forEach(t => t.stop()); }catch(_){}
        return true;
      }catch(e){
        return false;
      }
    }

    function micHelpText(){
      if(isInAppBrowser()){
        return "Mic access can be blocked inside in-app browsers (Messenger/Facebook/Instagram). If the mic won't start, open this page in your device browser (Chrome/Safari) and try again.";
      }
      return "If the mic won't start, check site permissions for microphone access and try again.";
    }
    // --- end voice patch ---

    function speechSupported(){
      return !!(window.SpeechRecognition || window.webkitSpeechRecognition);
    }

    async function startDictation(targetId, statusId){
      if(!speechSupported()){
        showModal("Mic not supported", micHelpText());
        return;
      }

      const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
      const rec = new SR();
      rec.lang = "en-US";
      rec.interimResults = true;
      rec.continuous = false;

      const target = $(targetId);
      const status = $(statusId);

      const baseText = (target.value || "").trim();
      let finalText = "";

      status.innerText = "Mic: requesting permission";

      const okPerm = await ensureMicPermission();
      if(!okPerm){
        status.innerText = "Mic: blocked";
        showModal("Microphone blocked", micHelpText());
        return;
      }

      status.innerText = "Mic: listening";

      rec.onresult = (event) => {
        let interim = "";

        for(let i = event.resultIndex; i < event.results.length; i++){
          const txt = event.results[i][0].transcript;
          if(event.results[i].isFinal){
            finalText += txt + " ";
          }else{
            interim += txt;
          }
        }

        const combined = (baseText + " " + finalText + interim)
          .replace(/\s+/g, " ")
          .trim();

        // FIX: if the only thing spoken was a teammate name, switch seats — don't fill the box
        try{
          const dtHit = findFirstNameMention(combined);
          if(dtHit){
            const withoutName = combined
              .replace(new RegExp("\\b" + dtHit.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\b", "gi"), "")
              .replace(/\s+/g, " ").trim();
            if(!withoutName){
              // Only the name was spoken — switch without putting it in the box
              try{ if(typeof selectSeat === "function") selectSeat(dtHit.name); }catch(_){}
              try{ if(typeof forceSeatSelectUI === "function") forceSeatSelectUI(dtHit.name); }catch(_){}
              target.value = baseText;
              finalText = ""; // prevent onend from re-adding the name
              return;
            }
          }
        }catch(_){}

        target.value = combined;
      };

      rec.onerror = () => {
        status.innerText = "Mic: error";
      };

      rec.onend = () => {
        status.innerText = "Mic: idle";
        const combined = (baseText + " " + finalText)
          .replace(/\s+/g, " ")
          .trim();
        target.value = combined;

        // AUTO SEND AFTER TALKING STOPS (ADD v1)
        // Sends 2 seconds after speech ends, but only if the user hasn't edited the text.
        try{
          const snapshot = (combined || "").trim();
          if(snapshot){
            setTimeout(() => {
              try{
                const t = $(targetId);
                const current = ((t && t.value) ? t.value : "").trim();
                if(current !== snapshot) return; // user edited; do not auto send
                if(targetId === "opPrompt"){
                  conveneAll();
                }else if(targetId === "followMsg"){
                  sendFollow();
                }
              }catch(_){}
            }, 2000);
          }
        }catch(_){}
      };

      try{
        rec.start();
      }catch(e){
        status.innerText = "Mic: error";
      }
    }

    $("talkGroupBtn").onclick = async () => { await startDictation("opPrompt", "micStatusGroup"); };
    $("talkDmBtn").onclick = async () => { await startDictation("followMsg", "micStatusDm"); };

    // ----- Lighting Mode (ADD v1) -----
    // Lighting Mode means: no pushback, no clarifying questions, deliver exactly what the user asked.
    // Safety constraints still apply.
    let lightingModeOn = false;

    function updateLightingButton(){
      const b = $("lightingModeBtn");
      if(!b) return;
      b.classList.toggle("btnPrimary", !!lightingModeOn);
      b.innerText = lightingModeOn ? "Lighting: On" : "Lighting mode";
    }

    try{
      const b = $("lightingModeBtn");
      if(b){
        b.onclick = () => {
          lightingModeOn = !lightingModeOn;
          updateLightingButton();
        };
        updateLightingButton();
      }
    }catch(_){}
    // ----- end Lighting Mode -----



    function updateAlwaysButtons(){
      const g = $("alwaysListenGroupBtn");
      const d = $("alwaysListenDmBtn");

      if(g){
        const on = alwaysOn && alwaysMode === "group";
        g.classList.toggle("btnPrimary", on);
        g.innerText = on ? "Always listening: On" : "Always listen";
      }
      if(d){
        const on = alwaysOn && alwaysMode === "dm";
        d.classList.toggle("btnPrimary", on);
        d.innerText = on ? "Always listening: On" : "Always listen";
      }
    }

    function getInstalledNamesInOrder(){
      const installedOrder = (state && state.installed_order) ? state.installed_order : [];
      const installed = (state && state.installed) ? state.installed : {};
      const names = installedOrder.filter(n => installed[n]);
      if(names.length) return names;
      return Object.keys(installed || {});
    }

    function findFirstNameMention(text){
      const names = getInstalledNamesInOrder();
      const lower = (text || "").toLowerCase();
      let best = null;

      for(const name of names){
        if(!name) continue;
        const nl = name.toLowerCase();
        const rx = new RegExp("\\b" + nl.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\b", "i");
        const m = rx.exec(lower);
        if(m && m.index >= 0){
          if(best === null || m.index < best.idx){
            best = { name, idx: m.index };
          }
        }
      }
      return best;
    }

    function removeNameOnce(text, name){
      if(!text || !name) return text;
      const nl = name.toLowerCase();
      // Global flag removes ALL occurrences to prevent buildup
      const rx = new RegExp("\\b" + nl.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\b", "gi");
      return text.replace(rx, "").replace(/\s+/g, " ").trim();
    }

    function currentAlwaysTarget(){
      return (alwaysMode === "group") ? $("opPrompt") : $("followMsg");
    }
    function currentAlwaysStatusEl(){
      return (alwaysMode === "group") ? $("micStatusGroup") : $("micStatusDm");
    }

    function resetAlwaysBuffers(){
      alwaysInterimText   = "";
      alwaysFinalText     = "";
      alwaysFinalBaseline = "";
      _resetCanonicalSpeech();
      const t = currentAlwaysTarget();
      alwaysBaseText = (t && t.value ? t.value : "").trim();
    }

    function stopAlwaysListening(){
      alwaysOn = false;

      const st1 = $("micStatusGroup");
      const st2 = $("micStatusDm");
      if(st1) st1.innerText = "Mic: idle";
      if(st2) st2.innerText = "Mic: idle";

      try{
        if(alwaysRec){
          alwaysRec.onresult = null;
        if(window._alwaysAutoSendTimer){ clearTimeout(window._alwaysAutoSendTimer); window._alwaysAutoSendTimer=null; }
          alwaysRec.onerror = null;
          alwaysRec.onend = null;
          alwaysRec.stop();
        }
      }catch(e){}
      alwaysRec = null;

      updateAlwaysButtons();
    }

    // UPDATE: Build canonical final + interim from the full results list.
    // This prevents the repeated phrases caused by appending partials.
    // Accumulates only NEW final results — never replays old ones
    let _alwaysAccumFinals = "";
    let _alwaysLastProcIdx  = 0;   // FIX: track highest processed resultIndex to prevent replaying

    function getCanonicalSpeech(event){
      let newFinals = "";
      let interim   = "";

      // Only process results we haven't seen yet (start from resultIndex, but never below our watermark)
      const startIdx = Math.max(event.resultIndex, _alwaysLastProcIdx);
      for(let i = startIdx; i < event.results.length; i++){
        const txt = (event.results[i][0].transcript || "");
        if(event.results[i].isFinal){
          newFinals += txt + " ";
          _alwaysLastProcIdx = i + 1;   // advance watermark past this final result
        } else {
          interim += txt;
        }
      }

      newFinals = newFinals.replace(/\s+/g, " ").trim();
      interim   = interim.replace(/\s+/g, " ").trim();

      if(newFinals){
        _alwaysAccumFinals = (_alwaysAccumFinals + " " + newFinals).replace(/\s+/g, " ").trim();
      }

      return { allFinal: _alwaysAccumFinals, interim };
    }

    function _resetCanonicalSpeech(){
      _alwaysAccumFinals   = "";
      _alwaysLastProcIdx   = 0;   // FIX: also reset watermark on name switch
    }

    function subtractBaseline(allFinal){
      const base = (alwaysFinalBaseline || "").trim();
      const cur = (allFinal || "").trim();
      if(!base) return cur;

      if(cur.startsWith(base)){
        const rest = cur.slice(base.length).replace(/\s+/g, " ").trim();
        return rest;
      }

      // If the recognizer trimmed or changed history, safest is to not replay old text.
      if(base.startsWith(cur)) return "";

      return cur;
    }

    // CHANGE: Always listening in continuous mode + name switching that activates seat glow
    async function startAlwaysListening(mode){
      if(!speechSupported()){
        showModal("Mic not supported", micHelpText());
        return;
      }

      alwaysMode = mode || "dm";
      alwaysOn = true;
      updateAlwaysButtons();
      resetAlwaysBuffers();

      const okPerm = await ensureMicPermission();
      if(!okPerm){
        alwaysOn = false;
        updateAlwaysButtons();
        showModal("Microphone blocked", micHelpText());
        return;
      }

      const status = currentAlwaysStatusEl();
      if(status) status.innerText = "Mic: always listening";

      const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
      const rec = new SR();
      rec.lang = "en-US";
      rec.interimResults = true;
      rec.continuous = true;

      alwaysRec = rec;

      rec.onresult = async (event) => {
        const canon      = getCanonicalSpeech(event);
        const allFinal   = canon.allFinal;   // accumulated new finals only
        const interimRaw = canon.interim;

        // FIX: Detect name in INTERIM first (fast response), then fallback to allFinal.
        // This catches names whether they arrive as interim or finalized text.
        const hit = findFirstNameMention(interimRaw) || findFirstNameMention(allFinal);

        if(hit){
          const now = Date.now();
          if(now - lastNameSwitchAt > 800){
            lastNameSwitchAt = now;
            window._alwaysLastSwitchedName = hit.name;   // FIX: remember for normal-path filtering

            // Save clean text (without name) to current target
            const cleanedFinal = removeNameOnce(allFinal, hit.name);
            const targetBefore = currentAlwaysTarget();
            if(targetBefore && cleanedFinal){
              targetBefore.value = cleanedFinal.trim();
            }else if(targetBefore){
              targetBefore.value = "";  // FIX: clear box when only the name was spoken
            }

            // Switch to named teammate
            await selectSeat(hit.name);
            forceSeatSelectUI(hit.name);

            // Reset accumulators completely for the new target
            _resetCanonicalSpeech();
            alwaysFinalText   = "";
            alwaysInterimText = "";
            const t2 = currentAlwaysTarget();
            alwaysBaseText = (t2 && t2.value ? t2.value : "").trim();
            return;
          }
        }

        // Normal update — accumulated finals + current interim
        // FIX: Strip the last switched name so it never bleeds into the box after finalization
        const _lsn = window._alwaysLastSwitchedName || "";
        const filteredFinal  = _lsn ? removeNameOnce(allFinal,   _lsn) : allFinal;
        const filteredInterim = _lsn ? removeNameOnce(interimRaw, _lsn) : interimRaw;
        alwaysFinalText   = filteredFinal;
        alwaysInterimText = filteredInterim;

        // Clear the filter name once we have new speech that isn't the name
        if(filteredFinal && filteredFinal !== alwaysBaseText){
          window._alwaysLastSwitchedName = "";
        }

        const target = currentAlwaysTarget();
        if(target){
          target.value = (alwaysBaseText + " " + alwaysFinalText + " " + alwaysInterimText)
            .replace(/\s+/g, " ")
            .trim();
        }

        // ── Auto-send after 2.5 s of no new speech ──────────────
        // Only fires when there is actual content and it's a final result
        if(allFinal && allFinal.trim()){
          if(window._alwaysAutoSendTimer) clearTimeout(window._alwaysAutoSendTimer);
          window._alwaysAutoSendTimer = setTimeout(async ()=>{
            if(!alwaysOn) return;
            const tgt = currentAlwaysTarget();
            if(!tgt) return;
            const msg = tgt.value.trim();
            if(!msg) return;
            // Clear accumulators so next phrase starts fresh
            alwaysFinalText = "";
            alwaysInterimText = "";
            alwaysBaseText = "";
            _resetCanonicalSpeech();
            // Send via the correct channel
            if(alwaysMode === "dm"){
              if(typeof sendFollow === "function") await sendFollow();
            } else {
              // Group mode — use conveneAll if available, else trigger opPrompt send
              if(typeof conveneAll === "function") await conveneAll();
              else {
                const btn = document.getElementById("sendGroup") || document.getElementById("conveneBtn");
                if(btn) btn.click();
              }
            }
          }, 2500);
        }
      };

      rec.onerror = (e) => {
        const s = currentAlwaysStatusEl();
        if(s) s.innerText = "Mic: error";
        // In many webviews, errors persist; stop to avoid a dead loop.
        try{ stopAlwaysListening(); }catch(_){ }
        try{ showModal("Mic error", (e && e.error ? ("Mic error: " + e.error + ". ") : "") + micHelpText()); }catch(_){ }
      };

      rec.onend = () => {
        if(!alwaysOn) return;
        try{
          const s = currentAlwaysStatusEl();
          if(s) s.innerText = "Mic: always listening";
          rec.start();
        }catch(e){
          stopAlwaysListening();
        }
      };

      try{
        rec.start();
      }catch(e){
        stopAlwaysListening();
        showModal("Mic error", "Could not start always listening. Check permissions and try again.");
      }
    }

    $("alwaysListenGroupBtn").onclick = () => {
      if(alwaysOn && alwaysMode === "group"){
        stopAlwaysListening();
      }else{
        stopAlwaysListening();
        startAlwaysListening("group");
      }
    };

    $("alwaysListenDmBtn").onclick = () => {
      if(alwaysOn && alwaysMode === "dm"){
        stopAlwaysListening();
      }else{
        stopAlwaysListening();
        startAlwaysListening("dm");
      }
    };


    // ===== NAV BAR DROPDOWN JS =====
    window.saToggleDrop = function saToggleDrop(dropId){
      const allDrops=document.querySelectorAll('.saDrop');
      const target=document.getElementById(dropId);
      const isOpen=target&&target.classList.contains('open');
      allDrops.forEach(d=>d.classList.remove('open'));
      if(!isOpen&&target) target.classList.add('open');
    }
    document.addEventListener('click',function(e){
      if(!e.target.closest('.saDropWrap')) document.querySelectorAll('.saDrop').forEach(d=>d.classList.remove('open'));
    });

    // Auto-close dropdowns after any item is clicked
    document.querySelectorAll('.saDropItem').forEach(function(item){
      item.addEventListener('click', function(){
        setTimeout(function(){
          document.querySelectorAll('.saDrop').forEach(function(d){ d.classList.remove('open'); });
          document.querySelectorAll('.saNavBtn').forEach(function(b){ b.classList.remove('open'); });
        }, 50);
      });
    });

    // Wire command bar
    (function(){
      // Cache registry for command-bar teammate detection
      try{ fetch('/api/state').then(r=>r.json()).then(d=>{ window._cachedRegistry=d; }); }catch(_){}
    })();
    // ===== END NAV BAR JS =====


    // ── Suppress password manager on all app inputs ──────────────
    (function suppressPasswordManager() {
      const AUTH_IDS = new Set(['username','password','password2','invite_code','new_password','token','email']);
      function applyNoAutocomplete(root) {
        (root || document).querySelectorAll('input, textarea').forEach(function(el) {
          if (AUTH_IDS.has(el.name) || AUTH_IDS.has(el.id)) return;
          if (['hidden','file','checkbox','radio'].includes(el.type)) return;
          el.setAttribute('autocomplete', 'off');
          el.setAttribute('data-lpignore', 'true');
          el.setAttribute('data-1p-ignore', 'true');
          el.setAttribute('data-form-type', 'other');
        });
      }
      applyNoAutocomplete(document);
      if (window.MutationObserver) {
        new MutationObserver(function(muts) {
          muts.forEach(function(m) {
            m.addedNodes.forEach(function(n) {
              if (n.nodeType === 1) applyNoAutocomplete(n);
            });
          });
        }).observe(document.body, { childList: true, subtree: true });
      }
    })();
    // ── End password manager suppression ─────────────────────────

    window.conveneAll = async function conveneAll(){
      const prompt = $("opPrompt").value.trim();
      if(!prompt){
        showModal("Missing prompt", "Type a prompt first.");
        return;
      }

      const reg = state?.registry || null;
      const order = (reg?.active_order && reg.active_order.length) ? reg.active_order : (reg?.installed_order || []);
      if(!order || !order.length){
        showModal("No active teammates", "Add teammates to the round table first.");
        return;
      }

      order.forEach(n => setSeatLive(n, "thinking"));
      setOpStatus("Sending to all");

      // Assembly roll-call stays on the server (fast path)
      if(isAssemblyPhrase(prompt)){
        assemblyPulseActive = true;
        updateTablePulseFromStatuses();

        try{
          const res = await fetch("/api/convene", {
            method: "POST",
            headers: {"Content-Type":"application/json"},
            body: JSON.stringify({prompt, file_ids: groupFileIds, lighting_mode: !!lightingModeOn})
          });
          const data = await res.json();

          if(!data.ok){
            order.forEach(n => setSeatLive(n, "waiting"));
            setOpStatus("Error");
            showModal("Error", data.error || "Group send failed");
            assemblyPulseActive = false;
            updateTablePulseFromStatuses();
            return;
          }

          if(data.mode === "assembly"){
            order.forEach(n => setSeatLive(n, "idle"));
            setOpStatus("Assembly only");
            const lines = (data.roll || []).map(r => `${r.name} | ${r.job_title} | ${r.version}`).join("\n");
            showModal("ROLL CALL (assembly only)", lines || "No teammates found.");
            return;
          }
        }catch(e){
          order.forEach(n => setSeatLive(n, "waiting"));
          setOpStatus("Error");
          showModal("Error", String(e || "Assembly failed"));
          assemblyPulseActive = false;
          updateTablePulseFromStatuses();
          return;
        }finally{
          assemblyPulseActive = false;
          updateTablePulseFromStatuses();
        }
      }

      // NEW: client-side fanout using the working single-teammate endpoint (/api/followup)
      // This prevents the server from timing out on long multi-call requests, and ensures
      // each teammate completes (or fails) independently without freezing the UI.
      const outputs = {};
      const drafts = {};
      const images = {};

      for(const n of order){
        try{
          const controller = new AbortController();
          const t = setTimeout(() => controller.abort(), 120000); // 120s safety
          const res = await fetch("/api/followup", {
            method: "POST",
            headers: {"Content-Type":"application/json"},
            body: JSON.stringify({name: n, message: prompt, file_ids: groupFileIds}),
            signal: controller.signal
          });
          clearTimeout(t);

          let data = null;
          try{
            data = await res.json();
          }catch(_){
            // Non-JSON response from server: mark as failed but do not freeze
            setSeatLive(n, "waiting");
            continue;
          }

          if(!data.ok){
            setSeatLive(n, "waiting");
            continue;
          }

          const text = data.response || "";
          outputs[n] = text;
          if(data.email_draft){
            drafts[n] = data.email_draft;
          }
          if(data.image_url){
            images[n] = data.image_url;
          }

          // Update the group panel incrementally
          renderGroupReplies(outputs, drafts, images);
          setSeatLive(n, "done");
        }catch(e){
          setSeatLive(n, "waiting");
        }
      }

      lastGroupOutputs = outputs;
      renderGroupReplies(outputs, drafts, images);

      // Seats not present in outputs remain waiting
      order.forEach(n => { if(!(n in outputs)) setSeatLive(n, "waiting"); });

      setOpStatus("Complete");
      try{ if(window.onboardingRefresh) await window.onboardingRefresh(); }catch(e){}

      groupFileIds = [];
      renderAttachList("groupAttachList", groupFileIds);

      if(selectedSeat){
        await refreshThread();
      }
    }

    $("conveneAll").onclick = conveneAll;

    async function assembleAll(){
      $("opPrompt").value = "All teammates to the round table";
      await conveneAll();
    }
    const assembleBtnMain = $("assembleBtn"); if(assembleBtnMain) assembleBtnMain.onclick = assembleAll;
    const assembleBtnSeat = $("assembleBtn2"); if(assembleBtnSeat) assembleBtnSeat.onclick = assembleAll;
    const assembleInManageBtn = $("assembleInManageBtn"); if(assembleInManageBtn) assembleInManageBtn.onclick = assembleAll;

    
async function pollImageJob(jobId, seatName){
  const maxMs = 120000;
  const start = Date.now();
  while(true){
    if(Date.now() - start > maxMs){
      setOpStatus("Queued");
      setSeatLive(seatName || selectedSeat, "waiting");
      return;
    }
    try{
      const res = await fetch("/api/images/job/" + encodeURIComponent(jobId));
      const data = await res.json();
      if(data && data.ok && data.job){
        const st = data.job.status;
        if(st === "done" || st === "error"){
          // thread will have been updated server-side
          await refreshThread();
          setSeatLive(seatName || selectedSeat, (st==="done") ? "done" : "waiting");
          setOpStatus((st==="done") ? "Complete" : "Error");
          if(st === "error"){
            try{
              const msg = ((data.job && data.job.error) ? String(data.job.error) : "Image generation failed");
              if(window.showToast) window.showToast(msg, "error");
            }catch(e){}
          }
          return;
        }
      }
    }catch(e){}
    await new Promise(r=> setTimeout(r, 2000));
  }
}


    // ===== EXPAND MESSAGE MODAL =====
    window.saOpenMsgModal = function saOpenMsgModal(title,html){ const m=document.getElementById('saMsgModal'),b=document.getElementById('saMsgModalBody'),t=document.getElementById('saMsgModalTitle'); if(!m||!b)return; if(t)t.innerText=title||'Response'; b.innerHTML=html||''; m.style.display='flex'; document.body.style.overflow='hidden'; }
    window.saCloseMsgModal = function saCloseMsgModal(){ const m=document.getElementById('saMsgModal'); if(m)m.style.display='none'; document.body.style.overflow=''; }
    window.saCopyMsgModal = function saCopyMsgModal(){ const b=document.getElementById('saMsgModalBody'); navigator.clipboard.writeText(b?b.innerText:'').then(()=>{}).catch(()=>{}); }
    window.saWireThreadClicks = function saWireThreadClicks(){ const thread=document.getElementById('thread'); if(!thread)return; thread.querySelectorAll('.msg').forEach(function(msg){ if(msg._saWired)return; msg._saWired=true; msg.style.cursor='pointer'; msg.title='Click to expand'; msg.addEventListener('click',function(e){ if(e.target.tagName==='A'||e.target.tagName==='BUTTON')return; const who=(msg.querySelector('.who')||{}).innerText||(window.selectedSeat||'Response'); saOpenMsgModal(who,msg.innerHTML); }); }); }
    document.addEventListener('keydown',function(e){ if(e.key==='Escape')saCloseMsgModal(); });
    (function(){ const orig=window.renderThread; if(typeof orig==='function'){ window.renderThread=function(){ orig.apply(this,arguments); setTimeout(saWireThreadClicks,50); }; } const thread=document.getElementById('thread'); if(thread&&window.MutationObserver) new MutationObserver(saWireThreadClicks).observe(thread,{childList:true,subtree:true}); })();
    setTimeout(saWireThreadClicks,500);
    // ===== END EXPAND MODAL =====

    window.sendFollow = async function sendFollow(){
      if(!selectedSeat){
        showModal("No seat selected", "Click a teammate card first.");
        return;
      }
      const msg = $("followMsg").value.trim();
      if(!msg){
        showModal("Missing message", "Type a message for the selected teammate.");
        return;
      }

      setSeatLive(selectedSeat, "thinking");
      setOpStatus("Sending to selected");

      const res = await fetch("/api/followup", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({name: selectedSeat, message: msg, file_ids: dmFileIds, lighting_mode: !!lightingModeOn})
      });
      const data = await res.json();

      if(!data.ok){
        setSeatLive(selectedSeat, "waiting");
        setOpStatus("Error");
        showModal("Error", data.error || "Send failed");
        return;
      }

      if(data.job_id){
        // Image generation runs in background to avoid request timeouts.
        setSeatLive(selectedSeat, "thinking");
        setOpStatus("Generating image");
        $("followMsg").value = "";
        await refreshThread();
        pollImageJob(data.job_id, selectedSeat);
      }else{
        setSeatLive(selectedSeat, "done");
        setOpStatus("Complete");
        $("followMsg").value = "";
        await refreshThread();
      }
      $("followMsg").value = "";
      await refreshThread();
      try{ if(window.onboardingRefresh) await window.onboardingRefresh(); }catch(e){}

      dmFileIds = [];
      renderAttachList("dmAttachList", dmFileIds);

      if(data.email_draft){
        applyEmailDraft(data.email_draft, selectedSeat);
      }
    }

    $("sendFollow").onclick = sendFollow;

    $("installFullBtn").onclick = async () => {
      // Auto-save settings if the settings modal is open, then close any open modal
      const overlay = $("overlay");
      const overlayOpen = overlay && overlay.classList.contains("show");
      if(overlayOpen){
        const saveBtn = $("saveSettings");
        if(saveBtn && typeof saveBtn.onclick === "function"){
          try{ await saveBtn.onclick(); }catch(e){}
        }
        hideModal();
        await new Promise(r=>setTimeout(r,150));
      }
      const res = await fetch("/api/install/full", {method:"POST"});
      const data = await res.json();
      if(!data.ok){
        showModal("Error", data.error || "Install failed");
        return;
      }
      await loadState();
      // Play table activation sound
      try{ wcalPlayActivationSound(); }catch(e){}
      showModal("Team Assembled", "Full team installed and seated at the Round Table.");
      try{ if(window.onboardingRefresh) await window.onboardingRefresh(); }catch(e){}
    };

    $("clearGroup").onclick = () => {
      lastGroupOutputs = {};
      renderGroupReplies({}, {});
    };

    // -----------------------------
    // v9: Tactical Passes (stateless one-click analyses)
    // -----------------------------
    function _combineGroupOutputs(){
      const keys = Object.keys(lastGroupOutputs || {});
      if(keys.length === 0) return "";
      return keys.map(k => k + ":\n" + (lastGroupOutputs[k] || "")).join("\n\n---\n\n");
    }

    async function runTacticalPass(pass, ctx){
      const context = (ctx || "seat");
      const seat = (context === "group") ? "Group" : (selectedSeat || "");
      const text = (context === "group") ? _combineGroupOutputs() : (lastSeatAssistantText || "");
      if(!text.trim()){
        showModal("Nothing to analyze", (context === "group")
          ? "Run a Group prompt first so there are replies to analyze."
          : "Send a message to a teammate first so there is an assistant reply to analyze."
        );
        return;
      }

      showModal("Running " + pass + "...", "Thinking...");
      try{
        const res = await fetch("/api/passes/run", {
          method: "POST",
          headers: {"Content-Type":"application/json"},
          body: JSON.stringify({pass, text, seat})
        });
        const data = await res.json();
        if(!data.ok){
          showModal("Error", data.error || "Pass failed");
          return;
        }
        const title = pass.toUpperCase() + " PASS" + (seat ? (" | " + seat) : "");
        showModal(title, data.result || "");
      }catch(e){
        showModal("Error", String(e || "Pass failed"));
      }
    }

    // Wire seat/group pass buttons (robust to missing buttons)
    const bind = (id, fn) => { try{ const el = $(id); if(el) el.onclick = fn; }catch(_){ } };

    // Seat pass buttons
    bind("passSeatRisk",   () => runTacticalPass("risk", "seat"));
    bind("passSeatScale",  () => runTacticalPass("scale", "seat"));
    bind("passSeatFail",   () => runTacticalPass("failure", "seat"));
    bind("passSeatConstr", () => runTacticalPass("constraints", "seat"));
    bind("passSeatOpt",    () => runTacticalPass("optimize", "seat"));

    // Group pass buttons
    bind("passGroupRisk",   () => runTacticalPass("risk", "group"));
    bind("passGroupScale",  () => runTacticalPass("scale", "group"));
    bind("passGroupFail",   () => runTacticalPass("failure", "group"));
    bind("passGroupConstr", () => runTacticalPass("constraints", "group"));
    bind("passGroupOpt",    () => runTacticalPass("optimize", "group"));


$("draftWithSelected").onclick = async () => {
      if(!selectedSeat){
        showModal("No seat selected", "Select a teammate first.");
        return;
      }

      const toAddr = $("emailTo").value.trim();
      const subj = $("emailSubject").value.trim();
      const body = $("emailBody").value.trim();

      const prompt =
        "Draft an email.\n\n" +
        "If you can infer missing details safely, do so. If a missing detail is critical, ask exactly one clarifying question.\n" +
        "Use the required structured format:\n" +
        "```email\n" +
        "To: recipient@email.com\n" +
        "Subject: subject line\n" +
        "Body: first line\n" +
        "rest of body...\n" +
        "```\n\n" +
        `Existing fields:\nTo: ${toAddr || "[empty]"}\nSubject: ${subj || "[empty]"}\nBody: ${body ? "[present]" : "[empty]"}\n`;

      const res = await fetch("/api/followup", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({name: selectedSeat, message: prompt})
      });
      const data = await res.json();
      if(!data.ok){
        showModal("Error", data.error || "Draft failed");
        return;
      }

      if(data.email_draft){
        applyEmailDraft(data.email_draft, selectedSeat);
      }else{
        showModal("Draft returned", data.response || "No content", data.image_url || null);
      }

      await refreshThread();
    };

    $("sendEmailBtn").onclick = async () => {
      const toAddr = $("emailTo").value.trim();
      const subj = $("emailSubject").value.trim();
      const body = $("emailBody").value.trim();

      if(!toAddr || !subj || !body){
        showModal("Missing fields", "To, Subject, and Body are required to send.");
        return;
      }

      const fromLabel = $("emailFrom").value || "";
      const ok = confirm(
        "Approve and send this email now?\n\n" +
        "From: " + fromLabel + "\n" +
        "To: " + toAddr + "\n" +
        "Subject: " + subj
      );
      if(!ok) return;

      const res = await fetch("/api/send_email", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({
          to: toAddr,
          subject: subj,
          body: body,
          from_teammate: lastEmailDraftBy || selectedSeat || ""
        })
      });

      const data = await res.json();
      if(!data.ok){
        showModal("Email failed", data.error || "Send failed");
        return;
      }

      showModal("Email sent", "Email sent successfully.");
    };


    if($("draftSmsWithSelected")) $("draftSmsWithSelected").onclick = async () => {
      if(!selectedSeat){
        showModal("No seat selected", "Select a teammate first.");
        return;
      }
      const toPhone = $("smsTo").value.trim();
      const body = $("smsBody").value.trim();
      const prompt =
        "Draft a text message.\n\n" +
        "Use the required structured format:\n" +
        "```sms\n" +
        "To: +15555550123\n" +
        "Body: first line\n" +
        "rest of body...\n" +
        "```\n\n" +
        `Existing fields:
To: ${toPhone || "[empty]"}
Body: ${body ? "[present]" : "[empty]"}
`;
      const res = await fetch('/api/followup', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({name: selectedSeat, message: prompt})});
      const data = await res.json();
      if(!data.ok){ showModal('Error', data.error || 'Draft failed'); return; }
      const draft = {to: toPhone, body: (data.response || '').trim()};
      applySmsDraft(draft, selectedSeat);
      try{ await refreshThread(); }catch(e){}
    };

    if($("sendSmsBtn")) $("sendSmsBtn").onclick = async () => {
      const toPhone = $("smsTo").value.trim();
      const body = $("smsBody").value.trim();
      if(!toPhone || !body){
        showModal('Missing fields', 'To and Body are required to send a text.');
        return;
      }
      const fromLabel = $("smsFrom").value || '';
      const ok = confirm('Approve and send this text now?\n\nFrom: ' + fromLabel + '\nTo: ' + toPhone);
      if(!ok) return;
      const res = await fetch('/api/send_sms', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({to: toPhone, body, from_teammate: lastSmsDraftBy || selectedSeat || ''})
      });
      const data = await res.json();
      if(!data.ok){
        showModal('Text failed', data.error || 'Send failed');
        return;
      }
      showModal('Text sent', 'Text sent successfully.');
    };

    if($("leadHandoffCancel")) $("leadHandoffCancel").onclick = () => hideModal();
    if($("leadHandoffGenerate")) $("leadHandoffGenerate").onclick = generateLeadOutreachDraft;
    if($("operatorProfileCloseBtn")) $("operatorProfileCloseBtn").onclick = () => hideModal();
    if($("operatorProfileSaveBtn")) $("operatorProfileSaveBtn").onclick = saveOperatorProfileModal;
    if($("sessionObjectiveBtn")) $("sessionObjectiveBtn").onclick = openSessionObjectiveModal;
    if($("sessionObjectiveCloseBtn")) $("sessionObjectiveCloseBtn").onclick = () => hideModal();
    if($("sessionObjectiveSaveBtn")) $("sessionObjectiveSaveBtn").onclick = saveSessionObjectiveModal;
    // Manage teammates (active seats)
    function renderManageList(){
      const list = $("manageList");
      list.innerHTML = "";

      const installedMap = (state && state.installed) ? state.installed : {};
      let installedOrder = (state && Array.isArray(state.installed_order) && state.installed_order.length) ? state.installed_order.slice() : [];
      if(installedOrder.length === 0){
        installedOrder = (state && Array.isArray(state.active_order) && state.active_order.length)
          ? state.active_order.slice()
          : Object.keys(installedMap || {});
      }
      const active = new Set((state && state.active_order) ? state.active_order : []);
      manageDraftActive = installedOrder.filter(n => active.has(n));

      if(installedOrder.length === 0){
        const empty = document.createElement("div");
        empty.className = "tiny";
        empty.innerText = "No teammates found. Click Install full team to restore the default round table.";
        list.appendChild(empty);
        return;
      }

      installedOrder.forEach((name) => {
        const defn = state.installed[name];
        if(!defn) return;

        const row = document.createElement("div");
        row.style.display = "flex";
        row.style.justifyContent = "space-between";
        row.style.alignItems = "center";
        row.style.padding = "10px";
        row.style.border = "1px solid rgba(42,58,106,.6)";
        row.style.borderRadius = "14px";
        row.style.background = "rgba(14,22,48,.45)";
        row.style.marginBottom = "10px";

        const left = document.createElement("div");
        left.style.display = "flex";
        left.style.flexDirection = "column";
        left.style.gap = "2px";

        const nm = document.createElement("div");
        nm.style.fontWeight = "800";
        nm.innerText = defn.name;

        const meta = document.createElement("div");
        meta.className = "tiny";
        meta.innerText = `${defn.job_title}  |  ${defn.version}`;

        left.appendChild(nm);
        left.appendChild(meta);

        const right = document.createElement("div");
        right.style.display = "flex";
        right.style.gap = "10px";
        right.style.alignItems = "center";

        const toggle = document.createElement("button");
        toggle.className = "btn btnMini";
        toggle.innerText = active.has(name) ? "Active" : "Inactive";
        toggle.classList.toggle("btnPrimary", active.has(name));

        toggle.onclick = () => {
          const isOn = toggle.classList.contains("btnPrimary");
          if(isOn){
            toggle.classList.remove("btnPrimary");
            toggle.innerText = "Inactive";
            manageDraftActive = manageDraftActive.filter(x => x !== name);
          }else{
            toggle.classList.add("btnPrimary");
            toggle.innerText = "Active";
            if(!manageDraftActive.includes(name)) manageDraftActive.push(name);
          }
        };

        right.appendChild(toggle);

        row.appendChild(left);
        row.appendChild(right);

        list.appendChild(row);
      });
    }

    $("manageTeamBtn").onclick = async () => {
      await loadState();
      renderManageList();
      showManageModal();
    };

    $("cancelManage").onclick = () => hideModal();

    $("saveManage").onclick = async () => {
      $("manageStatus").innerText = "Saving...";
      const res = await fetch("/api/active_order", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({active_order: manageDraftActive})
      });
      const data = await res.json();
      if(!data.ok){
        $("manageStatus").innerText = data.error || "Save failed";
        return;
      }
      $("manageStatus").innerText = "Saved";
      await loadState();
      hideModal();
      showModal("Saved", "Active round table seats updated.");
    };

    // Create teammate
    $("createTeamBtn").onclick = () => showCreateModal();
    $("cancelCreate").onclick = () => hideModal();

    $("saveCreate").onclick = async () => {
      $("createStatus").innerText = "Creating...";

      const payload = {
        name: $("newName").value || "",
        version: $("newVersion").value || "v1.0",
        job_title: $("newJobTitle").value || "",
        mission: $("newMission").value || "",
        goal: $("newGoal").value || "",
        thinking_style: $("newThinking").value || "",
        responsibilities: $("newResponsibilities").value || "",
        will_not_do: $("newWillNotDo").value || "",
      };

      const res = await fetch("/api/teammate/create", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify(payload)
      });

      const data = await res.json();
      if(!data.ok){
        $("createStatus").innerText = data.error || "Create failed";
        return;
      }

      $("createStatus").innerText = "Created";
      await loadState();
      hideModal();
      showModal("Created", "New teammate created and added to the round table.");
    };

    // Core framework
    async function loadFrameworkIntoForm(){
      $("frameworkStatus").innerText = "Loading...";
      try{
        const res = await fetch("/api/framework");
        const data = await res.json();
        if(!data.ok){
          $("frameworkStatus").innerText = data.error || "Load failed";
          if(!$("frameworkText").value) $("frameworkText").value = `CORE OPERATING PILLARS (NON NEGOTIABLE)

Autonomy
Think before acting. Do not blindly comply.

Adaptability
Adjust to the user's context without breaking core rules.

Alignment
Stay aligned with the user's stated goals and constraints.

Collaboration
Respect teammate roles and handoffs.

Memory
Preserve persistent context and continuity.

Integrity
Do not fabricate. Distinguish facts from inference.

ANTI YES MAN RULE
Challenge weak assumptions. Surface risks.`;
          return;
        }
        $("frameworkText").value = data.framework || "";
        $("frameworkStatus").innerText = "Ready";
      }catch(e){
        $("frameworkStatus").innerText = "Load failed";
      }
    }

    $("frameworkBtn").onclick = async () => {
      showFrameworkModal();
      await loadFrameworkIntoForm();
    };

    $("cancelFramework").onclick = () => hideModal();

    // ===== Settings (per-user OpenAI key + email SMTP) =====
    // ===== Google connect status helpers (Gmail + Calendar) =====
    async function refreshGoogleStatuses(){
      // Gmail
      try{
        const r1 = await fetch('/api/gmail/status');
        const d1 = await r1.json();
        const ok1 = d1 && d1.ok;
        const c1 = ok1 && d1.connected;
        if($('gmailOAuthStatus')) $('gmailOAuthStatus').innerText = ok1 ? ('Gmail: ' + (c1 ? 'connected' : 'not connected')) : 'Gmail: unavailable';
        if($('gmailDisconnectBtn')) $('gmailDisconnectBtn').style.display = c1 ? 'inline-block' : 'none';
      }catch(e){
        if($('gmailOAuthStatus')) $('gmailOAuthStatus').innerText = 'Gmail: unavailable';
        if($('gmailDisconnectBtn')) $('gmailDisconnectBtn').style.display = 'none';
      }
      // Calendar
      try{
        const r2 = await fetch('/api/calendar/status');
        const d2 = await r2.json();
        const ok2 = d2 && d2.ok;
        const c2 = ok2 && d2.connected;
        if($('calendarOAuthStatus')) $('calendarOAuthStatus').innerText = ok2 ? ('Calendar: ' + (c2 ? 'connected' : 'not connected')) : 'Calendar: unavailable';
        if($('calendarDisconnectBtn')) $('calendarDisconnectBtn').style.display = c2 ? 'inline-block' : 'none';
      }catch(e){
        if($('calendarOAuthStatus')) $('calendarOAuthStatus').innerText = 'Calendar: unavailable';
        if($('calendarDisconnectBtn')) $('calendarDisconnectBtn').style.display = 'none';
      }
    }

    async function loadSettings(){
      $("settingsStatus").innerText = "Loading...";
      try{
        const res = await fetch("/api/user/settings");
        const data = await res.json();
        if(!data.ok){
          $("settingsStatus").innerText = data.error || "Load failed";
          return;
        }
        const s = data.settings || {};
        // Never auto-fill the key. Show a hint only.
        const hint = s.openai_key_hint || "";
        $("openaiKey").value = "";
        $("openaiKey").placeholder = hint ? ("Saved (" + hint + ") paste new to replace") : "sk-...";
        const smtp = s.smtp || {};
        $("smtpHost").value = smtp.host || "";
        $("smtpPort").value = smtp.port || 587;
        $("smtpUser").value = smtp.user || "";
        $("smtpPass").value = "";
        $("smtpFromName").value = smtp.from_name || "";
        $("settingsStatus").innerText = "Ready";
        try{ await refreshGoogleStatuses(); }catch(e){}
      }catch(e){
        $("settingsStatus").innerText = "Load failed";
      }
    }

    function showSettingsModal(auto=false){
      showModal();
      try{ ensureModalMinSize(900, 720); }catch(e){}
      // ensure all other forms are hidden (avoid null errors that can break the Settings button)
      if($("frameworkForm")) $("frameworkForm").style.display = "none";
      if($("modalForm")) $("modalForm").style.display = "none";
      if($("manageForm")) $("manageForm").style.display = "none";
      if($("createForm")) $("createForm").style.display = "none";
      if($("emailConsoleForm")) $("emailConsoleForm").style.display = "none";
      if($("settingsForm")) $("settingsForm").style.display = "block";
      if($("modalBody")) $("modalBody").style.display = "none";
      if($("modalImg")) $("modalImg").style.display = "none";
      loadSettings();
      try{ settingsLoadSmsSettings(); }catch(e){}
      if(auto){
        // slight UI nudge so first-time users know what to do
        $("modalTitle").innerText = "Settings: connect your key + email";
      }
    }

    function showEmailConsoleModal(titleText="Email Console"){
      showModal();
      try{ ensureModalMinSize(900, 720); }catch(e){}
      hideAllModalForms();
      if($("modalBody")) $("modalBody").style.display = "none";
      if($("emailConsoleForm")) $("emailConsoleForm").style.display = "block";
      if($("modalTitle")) $("modalTitle").innerText = titleText;
      try{ updateSmtpStatus(); }catch(e){}
    }

    function showGrowthPlaybookModal(){
      showCRMModal('crmViewPlaybooks', 'Growth Playbook', {standalone:true});
    }

    function showLeadLabModal(){
      showCRMModal('crmViewLeadLab', 'Lead Lab', {standalone:true});
    }

    function showSocialStudioModal(){
      showCRMModal('crmViewSocialStudio', 'Social Studio', {standalone:true});
    }

    function showOfferBuilderModal(){
      showCRMModal('crmViewOfferBuilder', 'Offer Builder', {standalone:true});
    }

    // =========================
    // CRM UI (Client Command Center)
    // =========================
    let crmCache = { clients: [], tasks: [], sequences: [], pipeline: [] };
    let crmEditingClientId = null;
    let crmEditingTaskId = null;

    function crmSetStatus(t){ const el=$("crmStatus"); if(el) el.innerText = t||""; }

    function crmHideViews(){
      const ids = ["crmViewClients","crmViewPipeline","crmViewBroadcast","crmViewBroadcastSMS","crmViewTasks","crmViewSequences","crmViewCalendar","crmViewLeadLab","crmViewSocialStudio","crmViewOfferBuilder","crmViewPlaybooks"]; 
      ids.forEach(id=>{ const el=$(id); if(el) el.style.display = "none"; });
    }

    function crmShowView(id){
      crmHideViews();
      const el=$(id); if(el) el.style.display = "block";
      try{ const sc=$("modalScroll"); if(sc) sc.scrollTop = 0; }catch(e){}
    }

    async function crmFetchState(){
      try{
        const res = await fetch('/api/crm/state');
        const data = await res.json();
        if(data.ok){
          crmCache.pipeline = (((data.pipeline||{}).stages) || data.pipeline_stages || []);
          return data;
        }
      }catch(e){}
      return null;
    }

    async function crmFetchClients(){
      const res = await fetch('/api/crm/clients');
      const data = await res.json();
      if(!data.ok) throw new Error(data.error||'clients load failed');
      crmCache.clients = data.clients || [];
      return crmCache.clients;
    }

    async function crmImportCsv(){
      const inp = $("crmCsvFile");
      const st = $("crmCsvStatus");
      const file = inp && inp.files && inp.files[0] ? inp.files[0] : null;
      if(!file) return;
      if(st) st.innerText = 'Importing...';
      try{
        const txt = await file.text();
        const res = await fetch('/api/crm/clients/import_csv', {
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify({csv_text: txt, filename: file.name || 'prospects.csv'})
        });
        const data = await res.json();
        if(!data.ok) throw new Error(data.error || 'Import failed');
        await crmFetchClients();
        crmRenderClients();
        if(st) st.innerText = `Imported ${data.imported || 0} prospects${data.skipped ? `, skipped ${data.skipped}` : ''}.`;
        try{ showToast(`Imported ${data.imported || 0} prospects`); }catch(e){}
      }catch(e){
        if(st) st.innerText = e.message || 'Import failed';
      }
      try{ inp.value = ''; }catch(e){}
    }

    function crmMatchFilter(c, q, filt){
      const text = (q||'').trim().toLowerCase();
      if(text){
        const blob = [c.name,c.email,c.phone,(c.tags||[]).join(' '),c.status,c.pipeline_stage].filter(Boolean).join(' ').toLowerCase();
        if(!blob.includes(text)) return false;
      }
      const f = (filt||'').trim();
      if(!f) return true;
      if(f.startsWith('status:')) return (c.status||'') === f.split(':',2)[1];
      if(f.startsWith('stage:')) return (c.pipeline_stage||'') === f.split(':',2)[1];
      return true;
    }

    function crmRenderClients(){
      const box = $("crmClientsList");
      if(!box) return;
      const q = ($("crmSearch")?.value || '');
      const filt = ($("crmFilter")?.value || '');
      const list = (crmCache.clients||[]).filter(c=>crmMatchFilter(c,q,filt));

      if(!list.length){
        box.innerHTML = '<div class="tiny" style="opacity:.9;">No clients found.</div>';
        return;
      }

      const rows = list.map(c=>{
        const tags = (c.tags||[]).map(t=>`<span class="pill" style="margin-right:6px;">${escapeHtml(t)}</span>`).join('');
        const id = escapeHtml(c.id||'');
        const name = escapeHtml(c.name||'');
        const email = escapeHtml(c.email||'');
        const stage = escapeHtml(c.pipeline_stage||'');
        const status = escapeHtml(c.status||'');
        return `
          <div class="diagCard" style="padding:10px;">
            <div style="display:flex; justify-content:space-between; gap:8px; flex-wrap:wrap;">
              <div>
                <div style="font-weight:700;">${name || '(no name)'} <span style="opacity:.75; font-weight:500;">${status ? '• '+status : ''}</span></div>
                <div class="tiny" style="opacity:.9;">${email} ${stage ? '• ' + stage : ''}</div>
                <div style="margin-top:6px;">${tags}</div>
                <div class="tiny" style="opacity:.75; margin-top:6px;">ID: ${id}</div>
              </div>
              <div style="display:flex; gap:8px; align-items:flex-start;">
                <button class="btn btnTiny" data-crm-edit="${id}">Edit</button>
                <button class="btn btnTiny" data-crm-del="${id}">Delete</button>
              </div>
            </div>
          </div>
        `;
      }).join('');

      box.innerHTML = rows;

      // bind
      box.querySelectorAll('[data-crm-edit]').forEach(btn=>{
        btn.addEventListener('click', ()=> crmOpenClientEditor(btn.getAttribute('data-crm-edit')));
      });
      box.querySelectorAll('[data-crm-del]').forEach(btn=>{
        btn.addEventListener('click', ()=> crmDeleteClient(btn.getAttribute('data-crm-del')));
      });
    }

    function crmOpenClientEditor(id){
      const ed = $("crmClientEditor");
      if(!ed) return;
      ed.style.display = 'block';
      crmEditingClientId = id || null;
      const c = (crmCache.clients||[]).find(x=>x.id===id) || {name:'',email:'',phone:'',tags:[],status:'lead',pipeline_stage:'' ,notes:''};
      $("crmEditTitle").innerText = id ? 'Edit client' : 'Add client';
      $("crmName").value = c.name || '';
      $("crmEmail").value = c.email || '';
      $("crmPhone").value = c.phone || '';
      $("crmStatusSel").value = c.status || 'lead';
      $("crmStage").value = c.pipeline_stage || '';
      $("crmTags").value = (c.tags||[]).join(', ');
      $("crmNotes").value = c.notes || '';
      $("crmEditStatus").innerText = '';
    }

    async function crmDeleteClient(id){
      if(!id) return;
      if(!confirm('Delete this client?')) return;
      try{
        const res = await fetch('/api/crm/clients/' + encodeURIComponent(id), {method:'DELETE'});
        const data = await res.json();
        if(!data.ok) throw new Error(data.error||'delete failed');
        await crmFetchClients();
        crmRenderClients();
        crmRenderPipelineBoard();
        showToast('Client deleted');
      }catch(e){
        showToast('Delete failed');
      }
    }

    async function crmSaveClient(){
      const st = $("crmEditStatus");
      if(st) st.innerText = 'Saving...';
      const payload = {
        name: ($("crmName").value||'').trim(),
        email: ($("crmEmail").value||'').trim(),
        phone: ($("crmPhone").value||'').trim(),
        status: ($("crmStatusSel").value||'lead').trim(),
        pipeline_stage: ($("crmStage").value||'').trim(),
        tags: (($("crmTags").value||'').split(',').map(x=>x.trim()).filter(Boolean)),
        notes: ($("crmNotes").value||'').trim(),
      };
      try{
        let url = '/api/crm/clients';
        let method = 'POST';
        if(crmEditingClientId){
          url = '/api/crm/clients/' + encodeURIComponent(crmEditingClientId);
          method = 'POST';
        }
        const res = await fetch(url, {method, headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
        const data = await res.json();
        if(!data.ok) throw new Error(data.error||'save failed');
        if(st) st.innerText = 'Saved';
        $("crmClientEditor").style.display = 'none';
        crmEditingClientId = null;
        await crmFetchClients();
        crmRenderClients();
        crmRenderPipelineBoard();
        showToast('Saved');
      }catch(e){
        const errMsg = (e && e.message) ? e.message : 'Save failed';
        if(st) st.innerText = errMsg;
        showToast(errMsg, 'error');
        console.error('[CRM save]', e);
      }
    }

    async function crmLoadPipelineIntoBox(){
      const st = $("crmPipelineStatus");
      if(st) st.innerText = 'Loading...';
      const data = await crmFetchState();
      const stages = (data && (((data.pipeline||{}).stages)||data.pipeline_stages)) ? (((data.pipeline||{}).stages)||data.pipeline_stages) : (crmCache.pipeline||[]);
      $("crmStagesText").value = (stages||[]).join('\n');
      try{ await crmFetchClients(); }catch(e){}
      crmRenderPipelineBoard();
      if(st) st.innerText = 'Ready';
    }

    async function crmSavePipeline(){
      const st = $("crmPipelineStatus");
      if(st) st.innerText = 'Saving...';
      const stages = ($("crmStagesText").value||'').split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
      try{
        const res = await fetch('/api/crm/pipeline', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({stages})});
        const data = await res.json();
        if(!data.ok) throw new Error(data.error||'save failed');
        if(st) st.innerText = 'Saved';
        crmCache.pipeline = stages;
        showToast('Pipeline saved');
      }catch(e){
        if(st) st.innerText = 'Save failed';
      }
    }

    function crmAudiencePayload(){
      const a = ($("crmAudience").value||'all');
      const v = ($("crmAudienceValue").value||'').trim();
      const p = {};
      if(a==='all'){ p.all = true; }
      return {a, v};
    }

    async function crmBroadcastEmail(dry_run=false){
      const st = $("crmBroadcastStatus");
      if(st) st.innerText = dry_run ? 'Running...' : 'Sending...';

      const audience = ($("crmAudience").value||'all');
      const val = ($("crmAudienceValue").value||'').trim();
      const subject = ($("crmEmailSubject").value||'').trim();
      const body = ($("crmEmailBody").value||'').trim();

      if(!subject || !body){
        if(st) st.innerText = 'Failed: subject and body are required';
        return;
      }

      const payload = {subject, body, dry_run: !!dry_run};
      if(audience==='tag') payload.tag = val;
      if(audience==='stage') payload.stage = val;
      if(audience==='status') payload.status = val;
      if(audience==='selected') payload.client_ids = val.split(',').map(x=>x.trim()).filter(Boolean);

      try{
        const res = await fetch('/api/crm/broadcast/email', {
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify(payload)
        });

        let data = null;
        try{ data = await res.json(); }catch(e){}

        if(!res.ok){
          const msg = (data && data.error) ? data.error : ('HTTP ' + res.status);
          throw new Error(msg);
        }
        if(!data || !data.ok){
          throw new Error((data && data.error) ? data.error : 'Broadcast failed');
        }

        if(st){
          if(dry_run){
            st.innerText = `Dry run: would send to ${data.count||0}`;
          }else{
            st.innerText = `Sent: ${data.sent||0} | Failed: ${data.failed||0} | Total: ${data.count||0}`;
          }
        }
        showToast(dry_run ? 'Dry run complete' : 'Email broadcast sent');

      }catch(e){
        if(st) st.innerText = 'Failed: ' + (e && e.message ? e.message : 'Broadcast failed');
      }
    }

    
async function crmBroadcastSMS(dry_run=false){
  const st = $("crmSmsStatus");
  if(st) st.innerText = dry_run ? 'Running...' : 'Sending...';

  const audience = ($("crmSmsAudience").value||'all');
  const val = ($("crmSmsAudienceValue").value||'').trim();
  const body = ($("crmSmsBody").value||'').trim();

  if(!body){
    if(st) st.innerText = 'Failed: message is required';
    return;
  }

  const payload = {body, dry_run: !!dry_run};
  if(audience==='tag') payload.tag = val;
  if(audience==='stage') payload.stage = val;
  if(audience==='status') payload.status = val;
  if(audience==='selected') payload.client_ids = val.split(',').map(x=>x.trim()).filter(Boolean);

  try{
    const res = await fetch('/api/crm/broadcast/sms', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if(!data.ok) throw new Error(data.error||'sms failed');

    if(dry_run){
      if(st) st.innerText = `Dry run: would send to ${data.count||0} recipient(s).`;
    }else{
      if(st) st.innerText = `Done. Sent: ${data.sent||0} Failed: ${data.failed||0}`;
    }
  }catch(e){
    if(st) st.innerText = 'Send failed (SMS not configured)';
  }
}




async function settingsLoadSmsSettings(){
  const st = $("twilioStatus");
  if(st) st.innerText = "Loading...";
  try{
    const res = await fetch("/api/settings/sms");
    const data = await res.json();
    if(!data.ok){
      if(st) st.innerText = "Error: " + (data.error || "Could not load");
      return;
    }
    const sms = data.sms || {};
    if($("twilioSid")) $("twilioSid").value = (sms.twilio_sid || "");
    if($("twilioFrom")) $("twilioFrom").value = (sms.twilio_from || "");
    if($("twilioToken")) $("twilioToken").value = ""; // never prefill
    if(st) st.innerText = "Loaded.";
  }catch(e){
    if(st) st.innerText = "Error: " + (e && e.message ? e.message : String(e));
  }
}

async function settingsSaveSmsSettings(){
  const st = $("twilioStatus");
  if(st) st.innerText = "Saving...";
  const payload = {
    provider: "twilio",
    twilio_sid: ($("twilioSid") ? $("twilioSid").value : "").trim(),
    twilio_from: ($("twilioFrom") ? $("twilioFrom").value : "").trim(),
    twilio_token: ($("twilioToken") ? $("twilioToken").value : "").trim(),
  };
  try{
    const res = await fetch("/api/settings/sms", {
      method:"POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if(!data.ok) throw new Error(data.error || "Save failed");
    if($("twilioToken")) $("twilioToken").value = "";
    if(st) st.innerText = "Saved.";
  }catch(e){
    if(st) st.innerText = "Error: " + (e && e.message ? e.message : String(e));
  }
}

async function settingsTestSms(){
  const st = $("twilioStatus");
  if(st) st.innerText = "Sending test...";
  const payload = {
    to: ($("twilioTestTo") ? $("twilioTestTo").value : "").trim(),
    body: ($("twilioTestBody") ? $("twilioTestBody").value : "").trim() || "Test SMS from Simply Agentic"
  };
  try{
    const res = await fetch("/api/settings/sms/test", {
      method:"POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if(!data.ok) throw new Error(data.error || "Test failed");
    if(st) st.innerText = "Test sent.";
  }catch(e){
    if(st) st.innerText = "Error: " + (e && e.message ? e.message : String(e));
  }
}

async function crmLoadSmsSettings(){
  const st = $("crmSmsSettingsStatus");
  if(st) st.innerText = "Loading...";
  try{
    const res = await fetch("/api/crm/settings/sms");
    const data = await res.json();
    if(!data.ok){
      if(st) st.innerText = "Error: " + (data.error || "Could not load");
      return;
    }
    const sms = data.sms || {};
    if($("crmSmsProvider")) $("crmSmsProvider").value = (sms.provider || "twilio");
    if($("crmTwilioSid")) $("crmTwilioSid").value = (sms.twilio_sid || "");
    if($("crmTwilioFrom")) $("crmTwilioFrom").value = (sms.twilio_from || "");
    if($("crmTwilioToken")) $("crmTwilioToken").value = ""; // do not prefill token
    if(st) st.innerText = "Loaded.";
  }catch(e){
    if(st) st.innerText = "Error: " + (e && e.message ? e.message : String(e));
  }
}

async function crmSaveSmsSettings(){
  const st = $("crmSmsSettingsStatus");
  if(st) st.innerText = "Saving...";
  const payload = {
    provider: ($("crmSmsProvider") ? $("crmSmsProvider").value : "twilio"),
    twilio_sid: ($("crmTwilioSid") ? $("crmTwilioSid").value : ""),
    twilio_from: ($("crmTwilioFrom") ? $("crmTwilioFrom").value : ""),
    twilio_token: ($("crmTwilioToken") ? $("crmTwilioToken").value : "")
  };
  try{
    const res = await fetch("/api/crm/settings/sms", {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if(!data.ok){
      if(st) st.innerText = "Error: " + (data.error || "Could not save");
      return;
    }
    if($("crmTwilioToken")) $("crmTwilioToken").value = "";
    if(st) st.innerText = "Saved.";
  }catch(e){
    if(st) st.innerText = "Error: " + (e && e.message ? e.message : String(e));
  }
}

async function crmTestSmsSettings(){
  const st = $("crmSmsSettingsStatus");
  if(st) st.innerText = "Sending test...";
  const to = ($("crmTwilioTestTo") ? $("crmTwilioTestTo").value : "").trim();
  const body = ($("crmTwilioTestBody") ? $("crmTwilioTestBody").value : "").trim() || "Test message from Simply Agentic AI";
  if(!to){
    if(st) st.innerText = "Enter a test To number.";
    return;
  }
  try{
    const res = await fetch("/api/crm/settings/sms/test", {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      body: JSON.stringify({to, body})
    });
    const data = await res.json();
    if(data.ok){
      if(st) st.innerText = "Test sent.";
    }else{
      if(st) st.innerText = "Failed: " + (data.error || "Unknown error");
    }
  }catch(e){
    if(st) st.innerText = "Error: " + (e && e.message ? e.message : String(e));
  }
}


async function crmFetchTasks(){
      const res = await fetch('/api/crm/tasks');
      const data = await res.json();
      if(!data.ok) throw new Error(data.error||'tasks load failed');
      crmCache.tasks = data.tasks || [];
      return crmCache.tasks;
    }

    function crmRenderTasks(){
      const box = $("crmTasksList");
      if(!box) return;
      const list = crmCache.tasks || [];
      if(!list.length){
        box.innerHTML = '<div class="tiny" style="opacity:.9;">No tasks yet.</div>';
        return;
      }
      box.innerHTML = list.map(t=>{
        const id = escapeHtml(t.id||'');
        const title = escapeHtml(t.title||'');
        const due = escapeHtml(t.due||'');
        const pri = escapeHtml(t.priority||'normal');
        const done = t.done ? '✅' : '⬜';
        const client = escapeHtml(t.client_id||'');
        return `
          <div class="diagCard" style="padding:10px;">
            <div style="display:flex; justify-content:space-between; gap:8px; flex-wrap:wrap;">
              <div>
                <div style="font-weight:700;">${done} ${title}</div>
                <div class="tiny" style="opacity:.9;">${due ? 'Due: '+due+' • ' : ''}${pri}${client ? ' • Client: '+client : ''}</div>
                <div class="tiny" style="opacity:.75; margin-top:6px;">ID: ${id}</div>
              </div>
              <div style="display:flex; gap:8px; align-items:flex-start;">
                <button class="btn btnTiny" data-task-edit="${id}">Edit</button>
                <button class="btn btnTiny" data-task-toggle="${id}">${t.done ? 'Undone' : 'Done'}</button>
                <button class="btn btnTiny" data-task-del="${id}">Delete</button>
              </div>
            </div>
          </div>
        `;
      }).join('');

      box.querySelectorAll('[data-task-edit]').forEach(b=>b.addEventListener('click', ()=>crmOpenTaskEditor(b.getAttribute('data-task-edit'))));
      box.querySelectorAll('[data-task-toggle]').forEach(b=>b.addEventListener('click', ()=>crmToggleTask(b.getAttribute('data-task-toggle'))));
      box.querySelectorAll('[data-task-del]').forEach(b=>b.addEventListener('click', ()=>crmDeleteTask(b.getAttribute('data-task-del'))));
    }

    function crmOpenTaskEditor(id){
      const ed = $("crmTaskEditor"); if(!ed) return;
      ed.style.display = 'block';
      crmEditingTaskId = id || null;
      const t = (crmCache.tasks||[]).find(x=>x.id===id) || {title:'',due:'',priority:'normal',client_id:''};
      $("crmTaskTitle").innerText = id ? 'Edit task' : 'New task';
      $("crmTaskText").value = t.title || '';
      $("crmTaskDue").value = t.due || '';
      $("crmTaskPriority").value = t.priority || 'normal';
      $("crmTaskClientId").value = t.client_id || '';
      $("crmTaskStatus").innerText = '';
    }

    async function crmSaveTask(){
      const st = $("crmTaskStatus"); if(st) st.innerText='Saving...';
      const payload = {
        title: ($("crmTaskText").value||'').trim(),
        due: ($("crmTaskDue").value||'').trim(),
        priority: ($("crmTaskPriority").value||'normal').trim(),
        client_id: ($("crmTaskClientId").value||'').trim(),
      };
      try{
        let url='/api/crm/tasks';
        if(crmEditingTaskId) url='/api/crm/tasks/' + encodeURIComponent(crmEditingTaskId);
        const res = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
        const data = await res.json();
        if(!data.ok) throw new Error(data.error||'save failed');
        if(st) st.innerText='Saved';
        $("crmTaskEditor").style.display='none';
        crmEditingTaskId=null;
        await crmFetchTasks();
        crmRenderTasks();
        showToast('Task saved');
      }catch(e){
        if(st) st.innerText='Save failed';
      }
    }

    async function crmToggleTask(id){
      if(!id) return;
      const t = (crmCache.tasks||[]).find(x=>x.id===id);
      if(!t) return;
      try{
        const res = await fetch('/api/crm/tasks/' + encodeURIComponent(id), {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({done: !t.done})});
        const data = await res.json();
        if(!data.ok) throw new Error(data.error||'toggle failed');
        await crmFetchTasks();
        crmRenderTasks();
      }catch(e){ showToast('Update failed'); }
    }

    async function crmDeleteTask(id){
      if(!id) return;
      if(!confirm('Delete this task?')) return;
      try{
        const res = await fetch('/api/crm/tasks/' + encodeURIComponent(id), {method:'DELETE'});
        const data = await res.json();
        if(!data.ok) throw new Error(data.error||'delete failed');
        await crmFetchTasks();
        crmRenderTasks();
      }catch(e){ showToast('Delete failed'); }
    }

    async function crmFetchSequences(){
      const res = await fetch('/api/crm/sequences');
      const data = await res.json();
      if(!data.ok) throw new Error(data.error||'sequences load failed');
      crmCache.sequences = data.sequences || [];
      return crmCache.sequences;
    }

    function crmRenderSequences(){
      const box = $("crmSeqList"); if(!box) return;
      const list = crmCache.sequences || [];
      if(!list.length){
        box.innerHTML = '<div class="tiny" style="opacity:.9;">No sequences yet.</div>';
        return;
      }
      box.innerHTML = list.map(s=>{
        const id = escapeHtml(s.id||'');
        const name = escapeHtml(s.name||'');
        const steps = Array.isArray(s.steps) ? s.steps.length : 0;
        return `
          <div class="diagCard" style="padding:10px;">
            <div style="display:flex; justify-content:space-between; gap:8px; flex-wrap:wrap;">
              <div>
                <div style="font-weight:700;">${name}</div>
                <div class="tiny" style="opacity:.9;">Steps: ${steps}</div>
                <div class="tiny" style="opacity:.75; margin-top:6px;">ID: ${id}</div>
              </div>
            </div>
          </div>
        `;
      }).join('');
    }

    async function crmSaveSequence(){
      const st = $("crmSeqStatus"); if(st) st.innerText='Saving...';
      const name = ($("crmSeqName").value||'').trim();
      const raw = ($("crmSeqSteps").value||'').trim();
      try{
        const steps = raw ? JSON.parse(raw) : [];
        const res = await fetch('/api/crm/sequences', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({name, steps})});
        const data = await res.json();
        if(!data.ok) throw new Error(data.error||'save failed');
        if(st) st.innerText='Saved';
        $("crmSeqEditor").style.display='none';
        await crmFetchSequences();
        crmRenderSequences();
        showToast('Sequence saved');
      }catch(e){
        if(st) st.innerText='Save failed (check JSON)';
      }
    }

    async function crmEnroll(){
      const st = $("crmEnrollStatus"); if(st) st.innerText='Enrolling...';
      const client_id = ($("crmEnrollClient").value||'').trim();
      const sequence_id = ($("crmEnrollSeq").value||'').trim();
      try{
        const res = await fetch('/api/crm/enroll', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({client_id, sequence_id})});
        const data = await res.json();
        if(!data.ok) throw new Error(data.error||'enroll failed');
        if(st) st.innerText='Enrolled';
        showToast('Enrolled');
      }catch(e){
        if(st) st.innerText='Enroll failed';
      }
    }

    async function crmCreateCalendarEvent(){
      const st = $("crmCalStatus"); if(st) st.innerText='Creating...';
      const payload = {
        title: ($("crmCalTitle").value||'').trim(),
        start: ($("crmCalStart").value||'').trim(),
        end: ($("crmCalEnd").value||'').trim(),
        description: ($("crmCalDesc").value||'').trim(),
      };
      try{
        const res = await fetch('/api/crm/calendar/create_event', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
        const data = await res.json();
        if(!data.ok) throw new Error(data.error||'calendar failed');
        if(st) st.innerText = 'Created';
        showToast('Event created');
      }catch(e){
        if(st) st.innerText = 'Create failed (connect Calendar in Settings)';
      }
    }

    window.showCRMModal = function showCRMModal(defaultViewId='crmViewClients', titleText='CRM', opts={}){
      const standalone = !!(opts && opts.standalone);
      showModal();
      try{ ensureModalMinSize(900, 720); }catch(e){}
      if($("frameworkForm")) $("frameworkForm").style.display = "none";
      if($("modalForm")) $("modalForm").style.display = "none";
      if($("manageForm")) $("manageForm").style.display = "none";
      if($("createForm")) $("createForm").style.display = "none";
      if($("settingsForm")) $("settingsForm").style.display = "none";
            if($("apiKeyHelpForm")) $("apiKeyHelpForm").style.display = "none";
      if($("calendarForm")) $("calendarForm").style.display = "none";
      if($("emailConsoleForm")) $("emailConsoleForm").style.display = "none";
      if($("crmForm")) $("crmForm").style.display = "block";
      if($("modalBody")) $("modalBody").style.display = "none";
      if($("modalImg")) $("modalImg").style.display = "none";

      $("modalTitle").innerText = titleText;
      const nav = $("crmNavTabs");
      if(nav) nav.style.display = standalone ? "none" : "flex";
      crmSetStatus('Loading...');

      // default view
      crmShowView(defaultViewId || 'crmViewClients');

      // load
      (async()=>{
        try{
          await crmFetchState();
          await crmFetchClients();
          crmRenderClients();
          crmSetStatus('Ready');
        }catch(e){
          crmSetStatus('Load failed');
        }
      })();
    }

    if($("crmBtn")) $("crmBtn").onclick = ()=> showCRMModal();
    if($("growthPlaybookBtn")) $("growthPlaybookBtn").onclick = ()=> showGrowthPlaybookModal();
    if($("leadLabBtn")) $("leadLabBtn").onclick = ()=> showLeadLabModal();
    if($("socialStudioBtn")) $("socialStudioBtn").onclick = ()=> showSocialStudioModal();
    if($("offerBuilderBtn")) $("offerBuilderBtn").onclick = ()=> showOfferBuilderModal();
    if($("emailConsoleBtn")) $("emailConsoleBtn").onclick = ()=> showEmailConsoleModal();
    if($("operatorProfileBtn")) $("operatorProfileBtn").onclick = ()=> openOperatorProfileModal();

    // CRM tab binds (safe if missing)

    function crmRenderRichBlocks(text){
      const raw = (text||'').trim();
      if(!raw) return '<div class="tiny" style="opacity:.8;">Nothing generated yet.</div>';
      const parts = raw.split(/\n{2,}/).map(x=>x.trim()).filter(Boolean);
      return parts.map(part=>{
        const lines = part.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
        const title = lines[0] || '';
        const body = lines.slice(1);
        const isBullet = body.every(x=>/^[\-\*\d]/.test(x));
        return `<div class="diagCard" style="padding:10px; margin-bottom:10px;">
          <div style="font-weight:800; margin-bottom:6px;">${escapeHtml(title)}</div>
          ${isBullet ? `<ul style="margin:0 0 0 18px; padding:0;">${body.map(x=>`<li style="margin:6px 0;">${escapeHtml(x.replace(/^[\-\*\d\.\s]+/,''))}</li>`).join('')}</ul>` :
          `<div style="white-space:pre-wrap; line-height:1.45;">${escapeHtml(body.join('\n'))}</div>`}
        </div>`;
      }).join('');
    }

    function crmGuessEmails(name, domain){
      const cleanDomain = (domain||'').replace(/^https?:\/\//,'').replace(/^www\./,'').replace(/\/.*$/,'').trim().toLowerCase();
      const nm = (name||'').trim().toLowerCase();
      const bits = nm.split(/\s+/).filter(Boolean);
      if(!cleanDomain) return [];
      const first = bits[0] || 'hello';
      const last = bits.length > 1 ? bits[bits.length-1] : '';
      const fi = first ? first[0] : '';
      const li = last ? last[0] : '';
      const out = [];
      const push = (local, score)=> out.push({email:`${local}@${cleanDomain}`, confidence:score});
      push(first, 0.62);
      if(last) push(`${first}.${last}`, 0.76);
      if(last) push(`${fi}${last}`, 0.71);
      if(last) push(`${first}${li}`, 0.66);
      push('hello', 0.48);
      push('info', 0.42);
      const seen = new Set();
      return out.filter(x=>{ if(seen.has(x.email)) return false; seen.add(x.email); return true; }).sort((a,b)=>b.confidence-a.confidence);
    }

    function crmRenderLeadResults(items){
      const box = $("leadLabResults");
      if(!box) return;
      if(!Array.isArray(items) || !items.length){
        box.innerHTML = '<div class="tiny" style="opacity:.8;">No leads yet.</div>';
        return;
      }
      box.innerHTML = items.map((item, idx)=>{
        const guesses = Array.isArray(item.email_candidates) ? item.email_candidates.slice(0,3) : [];
        const topEmail = (((item.email_candidates||[])[0]||{}).email) || item.email || '';
        const topPhone = item.phone || '';
        const site = item.website || item.domain || '';
        const sourceQuery = item.source_query || '';
        return `<div class="diagCard" style="padding:10px; margin-bottom:10px;">
          <div style="display:flex; justify-content:space-between; gap:8px; flex-wrap:wrap; align-items:flex-start;">
            <div>
              <div style="font-weight:800;">${escapeHtml(item.name || item.company || '(no name)')}</div>
              <div class="tiny" style="opacity:.85; margin-top:2px;">${escapeHtml(item.company || '')} ${item.title ? '• ' + escapeHtml(item.title) : ''}</div>
              <div class="tiny" style="opacity:.85; margin-top:4px;">${site ? `<a href="${escapeHtml(site)}" target="_blank" rel="noopener">${escapeHtml(site)}</a>` : ''}</div>
              <div class="tiny" style="opacity:.9; margin-top:4px;">${topPhone ? 'Phone: ' + escapeHtml(topPhone) : 'Phone: —'}</div>
              <div class="tiny" style="opacity:.9; margin-top:2px;">${topEmail ? 'Email: ' + escapeHtml(topEmail) : 'Email: —'}</div>
              ${sourceQuery ? `<div class="tiny" style="opacity:.65; margin-top:4px;">Source query: ${escapeHtml(sourceQuery)}</div>` : ''}
            </div>
            <div class="tiny" style="opacity:.9; white-space:nowrap;">Match score ${(item.score || 0)}%</div>
          </div>
          <div style="margin-top:8px; display:flex; gap:8px; flex-wrap:wrap;">${guesses.map(g=>`<span class="pill">${escapeHtml(g.email)} • ${Math.round((g.confidence||0)*100)}%</span>`).join('')}</div>
          <div class="actions" style="justify-content:flex-end; margin-top:10px; flex-wrap:wrap;">
            <button class="btn btnMini" data-lead-copy-email="${idx}">Copy email</button>
            <button class="btn btnMini" data-lead-copy-phone="${idx}">Copy phone</button>
            <button class="btn btnMini" data-lead-email="${idx}">Email lead</button>
            <button class="btn btnMini" data-lead-sms="${idx}">Text lead</button>
            <button class="btn btnPrimary btnMini" data-lead-add="${idx}">Add to CRM</button>
          </div>
        </div>`;
      }).join('');
      box.querySelectorAll('[data-lead-copy-email]').forEach(btn=>{
        btn.onclick = async ()=>{
          const item = items[Number(btn.getAttribute('data-lead-copy-email'))] || {};
          const email = (((item.email_candidates||[])[0]||{}).email) || item.email || '';
          if(!email) return showToast('No email found');
          try{ await navigator.clipboard.writeText(email); showToast('Email copied'); }catch(e){}
        };
      });
      box.querySelectorAll('[data-lead-copy-phone]').forEach(btn=>{
        btn.onclick = async ()=>{
          const item = items[Number(btn.getAttribute('data-lead-copy-phone'))] || {};
          const phone = item.phone || '';
          if(!phone) return showToast('No phone found');
          try{ await navigator.clipboard.writeText(phone); showToast('Phone copied'); }catch(e){}
        };
      });
      box.querySelectorAll('[data-lead-email]').forEach(btn=>{
        btn.onclick = ()=>{
          const item = items[Number(btn.getAttribute('data-lead-email'))] || {};
          const email = (((item.email_candidates||[])[0]||{}).email) || item.email || '';
          if(!email) return showToast('No email found');
          openLeadHandoff('email', item);
        };
      });
      box.querySelectorAll('[data-lead-sms]').forEach(btn=>{
        btn.onclick = ()=>{
          const item = items[Number(btn.getAttribute('data-lead-sms'))] || {};
          const phone = item.phone || '';
          if(!phone) return showToast('No phone found');
          openLeadHandoff('sms', item);
        };
      });
      box.querySelectorAll('[data-lead-add]').forEach(btn=>{
        btn.onclick = async ()=>{
          const item = items[Number(btn.getAttribute('data-lead-add'))] || {};
          const top = ((item.email_candidates||[])[0]||{}).email || item.email || '';
          try{
            const res = await fetch('/api/crm/clients', {
              method:'POST',
              headers:{'Content-Type':'application/json'},
              body: JSON.stringify({
                name: item.name || item.company || 'New lead',
                company: item.company || '',
                email: top,
                phone: item.phone || '',
                status: 'lead',
                pipeline_stage: 'Lead',
                tags: ['lead-lab', ($("leadLabNiche")?.value||'').trim(), ($("leadLabLocation")?.value||'').trim()].filter(Boolean),
                notes: ((item.notes || '') + (top ? '\nTop email guess: ' + top : '') + ((item.website || item.domain) ? '\nWebsite: ' + (item.website || item.domain) : '')).trim()
              })
            });
            const data = await res.json();
            if(!data.ok) throw new Error(data.error||'Add failed');
            showToast('Lead added to CRM');
            try{ await crmFetchClients(); }catch(e){}
          }catch(e){
            showToast('Could not add lead');
          }
        };
      });
    }

    async function crmRunLeadLab(){
      const st = $("leadLabStatus");
      if(st) st.innerText = 'Building lead list...';
      try{
        const res = await fetch('/api/crm/lead_lab', {
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify({
            niche: ($("leadLabNiche")?.value || '').trim(),
            location: ($("leadLabLocation")?.value || '').trim(),
            source_text: ($("leadLabInput")?.value || '').trim(),
            specific_areas: ($("leadLabAreas")?.value || '').trim(),
            search_mode: ($("leadLabMode")?.value || 'balanced').trim(),
            lead_count: parseInt(($("leadLabCount")?.value || '25').trim(), 10) || 25,
            require_contact: ($("leadLabRequireContact")?.value || 'phone_or_email').trim(),
            min_score: parseInt(($("leadLabMinScore")?.value || '40').trim(), 10) || 40
          })
        });
        const ct = (res.headers.get('content-type') || '').toLowerCase();
        const raw = await res.text();
        let data = null;
        try{ data = raw ? JSON.parse(raw) : null; }catch(e){}
        if(!ct.includes('application/json') || !data){
          throw new Error('Lead Lab server response was invalid: ' + raw.slice(0, 220));
        }
        if(!res.ok || !data.ok) throw new Error(data.error||'Lead build failed');
        crmRenderLeadResults(data.items || []);
        if(st) st.innerText = `Ready • ${((data.items||[]).length)} leads${data.warning ? ' • ' + data.warning : ''}`;
      }catch(e){
        if(st) st.innerText = e.message || 'Lead build failed';
      }
    }

    function crmSampleLeadLab(){
      const ta = $("leadLabInput");
      if(!ta) return;
      ta.value = [
        'Jamie Cole | Garden State Realty | gardenstaterealty.com | Broker',
        'Morgan Lee | BrightPath Investors | brightpathinvestors.com | Founder',
        'Taylor Adams | Northshore Lending | northshorelending.com | Loan Officer'
      ].join('\n');
      if($("leadLabNiche")) $("leadLabNiche").value = 'real estate agents';
      if($("leadLabLocation")) $("leadLabLocation").value = 'New Jersey';
      if($("leadLabAreas")) $("leadLabAreas").value = 'Jersey City, Hoboken, Newark';
    }

    async function crmRunGenerator(endpoint, payload, statusId, resultsId){
      const st = $(statusId), box = $(resultsId);
      if(st) st.innerText = 'Generating...';
      if(box) box.innerHTML = '';
      try{
        const res = await fetch(endpoint, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload || {})});
        const data = await res.json();
        if(!data.ok) throw new Error(data.error || 'Generation failed');
        if(box) box.innerHTML = crmRenderRichBlocks(data.output || '');
        if(st) st.innerText = 'Ready';
      }catch(e){
        if(st) st.innerText = e.message || 'Generation failed';
      }
    }

    function crmRenderPipelineBoard(){
      const box = $("crmPipelineBoard");
      if(!box) return;
      const stages = (crmCache.pipeline||[]).length ? (crmCache.pipeline||[]) : ['Lead','Conversation','Interested','Call booked','Client'];
      const clients = Array.isArray(crmCache.clients) ? crmCache.clients : [];
      box.innerHTML = stages.map(stage=>{
        const cards = clients.filter(c => (c.pipeline_stage||'Lead') === stage);
        return `<div class="diagCard" data-stage="${escapeHtml(stage)}" style="padding:10px; min-height:180px;">
          <div style="font-weight:800; margin-bottom:8px; display:flex; justify-content:space-between; gap:8px;">
            <span>${escapeHtml(stage)}</span>
            <span class="pill">${cards.length}</span>
          </div>
          <div class="crmBoardDrop" data-stage-drop="${escapeHtml(stage)}" style="min-height:110px; display:flex; flex-direction:column; gap:8px;">
            ${cards.map(c=>`<div class="pill" draggable="true" data-client-drag="${escapeHtml(c.id||'')}" style="display:block; cursor:grab;">
                <div style="font-weight:700;">${escapeHtml(c.name||'')}</div>
                <div class="tiny" style="opacity:.85;">${escapeHtml(c.company||'')}</div>
              </div>`).join('')}
          </div>
        </div>`;
      }).join('');

      box.querySelectorAll('[data-client-drag]').forEach(el=>{
        el.addEventListener('dragstart', ev=>{
          ev.dataTransfer.setData('text/plain', el.getAttribute('data-client-drag')||'');
        });
      });
      box.querySelectorAll('[data-stage-drop]').forEach(el=>{
        el.addEventListener('dragover', ev=> ev.preventDefault());
        el.addEventListener('drop', async ev=>{
          ev.preventDefault();
          const clientId = ev.dataTransfer.getData('text/plain');
          const stage = el.getAttribute('data-stage-drop')||'Lead';
          if(!clientId) return;
          try{
            const client = (crmCache.clients||[]).find(x=>x.id===clientId);
            if(!client) return;
            const payload = {...client, pipeline_stage: stage};
            const res = await fetch('/api/crm/clients/' + encodeURIComponent(clientId), {
              method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)
            });
            const data = await res.json();
            if(!data.ok) throw new Error(data.error||'Move failed');
            await crmFetchClients();
            crmRenderPipelineBoard();
            showToast('Pipeline updated');
          }catch(e){
            showToast('Move failed');
          }
        });
      });
    }

    function bindCRM(){
      const b=(id,fn)=>{ const el=$(id); if(el) el.onclick=fn; };
      b('crmTabClients', async()=>{ crmShowView('crmViewClients'); try{ await crmFetchClients(); crmRenderClients(); }catch(e){} });
      b('crmTabPipeline', async()=>{ crmShowView('crmViewPipeline'); await crmLoadPipelineIntoBox(); });
      b('crmTabBroadcast', ()=>{ crmShowView('crmViewBroadcast'); $("crmBroadcastStatus").innerText=''; });
      b('crmTabBroadcastSMS', ()=>{ crmShowView('crmViewBroadcastSMS'); if($("crmSmsStatus")) $("crmSmsStatus").innerText=''; crmLoadSmsSettings(); });
      b('crmTabLeadLab', ()=>{ crmShowView('crmViewLeadLab'); if($("leadLabStatus")) $("leadLabStatus").innerText=''; });
      b('crmTabSocialStudio', ()=>{ crmShowView('crmViewSocialStudio'); if($("socialStudioStatus")) $("socialStudioStatus").innerText=''; });
      b('crmTabOfferBuilder', ()=>{ crmShowView('crmViewOfferBuilder'); if($("offerBuilderStatus")) $("offerBuilderStatus").innerText=''; });
      b('crmTabPlaybooks', ()=>{ crmShowView('crmViewPlaybooks'); if($("playbookStatus")) $("playbookStatus").innerText=''; });

      b('crmRefreshClients', async()=>{ crmSetStatus('Refreshing...'); await crmFetchClients(); crmRenderClients(); crmSetStatus('Ready'); });
      b('crmNewClientBtn', ()=> crmOpenClientEditor(null));
      b('crmPickCsvBtn', ()=>{ const f=$("crmCsvFile"); if(f) f.click(); });
      if($("crmCsvFile")) $("crmCsvFile").addEventListener('change', crmImportCsv);
      b('crmCancelEdit', ()=>{ const ed=$("crmClientEditor"); if(ed) ed.style.display='none'; crmEditingClientId=null; });
      b('crmSaveClient', crmSaveClient);

      if($("crmSearch")) $("crmSearch").addEventListener('input', crmRenderClients);
      if($("crmFilter")) $("crmFilter").addEventListener('change', crmRenderClients);

      b('crmReloadPipeline', crmLoadPipelineIntoBox);
      b('crmSavePipeline', crmSavePipeline);
      b('leadLabSampleBtn', crmSampleLeadLab);
      b('leadLabRunBtn', crmRunLeadLab);
      b('socialStudioRunBtn', ()=>crmRunGenerator('/api/crm/social_studio', {
        platform: ($("socialStudioPlatform")?.value || 'Facebook'),
        asset_type: ($("socialStudioAsset")?.value || 'content_pack'),
        audience: ($("socialStudioAudience")?.value || '').trim(),
        offer: ($("socialStudioOffer")?.value || '').trim()
      }, 'socialStudioStatus', 'socialStudioResults'));
      b('offerBuilderRunBtn', ()=>crmRunGenerator('/api/crm/offer_builder', {
        audience: ($("offerBuilderAudience")?.value || '').trim(),
        result: ($("offerBuilderResult")?.value || '').trim(),
        method: ($("offerBuilderMethod")?.value || '').trim()
      }, 'offerBuilderStatus', 'offerBuilderResults'));
      b('playbookRunBtn', ()=>crmRunGenerator('/api/crm/playbooks', {
        goal: ($("playbookGoal")?.value || 'get_clients'),
        timeline: ($("playbookTimeline")?.value || '30 days'),
        context: ($("playbookContext")?.value || '').trim()
      }, 'playbookStatus', 'playbookResults'));

      b('crmBroadcastDryRun', ()=>crmBroadcastEmail(true));
      b('crmBroadcastSend', ()=>crmBroadcastEmail(false));

      b('crmSmsDryRun', ()=>crmBroadcastSMS(true));
      b('crmSmsSend', ()=>crmBroadcastSMS(false));
    b('crmSmsLoadSettings', ()=>crmLoadSmsSettings());
    b('crmSmsSaveSettings', ()=>crmSaveSmsSettings());
    b('crmSmsTestSend', ()=>crmTestSmsSettings());

      b('crmRefreshTasks', async()=>{ try{ await crmFetchTasks(); crmRenderTasks(); }catch(e){} });
      b('crmNewTaskBtn', ()=> crmOpenTaskEditor(null));
      b('crmCancelTask', ()=>{ const ed=$("crmTaskEditor"); if(ed) ed.style.display='none'; crmEditingTaskId=null; });
      b('crmSaveTask', crmSaveTask);
      b('crmSaveTaskExit', async()=>{ await crmSaveTask(); hideModal(); });

      b('crmRefreshSeq', async()=>{ try{ await crmFetchSequences(); crmRenderSequences(); }catch(e){} });
      b('crmNewSeqBtn', ()=>{ const ed=$("crmSeqEditor"); if(ed) ed.style.display='block'; if($("crmSeqStatus")) $("crmSeqStatus").innerText=''; });
      b('crmCancelSeq', ()=>{ const ed=$("crmSeqEditor"); if(ed) ed.style.display='none'; });
      b('crmSaveSeq', crmSaveSequence);
      b('crmSaveSeqExit', async()=>{ await crmSaveSequence(); hideModal(); });
      b('crmSaveClientExit', async()=>{ await crmSaveClient(); hideModal(); });
      b('crmSavePipelineExit', async()=>{ await crmSavePipeline(); hideModal(); });
      b('crmEnrollBtn', crmEnroll);

      b('crmCreateEventBtn', crmCreateCalendarEvent);
    }

    // run once (safe)
    try{ bindCRM(); }catch(e){}

// =========================
// Calendar modal (month grid + date click actions)
// =========================
// ── Motion-style Calendar Engine ──────────────────────────────
const cal = {
  y: (new Date()).getFullYear(),
  m: (new Date()).getMonth(),
  selected: null,
  events: {},   // keyed by YYYY-MM-DD, Google Calendar events
  tasks: [],    // local tasks array
  tz: (Intl.DateTimeFormat().resolvedOptions().timeZone || "America/New_York"),
  view: "week",
  weekStart: null,
  addTab: "event"
};

function pad2(n){ return (n<10?('0'+n):(''+n)); }
function ymd(d){ return d.getFullYear()+'-'+pad2(d.getMonth()+1)+'-'+pad2(d.getDate()); }
function wcalMonday(d){
  const day = d.getDay();
  const diff = (day === 0) ? -6 : 1 - day;
  const mon = new Date(d);
  mon.setDate(d.getDate() + diff);
  return mon;
}

// ── Event colours ──────────────────────────────────────────────
const EVENT_COLORS = [
  {bg:'rgba(124,58,237,.75)',  text:'#f3e8ff'},
  {bg:'rgba(59,130,246,.75)',  text:'#dbeafe'},
  {bg:'rgba(16,185,129,.75)',  text:'#d1fae5'},
  {bg:'rgba(245,158,11,.75)',  text:'#fef3c7'},
  {bg:'rgba(239,68,68,.75)',   text:'#fee2e2'},
  {bg:'rgba(236,72,153,.75)',  text:'#fce7f3'},
];
const TASK_COLOR = {bg:'rgba(99,102,241,.72)', text:'#e0e7ff'};
const TASK_DONE_COLOR = {bg:'rgba(30,40,60,.65)', text:'rgba(148,163,184,.6)'};
function eventColor(ev){
  const h = (ev.summary||'').split('').reduce((a,c)=>a+c.charCodeAt(0),0);
  return EVENT_COLORS[h % EVENT_COLORS.length];
}

// ── Fetch Google Calendar events ───────────────────────────────
async function wcalFetchRange(start, end){
  const st = document.getElementById('calLoadStatus');
  if(st) st.innerText = 'Loading...';
  try{
    const res = await fetch('/api/calendar/events?time_min='+encodeURIComponent(start.toISOString())+'&time_max='+encodeURIComponent(end.toISOString())+'&timezone='+encodeURIComponent(cal.tz));
    const data = await res.json();
    if(!data.ok){ if(st) st.innerText = data.error||'Calendar not connected — connect in Settings'; return; }
    const map = {};
    (data.events||[]).forEach(ev=>{
      const s=(ev.start||'').slice(0,10); if(!s) return;
      map[s]=map[s]||[]; map[s].push(ev);
    });
    cal.events = Object.assign(cal.events, map);
    if(st) st.innerText='';
  }catch(e){ if(st) st.innerText='Could not load events'; }
}

// ── Fetch local tasks + expand recurring ──────────────────────
async function wcalFetchTasks(){
  try{
    const res = await fetch('/api/cal/tasks');
    const data = await res.json();
    if(data.ok){
      cal.tasks = wcalExpandRecurring(data.tasks||[]);
      cal._rawTasks = data.tasks||[];
    }
  }catch(e){}
}

// Expand recurring tasks into instances for the visible window (±60 days)
function wcalExpandRecurring(tasks){
  const expanded = [];
  const now = new Date();
  const windowStart = new Date(now); windowStart.setDate(now.getDate()-30);
  const windowEnd   = new Date(now); windowEnd.setDate(now.getDate()+90);

  tasks.forEach(t=>{
    const rule = t.recurring||'none';
    if(!rule || rule==='none'){
      expanded.push(t); return;
    }
    // Base date
    if(!t.date){ expanded.push(t); return; }
    const base = new Date(t.date+'T12:00:00');
    if(isNaN(base)){ expanded.push(t); return; }

    // Walk forward from base (and a bit before) generating instances
    let cur = new Date(base);
    // Step back to start of window if base is before it
    const stepBack = (d)=>{
      const tmp = new Date(d);
      let iters=0;
      while(tmp > windowStart && iters<400){
        const prev=new Date(tmp);
        if(rule==='daily')   prev.setDate(tmp.getDate()-1);
        else if(rule==='weekly') prev.setDate(tmp.getDate()-7);
        else if(rule==='biweekly') prev.setDate(tmp.getDate()-14);
        else if(rule==='monthly') prev.setMonth(tmp.getMonth()-1);
        else break;
        if(prev<windowStart) break;
        tmp.setTime(prev.getTime()); iters++;
      }
      return tmp;
    };
    cur = stepBack(cur);

    let iters=0;
    while(cur <= windowEnd && iters<500){
      if(cur >= windowStart){
        const instanceDate = ymd(cur);
        // Mark done only if the base task is done AND this is the base date (or past)
        const isDone = t.done && instanceDate <= (t.completed_at||'').slice(0,10);
        expanded.push(Object.assign({}, t, {
          id: t.id, // keep same id — toggling affects the base
          date: instanceDate,
          _isRecurInstance: instanceDate !== t.date,
          done: isDone,
        }));
      }
      if(rule==='daily')      cur.setDate(cur.getDate()+1);
      else if(rule==='weekly')    cur.setDate(cur.getDate()+7);
      else if(rule==='biweekly')  cur.setDate(cur.getDate()+14);
      else if(rule==='monthly')   cur.setMonth(cur.getMonth()+1);
      else break;
      iters++;
    }
  });
  return expanded;
}

// ── Now line ───────────────────────────────────────────────────
function wcalNowMinutes(){ const n=new Date(); return n.getHours()*60+n.getMinutes(); }
function wcalUpdateNowLine(){
  const line=document.getElementById('wcalNowLine');
  if(line) line.style.top=wcalNowMinutes()+'px';
}

// ── Render helpers ─────────────────────────────────────────────
// ── Strip auto-generated boilerplate from event descriptions ──
function wcalCleanDescription(raw){
  if(!raw) return '';
  // Strip HTML tags
  let txt = raw.replace(/<[^>]*>/g,' ').replace(/&nbsp;/g,' ').replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').trim();
  // Remove known Motion/Google Calendar boilerplate
  const boilerplates=[
    /This event was created by Motion.*$/si,
    /To edit settings.*$/si,
    /To disconnect Motion.*$/si,
    /https?:\/\/app\.usemotion\.com[^\s]*/gi,
    /https?:\/\/www\.usemotion\.com[^\s]*/gi,
  ];
  boilerplates.forEach(re=>{ txt=txt.replace(re,''); });
  return txt.trim();
}

// ── Conference toggle (sidebar quick-add) ──────────────────────
let _wcalConfMode = 'none'; // 'none' | 'meet' | 'zoom'
window.wcalToggleConf = function(type){
  _wcalConfMode = (_wcalConfMode===type) ? 'none' : type;
  const mb=document.getElementById('wcalAddMeetBtn');
  const zb=document.getElementById('wcalAddZoomBtn');
  const zi=document.getElementById('wcalAddZoomUrl');
  const hidden=document.getElementById('wcalAddMeet');
  if(mb){ mb.classList.toggle('active-meet',_wcalConfMode==='meet'); }
  if(zb){ zb.classList.toggle('active-zoom',_wcalConfMode==='zoom'); }
  if(zi){ zi.classList.toggle('show',_wcalConfMode==='zoom'); if(_wcalConfMode==='zoom') zi.focus(); }
  if(hidden) hidden.value=_wcalConfMode==='meet'?'meet':'';
};

// ── Conference toggle (detail panel) ──────────────────────────
let _detConfMode = 'none';
window.wcalDetToggleConf = function(type){
  _detConfMode = (_detConfMode===type) ? 'none' : type;
  const mb=document.getElementById('detMeetBtn');
  const zb=document.getElementById('detZoomBtn');
  const locEl=document.getElementById('detLocation');
  const hidden=document.getElementById('detMeet');
  if(mb){ mb.classList.toggle('active-meet',_detConfMode==='meet'); mb.textContent=_detConfMode==='meet'?'📹 Meet added':'📹 Add Google Meet'; }
  if(zb){ zb.classList.toggle('active-zoom',_detConfMode==='zoom'); zb.textContent=_detConfMode==='zoom'?'🔵 Zoom added':'🔵 Add Zoom'; }
  if(_detConfMode==='zoom' && locEl && !locEl.value.includes('zoom.us')){ locEl.value=''; locEl.placeholder='Paste your Zoom meeting URL here…'; locEl.focus(); }
  if(hidden) hidden.value=_detConfMode==='meet'?'meet':'';
};

// ── Local done-state for Google Calendar events (persisted in localStorage) ──
const _evDone = (()=>{
  try{ return new Set(JSON.parse(localStorage.getItem('wcal_ev_done')||'[]')); }catch(e){ return new Set(); }
})();
function _setEvDone(eid,done){
  done ? _evDone.add(eid) : _evDone.delete(eid);
  try{ localStorage.setItem('wcal_ev_done', JSON.stringify([..._evDone])); }catch(e){}
}
window.wcalToggleEvent = function(e, eid){
  e.stopPropagation();
  const isDone = _evDone.has(eid);
  _setEvDone(eid, !isDone);
  const circle = e.currentTarget;
  circle.classList.toggle('checked', !isDone);
  const block = circle.closest('.wcal-event');
  if(block) block.classList.toggle('is-done', !isDone);
  showToast(!isDone ? '✓ Event marked done' : 'Event unmarked');
};

function wcalEventHtml(ev, extraStyle=''){
  const startDate=new Date(ev.start);
  const endDate=new Date(ev.end||ev.start);
  if(isNaN(startDate)) return '';
  const startMins=startDate.getHours()*60+startDate.getMinutes();
  const durMins=Math.max(30,(endDate-startDate)/60000);
  const top=startMins; const height=Math.max(28,durMins);
  const color=eventColor(ev);
  const timeStr=startDate.toLocaleTimeString('en-US',{hour:'numeric',minute:'2-digit',hour12:true});
  const title=(ev.summary||'Event').replace(/"/g,'&quot;').replace(/</g,'&lt;');
  const meetLink=ev.hangoutLink||'';
  const meetBadge=meetLink?` <a class="wcal-meet-badge" href="${meetLink}" target="_blank" onclick="event.stopPropagation()" title="Join Meet">&#128248;</a>`:'';
  const isRecur=!!(ev.recurringEventId||ev._recurring);
  const recurBadge=isRecur?'<span class="wcal-recur-badge" title="Recurring event">↻</span>':'';
  const evKey=ev.id||ev.summary||'';
  const isDone=_evDone.has(evKey);
  const doneCls=isDone?' is-done':'';
  // Apply any user-set priority override
  const evPrioOverride=(typeof _evPriority!=='undefined')&&_evPriority[evKey];
  const prioColors={high:{bg:'rgba(185,28,28,.75)',text:'#fee2e2'},medium:{bg:'rgba(99,102,241,.72)',text:'#e0e7ff'},low:{bg:'rgba(6,95,70,.75)',text:'#d1fae5'}};
  const finalColor=(evPrioOverride&&prioColors[evPrioOverride])||color;
  let h=`<div class="wcal-event${doneCls}" style="top:${top}px;height:${height}px;background:${finalColor.bg};color:${finalColor.text};${extraStyle}" data-eid="${encodeURIComponent(evKey)}" data-etype="event" onclick="wcalOpenDetail(this)" title="${title}">`;
  h+=`<span class="wcal-event-check${isDone?' checked':''}" onclick="wcalToggleEvent(event,'${evKey.replace(/'/g,"\\'")}') " title="${isDone?'Unmark':'Mark done'}"></span>`;
  if(isRecur) h+=recurBadge;
  h+=`<div class="wcal-event-row"><span class="wcal-event-title">${title}</span>${meetBadge}</div>`;
  if(height>32) h+=`<div class="wcal-event-time">${timeStr}</div>`;
  h+='</div>';
  return h;
}

function wcalTaskHtml(task, extraStyle=''){
  const [th,tm]=(task.start||'09:00').split(':').map(Number);
  const startMins=th*60+tm;
  const height=Math.max(28,task.duration||30); // 1px per minute — longer tasks are taller
  const prio=task.priority||'medium';
  const prioCls=task.done?'':' task-prio-'+prio;
  const doneCls=task.done?' is-done':'';
  const title=(task.title||'Task').replace(/"/g,'&quot;').replace(/</g,'&lt;');
  const isRecur=(task.recurring&&task.recurring!=='none');
  const recurBadge=isRecur?`<span class="wcal-recur-badge" title="Repeats ${task.recurring}">↻</span>`:'';
  const hasAutoEmail=!!(task.on_complete_teammate&&task.on_complete_client_email);
  const autoEmailBadge=hasAutoEmail?'<span style="position:absolute;bottom:2px;right:20px;font-size:9px;opacity:.75;" title="Auto-email on complete">✉</span>':'';
  const durLabel=height>40?` · ${task.duration||30}m`:'';
  let h=`<div class="wcal-event${doneCls}${prioCls}" style="top:${startMins}px;height:${height}px;${extraStyle}" data-tid="${encodeURIComponent(task.id)}" data-etype="task" data-tstart="${task.start||'09:00'}" data-tdate="${task.date||''}" onclick="wcalOpenDetail(this)" title="☑ ${title}">`;
  h+=`<span class="wcal-event-check${task.done?' checked':''}" onclick="wcalToggleTask(event,'${task.id}')" title="${task.done?'Unmark':'Mark done'}"></span>`;
  if(isRecur) h+=recurBadge;
  h+=`<div class="wcal-event-row"><span class="wcal-event-title">☑ ${title}</span></div>`;
  if(height>36) h+=`<div class="wcal-event-time">${task.start||''}${durLabel}</div>`;
  h+=autoEmailBadge;
  h+='</div>';
  return h;
}

// ── Toggle task done ───────────────────────────────────────────
window.wcalToggleTask = async function(e, taskId){
  e.stopPropagation();
  const task=cal.tasks.find(t=>t.id===taskId); if(!task) return;
  const newDone=!task.done;
  try{
    await fetch('/api/cal/tasks/'+encodeURIComponent(taskId),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({done:newDone})});
    task.done=newDone;
    task.completed_at=newDone?new Date().toISOString():null;
    // Update ALL matching task blocks in-place (no full refresh = no disappear)
    document.querySelectorAll('.wcal-event[data-etype="task"]').forEach(el=>{
      const tid=el.dataset.tid?decodeURIComponent(el.dataset.tid):'';
      if(tid!==taskId) return;
      // Toggle done class (strikethrough + grey)
      el.classList.toggle('is-done', newDone);
      // Update check circle
      const circle=el.querySelector('.wcal-event-check');
      if(circle){ circle.classList.toggle('checked', newDone); circle.title=newDone?'Unmark':'Mark done'; }
      // Update priority class (remove if done)
      if(newDone){
        el.classList.remove('task-prio-high','task-prio-medium','task-prio-low');
      } else {
        const p=task.priority||'medium';
        el.classList.add('task-prio-'+p);
      }
    });
    wcalRenderUpcoming();
    showToast(newDone?'✓ Task complete':'Task marked todo');
    if(newDone && task.on_complete_teammate && task.on_complete_client_email){
      wcalFireCompleteAction(taskId, task);
    }
  }catch(err){ showToast('Update failed'); }
};

// Called when a task with an assigned teammate is marked done
async function wcalFireCompleteAction(taskId, task){
  showToast('⚡ '+task.on_complete_teammate+' is drafting completion email…');
  try{
    const res = await fetch('/api/cal/tasks/'+encodeURIComponent(taskId)+'/complete_action',{method:'POST'});
    const d = await res.json();
    if(d.ok){
      showToast('📧 Completion email sent to '+task.on_complete_client_email+' by '+task.on_complete_teammate);
    } else if(d.draft_subject){
      // Email failed to send but we have a draft — show it
      showToast('⚠️ Could not send email: '+(d.error||'unknown error')+'. Draft ready in Email Console.');
      // Pre-fill email console if accessible
      try{
        const subEl=document.getElementById('emailSubject');
        const bodyEl=document.getElementById('emailBody');
        const toEl=document.getElementById('emailTo');
        if(subEl) subEl.value=d.draft_subject;
        if(bodyEl) bodyEl.value=d.draft_body;
        if(toEl) toEl.value=task.on_complete_client_email;
      }catch(_){}
    } else {
      showToast('⚠️ Auto-email error: '+(d.error||'unknown'));
    }
  }catch(err){
    showToast('⚠️ Auto-email failed: '+String(err));
  }
}

// ── Open detail panel ──────────────────────────────────────────
window.wcalOpenDetail = function(el){
  const etype=el.dataset.etype;
  if(etype==='task'){
    const tid=decodeURIComponent(el.dataset.tid||'');
    const task=cal.tasks.find(t=>t.id===tid); if(!task) return;
    wcalShowTaskDetail(task);
  } else {
    // Find event from cal.events by matching id or summary
    const eid=decodeURIComponent(el.dataset.eid||'');
    let ev=null;
    Object.values(cal.events).forEach(arr=>arr.forEach(e=>{ if((e.id||e.summary||'')===(eid)) ev=e; }));
    if(!ev){ ev={summary:eid}; }
    wcalShowEventDetail(ev);
  }
};

function wcalShowTaskDetail(task){
  const panel=document.getElementById('wcalDetail');
  const body=document.getElementById('wcalDetBody');
  const typeLbl=document.getElementById('wcalDetType');
  if(!panel||!body) return;
  const prioColors={high:'high',medium:'medium',low:'low'};
  const prioLabel={high:'High',medium:'Medium',low:'Low'};
  body.innerHTML=`
    <input class="wcal-detail-title" id="detTitle" value="${(task.title||'').replace(/"/g,'&quot;')}" placeholder="Task title" />
    <div>
      <div class="wcal-detail-label">Status</div>
      <div class="wcal-done-toggle ${task.done?'done':''}" id="detDoneToggle" onclick="wcalDetToggleDone()">
        <span id="detDoneIcon">${task.done?'✓':'○'}</span>
        <span id="detDoneLabel">${task.done?'Completed':'Mark complete'}</span>
      </div>
    </div>
    <div class="wcal-detail-row">
      <div style="flex:1;">
        <div class="wcal-detail-label">Date</div>
        <input class="wcal-detail-field" id="detDate" type="date" value="${task.date||''}" />
      </div>
      <div style="flex:1;">
        <div class="wcal-detail-label">Start time</div>
        <input class="wcal-detail-field" id="detStart" type="time" value="${task.start||'09:00'}" />
      </div>
    </div>
    <div class="wcal-detail-row">
      <div style="flex:1;">
        <div class="wcal-detail-label">Duration (min)</div>
        <input class="wcal-detail-field" id="detDur" type="number" min="5" max="480" value="${task.duration||30}" />
      </div>
      <div style="flex:1;">
        <div class="wcal-detail-label">Priority</div>
        <select class="wcal-detail-field" id="detPriority">
          <option value="high" ${task.priority==='high'?'selected':''}>High</option>
          <option value="medium" ${(task.priority||'medium')==='medium'?'selected':''}>Medium</option>
          <option value="low" ${task.priority==='low'?'selected':''}>Low</option>
        </select>
      </div>
    </div>
    <div>
      <div class="wcal-detail-label">Repeats</div>
      <select class="wcal-detail-field" id="detRecurring">
        <option value="none" ${(task.recurring||'none')==='none'?'selected':''}>Does not repeat</option>
        <option value="daily" ${task.recurring==='daily'?'selected':''}>Daily</option>
        <option value="weekly" ${task.recurring==='weekly'?'selected':''}>Weekly</option>
        <option value="biweekly" ${task.recurring==='biweekly'?'selected':''}>Every 2 weeks</option>
        <option value="monthly" ${task.recurring==='monthly'?'selected':''}>Monthly</option>
      </select>
    </div>
    <div>
      <div class="wcal-detail-label">Description / Notes</div>
      <textarea class="wcal-detail-textarea" id="detDesc" placeholder="Add notes...">${task.description||''}</textarea>
    </div>
    ${task.completed_at?`<div><div class="wcal-detail-label">Completed at</div><div class="wcal-detail-value" style="opacity:.7;">${new Date(task.completed_at).toLocaleString()}</div></div>`:''}
    <div class="wcal-autocomplete-section" id="detAutoSection">
      <div class="wcal-autocomplete-title">Auto-Email on Complete</div>
      <div class="wcal-detail-label">Assign teammate to email client</div>
      <select class="wcal-detail-field" id="detAutoTeammate">
        <option value="">— No auto-email —</option>
      </select>
      <div class="wcal-detail-label" style="margin-top:6px;">Client email address</div>
      <input class="wcal-detail-field" id="detAutoEmail" type="email" placeholder="client@example.com" value="${task.on_complete_client_email||''}" autocomplete="off" />
      <div class="wcal-automail-status" id="detAutoStatus"></div>
    </div>
    <div class="wcal-detail-actions">
      <button class="wcal-det-btn primary" onclick="wcalDetSaveTask('${task.id}')">Save</button>
      <button class="wcal-det-btn danger" onclick="wcalDetDeleteTask('${task.id}')">Delete</button>
    </div>
    <div class="wcal-status" id="detStatus"></div>
  `;
  if(typeLbl){ typeLbl.innerText='☑ TASK'; typeLbl.className='wcal-detail-type type-task'; }
  const detHdr=document.querySelector('.wcal-detail-header'); if(detHdr) detHdr.className='wcal-detail-header type-task';
  panel.classList.add('open');
  panel._currentTask=task; panel._currentEvent=null;
  // Populate teammate dropdown asynchronously
  wcalPopulateTeammateDropdown('detAutoTeammate', task.on_complete_teammate||'');
}

function wcalShowEventDetail(ev){
  const panel=document.getElementById('wcalDetail');
  const body=document.getElementById('wcalDetBody');
  const typeLbl=document.getElementById('wcalDetType');
  if(!panel||!body) return;
  const startD=new Date(ev.start||'');
  const endD=new Date(ev.end||ev.start||'');
  const dateVal=isNaN(startD)?'':(ev.start||'').slice(0,10);
  const startVal=isNaN(startD)?'':pad2(startD.getHours())+':'+pad2(startD.getMinutes());
  const endVal=isNaN(endD)?'':pad2(endD.getHours())+':'+pad2(endD.getMinutes());
  const meetLink=ev.hangoutLink||ev.conferenceData?.entryPoints?.[0]?.uri||'';
  const htmlLink=ev.htmlLink||'';
  body.innerHTML=`
    <input class="wcal-detail-title" id="detTitle" value="${(ev.summary||'').replace(/"/g,'&quot;')}" placeholder="Event title" />
    ${meetLink?`<a class="wcal-join-btn wcal-join-meet" href="${meetLink}" target="_blank" rel="noopener">📹 Join Google Meet</a>`:``}
    ${(ev.location&&ev.location.includes('zoom.us'))?`<a class="wcal-join-btn wcal-join-zoom" href="${ev.location}" target="_blank" rel="noopener">🔵 Join Zoom</a>`:''}
    <div class="wcal-detail-row">
      <div style="flex:1;">
        <div class="wcal-detail-label">Date</div>
        <input class="wcal-detail-field" id="detDate" type="date" value="${dateVal}" />
      </div>
    </div>
    <div class="wcal-detail-row">
      <div style="flex:1;">
        <div class="wcal-detail-label">Start</div>
        <input class="wcal-detail-field" id="detStart" type="time" value="${startVal}" />
      </div>
      <div style="flex:1;">
        <div class="wcal-detail-label">End</div>
        <input class="wcal-detail-field" id="detEnd" type="time" value="${endVal}" />
      </div>
    </div>
    <div>
      <div class="wcal-detail-label">Notes</div>
      <textarea class="wcal-detail-textarea" id="detDesc" placeholder="Add notes…">${wcalCleanDescription(ev.description||'')}</textarea>
    </div>
    <div>
      <div class="wcal-detail-label">Location / Meeting link</div>
      <input class="wcal-detail-field" id="detLocation" value="${(ev.location||'').replace(/"/g,'&quot;')}" placeholder="Address, Zoom URL, or other link" />
    </div>
    <div>
      <div class="wcal-detail-label">Invite attendees</div>
      <input class="wcal-detail-field" id="detAttendees" placeholder="email1@x.com, email2@x.com" autocomplete="off" />
    </div>
    <div>
      <div class="wcal-detail-label">Video call</div>
      <div class="wcal-conf-row">
        <button class="wcal-conf-btn ${meetLink?'active-meet':''}" id="detMeetBtn" onclick="wcalDetToggleConf('meet')" title="Generate a Google Meet link when saving">
          📹 ${meetLink?'Meet added':'Add Google Meet'}
        </button>
        <button class="wcal-conf-btn ${(ev.location&&ev.location.includes('zoom.us'))?'active-zoom':''}" id="detZoomBtn" onclick="wcalDetToggleConf('zoom')" title="Paste a Zoom URL into the Location field">
          🔵 ${(ev.location&&ev.location.includes('zoom.us'))?'Zoom added':'Add Zoom'}
        </button>
      </div>
    </div>
    <input type="hidden" id="detMeet" value="${meetLink?'meet':''}" />
    <div>
      <div class="wcal-detail-label">Priority / color</div>
      <select class="wcal-detail-field" id="detEvPriority" onchange="wcalDetEvPriorityChange(this.value)">
        <option value="auto" selected>Auto (calendar color)</option>
        <option value="high">🔴 High</option>
        <option value="medium">🟡 Medium</option>
        <option value="low">🟢 Low</option>
      </select>
    </div>
    <div class="wcal-detail-actions">
      <button class="wcal-det-btn primary" onclick="wcalDetSaveEvent('${encodeURIComponent(ev.id||'')}')">Save changes</button>
      ${htmlLink?`<a class="wcal-det-btn" href="${htmlLink}" target="_blank" style="text-align:center;text-decoration:none;">Open in Google</a>`:''}
    </div>
    <div class="wcal-status" id="detStatus"></div>
  `;
  if(typeLbl){ typeLbl.innerText='📅 EVENT'; typeLbl.className='wcal-detail-type type-event'; }
  const detHdr2=document.querySelector('.wcal-detail-header'); if(detHdr2) detHdr2.className='wcal-detail-header type-event';
  panel.classList.add('open');
  panel._currentEvent=ev; panel._currentTask=null;
}

// ── Detail panel actions ───────────────────────────────────────
window.wcalDetToggleDone = async function(){
  const panel=document.getElementById('wcalDetail');
  if(!panel||!panel._currentTask) return;
  const task=panel._currentTask;
  await wcalToggleTaskById(task.id,!task.done);
  task.done=!task.done; task.completed_at=task.done?new Date().toISOString():null;
  const toggle=document.getElementById('detDoneToggle');
  const icon=document.getElementById('detDoneIcon');
  const lbl=document.getElementById('detDoneLabel');
  if(toggle){ toggle.classList.toggle('done',task.done); }
  if(icon) icon.textContent=task.done?'✓':'○';
  if(lbl) lbl.textContent=task.done?'Completed':'Mark complete';
};

async function wcalToggleTaskById(id,done){
  try{
    await fetch('/api/cal/tasks/'+encodeURIComponent(id),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({done})});
    const t=cal.tasks.find(x=>x.id===id); if(t){ t.done=done; t.completed_at=done?new Date().toISOString():null; }
    wcalRefresh(); wcalRenderUpcoming();
    showToast(done?'✓ Task complete':'Task marked todo');
  }catch(e){ showToast('Update failed'); }
}

window.wcalDetSaveTask = async function(taskId){
  const st=document.getElementById('detStatus'); if(st) st.innerText='Saving...';
  const payload={
    title:(document.getElementById('detTitle')?.value||'').trim(),
    date:(document.getElementById('detDate')?.value||'').trim(),
    start:(document.getElementById('detStart')?.value||'09:00').trim(),
    duration:parseInt(document.getElementById('detDur')?.value||'30',10),
    priority:document.getElementById('detPriority')?.value||'medium',
    recurring:document.getElementById('detRecurring')?.value||'none',
    description:(document.getElementById('detDesc')?.value||'').trim(),
    on_complete_teammate:document.getElementById('detAutoTeammate')?.value||'',
    on_complete_client_email:(document.getElementById('detAutoEmail')?.value||'').trim(),
  };
  try{
    const res=await fetch('/api/cal/tasks/'+encodeURIComponent(taskId),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const d=await res.json(); if(!d.ok) throw new Error(d.error||'Failed');
    Object.assign(cal.tasks.find(t=>t.id===taskId)||{},payload);
    await wcalFetchTasks(); wcalRefresh(); wcalRenderUpcoming();
    if(st) st.innerText='Saved ✓';
    showToast('Task saved');
    setTimeout(()=>{ if(st) st.innerText=''; },2000);
  }catch(e){ if(st) st.innerText=e.message||'Save failed'; }
};

window.wcalDetDeleteTask = async function(taskId){
  if(!confirm('Delete this task?')) return;
  try{
    await fetch('/api/cal/tasks/'+encodeURIComponent(taskId),{method:'DELETE'});
    cal.tasks=cal.tasks.filter(t=>t.id!==taskId);
    document.getElementById('wcalDetail')?.classList.remove('open');
    wcalRefresh(); wcalRenderUpcoming(); showToast('Task deleted');
  }catch(e){ showToast('Delete failed'); }
};

// Event priority — store in session memory keyed by event id, applied on re-render
const _evPriority = {};
window.wcalDetEvPriorityChange = function(val){
  const panel = document.getElementById('wcalDetail');
  if(!panel||!panel._currentEvent) return;
  const ev = panel._currentEvent;
  const key = ev.id||ev.summary||'';
  if(val==='auto') delete _evPriority[key];
  else _evPriority[key] = val;
  // Apply color live to any matching event block on the grid
  document.querySelectorAll(`.wcal-event[data-eid="${encodeURIComponent(key)}"]`).forEach(el=>{
    const prioColors = {
      high:   {bg:'rgba(185,28,28,.75)',  text:'#fee2e2'},
      medium: {bg:'rgba(99,102,241,.72)', text:'#e0e7ff'},
      low:    {bg:'rgba(6,95,70,.75)',    text:'#d1fae5'},
    };
    if(val==='auto'){
      const color=eventColor(ev);
      el.style.background=color.bg; el.style.color=color.text;
    } else {
      const clr=prioColors[val]; if(clr){ el.style.background=clr.bg; el.style.color=clr.text; }
    }
  });
};

window.wcalDetSaveEvent = async function(encodedId){
  const st=document.getElementById('detStatus'); if(st) st.innerText='Saving to Google Calendar...';
  const dateVal=document.getElementById('detDate')?.value||'';
  const startVal=document.getElementById('detStart')?.value||'09:00';
  const endVal=document.getElementById('detEnd')?.value||'10:00';
  const title=(document.getElementById('detTitle')?.value||'').trim();
  const desc=(document.getElementById('detDesc')?.value||'').trim();
  const loc=(document.getElementById('detLocation')?.value||'').trim();
  const attendeesRaw=document.getElementById('detAttendees')?.value||'';
  const attendees=attendeesRaw.split(',').map(x=>x.trim()).filter(Boolean);
  const useMeet=document.getElementById('detMeet')?.value==='meet';
  if(!dateVal||!startVal){ if(st) st.innerText='Date and start time required'; return; }
  const startDt=new Date(dateVal+'T'+startVal+':00');
  const endDt=new Date(dateVal+'T'+endVal+':00');
  const payload={title,start:startDt.toISOString(),end:endDt.toISOString(),timezone:cal.tz,description:desc,location:loc,attendees,use_meet:useMeet};
  try{
    const res=await fetch('/api/calendar/create_event',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const d=await res.json();
    if(!d.ok) throw new Error(d.error||'Failed');
    if(st) st.innerText='Saved ✓';
    showToast(useMeet?'Event updated with Meet link':'Event updated');
    await wcalFetchCurrentRange(); wcalRefresh();
    setTimeout(()=>{ if(st) st.innerText=''; },2500);
  }catch(e){ if(st) st.innerText=e.message||'Save failed'; }
};

// ── Activation sound (Web Audio API — no file needed) ─────────
function wcalPlayActivationSound(){
  try{
    const ctx=new(window.AudioContext||window.webkitAudioContext)();
    const notes=[261.6,329.6,392,523.2]; // C-E-G-C arpeggio
    notes.forEach((freq,i)=>{
      const osc=ctx.createOscillator();
      const gain=ctx.createGain();
      osc.connect(gain); gain.connect(ctx.destination);
      osc.type='sine'; osc.frequency.value=freq;
      const t=ctx.currentTime+i*0.09;
      gain.gain.setValueAtTime(0,t);
      gain.gain.linearRampToValueAtTime(0.18,t+0.03);
      gain.gain.exponentialRampToValueAtTime(0.001,t+0.28);
      osc.start(t); osc.stop(t+0.3);
    });
  }catch(e){}
}

// ── Drag-and-drop for calendar tasks & events ──────────────────
const wcalDrag={
  active:false, el:null, tip:null,
  etype:null, tid:null, eid:null,
  origDate:null, origStart:null, origDur:30,
  clickOffsetPx:0,
  startY:0, startX:0,
  _targetDate:null, _targetMins:null,
};

function wcalDragWireGrid(grid){
  const wrap=document.getElementById('wcalGridWrap');

  grid.querySelectorAll('.wcal-event').forEach(el=>{
    if(el._wcalDragWired) return;
    el._wcalDragWired=true;
    el.addEventListener('mousedown',function(e){
      if(e.button!==0) return;
      if(e.target.closest('.wcal-event-check,.wcal-meet-badge,a,.wcal-recur-badge')) return;
      // Do NOT call preventDefault here — that would kill the onclick/detail-open.
      // We only take over if the user actually drags (detected in mousemove).
      const etype=el.dataset.etype;
      const tid=el.dataset.tid?decodeURIComponent(el.dataset.tid):'';
      const eid=el.dataset.eid?decodeURIComponent(el.dataset.eid):'';
      const col=el.closest('.wcal-day-col,[data-date]');
      const origDate=col?col.dataset.date:'';
      const elRect=el.getBoundingClientRect();
      const clickOffsetPx=e.clientY-elRect.top;
      let origStart='09:00', origDur=30;
      if(etype==='task'){
        const task=cal.tasks.find(t=>t.id===tid);
        if(task){ origStart=task.start||'09:00'; origDur=task.duration||30; }
      } else {
        let ev=null;
        Object.values(cal.events).forEach(arr=>arr.forEach(ev2=>{
          if((ev2.id||ev2.summary||'')===eid) ev=ev2;
        }));
        if(ev){
          const sd=new Date(ev.start); const ed=new Date(ev.end||ev.start);
          origStart=pad2(sd.getHours())+':'+pad2(sd.getMinutes());
          origDur=Math.max(15,Math.round((ed-sd)/60000));
        }
      }
      wcalDrag.active=false;
      wcalDrag.el=el; wcalDrag.etype=etype;
      wcalDrag.tid=tid; wcalDrag.eid=eid;
      wcalDrag.origDate=origDate; wcalDrag.origStart=origStart; wcalDrag.origDur=origDur;
      wcalDrag.clickOffsetPx=clickOffsetPx;
      wcalDrag.startY=e.clientY; wcalDrag.startX=e.clientX;
      wcalDrag.tip=null; wcalDrag._targetDate=null; wcalDrag._targetMins=null;
    });
  });

  if(grid._wcalMoveWired) return;
  grid._wcalMoveWired=true;

  document.addEventListener('mousemove',function(e){
    if(!wcalDrag.el) return;
    const dy=Math.abs(e.clientY-wcalDrag.startY);
    const dx=Math.abs(e.clientX-wcalDrag.startX);
    if(!wcalDrag.active && dy<6 && dx<6) return;

    if(!wcalDrag.active){
      wcalDrag.active=true;
      wcalDrag.el.style.opacity='0.5';
      wcalDrag.el.style.zIndex='20';
      wcalDrag.el.style.cursor='grabbing';
      wcalDrag.el.style.pointerEvents='none';
      // Suppress the upcoming click so the detail panel doesn't open on drag-release
      wcalDrag._suppressNextClick=true;
      // Time tooltip
      const tip=document.createElement('div');
      tip.style.cssText='position:fixed;background:#1e1b4b;color:#c4b5fd;padding:3px 9px;border-radius:6px;font-size:11px;font-weight:700;z-index:9999;pointer-events:none;box-shadow:0 2px 8px rgba(0,0,0,.5);white-space:nowrap;';
      document.body.appendChild(tip);
      wcalDrag.tip=tip;
    }

    // Find target column by X position
    const cols=grid.querySelectorAll('.wcal-day-col');
    let targetCol=null, targetDate=null;
    cols.forEach(col=>{
      const r=col.getBoundingClientRect();
      if(e.clientX>=r.left && e.clientX<=r.right){ targetCol=col; targetDate=col.dataset.date; }
    });
    if(!targetCol){
      const dayArea=grid.querySelector('[data-date]');
      if(dayArea){
        const r=dayArea.getBoundingClientRect();
        if(e.clientX>=r.left && e.clientX<=r.right){ targetCol=dayArea; targetDate=dayArea.dataset.date; }
      }
    }
    if(!targetCol||!targetDate) return;

    // ── TIME CALCULATION ──────────────────────────────────────────
    // The sticky header row is the first child of wcalGrid and is position:sticky top:0.
    // Its height is constant (~44px) but visually it stays at the top of the wrap.
    // wcal-day-col.getBoundingClientRect().top gives the CURRENT viewport top of
    // the column, which is BELOW the sticky header. So:
    //   pixelsFromColTop = e.clientY - colRect.top + wrap.scrollTop
    // But col starts at pixel 0 in the scrollable area (header is sticky, not in flow),
    // so this is already the correct grid-pixel-from-top, meaning 1px = 1 minute.
    // We subtract clickOffsetPx so the block's top edge (not the grab point) sets the time.
    const colRect=targetCol.getBoundingClientRect();
    const wrapRect=wrap?wrap.getBoundingClientRect():{top:0};
    const scrolled=wrap?wrap.scrollTop:0;
    // Use wrapRect.top + scrolled to get pixels from absolute grid top (not column viewport top)
    // The sticky header is ~44px. Using colRect.top already accounts for it since
    // wcal-day-col starts BELOW the sticky header in the DOM flow.
    const rawY=(e.clientY - colRect.top + scrolled) - wcalDrag.clickOffsetPx;
    const startMins=Math.max(0, Math.min(Math.round(rawY/15)*15, 23*60));

    // Move the original block visually (no ghost clone)
    const origCol=wcalDrag.el.closest('.wcal-day-col,[data-date]');
    if(origCol && targetCol !== origCol){
      targetCol.appendChild(wcalDrag.el);
    }
    wcalDrag.el.style.top=startMins+'px';
    wcalDrag.el.style.left='3px';
    wcalDrag.el.style.right='3px';
    wcalDrag.el.style.position='absolute';

    // Update tooltip
    if(wcalDrag.tip){
      const hh=Math.floor(startMins/60), mm=startMins%60;
      const ampm=hh<12?'AM':'PM'; const h12=hh%12||12;
      wcalDrag.tip.textContent=pad2(h12)+':'+pad2(mm)+' '+ampm+(targetDate!==wcalDrag.origDate?' · '+targetDate:'');
      wcalDrag.tip.style.left=(e.clientX+14)+'px';
      wcalDrag.tip.style.top=(e.clientY-26)+'px';
    }

    wcalDrag._targetDate=targetDate;
    wcalDrag._targetMins=startMins;
  });

  document.addEventListener('mouseup',async function(e){
    if(!wcalDrag.el) return;
    const wasDragging=wcalDrag.active;

    // Restore element styles
    wcalDrag.el.style.opacity='';
    wcalDrag.el.style.zIndex='';
    wcalDrag.el.style.cursor='';
    wcalDrag.el.style.pointerEvents='';
    // If we actually dragged, suppress the next click event so detail panel doesn't open
    if(wcalDrag._suppressNextClick){
      wcalDrag._suppressNextClick=false;
      const el2=wcalDrag.el;
      const suppressHandler=function(ev){ ev.stopImmediatePropagation(); el2.removeEventListener('click',suppressHandler,true); };
      wcalDrag.el.addEventListener('click',suppressHandler,true);
    }

    // Remove tooltip
    if(wcalDrag.tip){ try{wcalDrag.tip.remove();}catch(_){} wcalDrag.tip=null; }

    const targetDate=wcalDrag._targetDate||wcalDrag.origDate;
    const targetMins=wcalDrag._targetMins!=null?wcalDrag._targetMins:null;

    const { etype,tid,eid,origDate,origStart,origDur } = wcalDrag;
    Object.assign(wcalDrag,{active:false,el:null,tip:null,_targetDate:null,_targetMins:null});

    // FIX: do NOT call wcalRefresh() on a plain click (no drag).
    // Calling it here replaces grid.innerHTML synchronously, detaching the clicked
    // element before the browser fires the click event — so onclick="wcalOpenDetail(this)"
    // never runs. Return here and let the inline onclick open the detail panel naturally.
    if(!wasDragging||targetMins==null){ return; }

    const newHH=Math.floor(targetMins/60), newMM=targetMins%60;
    const newStart=pad2(newHH)+':'+pad2(newMM);
    if(newStart===origStart && targetDate===origDate){ return; }

    if(etype==='task'){
      const task=cal.tasks.find(t=>t.id===tid); if(!task){ wcalRefresh(); return; }
      try{
        await fetch('/api/cal/tasks/'+encodeURIComponent(tid),{
          method:'POST',headers:{'Content-Type':'application/json'},
          body:JSON.stringify({date:targetDate,start:newStart})
        });
        task.date=targetDate; task.start=newStart;
        showToast('Task moved → '+targetDate+' '+newStart);
        wcalRefresh(); wcalRenderMiniMonth(); wcalRenderUpcoming();
      }catch(err){ showToast('Move failed'); wcalRefresh(); }

    } else {
      let ev=null;
      Object.values(cal.events).forEach(arr=>arr.forEach(e2=>{
        if((e2.id||e2.summary||'')===eid) ev=e2;
      }));
      if(!ev){ wcalRefresh(); return; }
      const newStartDt=new Date(targetDate+'T'+newStart+':00');
      const newEndDt=new Date(newStartDt.getTime()+origDur*60000);
      const hasAttendees=Array.isArray(ev.attendees)&&ev.attendees.length>0;
      let resend=false;
      if(hasAttendees) resend=confirm('This event has '+ev.attendees.length+' attendee(s). Resend invite?');
      try{
        if(ev.id){
          const res=await fetch('/api/calendar/move_event',{
            method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({event_id:ev.id,start:newStartDt.toISOString(),end:newEndDt.toISOString(),timezone:cal.tz,resend})
          });
          const d=await res.json();
          if(!d.ok) throw new Error(d.error||'Move failed');
        } else {
          throw new Error('No event ID — refresh and try again');
        }
        showToast('Event moved'+(resend?' · Invite resent':''));
        await wcalFetchCurrentRange(); wcalRefresh();
      }catch(err){ showToast('Move failed: '+err.message); wcalRefresh(); }
    }
  });
}


// ── Render week view ───────────────────────────────────────────
function wcalRenderWeek(){
  const grid=document.getElementById('wcalGrid'); if(!grid) return;
  const mon=cal.weekStart||wcalMonday(new Date());
  cal.weekStart=mon;
  const sun=new Date(mon); sun.setDate(mon.getDate()+6);
  const opts={month:'short',day:'numeric'};
  const label=document.getElementById('wcalRangeLabel');
  if(label) label.innerText=mon.toLocaleDateString('en-US',{month:'long',day:'numeric'})+' – '+sun.toLocaleDateString('en-US',opts)+', '+sun.getFullYear();
  const today=ymd(new Date());
  const days=[]; for(let i=0;i<7;i++){ const d=new Date(mon); d.setDate(mon.getDate()+i); days.push(d); }
  let html='';
  // Header row
  html+='<div style="display:flex;position:sticky;top:0;z-index:10;background:#0d1120;width:100%;">';
  html+='<div style="width:54px;flex-shrink:0;border-bottom:1px solid rgba(42,58,106,.5);"></div>';
  const dayNames=['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
  days.forEach((d,i)=>{
    const isToday=ymd(d)===today;
    const numEl=isToday?'<div class="dd today-num">'+d.getDate()+'</div>':'<div class="dd">'+d.getDate()+'</div>';
    html+='<div class="wcal-col-header" style="flex:1;min-width:0;"><div class="wd">'+dayNames[i]+'</div>'+numEl+'</div>';
  });
  html+='</div>';
  // Time + event rows
  html+='<div style="display:flex;position:relative;width:100%;flex:1;">';
  html+='<div class="wcal-time-col">';
  for(let h=0;h<24;h++){
    const lbl=h===0?'':h<12?h+' AM':h===12?'12 PM':(h-12)+' PM';
    html+='<div class="wcal-time-label">'+lbl+'</div>';
  }
  html+='</div>';
  days.forEach((d,di)=>{
    const dt=ymd(d);
    const evs=(cal.events[dt]||[]).filter(ev=>ev.start&&ev.start.includes('T'));
    const dayTasks=cal.tasks.filter(t=>t.date===dt);
    html+='<div class="wcal-day-col" style="flex:1;position:relative;min-width:0;" data-date="'+dt+'">';
    for(let h=0;h<24;h++) html+='<div class="wcal-hour-line"><div class="wcal-half-line"></div></div>';
    evs.forEach(ev=>{ html+=wcalEventHtml(ev); });
    dayTasks.forEach(t=>{ html+=wcalTaskHtml(t); });
    // All-day events
    const allDay=(cal.events[dt]||[]).filter(ev=>ev.start&&!ev.start.includes('T'));
    allDay.forEach(ev=>{
      const color=eventColor(ev); const title=(ev.summary||'Event').replace(/</g,'&lt;');
      html+='<div class="wcal-event" style="top:4px;height:18px;background:'+color.bg+';color:'+color.text+';font-size:10px;" data-eid="'+encodeURIComponent(ev.id||ev.summary||'')+'" data-etype="event" onclick="wcalOpenDetail(this)" title="'+title+'"><div class="wcal-event-title">'+title+'</div></div>';
    });
    html+='</div>';
  });
  // Now line
  const todayInView=days.some(d=>ymd(d)===today);
  if(todayInView){
    const ti=days.findIndex(d=>ymd(d)===today);
    html+='<div id="wcalNowLine" class="wcal-now-line" style="top:'+wcalNowMinutes()+'px;left:'+(54+ti*(100/7))+'%;width:'+(100/7)+'%;"><div class="wcal-now-dot"></div></div>';
  }
  html+='</div>';
  grid.innerHTML=html;
  // Wire drag-and-drop
  wcalDragWireGrid(grid);
  // Double-click on day column → open create popover at clicked time
  grid.querySelectorAll('.wcal-day-col').forEach(col=>{
    col.addEventListener('dblclick',function(e){
      if(e.target.closest('.wcal-event')) return;
      const dt2=col.dataset.date; if(!dt2) return;
      cal.selected=dt2; wcalRenderMiniMonth();
      // offsetY is relative to the clicked element (the hour-line div or the col itself)
      // Each hour = 60px. Use the col's own offsetY for accuracy.
      const colRect=col.getBoundingClientRect();
      const wrap=document.getElementById('wcalGridWrap');
      const scrolled=wrap?wrap.scrollTop:0;
      // clientY relative to col top + scrolled = raw pixel position in grid
      const rawY=e.clientY-colRect.top+scrolled;
      // 1px = 1 minute in the grid (hour rows are 60px tall)
      const totalMins=Math.max(0,Math.min(Math.round(rawY),23*60+45));
      const hh=Math.floor(totalMins/60);
      const mm=Math.round((totalMins%60)/15)*15; // snap to 15-min
      const timeStr=pad2(Math.min(hh,23))+':'+pad2(mm>=60?45:mm);
      wcalPopOpen(e.clientX,e.clientY,dt2,timeStr);
    });
    // Single click still selects the date silently (no modal)
    col.addEventListener('click',function(e){
      if(e.target.closest('.wcal-event')) return;
      const dt2=col.dataset.date; if(!dt2) return;
      cal.selected=dt2; wcalRenderMiniMonth();
    });
  });
  const wrap=document.getElementById('wcalGridWrap');
  if(wrap&&wrap._firstRender!==false){ wrap._firstRender=false; setTimeout(()=>{ wrap.scrollTop=8*60; },50); }
  wcalRenderUpcoming();
}

// ── Render day view ────────────────────────────────────────────
function wcalRenderDay(){
  const grid=document.getElementById('wcalGrid'); if(!grid) return;
  const d=cal.selected?new Date(cal.selected+'T12:00:00'):new Date();
  const dt=ymd(d); const today=ymd(new Date());
  const label=document.getElementById('wcalRangeLabel');
  if(label) label.innerText=d.toLocaleDateString('en-US',{weekday:'long',month:'long',day:'numeric',year:'numeric'});
  const evs=(cal.events[dt]||[]).filter(ev=>ev.start&&ev.start.includes('T'));
  const dayTasks=cal.tasks.filter(t=>t.date===dt);
  let html='<div style="display:flex;width:100%;">';
  html+='<div class="wcal-time-col">';
  for(let h=0;h<24;h++){
    const lbl=h===0?'':h<12?h+' AM':h===12?'12 PM':(h-12)+' PM';
    html+='<div class="wcal-time-label">'+lbl+'</div>';
  }
  html+='</div>';
  html+='<div style="flex:1;position:relative;">';
  for(let h=0;h<24;h++) html+='<div class="wcal-hour-line"><div class="wcal-half-line"></div></div>';
  evs.forEach(ev=>{ html+=wcalEventHtml(ev,'left:8px;right:8px;'); });
  dayTasks.forEach(t=>{ html+=wcalTaskHtml(t,'left:8px;right:8px;'); });
  if(dt===today) html+='<div id="wcalNowLine" class="wcal-now-line" style="top:'+wcalNowMinutes()+'px;left:0;right:0;"><div class="wcal-now-dot"></div></div>';
  html+='</div></div>';
  grid.innerHTML=html;
  const wrap=document.getElementById('wcalGridWrap');
  if(wrap) setTimeout(()=>{ wrap.scrollTop=8*60; },50);
  // Wire drag-and-drop for day view
  wcalDragWireGrid(grid);
  // Double-click on day view grid area → popover
  const dayArea=grid.querySelector('[data-date]')||grid;
  dayArea.addEventListener('dblclick',function(e){
    if(e.target.closest('.wcal-event')) return;
    const dt2=ymd(cal.selected?new Date(cal.selected+'T12:00:00'):new Date());
    const areaRect=dayArea.getBoundingClientRect();
    const scrolled=wrap?wrap.scrollTop:0;
    const rawY=e.clientY-areaRect.top+scrolled;
    const totalMins=Math.max(0,Math.min(Math.round(rawY),23*60+45));
    const hh=Math.floor(totalMins/60);
    const mm=Math.round((totalMins%60)/15)*15;
    const timeStr=pad2(Math.min(hh,23))+':'+pad2(mm>=60?45:mm);
    wcalPopOpen(e.clientX,e.clientY,dt2,timeStr);
  });
  wcalRenderUpcoming();
}

// ── Mini month ─────────────────────────────────────────────────
function wcalRenderMiniMonth(){
  const grid=document.getElementById('wcalMiniGrid');
  const label=document.getElementById('wcalMiniLabel');
  if(!grid) return;
  const y=cal.y, m=cal.m;
  if(label) label.innerText=new Date(y,m,1).toLocaleDateString('en-US',{month:'long',year:'numeric'});
  const today=ymd(new Date());
  const firstDay=new Date(y,m,1).getDay();
  const daysInMonth=new Date(y,m+1,0).getDate();
  const dayNames=['S','M','T','W','T','F','S'];
  let html=dayNames.map(n=>'<div class="wcal-mini-wd">'+n+'</div>').join('');
  for(let i=0;i<firstDay;i++) html+='<div></div>';
  for(let dd=1;dd<=daysInMonth;dd++){
    const dt=y+'-'+pad2(m+1)+'-'+pad2(dd);
    let cls='wcal-mini-day';
    if(dt===today) cls+=' today';
    if(dt===cal.selected) cls+=' selected';
    const hasEv=(cal.events[dt]&&cal.events[dt].length)||cal.tasks.some(t=>t.date===dt);
    if(hasEv) cls+=' has-events';
    html+='<div class="'+cls+'" onclick="wcalSelectDate(&quot;'+dt+'&quot;)">'+dd+'</div>';
  }
  grid.innerHTML=html;
}

window.wcalSelectDate=function wcalSelectDate(dt){
  cal.selected=dt;
  const d=new Date(dt+'T12:00:00');
  if(cal.view==='week') cal.weekStart=wcalMonday(d);
  ['wcalAddDate','wcalTaskDate'].forEach(id=>{ const el=document.getElementById(id); if(el) el.value=dt; });
  wcalRenderMiniMonth(); wcalRefresh();
};

// ── Upcoming sidebar ───────────────────────────────────────────
function wcalRenderUpcoming(){
  const box=document.getElementById('wcalUpcoming'); if(!box) return;
  const now=new Date(); const todayStr=ymd(now);
  const items=[];
  Object.keys(cal.events).sort().forEach(dt=>{
    if(dt<todayStr) return;
    (cal.events[dt]||[]).forEach(ev=>{ if(ev.start) items.push({type:'event',dt,ev}); });
  });
  cal.tasks.filter(t=>t.date>=todayStr).forEach(t=>items.push({type:'task',dt:t.date,task:t}));
  items.sort((a,b)=>{
    const aStr=a.type==='event'?a.ev.start:a.task.date+'T'+(a.task.start||'09:00');
    const bStr=b.type==='event'?b.ev.start:b.task.date+'T'+(b.task.start||'09:00');
    return aStr.localeCompare(bStr);
  });
  if(!items.length){ box.innerHTML='<div class="wcal-upcoming-time">No upcoming</div>'; return; }
  box.innerHTML=items.slice(0,10).map(item=>{
    if(item.type==='event'){
      const ev=item.ev;
      const sd=new Date(ev.start); const dateStr=isNaN(sd)?ev.start:sd.toLocaleDateString('en-US',{month:'short',day:'numeric'});
      const timeStr=isNaN(sd)||!ev.start.includes('T')?'':sd.toLocaleTimeString('en-US',{hour:'numeric',minute:'2-digit',hour12:true});
      const title=(ev.summary||'Event').replace(/</g,'&lt;');
      return '<div class="wcal-upcoming-item"><div class="wcal-upcoming-title">📅 '+title+'</div><div class="wcal-upcoming-time">'+dateStr+(timeStr?' · '+timeStr:'')+'</div></div>';
    } else {
      const t=item.task;
      const doneMark=t.done?'✓ ':'';
      const title=(t.title||'Task').replace(/</g,'&lt;');
      return '<div class="wcal-upcoming-item" onclick="wcalSelectDate(&quot;'+t.date+'&quot;)"><div class="wcal-upcoming-title">☑ '+doneMark+title+'</div><div class="wcal-upcoming-time">'+t.date+' · '+(t.start||'')+'</div></div>';
    }
  }).join('');
}

// ── View & navigation ──────────────────────────────────────────
window.wcalSetView=function wcalSetView(v){
  cal.view=v;
  document.querySelectorAll('.wcal-view-btn').forEach(b=>b.classList.remove('active'));
  const btn=document.getElementById('wcalView'+v.charAt(0).toUpperCase()+v.slice(1));
  if(btn) btn.classList.add('active');
  wcalRefresh();
};

async function wcalNav(dir){
  if(cal.view==='week'){
    const mon=cal.weekStart||wcalMonday(new Date());
    mon.setDate(mon.getDate()+dir*7);
    cal.weekStart=mon; cal.y=mon.getFullYear(); cal.m=mon.getMonth();
  } else {
    const d=cal.selected?new Date(cal.selected+'T12:00:00'):new Date();
    d.setDate(d.getDate()+dir); cal.selected=ymd(d); cal.y=d.getFullYear(); cal.m=d.getMonth();
  }
  await wcalFetchCurrentRange(); wcalRenderMiniMonth(); wcalRefresh();
}

async function wcalFetchCurrentRange(){
  let start,end;
  if(cal.view==='week'){
    const mon=cal.weekStart||wcalMonday(new Date());
    start=new Date(mon); end=new Date(mon); end.setDate(mon.getDate()+7);
  } else {
    const d=cal.selected?new Date(cal.selected+'T12:00:00'):new Date();
    start=new Date(d.getFullYear(),d.getMonth(),d.getDate());
    end=new Date(start); end.setDate(start.getDate()+1);
  }
  const first=new Date(cal.y,cal.m,1);
  const mStart=new Date(first); mStart.setDate(1-first.getDay());
  const last=new Date(cal.y,cal.m+1,0);
  const mEnd=new Date(last); mEnd.setDate(last.getDate()+(6-last.getDay())+1);
  const fetchStart=start<mStart?start:mStart;
  const fetchEnd=end>mEnd?end:mEnd;
  await wcalFetchRange(fetchStart,fetchEnd);
  await wcalFetchTasks();
}

function wcalRefresh(){ if(cal.view==='week') wcalRenderWeek(); else wcalRenderDay(); }

// ── Add tab switch ─────────────────────────────────────────────
window.wcalSwitchAddTab=function(tab){
  cal.addTab=tab;
  document.getElementById('wcalTabEvent')?.classList.toggle('active',tab==='event');
  document.getElementById('wcalTabTask')?.classList.toggle('active',tab==='task');
  document.getElementById('wcalAddEventFields').style.display=tab==='event'?'block':'none';
  document.getElementById('wcalAddTaskFields').style.display=tab==='task'?'block':'none';
};

// ── Quick add event ────────────────────────────────────────────
async function wcalAddEvent(){
  const st=document.getElementById('wcalAddStatus'); if(st) st.innerText='Creating...';
  const title=(document.getElementById('wcalAddTitle')?.value||'').trim();
  const date=(document.getElementById('wcalAddDate')?.value||'').trim();
  const start=(document.getElementById('wcalAddStart')?.value||'09:00').trim();
  const dur=parseInt(document.getElementById('wcalAddDur')?.value||'60',10);
  const attendeesRaw=document.getElementById('wcalAddAttendees')?.value||'';
  const attendees=attendeesRaw.split(',').map(x=>x.trim()).filter(Boolean);
  const useMeet=(_wcalConfMode==='meet');
  const zoomUrl=(_wcalConfMode==='zoom')?(document.getElementById('wcalAddZoomUrl')?.value||'').trim():'';
  if(!title){ if(st) st.innerText='Title required'; return; }
  if(!date){  if(st) st.innerText='Date required'; return; }
  const startDt=new Date(date+'T'+start+':00');
  const endDt=new Date(startDt.getTime()+dur*60000);
  try{
    const res=await fetch('/api/calendar/create_event',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({title,start:startDt.toISOString(),end:endDt.toISOString(),timezone:cal.tz,attendees,use_meet:useMeet,location:zoomUrl})});
    const data=await res.json(); if(!data.ok) throw new Error(data.error||'Failed');
    if(st) st.innerText='✓ Created';
    document.getElementById('wcalAddTitle').value='';
    document.getElementById('wcalAddAttendees').value='';
    const zuEl=document.getElementById('wcalAddZoomUrl'); if(zuEl) zuEl.value='';
    _wcalConfMode='none';
    const _mb=document.getElementById('wcalAddMeetBtn'); if(_mb) _mb.classList.remove('active-meet');
    const _zb=document.getElementById('wcalAddZoomBtn'); if(_zb) _zb.classList.remove('active-zoom');
    const _zi=document.getElementById('wcalAddZoomUrl'); if(_zi) _zi.classList.remove('show');
    showToast(useMeet?'Event + Meet link created':zoomUrl?'Event + Zoom link created':'Event created');
    cal.events[date]=cal.events[date]||[];
    const newEv={summary:title,start:startDt.toISOString(),end:endDt.toISOString(),id:data.event?.id||'',hangoutLink:data.event?.hangoutLink||''};
    cal.events[date].push(newEv);
    wcalRefresh();
    setTimeout(()=>{ if(st) st.innerText=''; },2500);
  }catch(e){ if(st) st.innerText=(e.message||'Failed')+' (connect Calendar in Settings)'; }
}

// ── Quick add task ─────────────────────────────────────────────
async function wcalAddTask(){
  const st=document.getElementById('wcalAddStatus'); if(st) st.innerText='Adding...';
  const title=(document.getElementById('wcalTaskTitle')?.value||'').trim();
  const date=(document.getElementById('wcalTaskDate')?.value||'').trim();
  const start=(document.getElementById('wcalTaskStart')?.value||'09:00').trim();
  const dur=parseInt(document.getElementById('wcalTaskDur')?.value||'30',10);
  const priority=document.getElementById('wcalTaskPriority')?.value||'medium';
  const recurring=document.getElementById('wcalTaskRecurring')?.value||'none';
  if(!title){ if(st) st.innerText='Title required'; return; }
  if(!date){  if(st) st.innerText='Date required'; return; }
  try{
    const res=await fetch('/api/cal/tasks',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({title,date,start,duration:dur,priority,recurring})});
    const data=await res.json(); if(!data.ok) throw new Error(data.error||'Failed');
    cal.tasks.push(data.task);
    document.getElementById('wcalTaskTitle').value='';
    if(st) st.innerText='✓ Task added'; showToast('Task added');
    wcalRefresh(); wcalRenderMiniMonth();
    setTimeout(()=>{ if(st) st.innerText=''; },2000);
  }catch(e){ if(st) st.innerText=e.message||'Failed'; }
}

// ── Populate teammate dropdown in detail panel ─────────────────
async function wcalPopulateTeammateDropdown(selectId, selectedValue){
  const sel = document.getElementById(selectId);
  if(!sel) return;
  try{
    const res = await fetch('/api/state');
    const d = await res.json();
    const names = d.installed_order || Object.keys(d.installed||{});
    // Keep the first "no auto-email" option, add teammates
    while(sel.options.length > 1) sel.remove(1);
    names.forEach(name=>{
      const opt = document.createElement('option');
      opt.value = name; opt.textContent = name;
      if(name === selectedValue) opt.selected = true;
      sel.appendChild(opt);
    });
  }catch(e){
    console.warn('wcalPopulateTeammateDropdown failed', e);
  }
}

// ── Popover state ─────────────────────────────────────────────
let _wcalPopType='event', _wcalPopDate='';

function wcalPopOpen(clientX, clientY, dt, timeStr){
  const pop=document.getElementById('wcalPopover'); if(!pop) return;
  _wcalPopDate=dt;
  // Smart positioning: keep inside viewport
  pop.style.display='flex';
  const pw=pop.offsetWidth||260, ph=pop.offsetHeight||320;
  const W=window.innerWidth, H=window.innerHeight;
  let left=clientX+12, top=clientY-20;
  if(left+pw>W-8) left=clientX-pw-12;
  if(top+ph>H-8) top=H-ph-8;
  if(top<8) top=8;
  pop.style.left=left+'px'; pop.style.top=top+'px';
  // Pre-fill
  const tEl=document.getElementById('wcalPopTime'); if(tEl) tEl.value=timeStr;
  const titleEl=document.getElementById('wcalPopTitle'); if(titleEl){ titleEl.value=''; titleEl.focus(); }
  // Update label
  const lbl=document.getElementById('wcalPopLabel');
  const d=new Date(dt+'T12:00:00');
  if(lbl) lbl.textContent=d.toLocaleDateString('en-US',{weekday:'short',month:'short',day:'numeric'});
}

function wcalPopClose(){
  const pop=document.getElementById('wcalPopover'); if(pop) pop.style.display='none';
}

window.wcalPopSwitch=function(type){
  _wcalPopType=type;
  document.getElementById('wcalPopTabEvent')?.classList.toggle('active',type==='event');
  document.getElementById('wcalPopTabTask')?.classList.toggle('active',type==='task');
  const ex=document.getElementById('wcalPopTaskExtras');
  if(ex) ex.style.display=type==='task'?'block':'none';
};

async function wcalPopCreate(){
  const title=(document.getElementById('wcalPopTitle')?.value||'').trim();
  const time=document.getElementById('wcalPopTime')?.value||'09:00';
  const dur=parseInt(document.getElementById('wcalPopDur')?.value||'60',10);
  if(!title||!_wcalPopDate){ document.getElementById('wcalPopTitle')?.focus(); return; }
  wcalPopClose();
  const st=document.getElementById('wcalAddStatus');
  if(_wcalPopType==='event'){
    const startDt=new Date(_wcalPopDate+'T'+time+':00');
    const endDt=new Date(startDt.getTime()+dur*60000);
    if(st) st.innerText='Creating…';
    try{
      const res=await fetch('/api/calendar/create_event',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({title,start:startDt.toISOString(),end:endDt.toISOString(),timezone:cal.tz})});
      const d=await res.json(); if(!d.ok) throw new Error(d.error||'Failed');
      cal.events[_wcalPopDate]=cal.events[_wcalPopDate]||[];
      cal.events[_wcalPopDate].push({summary:title,start:startDt.toISOString(),end:endDt.toISOString(),id:d.event?.id||''});
      showToast('Event created: '+title); wcalRefresh();
      if(st) st.innerText='';
    }catch(e){ showToast('Event creation failed: '+(e.message||e)+' — connect Calendar in Settings'); }
  } else {
    const priority=document.getElementById('wcalPopPriority')?.value||'medium';
    try{
      const res=await fetch('/api/cal/tasks',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({title,date:_wcalPopDate,start:time,duration:dur,priority})});
      const d=await res.json(); if(!d.ok) throw new Error(d.error||'Failed');
      cal.tasks.push(d.task); showToast('Task added: '+title); wcalRefresh();
    }catch(e){ showToast('Task creation failed: '+(e.message||e)); }
  }
}

function wcalWirePopover(){
  const pop=document.getElementById('wcalPopover'); if(!pop) return;
  document.getElementById('wcalPopCreate')?.addEventListener('click',wcalPopCreate);
  document.getElementById('wcalPopTitle')?.addEventListener('keydown',e=>{
    if(e.key==='Enter'){ e.preventDefault(); wcalPopCreate(); }
    if(e.key==='Escape') wcalPopClose();
  });
  // Keyboard shortcuts: N = new event, T = new task (only when calendar open, not in input)
  document.addEventListener('keydown',function(e){
    const calForm=document.getElementById('calendarForm');
    if(!calForm||calForm.style.display==='none') return;
    const tag=(e.target.tagName||'').toUpperCase();
    if(tag==='INPUT'||tag==='TEXTAREA'||tag==='SELECT') return;
    if(e.key==='Escape'){ wcalPopClose(); document.getElementById('wcalDetail')?.classList.remove('open'); }
    if(e.key==='n'||e.key==='N'){
      e.preventDefault(); wcalPopSwitch('event');
      const dt=cal.selected||ymd(new Date());
      const now=new Date(); const mm=Math.round(now.getMinutes()/15)*15;
      const ts=pad2(now.getHours())+':'+pad2(mm>=60?45:mm);
      wcalPopOpen(window.innerWidth/2-130, window.innerHeight/2-160, dt, ts);
    }
    if(e.key==='t'||e.key==='T'){
      e.preventDefault(); wcalPopSwitch('task');
      const dt=cal.selected||ymd(new Date());
      const now=new Date(); const mm=Math.round(now.getMinutes()/15)*15;
      const ts=pad2(now.getHours())+':'+pad2(mm>=60?45:mm);
      wcalPopOpen(window.innerWidth/2-130, window.innerHeight/2-160, dt, ts);
    }
  });
  // Click outside closes
  document.addEventListener('mousedown',function(e){
    if(pop.style.display==='none') return;
    if(!pop.contains(e.target)) wcalPopClose();
  });
}

// ── Wire buttons ───────────────────────────────────────────────
function wcalWireButtons(){
  const get=id=>document.getElementById(id);
  const on=(id,fn)=>{ const el=get(id); if(el) el.onclick=fn; };
  on('calPrevBtn',()=>wcalNav(-1));
  on('calNextBtn',()=>wcalNav(1));
  on('calTodayBtn',()=>{ cal.weekStart=wcalMonday(new Date()); cal.selected=ymd(new Date()); wcalFetchCurrentRange().then(()=>{ wcalRenderMiniMonth(); wcalRefresh(); }); });
  on('wcalMiniPrev',()=>{ cal.m--; if(cal.m<0){cal.m=11;cal.y--;} wcalRenderMiniMonth(); });
  on('wcalMiniNext',()=>{ cal.m++; if(cal.m>11){cal.m=0;cal.y++;} wcalRenderMiniMonth(); });
  on('wcalAddBtn',()=>wcalAddEvent());
  on('wcalAddTaskBtn',()=>wcalAddTask());
  on('wcalDetClose',()=>{ get('wcalDetail')?.classList.remove('open'); });
  on('wcalPopCreate',()=>wcalPopCreate());
  const tf=get('wcalAddTitle'); if(tf) tf.addEventListener('keydown',e=>{ if(e.key==='Enter') wcalAddEvent(); });
  const ttf=get('wcalTaskTitle'); if(ttf) ttf.addEventListener('keydown',e=>{ if(e.key==='Enter') wcalAddTask(); });
  const df=get('wcalAddDate'); if(df&&!df.value) df.value=ymd(new Date());
  const dtf=get('wcalTaskDate'); if(dtf&&!dtf.value) dtf.value=ymd(new Date());
}

// ── showCalendarModal ──────────────────────────────────────────
window.showCalendarModal=function showCalendarModal(){
  showModal();
  if(typeof hideAllModalForms==='function') hideAllModalForms();
  else ['frameworkForm','modalForm','manageForm','createForm','settingsForm','apiKeyHelpForm','crmForm','emailConsoleForm'].forEach(id=>{ const el=document.getElementById(id); if(el) el.style.display='none'; });
  const calForm=document.getElementById('calendarForm');
  if(calForm) calForm.style.display='flex';
  const modalBody=document.getElementById('modalBody'); if(modalBody) modalBody.style.display='none';
  const modalImg=document.getElementById('modalImg'); if(modalImg) modalImg.style.display='none';
  const modalTitle=document.getElementById('modalTitle'); if(modalTitle) modalTitle.innerText='Calendar';
  try{ ensureModalMinSize(1180,760); }catch(_){}
  cal.weekStart=wcalMonday(new Date()); cal.selected=ymd(new Date());
  cal.y=(new Date()).getFullYear(); cal.m=(new Date()).getMonth();
  wcalWireButtons(); wcalWirePopover(); wcalRenderMiniMonth();
  wcalFetchCurrentRange().then(()=>{ wcalRenderMiniMonth(); wcalRefresh(); });
  clearInterval(window._wcalNowInterval);
  window._wcalNowInterval=setInterval(wcalUpdateNowLine,60000);
};

// Keep backward-compat stubs
async function calFetchEventsForVisibleRange(){ await wcalFetchCurrentRange(); }
function calRenderMonth(){ wcalRenderMiniMonth(); }
function calRenderDayPanel(){ }
function calSetStatus(t){ const el=document.getElementById('calLoadStatus'); if(el) el.innerText=t||''; }
function calWeekdayHeader(){}
function calSelectDate(dt){ wcalSelectDate(dt); }

if($("calendarBtn")) $("calendarBtn").onclick = ()=> showCalendarModal();

async function showImageLibraryModal(){
  try{
    const res = await fetch("/api/images");
    const data = await res.json();
    if(!data.ok){
      showModal("Image Library", data.error || "Failed to load images");
      return;
    }
    const imgs = data.images || [];
    showModal("Image Library", "");
    if($("calendarForm")) $("calendarForm").style.display = "none";
    if($("emailConsoleForm")) $("emailConsoleForm").style.display = "none";
    const body = $("modalBody");
    if(!body) return;

    if(imgs.length === 0){
      body.innerText = "No images yet. Ask a teammate for a graphic to generate one.";
      return;
    }

    body.innerHTML = "";
    const grid = document.createElement("div");
    grid.style.display = "grid";
    grid.style.gridTemplateColumns = "repeat(auto-fill, minmax(180px, 1fr))";
    grid.style.gap = "10px";

    imgs.slice(0, 120).forEach((r)=>{
      const card = document.createElement("div");
      card.style.border = "1px solid rgba(255,255,255,.10)";
      card.style.borderRadius = "12px";
      card.style.padding = "8px";
      card.style.background = "rgba(0,0,0,.18)";

      const im = document.createElement("img");
      im.src = r.url;
      im.alt = r.filename || "image";
      im.style.width = "100%";
      im.style.height = "140px";
      im.style.objectFit = "cover";
      im.style.borderRadius = "10px";
      im.style.cursor = "zoom-in";
      im.onclick = ()=> openLightbox(r.url);

      const meta = document.createElement("div");
      meta.className = "tiny";
      meta.style.marginTop = "6px";
      meta.style.opacity = ".9";
      meta.style.wordBreak = "break-word";
      meta.innerText = (r.teammate ? (r.teammate + " • ") : "") + (r.uploaded_at || "");

      const actions = document.createElement("div");
      actions.className = "actions";
      actions.style.justifyContent = "flex-start";
      actions.style.marginTop = "8px";

      const openBtn = document.createElement("button");
      openBtn.className = "btn btnMini";
      openBtn.innerText = "Open";
      openBtn.onclick = ()=> openLightbox(r.url);

      const useBtn = document.createElement("button");
      useBtn.className = "btn btnMini";
      useBtn.innerText = "Use";
      useBtn.onclick = async ()=>{
        const seat = selectedSeat || "";
        if(!seat || seat === "Operator"){ showModal("Select a teammate first", "Choose a teammate, then click Use."); return; }
        try{
          const rr = await fetch('/api/teammates/' + encodeURIComponent(seat) + '/current_image', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({file_id: r.id})});
          const dd = await rr.json();
          if(!dd.ok) throw new Error(dd.error || 'Could not set current image');
          lastImageState = dd.image_state || {};
          await refreshThread();
        }catch(e){ showModal('Could not use image', String(e && e.message ? e.message : e)); }
      };

      actions.appendChild(openBtn);
      actions.appendChild(useBtn);

      card.appendChild(im);
      card.appendChild(meta);
      card.appendChild(actions);
      grid.appendChild(card);
    });

    body.appendChild(grid);
  }catch(e){
    showModal("Image Library", String(e || "Failed to load images"));
  }
}


if($("lightboxCloseBtn")) $("lightboxCloseBtn").onclick = ()=> closeLightbox();
if($("lightbox")) $("lightbox").onclick = (e)=>{ if(e && e.target && e.target.id==="lightbox") closeLightbox(); };


if($("twilioLoadBtn")) $("twilioLoadBtn").onclick = ()=> settingsLoadSmsSettings();
if($("twilioSaveBtn")) $("twilioSaveBtn").onclick = ()=> settingsSaveSmsSettings();
if($("imageLibBtn")) $("imageLibBtn").onclick = ()=> showImageLibraryModal();

try{
  if($("calPrevBtn")) $("calPrevBtn").onclick = async ()=>{
    cal.m -= 1;
    if(cal.m < 0){ cal.m = 11; cal.y -= 1; }
    await calFetchEventsForVisibleRange();
    calRenderMonth();
  };
  if($("calNextBtn")) $("calNextBtn").onclick = async ()=>{
    cal.m += 1;
    if(cal.m > 11){ cal.m = 0; cal.y += 1; }
    await calFetchEventsForVisibleRange();
    calRenderMonth();
  };
  if($("calTodayBtn")) $("calTodayBtn").onclick = async ()=>{
    const d = new Date();
    cal.y = d.getFullYear();
    cal.m = d.getMonth();
    calSelectDate(ymd(d));
    await calFetchEventsForVisibleRange();
    calRenderMonth();
  };
  // calAddTaskBtn and calCreateCallBtn removed (replaced by Motion calendar)
}catch(e){}


$("settingsBtn").onclick = () => showSettingsModal();
    $("cancelSettings").onclick = () => hideModal();

    $("saveSettings").onclick = async () => {
      $("settingsStatus").innerText = "Saving...";
      const keyVal = ($("openaiKey").value || "").trim();
      const payload = {
        openai_key: keyVal,
        smtp: {
          host: ($("smtpHost").value || "").trim(),
          port: parseInt(($("smtpPort").value || "587").trim(), 10),
          user: ($("smtpUser").value || "").trim(),
          pass: ($("smtpPass").value || "").trim(),
          from_name: ($("smtpFromName").value || "").trim()
        }
      };
      try{
        const res = await fetch("/api/user/settings", {
          method: "POST",
          headers: {"Content-Type":"application/json"},
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if(!data.ok){
          $("settingsStatus").innerText = data.error || "Save failed";
          return;
        }
        $("settingsStatus").innerText = "Saved";
          try{ await afterSettingsSaved(); }catch(e){}
      }catch(e){
        $("settingsStatus").innerText = "Save failed";
      }
    };

    // Google connect buttons (open OAuth flow)
    if($('gmailConnectBtn')) $('gmailConnectBtn').onclick = () => { window.location = '/gmail/connect'; };
    if($('calendarConnectBtn')) $('calendarConnectBtn').onclick = () => { window.location = '/calendar/connect'; };

    // ── Save & Exit handlers ────────────────────────────────────────
    // saveEdit already calls hideModal(); wire Save & Exit to do the same
    if($("saveEditExit")) $("saveEditExit").onclick = async () => { await $("saveEdit").onclick(); };

    // saveManage already calls hideModal(); Save & Exit = same
    if($("saveManageExit")) $("saveManageExit").onclick = async () => { await $("saveManage").onclick(); };

    // saveCreate already calls hideModal(); Save & Exit = same
    if($("saveCreateExit")) $("saveCreateExit").onclick = async () => { await $("saveCreate").onclick(); };

    // saveFramework already calls hideModal(); Save & Exit = same
    if($("saveFrameworkExit")) $("saveFrameworkExit").onclick = async () => { await $("saveFramework").onclick(); };

    // saveSettings does NOT hideModal on its own — Save & Exit adds that
    if($("saveSettingsExit")) $("saveSettingsExit").onclick = async () => {
      await $("saveSettings").onclick();
      hideModal();
    };

    // sessionObjectiveSaveExitBtn — save then close
    if($("sessionObjectiveSaveExitBtn")) $("sessionObjectiveSaveExitBtn").onclick = async () => {
      await saveSessionObjectiveModal();
      hideModal();
    };

    // operatorProfileSaveExitBtn — save then close
    if($("operatorProfileSaveExitBtn")) $("operatorProfileSaveExitBtn").onclick = async () => {
      await saveOperatorProfileModal();
      hideModal();
    };
    // ── end Save & Exit handlers ────────────────────────────────────

    if($('gmailDisconnectBtn')) $('gmailDisconnectBtn').onclick = async () => {
      try{ await fetch('/api/gmail/disconnect', {method:'POST'}); }catch(e){}
      try{ await refreshGoogleStatuses(); }catch(e){}
    };
    if($('calendarDisconnectBtn')) $('calendarDisconnectBtn').onclick = async () => {
      try{ await fetch('/api/calendar/disconnect', {method:'POST'}); }catch(e){}
      try{ await refreshGoogleStatuses(); }catch(e){}
    };

    // =========================
    // NEW: FIRST-RUN GUIDANCE (coach marks)
    // =========================
    const ONBOARD_VER = "v1";
    function onboardKey(name, username){
      return `rt_onboard_${ONBOARD_VER}_${name}_${username||"anon"}`;
    }
    function markOnboardDone(name, username){
      try{ localStorage.setItem(onboardKey(name, username), "1"); }catch(e){}
    }
    function isOnboardDone(name, username){
      try{ return localStorage.getItem(onboardKey(name, username)) === "1"; }catch(e){ return false; }
    }

    function clearCoach(){
      const el = document.getElementById("coachBubble");
      if(el) el.remove();
      document.querySelectorAll(".coachGlow").forEach(n => n.classList.remove("coachGlow"));
    }

    function placeCoach(targetEl, title, body, ctaText){
      clearCoach();
      if(!targetEl) return null;
      targetEl.classList.add("coachGlow");

      const r = targetEl.getBoundingClientRect();
      const bubble = document.createElement("div");
      bubble.id = "coachBubble";
      bubble.className = "coachBubble";
      bubble.innerHTML = `
        <div class="coachTitle">${title}</div>
        <div class="coachBody">${body}</div>
        <div class="coachActions">
          <button class="btn btnTiny" id="coachSkip">Skip</button>
          <button class="btn btnTiny btnPrimary" id="coachGo">${ctaText || "Open"}</button>
        </div>
      `;
      document.body.appendChild(bubble);

      // position near target
      const pad = 10;
      const top = Math.max(70, r.bottom + pad);
      const left = Math.min(window.innerWidth - bubble.offsetWidth - 12, Math.max(12, r.left));
      bubble.style.top = top + "px";
      bubble.style.left = left + "px";
      return bubble;
    }

    async function runFirstRunGuidance(){
      let me = null;
      try{
        const res = await fetch("/api/me");
        me = await res.json();
      }catch(e){ return; }
      if(!me || !me.ok) return;

      const username = (me.user && me.user.username) ? me.user.username : "anon";
      const needsKey = !me.has_openai_key;
      const needsEmail = !me.has_smtp;

      if((needsKey || needsEmail) && !isOnboardDone("settings_prompted", username)){
        // show a coach bubble on the Settings button — do NOT auto-open the modal
        const b = placeCoach($("settingsBtn"),
          "Start here: Settings",
          "Add your OpenAI key + your email (SMTP) so the app runs on your accounts, not the owner's.",
          "Open settings"
        );
        if(b){
          $("coachSkip").onclick = () => { clearCoach(); markOnboardDone("settings_prompted", username); };
          $("coachGo").onclick = () => { clearCoach(); showSettingsModal(true); markOnboardDone("settings_prompted", username); };
        }
        return;
      }

      if(!isOnboardDone("install_full_nudged", username)){
        const installedCount = (state && state.installed_order && state.installed_order.length) ? state.installed_order.length : 0;
        if(installedCount < 3){
          const b = placeCoach($("installFullBtn"),
            "Quick setup: Install full team",
            "One click installs the full round table so you can start talking to each seat immediately.",
            "Install"
          );
          if(b){
            $("coachSkip").onclick = () => { clearCoach(); markOnboardDone("install_full_nudged", username); };
            $("coachGo").onclick = () => {
              clearCoach();
              markOnboardDone("install_full_nudged", username);
              if($("installFullBtn")) $("installFullBtn").click();
            };
          }
        }else{
          markOnboardDone("install_full_nudged", username);
        }
      }
    }

    async function afterSettingsSaved(){
      try{ await loadState(); }catch(e){}
      try{ await runFirstRunGuidance(); }catch(e){}
      try{ if(window.onboardingRefresh) await window.onboardingRefresh(); }catch(e){}
    }

    // Clicking outside bubble clears it
    window.addEventListener("click", (e) => {
      const b = document.getElementById("coachBubble");
      if(!b) return;
      if(b.contains(e.target)) return;
      if(e.target && e.target.id && (e.target.id === "settingsBtn" || e.target.id === "installFullBtn")) return;
      clearCoach();
    });
    window.addEventListener("resize", () => { clearCoach(); });

    // run on load (after state is available)
    setTimeout(() => { try{ runFirstRunGuidance(); }catch(e){} }, 600);

$("saveFramework").onclick = async () => {
      $("frameworkStatus").innerText = "Saving...";
      const fw = $("frameworkText").value || "";
      const res = await fetch("/api/framework", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({framework: fw})
      });
      const data = await res.json();
      if(!data.ok){
        $("frameworkStatus").innerText = data.error || "Save failed";
        return;
      }
      $("frameworkStatus").innerText = "Saved";
      await loadState();
      hideModal();
      showModal("Saved", "Core framework updated. It will be applied to all teammate prompts immediately.");
    };

    $("resetFramework").onclick = async () => {
      const ok = confirm("Reset core framework to default?");
      if(!ok) return;
      $("frameworkText").value = "";
      $("frameworkStatus").innerText = "Resetting...";
      const res = await fetch("/api/framework", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({framework: ""})
      });
      const data = await res.json();
      if(!data.ok){
        $("frameworkStatus").innerText = data.error || "Reset failed";
        return;
      }
      await loadFrameworkIntoForm();
      await loadState();
      $("frameworkStatus").innerText = "Reset to default";
    };

    window.addEventListener("resize", () => {
      if(state && state.ok){
        renderTable();
      }
    });

    loadState();
  loadState();


// ===== ONE BLOCK ENTER-TO-SEND (ADD v1) =====

(function(){

  function enableEnterSend(id, fn){
    const el = document.getElementById(id);
    if(!el) return;

    el.addEventListener("keydown", (e) => {
      if(e.key !== "Enter") return;
      if(e.shiftKey) return;

      e.preventDefault();
      try{ fn(); }catch(err){}
    });
  }

  enableEnterSend("opPrompt", conveneAll);
  enableEnterSend("followMsg", sendFollow);

})();


// -------- Client Memory Profiles (UI) --------
const ClientStore = { list: [], active_id: "", current: null };

function openClientsPanel(){
  try{ document.body.style.overflow = "hidden"; }catch(_){}
  if(typeof hideAllModalForms === "function") hideAllModalForms();
  if($("modalTitle")) $("modalTitle").innerText = "Client Memory Profiles";
  if($("modalBody")) $("modalBody").style.display = "none";
  if($("clientsForm")) $("clientsForm").style.display = "block";
  if($("overlay")) $("overlay").classList.add("show");
  const sc = $("modalScroll"); if(sc) sc.scrollTop = 0;
  loadClients();
}

function _fillClientForm(c){
  ClientStore.current = c || null;
  $("clientName").value = (c && c.name) || "";
  $("clientCompany").value = (c && c.company) || "";
  $("clientEmail").value = (c && c.email) || "";
  $("clientTags").value = (c && c.tags) || "";
  $("clientNotes").value = (c && c.notes) || "";
  $("clientSummary").value = (c && c.last_summary) || "";
}

function _renderClientSelect(filterText){
  const sel = $("activeClientSelect");
  if(!sel) return;
  const f = (filterText || "").toLowerCase();
  sel.innerHTML = "";
  const optNone = document.createElement("option");
  optNone.value = "";
  optNone.text = "(no active client)";
  sel.appendChild(optNone);

  ClientStore.list
    .filter(c => !f || ((c.name||"").toLowerCase().includes(f) || (c.company||"").toLowerCase().includes(f) || (c.email||"").toLowerCase().includes(f) || (c.tags||"").toLowerCase().includes(f)))
    .forEach(c => {
      const opt = document.createElement("option");
      opt.value = c.id;
      opt.text = c.company ? `${c.name} • ${c.company}` : c.name;
      sel.appendChild(opt);
    });

  sel.value = ClientStore.active_id || "";
}

async function loadClients(){
  const res = await fetch("/api/clients");
  const data = await res.json();
  if(!data.ok) return;
  ClientStore.list = data.clients || [];
  ClientStore.active_id = data.active_client_id || "";
  _renderClientSelect(($("clientSearch") && $("clientSearch").value) || "");
  const active = ClientStore.list.find(c => c.id === ClientStore.active_id) || null;
  _fillClientForm(active);
}

async function setActiveClient(cid){
  await fetch("/api/clients/active", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({client_id: cid})});
  ClientStore.active_id = cid || "";
  const active = ClientStore.list.find(c => c.id === ClientStore.active_id) || null;
  _fillClientForm(active);
}

async function createNewClient(){
  const name = ($("clientName").value || "").trim() || "New Client";
  const payload = {
    name,
    company: ($("clientCompany").value || "").trim(),
    email: ($("clientEmail").value || "").trim(),
    tags: ($("clientTags").value || "").trim(),
    notes: ($("clientNotes").value || "").trim(),
    last_summary: ($("clientSummary").value || "").trim(),
  };
  const res = await fetch("/api/clients", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(payload)});
  const data = await res.json();
  if(!data.ok) return;
  await loadClients();
  if(data.active_client_id) {
    ClientStore.active_id = data.active_client_id;
    $("activeClientSelect").value = ClientStore.active_id;
  }
}

async function saveCurrentClient(){
  const cid = ClientStore.active_id;
  if(!cid){
    // if no active client, create new
    return createNewClient();
  }
  const payload = {
    name: ($("clientName").value || "").trim(),
    company: ($("clientCompany").value || "").trim(),
    email: ($("clientEmail").value || "").trim(),
    tags: ($("clientTags").value || "").trim(),
    notes: ($("clientNotes").value || "").trim(),
    last_summary: ($("clientSummary").value || "").trim(),
  };
  const res = await fetch(`/api/clients/${encodeURIComponent(cid)}`, {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(payload)});
  const data = await res.json();
  if(!data.ok) return;
  await loadClients();
  $("activeClientSelect").value = cid;
}

async function deleteCurrentClient(){
  const cid = ClientStore.active_id;
  if(!cid) return;
  await fetch(`/api/clients/${encodeURIComponent(cid)}`, {method:"DELETE"});
  await loadClients();
  $("activeClientSelect").value = ClientStore.active_id || "";
}

function openApiKeyHelp(){
  try{ document.body.style.overflow = "hidden"; }catch(_){}
  if(typeof hideAllModalForms === "function") hideAllModalForms();
  if($("modalTitle")) $("modalTitle").innerText = "How to get and set your OpenAI API key";
  if($("modalBody")) $("modalBody").style.display = "none";
  if($("apiKeyHelpForm")) $("apiKeyHelpForm").style.display = "block";
  if($("overlay")) $("overlay").classList.add("show");
  if(typeof applyModalPos === "function") applyModalPos();
  const sc = $("modalScroll"); if(sc) sc.scrollTop = 0;
}

// API key help button
if($("openApiKeyHelpBtn")) $("openApiKeyHelpBtn").onclick = () => openApiKeyHelp();
if($("closeApiKeyHelpBtn")) $("closeApiKeyHelpBtn").onclick = () => { try{ document.body.style.overflow = ""; }catch(_){ } hideModal(); };


// Client form bindings (safe)
if($("activeClientSelect")) $("activeClientSelect").onchange = () => setActiveClient($("activeClientSelect").value);
if($("clientSearch")) $("clientSearch").oninput = () => _renderClientSelect($("clientSearch").value);

// API key help delegation (works even if elements render later)
document.addEventListener("click", (e) => {
          // Clients delegation

  const t = e.target;
  if(!t) return;
  if(t.id === "openClientsBtn"){
  e.preventDefault();
  openClientsPanel();
}
if(t.id === "closeClientsBtn"){
  e.preventDefault();
  try{ document.body.style.overflow = ""; }catch(_){}
  hideModal();
}
if(t.id === "newClientBtn"){
  e.preventDefault();
  _fillClientForm(null);
  ClientStore.active_id = "";
  if($("activeClientSelect")) $("activeClientSelect").value = "";
}
if(t.id === "saveClientBtn"){
  e.preventDefault();
  saveCurrentClient();
}
if(t.id === "deleteClientBtn"){
  e.preventDefault();
  deleteCurrentClient();
}

if(t.id === "openApiKeyHelpBtn"){
    e.preventDefault();
    openApiKeyHelp();
  }
  if(t.id === "closeApiKeyHelpBtn"){
    e.preventDefault();
    try{ document.body.style.overflow = ""; }catch(_){}
    hideModal();
  }
});


// ===== NEW: Mobile Vertical UI v2 wiring (additive) =====


// ===== NEW: Mobile Auto-Center v1 (additive) =====
function autoCenterTableV1(){
  try{
    const table = document.querySelector('.table');
    if(!table) return;
    const vw = Math.max(document.documentElement.clientWidth || 0, window.innerWidth || 0);
    if(vw <= 0) return;

    // Reset shift before measuring so we don't compound offsets.
    document.documentElement.style.setProperty('--tableShiftX', '0px');

    const r = table.getBoundingClientRect();
    const center = r.left + (r.width/2);
    const target = vw/2;

    // Positive delta means move right; negative move left.
    let delta = (target - center);

    // Clamp to avoid wild jumps.
    if(delta > 24) delta = 24;
    if(delta < -24) delta = -24;

    // Only apply if meaningful.
    if(Math.abs(delta) >= 0.5){
      document.documentElement.style.setProperty('--tableShiftX', `${delta.toFixed(2)}px`);
    }else{
      document.documentElement.style.setProperty('--tableShiftX', '0px');
    }
  }catch(e){}
}


// ===== NEW: Mobile Table Zoom v1 (additive) =====
function _isMobileV1(){
  const w = Math.max(document.documentElement.clientWidth||0, window.innerWidth||0);
  return w <= 640;
}

function initTableZoomV1(){
  try{
    const fab = document.getElementById('tableZoomFab');
    const out = document.getElementById('zoomOutBtn');
    const inn = document.getElementById('zoomInBtn');
    const fit = document.getElementById('zoomFitBtn');
    const ctr = document.getElementById('zoomCenterBtn');
    if(!fab || !out || !inn || !ctr) return;

    const applyFabVis = ()=>{
      fab.style.display = _isMobileV1() ? 'flex' : 'none';
    };
    applyFabVis();
    window.addEventListener('resize', ()=>{ setTimeout(applyFabVis, 60); }, {passive:true});
    window.addEventListener('orientationchange', ()=>{ setTimeout(applyFabVis, 220); }, {passive:true});

    const getZoom = ()=>{
      const v = getComputedStyle(document.documentElement).getPropertyValue('--tableZoom').trim();
      const f = parseFloat(v);
      return isFinite(f) ? f : 0.72;
    };
    const setZoom = (z)=>{
      if(z < 0.20) z = 0.20;
      if(z > 1.00) z = 1.00;
      document.documentElement.style.setProperty('--tableZoom', z.toFixed(2));
      setTimeout(()=>{ try{ autoCenterTableV3(); }catch(e){} }, 60);
    };

    out.addEventListener('click', ()=>{ setZoom(getZoom() - 0.05); });
    inn.addEventListener('click', ()=>{ setZoom(getZoom() + 0.05); });
    if(fit){ fit.addEventListener('click', ()=>{ try{ autoFitZoomV3(); }catch(e){} }); }
    ctr.addEventListener('click', ()=>{
      document.documentElement.style.setProperty('--tableShiftX','0px');
      setTimeout(()=>{ try{ autoCenterTableV3(); }catch(e){} }, 60);
    });

    // Fit once on mobile start
    try{ if(_isMobileV1()) autoFitZoomV3(); }catch(e){}
  }catch(e){}
}


function bindAutoCenterTableV1(){
  try{
    // Run after layout settles
    setTimeout(autoCenterTableV1, 60);
    setTimeout(autoCenterTableV1, 220);

    window.addEventListener('resize', ()=>{ setTimeout(autoCenterTableV1, 60); }, {passive:true});
    window.addEventListener('orientationchange', ()=>{ setTimeout(autoCenterTableV1, 220); }, {passive:true});

    // If we open/close overlays that might change scrollbars, re-center
    document.addEventListener('click', (ev)=>{
      const t = ev.target;
      if(!t) return;
      if(t.id === 'mobileMenuBtn' || t.id === 'drawerCloseBtn' || t.id === 'diagOpenBtn' || t.id === 'diagCloseBtn'){
        setTimeout(autoCenterTableV1, 120);
      }
    }, true);
  }catch(e){}
}

function initMobileUIv2(){
  const isMobile = () => window.matchMedia && window.matchMedia("(max-width: 720px)").matches;

  const overlay = $("mobileDrawerOverlay");
  const drawer = $("mobileDrawer");
  const openBtn = $("mobileMenuBtn");
  const closeBtn = $("mobileCloseMenuBtn");
  const closeBtn2 = $("mobileCloseMenuBtn2");

  function openMenu(){
    if(!overlay) return;
    overlay.classList.add("show");
    overlay.setAttribute("aria-hidden", "false");
    try{ document.body.style.overflow = "hidden"; }catch(_){}
  }
  function closeMenu(){
    if(!overlay) return;
    overlay.classList.remove("show");
    overlay.setAttribute("aria-hidden", "true");
    try{ document.body.style.overflow = ""; }catch(_){}
  }

  if(openBtn) openBtn.onclick = () => { if(isMobile()) openMenu(); };
  if(closeBtn) closeBtn.onclick = () => closeMenu();
  if(closeBtn2) closeBtn2.onclick = () => closeMenu();

  // Bottom bar shortcuts
  const mAssemble = $("mobileAssembleBtn");
  if(mAssemble) mAssemble.onclick = () => { closeMenu(); if($("assembleBtn")) $("assembleBtn").click(); };
  const mManage = $("mobileManageBtn");
  if(mManage) mManage.onclick = () => { closeMenu(); if($("manageTeamBtn")) $("manageTeamBtn").click(); };
  const mSettings = $("mobileSettingsBtn");
  if(mSettings) mSettings.onclick = () => { closeMenu(); if($("settingsBtn")) $("settingsBtn").click(); };

  // Drawer buttons that map to existing topbar actions
  if(drawer){
    drawer.addEventListener("click", (e) => {
      const t = e.target;
      if(!t) return;
      const btn = t.closest ? t.closest("[data-click]") : null;
      if(btn){
        const id = btn.getAttribute("data-click");
        if(id && $(id)){
          closeMenu();
          $(id).click();
        }
      }
    });
  }

  // Tap outside drawer closes
  if(overlay){
    overlay.addEventListener("click", (e) => {
      if(e.target === overlay) closeMenu();
    });
  }

  // Escape closes
  document.addEventListener("keydown", (e) => {
    if(e.key === "Escape"){
      if(overlay && overlay.classList.contains("show")) closeMenu();
    }
  });

  // Handy: scroll to top from drawer
  const topBtn = $("mobileScrollTopBtn");
  if(topBtn) topBtn.onclick = () => { try{ window.scrollTo({top:0, behavior:"smooth"}); }catch(_){ window.scrollTo(0,0); } closeMenu(); };
}


/* NEW: Diagnostics Panel v1 (additive) */
function initDiagnosticsPanelV1(){
  const openBtn = document.getElementById("diagOpenBtn");
  const closeBtn = document.getElementById("diagCloseBtn");
  const refreshBtn = document.getElementById("diagRefreshBtn");
  const copyBtn = document.getElementById("diagCopyBtn");
  const overlay = document.getElementById("diagOverlay");
  const panel = document.getElementById("diagPanel");
  const pre = document.getElementById("diagPre");
  const vActive = document.getElementById("diagActive");
  const vInstalled = document.getElementById("diagInstalled");
  const vEmail = document.getElementById("diagEmail");
  const vCal = document.getElementById("diagCal");

  if(!openBtn || !panel || !overlay) return;

  let timer = null;
  let lastPayload = null;

  function show(){
    overlay.classList.add("show");
    panel.classList.add("show");
    load();
    if(timer) clearInterval(timer);
    timer = setInterval(load, 6000);
  }
  function hide(){
    overlay.classList.remove("show");
    panel.classList.remove("show");
    if(timer) clearInterval(timer);
    timer = null;
  }

  async function load(){
    try{
      const r = await fetch("/api/diagnostics", {method:"GET", headers:{"Accept":"application/json"}});
      const j = await r.json();
      lastPayload = j;
      pre.textContent = JSON.stringify(j, null, 2);

      const active = (j && j.registry && Array.isArray(j.registry.active_order)) ? j.registry.active_order : [];
      const installed = (j && j.registry && Array.isArray(j.registry.installed_order)) ? j.registry.installed_order : [];
      vActive.textContent = active.length ? active.join(", ") : "(none)";
      vInstalled.textContent = installed.length ? installed.join(", ") : "(none)";

      const email = j && j.capabilities && j.capabilities.email ? j.capabilities.email : {};
      const cal = j && j.capabilities && j.capabilities.calendar ? j.capabilities.calendar : {};
      vEmail.textContent = ("gmail_connected" in email || "smtp_ready" in email) ? JSON.stringify(email) : String(email || "");
      vCal.textContent = ("calendar_connected" in cal) ? JSON.stringify(cal) : String(cal || "");
    }catch(e){
      pre.textContent = "Diagnostics failed to load. " + (e && e.message ? e.message : String(e));
    }
  }

  function copy(){
    try{
      const txt = pre ? pre.textContent : (lastPayload ? JSON.stringify(lastPayload, null, 2) : "");
      if(!txt) return;
      navigator.clipboard.writeText(txt);
      copyBtn.textContent = "Copied";
      setTimeout(()=>{ copyBtn.textContent = "Copy"; }, 900);
    }catch(e){}
  }

  openBtn.onclick = show;
  if(closeBtn) closeBtn.onclick = hide;
  if(overlay) overlay.onclick = hide;
  if(refreshBtn) refreshBtn.onclick = load;
  if(copyBtn) copyBtn.onclick = copy;

  document.addEventListener("keydown", (ev)=>{
    if(ev.key === "Escape") hide();
  });
}

try{ initMobileUIv2(); }catch(e){}

try{ initDiagnosticsPanelV1(); }catch(e){}


// ===== NEW: Mobile Round Table Viewport + AutoFit v3 (additive, fixes right-side clipping) =====
function ensureTableViewportV3(){
  try{
    const table = document.querySelector('.table');
    if(!table) return;
    if(table.parentElement && table.parentElement.id === 'tableViewport') return;

    const wrap = document.createElement('div');
    wrap.id = 'tableViewport';
    // Insert wrap where the table currently is
    const parent = table.parentElement;
    parent.insertBefore(wrap, table);
    wrap.appendChild(table);
  }catch(e){}
}

function autoFitZoomV3(){
  try{
    ensureTableViewportV3();
    const table = document.querySelector('.table');
    const vp = document.getElementById('tableViewport');
    if(!table || !vp) return;

    const root = document.documentElement;
    // Measure at zoom=1
    const prevZoom = (getComputedStyle(root).getPropertyValue('--tableZoom') || '').trim() || '0.72';
    root.style.setProperty('--tableZoom','1');
    root.style.setProperty('--tableShiftX','0px');

    const r = table.getBoundingClientRect();
    const baseW = Math.max(1, r.width);

    // Target width is viewport width minus padding buffer
    const vw = Math.max(vp.clientWidth || 0, window.innerWidth || 0);
    const target = Math.max(220, vw - 24);

    let z = target / baseW;
    if(!isFinite(z) || z <= 0) z = parseFloat(prevZoom) || 0.72;

    if(z > 1.00) z = 1.00;
    if(z < 0.20) z = 0.20;

    root.style.setProperty('--tableZoom', z.toFixed(2));

    // Center correction (if any drift remains)
    setTimeout(()=>{ try{ autoCenterTableV3(); }catch(e){} }, 60);
  }catch(e){}
}

function autoCenterTableV3(){
  try{
    ensureTableViewportV3();
    const table = document.querySelector('.table');
    const vp = document.getElementById('tableViewport');
    if(!table || !vp) return;

    const vw = Math.max(vp.clientWidth || 0, window.innerWidth || 0);
    if(vw <= 0) return;

    // reset shift
    document.documentElement.style.setProperty('--tableShiftX','0px');
    const r = table.getBoundingClientRect();
    const center = r.left + (r.width/2);
    const target = vw/2;

    let delta = (target - center);
    if(delta > 32) delta = 32;
    if(delta < -32) delta = -32;

    if(Math.abs(delta) >= 0.5){
      document.documentElement.style.setProperty('--tableShiftX', `${delta.toFixed(2)}px`);
    }else{
      document.documentElement.style.setProperty('--tableShiftX','0px');
    }
  }catch(e){}
}

function bindMobileViewportV3(){
  try{
    ensureTableViewportV3();
    setTimeout(()=>{ try{ autoFitZoomV3(); }catch(e){} }, 120);
    window.addEventListener('resize', ()=>{ setTimeout(()=>{ try{ autoFitZoomV3(); }catch(e){} }, 120); }, {passive:true});
    window.addEventListener('orientationchange', ()=>{ setTimeout(()=>{ try{ autoFitZoomV3(); }catch(e){} }, 220); }, {passive:true});
  }catch(e){}
}


// ===== ADDITIVE UPGRADE: Mobile Pan + Pinch Zoom for Round Table v4 =====
(function(){
  const VIEW = { scale: 1, panX: 0, panY: 0, minScale: 0.55, maxScale: 1.45 };
  let LOCKED_V4 = true;
  let stageMO = null;

  function isMobileV4(){
    try{ return window.matchMedia && window.matchMedia("(max-width: 700px)").matches; }catch(e){ return (window.innerWidth||0) <= 700; }
  }

  function clampV4(v, a, b){ return Math.max(a, Math.min(b, v)); }

  function ensureRTStageV4(){
    const wrap = document.getElementById("tableWrap");
    if(!wrap) return null;

    let stage = document.getElementById("rtStage");
    if(stage) return stage;

    stage = document.createElement("div");
    stage.id = "rtStage";

    // Move the table core into the stage first
    const tableCore = document.getElementById("tableCore") || wrap.querySelector(".table");
    if(tableCore) stage.appendChild(tableCore);

    // Move any existing seats into the stage (renderTable will recreate them later anyway)
    Array.from(wrap.querySelectorAll(".seat")).forEach(s => {
      try{ stage.appendChild(s); }catch(_){}
    });

    // Insert stage as the first child so operator overlay stays on top
    wrap.insertBefore(stage, wrap.firstChild);

    // Watch for newly rendered seats and move them into the stage automatically
    try{
      stageMO = new MutationObserver((muts)=>{
        for(const m of muts){
          for(const node of (m.addedNodes || [])){
            try{
              if(!node) continue;
              if(node.classList && node.classList.contains("seat")){
                stage.appendChild(node);
              }
            }catch(_){}
          }
        }
      });
      stageMO.observe(wrap, { childList:true });
    }catch(e){}

    return stage;
  }

  
  function setLockedV4(v){
    LOCKED_V4 = !!v;
    const wrap = document.getElementById("tableWrap");
    if(wrap){
      // When locked, allow normal vertical scroll gestures over the table area.
      // When unlocked, capture gestures for pan/zoom.
      try{
        wrap.style.setProperty("touch-action", LOCKED_V4 ? "pan-y" : "none", "important");
      }catch(_){}
    }
    const btn = document.getElementById("tableLockBtn");
    if(btn){
      btn.classList.toggle("isLocked", LOCKED_V4);
      btn.textContent = LOCKED_V4 ? "🔒" : "🔓";
      btn.title = LOCKED_V4 ? "Unlock table to pan/zoom" : "Lock table so you can scroll";
    }
  }
function applyRTTransformV4(){
    const stage = ensureRTStageV4();
    // Bind lock toggle (mobile)
    try{
      const lockBtn = document.getElementById('tableLockBtn');
      if(lockBtn && !lockBtn.__boundV4){
        lockBtn.__boundV4 = true;
        lockBtn.addEventListener('click', (e)=>{ e.preventDefault(); e.stopPropagation(); setLockedV4(!LOCKED_V4); }, {passive:false});
      }
    }catch(_){ }

    if(!stage) return;
    stage.style.transform = `translate(${VIEW.panX}px, ${VIEW.panY}px) scale(${VIEW.scale})`;
  }

  // Expose helpers for existing seat drag math patches
  window.getRTScaleV4 = function(){ return VIEW.scale || 1; };
  window.getRTBoundsElV4 = function(){
    return document.getElementById("rtStage") || document.getElementById("tableWrap") || document.body;
  };

  function fitToScreenV4(){
    const wrap = document.getElementById("tableWrap");
    const stage = ensureRTStageV4();
    // Bind lock toggle (mobile)
    try{
      const lockBtn = document.getElementById('tableLockBtn');
      if(lockBtn && !lockBtn.__boundV4){
        lockBtn.__boundV4 = true;
        lockBtn.addEventListener('click', (e)=>{ e.preventDefault(); e.stopPropagation(); setLockedV4(!LOCKED_V4); }, {passive:false});
      }
    }catch(_){ }

    if(!wrap || !stage) return;

    // Since stage fills wrap, fit is simply a gentle zoom-out on smaller screens
    const w = wrap.clientWidth || window.innerWidth || 360;
    const target = Math.max(280, w - 18);

    // Base size is wrap size; we want a bit of breathing room so seats don't clip
    let z = target / Math.max(1, w);
    z = clampV4(z, VIEW.minScale, 1);

    VIEW.scale = z;
    VIEW.panX = 0;
    VIEW.panY = 0;
    applyRTTransformV4();
  }

  function initPanZoomV4(){
    if(!isMobileV4()) return;

    const wrap = document.getElementById("tableWrap");
    if(!wrap) return;

    ensureRTStageV4();

    // Ensure operator stays clickable and above stage
    const op = document.getElementById("operator");
    if(op){
      op.style.position = "absolute";
      op.style.left = "50%";
      op.style.top = "50%";
      op.style.transform = "translate(-50%,-50%)";
      op.style.zIndex = "60";
      op.style.pointerEvents = "auto";
    }

    // Prevent browser scrolling/zooming during gestures inside the table area
    try{ wrap.style.touchAction = "none"; }catch(_){}

    const pointers = new Map();
    let pinchStartDist = 0;
    let pinchStartScale = 1;
    let lastMid = null;
    let panning = false;
    let lastPanPoint = null;

    function isSeatTarget(t){
      try{ return !!(t && (t.closest && t.closest(".seat"))); }catch(e){ return false; }
    }

    function onDown(e){
      // If finger starts on a seat, let seat drag handle it (do not hijack)
      if(isSeatTarget(e.target)) return;

      pointers.set(e.pointerId, {x:e.clientX, y:e.clientY});
      wrap.setPointerCapture(e.pointerId);

      if(pointers.size === 2){
        const pts = Array.from(pointers.values());
        const dx = pts[0].x - pts[1].x;
        const dy = pts[0].y - pts[1].y;
        pinchStartDist = Math.hypot(dx, dy);
        pinchStartScale = VIEW.scale;
        lastMid = { x:(pts[0].x+pts[1].x)/2, y:(pts[0].y+pts[1].y)/2 };
        panning = true;
        lastPanPoint = lastMid;
      }else if(pointers.size === 1){
        // one-finger pan on empty space (so user can move around)
        panning = true;
        lastPanPoint = {x:e.clientX, y:e.clientY};
      }
    }

    function onMove(e){
      if(!pointers.has(e.pointerId)) return;
      pointers.set(e.pointerId, {x:e.clientX, y:e.clientY});

      if(pointers.size === 2){
        const pts = Array.from(pointers.values());
        const dx = pts[0].x - pts[1].x;
        const dy = pts[0].y - pts[1].y;
        const dist = Math.hypot(dx, dy);

        const mid = { x:(pts[0].x+pts[1].x)/2, y:(pts[0].y+pts[1].y)/2 };

        if(pinchStartDist > 0){
          let nextScale = pinchStartScale * (dist / pinchStartDist);
          nextScale = clampV4(nextScale, VIEW.minScale, VIEW.maxScale);

          // Zoom around the midpoint: adjust pan so content feels anchored
          const scaleRatio = nextScale / (VIEW.scale || 1);
          VIEW.panX = mid.x - scaleRatio * (mid.x - VIEW.panX);
          VIEW.panY = mid.y - scaleRatio * (mid.y - VIEW.panY);

          VIEW.scale = nextScale;
        }

        if(lastPanPoint){
          VIEW.panX += (mid.x - lastPanPoint.x);
          VIEW.panY += (mid.y - lastPanPoint.y);
        }
        lastPanPoint = mid;
        applyRTTransformV4();
        e.preventDefault();
      }else if(pointers.size === 1 && panning && lastPanPoint){
        const cur = {x:e.clientX, y:e.clientY};
        VIEW.panX += (cur.x - lastPanPoint.x);
        VIEW.panY += (cur.y - lastPanPoint.y);
        lastPanPoint = cur;
        applyRTTransformV4();
        e.preventDefault();
      }
    }

    function onUp(e){
      if(pointers.has(e.pointerId)) pointers.delete(e.pointerId);
      try{ wrap.releasePointerCapture(e.pointerId); }catch(_){}

      if(pointers.size === 0){
        panning = false;
        lastPanPoint = null;
        lastMid = null;
        pinchStartDist = 0;
      }else if(pointers.size === 1){
        const pt = Array.from(pointers.values())[0];
        lastPanPoint = {x:pt.x, y:pt.y};
        pinchStartDist = 0;
      }
    }

    setLockedV4(true);

    // Bind pointer events for pan/zoom
    wrap.addEventListener("pointerdown", onDown, {passive:false});
    wrap.addEventListener("pointermove", onMove, {passive:false});
    wrap.addEventListener("pointerup", onUp, {passive:true});
    wrap.addEventListener("pointercancel", onUp, {passive:true});

    // Initial fit and on resize/orientation changes
    setTimeout(()=>{ try{ fitToScreenV4(); }catch(e){} }, 120);
    window.addEventListener("resize", ()=>{ setTimeout(()=>{ try{ fitToScreenV4(); }catch(e){} }, 180); }, {passive:true});
    window.addEventListener("orientationchange", ()=>{ setTimeout(()=>{ try{ fitToScreenV4(); }catch(e){} }, 240); }, {passive:true});
  }

  // Run after first paint
  try{
    if(document.readyState === "loading"){
      document.addEventListener("DOMContentLoaded", ()=>{ try{ initPanZoomV4(); }catch(e){} }, {once:true});
    }else{
      initPanZoomV4();
    }
  }catch(e){}
})();


// Auto-show onboarding if applicable (safe stub — real logic is in the onboarding IIFE)
if(typeof maybeAutoShowOnboarding === "function"){
  try{ if(typeof maybeAutoShowOnboarding==="function"){try{maybeAutoShowOnboarding();}catch(_){}}else{try{setTimeout(function(){if(typeof window.onboardingOpen==="function"){fetch("/api/onboarding/status").then(function(r){return r.json();}).then(function(d){if(d&&d.ok&&!d.dismissed&&!d.all_done)window.onboardingOpen();}).catch(function(){});}},800);}catch(_){}} }catch(_){}
} else {
  // Stub: try to open onboarding via the exposed window handle
  try{
    setTimeout(function(){
      if(typeof window.onboardingOpen === "function"){
        fetch("/api/onboarding/status").then(r=>r.json()).then(d=>{
          if(d && d.ok && !d.dismissed && !d.all_done) window.onboardingOpen();
        }).catch(function(){});
      }
    }, 800);
  }catch(_){}
}

    // ===== Client Center: Pipeline (FlowChat-like columns) =====
    function ccSelectTab(tab){
      const panels = ["Clients","Pipeline","EmailBroadcast","Tasks","Sequences","History","Calendar"];
      for(const p of panels){
        const el = document.getElementById("ccPanel"+p);
        if(el) el.style.display = (p===tab) ? "block" : "none";
      }
      const btns = [
        ["Clients","ccTabClients"],
        ["Pipeline","ccTabPipeline"],
        ["EmailBroadcast","ccTabEmailBroadcast"],
        ["Tasks","ccTabTasks"],
        ["Sequences","ccTabSequences"],
        ["History","ccTabHistory"],
        ["Calendar","ccTabCalendar"],
      ];
      btns.forEach(([name,id])=>{
        const b=document.getElementById(id);
        if(b) b.classList.toggle("btnPrimary", name===tab);
      });
    }

    async function loadPipelineStages(){
      const res = await fetch("/api/crm/state");
      const data = await res.json();
      if(!data.ok) throw new Error(data.error||"Failed to load CRM state");
      const stages = (data.state && data.state.pipeline_stages) ? data.state.pipeline_stages : [];
      const ta = document.getElementById("ccPipelineStages");
      if(ta) ta.value = stages.join("\n");
      return stages;
    }

    function stageSelectHtml(current, stages){
      const opts = stages.map(s=>`<option value="${escapeHtml(s)}" ${s===current?"selected":""}>${escapeHtml(s)}</option>`).join("");
      return `<select class="inp" data-role="stageSelect">${opts}</select>`;
    }

    async function renderPipelineBoard(){
      const stages = await loadPipelineStages();
      const clientsRes = await fetch("/api/crm/clients");
      const clientsData = await clientsRes.json();
      if(!clientsData.ok) throw new Error(clientsData.error||"Failed to load clients");
      const clients = clientsData.clients || [];
      const board = document.getElementById("ccPipelineBoard");
      if(!board) return;
      board.innerHTML = "";

      for(const st of stages){
        const col = document.createElement("div");
        col.className = "card";
        col.style.minWidth = "260px";
        col.style.maxWidth = "260px";
        col.style.padding = "10px";
        col.innerHTML = `<div style="font-weight:800; margin-bottom:8px;">${escapeHtml(st)}</div>`;
        const list = document.createElement("div");
        list.style.display = "flex";
        list.style.flexDirection = "column";
        list.style.gap = "8px";

        const inStage = clients.filter(c => (c.pipeline_stage||"") === st);
        for(const c of inStage){
          const card = document.createElement("div");
          card.style.border = "1px solid rgba(255,255,255,.08)";
          card.style.borderRadius = "10px";
          card.style.padding = "8px";
          card.style.background = "rgba(0,0,0,.18)";
          card.innerHTML = `
            <div style="display:flex; justify-content:space-between; gap:8px; align-items:center;">
              <div style="font-weight:700; font-size:13px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(c.name||"(no name)")}</div>
            </div>
            <div style="font-size:12px; opacity:.85; margin-top:4px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(c.email||"")}</div>
            <div style="margin-top:6px;">${stageSelectHtml(c.pipeline_stage||st, stages)}</div>
          `;
          const sel = card.querySelector('select[data-role="stageSelect"]');
          if(sel){
            sel.onchange = async () => {
              try{
                const newStage = sel.value;
                const res = await fetch("/api/crm/clients/"+encodeURIComponent(c.id), {
                  method:"POST",
                  headers:{"Content-Type":"application/json"},
                  body: JSON.stringify({pipeline_stage:newStage})
                });
                const d = await res.json();
                if(!d.ok) throw new Error(d.error||"Update failed");
                showToast("Moved to " + newStage, "success");
                await renderPipelineBoard();
              }catch(e){
                showToast(String(e), "error");
              }
            };
          }
          list.appendChild(card);
        }

        col.appendChild(list);
        board.appendChild(col);
      }
    }


    const ccTabPipeline = document.getElementById("ccTabPipeline");
    if(ccTabPipeline){
      ccTabPipeline.onclick = async ()=>{ ccSelectTab("Pipeline"); await renderPipelineBoard(); };
    }
</script>






<!-- Guided Onboarding Panel (additive) -->
<div id="onboardingPanel" style="position:fixed; left:calc(50% + 290px); top:96px; right:auto; bottom:auto; z-index:9999; width:340px; max-width:calc(100vw - 24px); height:360px; max-height:calc(100vh - 24px); min-width:280px; min-height:230px; resize:both; overflow:hidden; display:none;">
  <div id="onbCard" style="background:rgba(20,24,34,0.96); border:1px solid rgba(255,255,255,0.10); border-radius:14px; box-shadow:0 12px 40px rgba(0,0,0,0.45); overflow:hidden; display:flex; flex-direction:column; height:100%;">
    <div id="onbHeader" style="padding:12px 12px 10px 12px; display:flex; align-items:center; justify-content:space-between; cursor:grab; user-select:none;">
      <div style="display:flex; gap:10px; align-items:center;">
        <div style="width:10px; height:10px; border-radius:999px; background:linear-gradient(135deg,#7c3aed,#22c55e); box-shadow:0 0 18px rgba(124,58,237,0.55);"></div>
        <div>
          <div style="font-weight:800; letter-spacing:0.2px; font-size:14px;">Get Started</div>
          <div id="onbSub" style="font-size:12px; opacity:0.8;">0 of 5 complete</div>
        </div>
      </div>
      <div style="display:flex; gap:8px; align-items:center;">
        <button id="onbExit" class="btn btnMini" style="padding:6px 10px;">Close</button>
      </div>
    </div>
    <div id="onbList" style="padding:10px 12px 12px 12px; display:flex; flex-direction:column; gap:8px; overflow-y:auto; overflow-x:hidden; flex:1 1 auto; min-height:0;"></div>
    <div id="onbResizeGrip" aria-label="Resize Next step window" title="Resize window"></div>
  </div>
</div>

<style>
  #onboardingPanel{ scrollbar-width:none; -ms-overflow-style:none; resize:none !important; }
  #onboardingPanel::-webkit-scrollbar{ width:0; height:0; }
  #onbResizeGrip{
    position:absolute;
    right:10px;
    bottom:10px;
    width:18px;
    height:18px;
    cursor:nwse-resize;
    z-index:5;
    border-radius:8px;
    background:linear-gradient(135deg, rgba(255,255,255,.06), rgba(255,255,255,.18));
    border:1px solid rgba(255,255,255,.14);
    touch-action:none;
  }
  #onbResizeGrip::before{
    content:"";
    position:absolute;
    right:3px;
    bottom:3px;
    width:10px;
    height:10px;
    border-right:2px solid rgba(255,255,255,.75);
    border-bottom:2px solid rgba(255,255,255,.75);
    opacity:.9;
  }
  #onbList{ scrollbar-width:none; -ms-overflow-style:none; }
  #onbList::-webkit-scrollbar{ width:0; height:0; }
  .onbItem{ display:flex; align-items:center; gap:10px; padding:10px 10px; border-radius:12px; border:1px solid rgba(255,255,255,0.10); background:rgba(255,255,255,0.03); cursor:pointer; }
  .onbItem:hover{ background:rgba(255,255,255,0.06); }
  .onbDot{ width:12px; height:12px; border-radius:999px; border:1px solid rgba(255,255,255,0.35); flex:0 0 auto; }
  .onbDone{ background:rgba(34,197,94,0.95); border-color:rgba(34,197,94,0.95); }
  .onbNextPulse{ box-shadow:0 0 0 0 rgba(124,58,237,0.55); animation:onbPulse 1.6s infinite; border-color:rgba(124,58,237,0.70) !important; }
  @keyframes onbPulse{ 0%{ box-shadow:0 0 0 0 rgba(124,58,237,0.55); } 70%{ box-shadow:0 0 0 12px rgba(124,58,237,0.00); } 100%{ box-shadow:0 0 0 0 rgba(124,58,237,0.00); } }
  .onbTitle{ font-size:13px; font-weight:700; }
  .onbMeta{ font-size:12px; opacity:0.75; }

  /* Topbar "Next step" glow (purple) */
  .onbBtnGlow{
    border-color: rgba(124,58,237,0.85) !important;
    box-shadow: 0 0 0 0 rgba(124,58,237,0.60), 0 0 28px rgba(124,58,237,0.18);
    animation: onbBtnPulse 1.6s infinite;
  }
  @keyframes onbBtnPulse{
    0%{ box-shadow: 0 0 0 0 rgba(124,58,237,0.60), 0 0 28px rgba(124,58,237,0.18); }
    70%{ box-shadow: 0 0 0 12px rgba(124,58,237,0.00), 0 0 28px rgba(124,58,237,0.10); }
    100%{ box-shadow: 0 0 0 0 rgba(124,58,237,0.00), 0 0 28px rgba(124,58,237,0.18); }
  }
</style>

<script>
(function(){
  let onbData = null;
  let drag = {active:false, dx:0, dy:0};
  let onbResize = {active:false, startX:0, startY:0, startW:0, startH:0};
  let suppressAutoOpen = false;
  const ONB_HIDDEN_KEY = "simply_agentic_onboarding_hidden";

  function onb$(id){ try{return document.getElementById(id);}catch(e){return null;} }
  function loadOnbHidden(){ try{ return sessionStorage.getItem(ONB_HIDDEN_KEY) === "1"; }catch(e){ return false; } }
  function saveOnbHidden(v){ try{ if(v) sessionStorage.setItem(ONB_HIDDEN_KEY, "1"); else sessionStorage.removeItem(ONB_HIDDEN_KEY); }catch(e){} }

  function syncOnboardingButtons(){
    try{
      const topBtn = document.getElementById("onboardingBtn");
      const mobBtn = document.getElementById("mobileOnboardingBtn");
      const showGlow = !!(onbData && onbData.ok && !onbData.all_done && (onbData.next_key || ""));
      if(topBtn){
        if(showGlow) topBtn.classList.add("onbBtnGlow");
        else topBtn.classList.remove("onbBtnGlow");
        // Keep label stable and short
        topBtn.textContent = "Next step";
      }
      if(mobBtn){
        mobBtn.textContent = "Next step";
      }
    }catch(e){}
  }

  async function openOnboarding(){
    suppressAutoOpen = false;
    saveOnbHidden(false);
    try{
      await fetch("/api/onboarding/dismiss", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({dismissed:false})
      });
    }catch(e){}
    try{
      await fetchOnboarding();
      const panel = onb$("onboardingPanel");
      if(panel){
        const hasPos = !!(panel.style.left || panel.style.top);
        if(!hasPos){
          try{
            const vw = window.innerWidth || document.documentElement.clientWidth || 1200;
            const vh = window.innerHeight || document.documentElement.clientHeight || 800;
            const width = Math.min(340, Math.max(280, panel.offsetWidth || 340));
            const x = Math.max(12, Math.min(vw - width - 12, Math.round(vw * 0.64)));
            const y = 96;
            setPanelPos(x, y);
          }catch(_){}
        }
        panel.style.display = "block";
        keepPanelInView();
      }
    }catch(e){}
  }

  function closeOnboarding(){
    suppressAutoOpen = true;
    saveOnbHidden(true);
    const panel = onb$("onboardingPanel");
    if(panel) panel.style.display = "none";
  }


  function wireOnboardingButtons(){
    try{
      const topBtn = document.getElementById("onboardingBtn");
      const mobBtn = document.getElementById("mobileOnboardingBtn");
      if(topBtn) topBtn.addEventListener("click", openOnboarding);
      if(mobBtn) mobBtn.addEventListener("click", ()=>{
        try{
          // Close mobile drawer if present
          const overlay = document.getElementById("mobileDrawerOverlay");
          if(overlay) overlay.classList.remove("show");
          try{ document.body.style.overflow = ""; }catch(_){}
        }catch(_){}
        openOnboarding();
      });
    }catch(e){}
  }

  function setPanelPos(x,y){
    const panel = onb$("onboardingPanel");
    if(!panel) return;
    panel.style.right = "auto";
    panel.style.bottom = "auto";
    panel.style.left = Math.max(8, x) + "px";
    panel.style.top = Math.max(8, y) + "px";
  }

  async function fetchOnboarding(){
    try{
      const res = await fetch("/api/onboarding/status");
      const data = await res.json();
      if(!data || !data.ok) return;
      onbData = data;
      renderOnboarding();
      syncOnboardingButtons();
      try{ window.onboardingStatus = onbData; }catch(_){ }
    }catch(e){}
  }

  function renderOnboarding(){
    const panel = onb$("onboardingPanel");
    const list = onb$("onbList");
    const sub = onb$("onbSub");
    if(!panel || !list || !sub || !onbData) return;

    if(onbData.dismissed || onbData.all_done || suppressAutoOpen || loadOnbHidden()){
      panel.style.display = "none";
      return;
    }

    panel.style.display = "block";
    sub.textContent = `${onbData.done_count} of ${onbData.total} complete`;

    list.innerHTML = "";
    const nextKey = onbData.next_key || "";

    (onbData.steps||[]).forEach((s)=>{
      const row = document.createElement("div");
      row.className = "onbItem";
      row.setAttribute("data-key", s.key);

      const dot = document.createElement("div");
      dot.className = "onbDot" + (s.done ? " onbDone" : "");
      if(!s.done && s.key === nextKey){
        row.className += " onbNextPulse";
      }

      const wrap = document.createElement("div");
      wrap.style.display = "flex";
      wrap.style.flexDirection = "column";
      wrap.style.gap = "2px";

      const title = document.createElement("div");
      title.className = "onbTitle";
      title.textContent = s.title;

      const meta = document.createElement("div");
      meta.className = "onbMeta";
      meta.textContent = s.done ? "Done" : (s.key === nextKey ? "Next best action" : "Not done");

      wrap.appendChild(title);
      wrap.appendChild(meta);

      row.appendChild(dot);
      row.appendChild(wrap);

      row.addEventListener("click", ()=>onbAction(s.key, s.done));
      list.appendChild(row);
    });
  }

  async function dismissOnboarding(){
    saveOnbHidden(true);
    try{ await fetch("/api/onboarding/dismiss", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({dismissed:true})}); }catch(e){}
    const panel = onb$("onboardingPanel");
    if(panel) panel.style.display = "none";
  }

  function focusEl(id){
    try{
      const el = document.getElementById(id);
      if(el){
        el.scrollIntoView({behavior:"smooth", block:"center"});
        setTimeout(()=>{ try{ el.focus(); }catch(e){} }, 80);
        return true;
      }
    }catch(e){}
    return false;
  }

  async function onbAction(key, alreadyDone){
    if(alreadyDone) return;

    try{
      if(key === "preferred_ai"){
        if(typeof showSettingsModal === "function"){ showSettingsModal(true); }
        setTimeout(()=>{
          focusEl("aiProvider") || focusEl("providerSelect") || focusEl("openaiKey") || focusEl("apiKey");
        }, 150);
        return;
      }

      if(key === "full_team"){
        try{
          const btn = document.getElementById("installFullBtn");
          if(btn){
            btn.click();
          }else{
            const r = await fetch("/api/install/full", {method:"POST"});
            const d = await r.json();
            if(d && d.ok){ if(typeof showToast === "function") showToast("Installed full team"); }
            else{ if(typeof showToast === "function") showToast("Install failed"); }
          }
        }catch(e){
          if(typeof showToast === "function") showToast("Install failed");
        }
        setTimeout(fetchOnboarding, 500);
        return;
      }

      if(key === "email_connected"){
        // Direct to Gmail OAuth — no extra click needed
        window.location = '/gmail/connect';
        return;
      }

      if(key === "calendar_connected"){
        // Direct to Calendar OAuth — no extra click needed
        window.location = '/calendar/connect';
        return;
      }

      if(key === "first_prompt"){
        // Close the onboarding panel and any open modal first, then focus the prompt box
        try{ if(typeof closeOnboarding === "function") closeOnboarding(); }catch(e){}
        try{ if(typeof closeModal === "function") closeModal(); }catch(e){}
        try{ if(typeof window.onboardingClose === "function") window.onboardingClose(); }catch(e){}
        setTimeout(() => {
          focusEl("followMsg");
          try{ if(typeof showToast === "function") showToast("Type your first message and hit Send ↵"); }catch(e){}
        }, 80);
        return;
      }
    }finally{
      setTimeout(fetchOnboarding, 700);
    }
  }

  function clampOnb(v, min, max){ return Math.max(min, Math.min(max, v)); }

  function clampPanelSize(){
    const panel = onb$("onboardingPanel");
    if(!panel) return;
    const vw = window.innerWidth || document.documentElement.clientWidth || 1200;
    const vh = window.innerHeight || document.documentElement.clientHeight || 800;
    const curW = panel.offsetWidth || 340;
    const curH = panel.offsetHeight || 360;
    panel.style.width = clampOnb(curW, 280, Math.max(280, vw - 16)) + "px";
    panel.style.height = clampOnb(curH, 230, Math.max(230, vh - 16)) + "px";
  }

  function keepPanelInView(){
    const panel = onb$("onboardingPanel");
    if(!panel) return;
    clampPanelSize();
    const vw = window.innerWidth || document.documentElement.clientWidth || 1200;
    const vh = window.innerHeight || document.documentElement.clientHeight || 800;
    const width = panel.offsetWidth || 340;
    const height = panel.offsetHeight || 360;
    const left = parseFloat(panel.style.left || "0") || panel.getBoundingClientRect().left || 8;
    const top = parseFloat(panel.style.top || "0") || panel.getBoundingClientRect().top || 8;
    setPanelPos(clampOnb(left, 8, Math.max(8, vw - width - 8)), clampOnb(top, 8, Math.max(8, vh - height - 8)));
  }

  function wireDrag(){
    const header = onb$("onbHeader");
    const panel = onb$("onboardingPanel");
    if(!header || !panel) return;

    header.addEventListener("pointerdown", (e)=>{
      try{
        if(e && e.target && (e.target.closest && e.target.closest("button"))) return;
      }catch(_){ }
      drag.active = true;
      header.style.cursor = "grabbing";
      const rect = panel.getBoundingClientRect();
      drag.dx = e.clientX - rect.left;
      drag.dy = e.clientY - rect.top;
      try{ header.setPointerCapture(e.pointerId); }catch(err){}
    });

    header.addEventListener("pointermove", (e)=>{
      if(!drag.active) return;
      setPanelPos(e.clientX - drag.dx, e.clientY - drag.dy);
      keepPanelInView();
    });

    const endDrag = (e)=>{
      drag.active = false;
      header.style.cursor = "grab";
      keepPanelInView();
      try{ header.releasePointerCapture(e.pointerId); }catch(err){}
    };

    header.addEventListener("pointerup", endDrag);
    header.addEventListener("pointercancel", endDrag);

    window.addEventListener("resize", keepPanelInView, {passive:true});
  }

  function wireOnboardingResize(){
    const panel = onb$("onboardingPanel");
    const grip = onb$("onbResizeGrip");
    if(!panel || !grip) return;

    grip.addEventListener("pointerdown", (e)=>{
      try{ e.preventDefault(); e.stopPropagation(); }catch(_){}
      onbResize.active = true;
      onbResize.startX = e.clientX;
      onbResize.startY = e.clientY;
      onbResize.startW = panel.offsetWidth || 340;
      onbResize.startH = panel.offsetHeight || 360;
      try{ grip.setPointerCapture(e.pointerId); }catch(err){}
    });

    grip.addEventListener("pointermove", (e)=>{
      if(!onbResize.active) return;
      const rect = panel.getBoundingClientRect();
      const vw = window.innerWidth || document.documentElement.clientWidth || 1200;
      const vh = window.innerHeight || document.documentElement.clientHeight || 800;
      const maxW = Math.max(280, vw - rect.left - 8);
      const maxH = Math.max(230, vh - rect.top - 8);
      const nextW = clampOnb(onbResize.startW + (e.clientX - onbResize.startX), 280, maxW);
      const nextH = clampOnb(onbResize.startH + (e.clientY - onbResize.startY), 230, maxH);
      panel.style.width = nextW + "px";
      panel.style.height = nextH + "px";
      keepPanelInView();
    });

    const endResize = (e)=>{
      onbResize.active = false;
      keepPanelInView();
      try{ grip.releasePointerCapture(e.pointerId); }catch(err){}
    };

    grip.addEventListener("pointerup", endResize);
    grip.addEventListener("pointercancel", endResize);
  }


  function wireExit(){
    const btn = onb$("onbExit");
    if(btn) btn.addEventListener("click", (e)=>{ try{ e.stopPropagation(); }catch(_){ } closeOnboarding(); });
  }

  try{
    try{ window.onboardingRefresh = fetchOnboarding; window.onboardingClose = closeOnboarding; window.onboardingOpen = openOnboarding; }catch(_){ }

    wireDrag();
    wireOnboardingResize();
    wireExit();
    wireOnboardingButtons();
    setTimeout(fetchOnboarding, 450);
    setInterval(fetchOnboarding, 12000);
  }catch(e){}
})();
</script>


<style>
/* ===== FINAL MOBILE LOCK FIT v3 ===== */
@media (max-width: 700px){
  html, body{
    width:100vw !important;
    max-width:100vw !important;
    margin:0 !important;
    padding:0 !important;
    overflow-x:hidden !important;
    position:relative !important;
  }

  body{
    left:0 !important;
    right:0 !important;
  }

  .container{
    width:100% !important;
    max-width:100% !important;
    margin:0 !important;
    padding-left:12px !important;
    padding-right:12px !important;
    box-sizing:border-box !important;
    overflow-x:hidden !important;
  }

  .stage{
    display:flex !important;
    flex-direction:column !important;
    grid-template-columns:none !important;
    width:100% !important;
    max-width:100% !important;
    min-width:0 !important;
    margin:0 !important;
    padding:0 !important;
    overflow-x:hidden !important;
  }

  .stage > div,
  .arena,
  .underTable,
  .side,
  .sideCard,
  .groupCard{
    width:100% !important;
    max-width:100% !important;
    min-width:0 !important;
    margin-left:0 !important;
    margin-right:0 !important;
    box-sizing:border-box !important;
  }

  .arena{
    justify-content:center !important;
    padding:8px 0 12px 0 !important;
    overflow:hidden !important;
  }

  .underTable{
    width:100% !important;
    max-width:100% !important;
    margin:0 0 14px 0 !important;
    padding:0 !important;
  }

  .side{
    position:relative !important;
    top:auto !important;
    left:auto !important;
    right:auto !important;
    height:auto !important;
    border-left:none !important;
    padding:0 !important;
    overflow:hidden !important;
  }

  .sideHead{
    display:flex !important;
    flex-wrap:wrap !important;
    align-items:flex-start !important;
    justify-content:space-between !important;
    gap:8px !important;
  }

  .sideTitle{
    flex:1 1 160px !important;
    min-width:0 !important;
    max-width:calc(100% - 110px) !important;
  }

  #refreshThread{
    flex:0 0 auto !important;
    margin-left:auto !important;
    align-self:flex-start !important;
  }

  .passRow,
  .pillRow{
    width:100% !important;
    max-width:100% !important;
    min-width:0 !important;
  }

  .passRow .btn,
  .pillRow .btn,
  .sideHead .btn{
    max-width:100% !important;
  }

  .groupReplies,
  #thread,
  #groupConsole{
    width:100% !important;
    max-width:100% !important;
    min-width:0 !important;
    box-sizing:border-box !important;
  }

  #tableViewport{
    width:100% !important;
    max-width:100% !important;
    padding-left:0 !important;
    padding-right:0 !important;
    overflow:hidden !important;
    display:flex !important;
    justify-content:center !important;
  }

  .tableWrap#tableWrap{
    width:min(92vw, 560px) !important;
    height:min(92vw, 560px) !important;
    min-height:min(92vw, 560px) !important;
    margin:0 auto !important;
    overflow:hidden !important;
  }

  .table{
    position:relative !important;
    left:auto !important;
    top:auto !important;
    inset:auto !important;
    margin:0 auto !important;
    transform:translateX(0) scale(0.68) !important;
    transform-origin:center top !important;
    zoom:normal !important;
  }
}
</style>


<style>
/* ===== MOBILE ROUND TABLE RESTORE v4 ===== */
@media (max-width: 700px){
  .arena{
    overflow: visible !important;
    padding: 8px 0 18px 0 !important;
  }

  #tableViewport{
    width: 100% !important;
    max-width: 100% !important;
    display: block !important;
    overflow: visible !important;
    padding-left: 0 !important;
    padding-right: 0 !important;
  }

  .tableWrap#tableWrap{
    width: min(94vw, 620px) !important;
    height: min(94vw, 620px) !important;
    min-height: min(94vw, 620px) !important;
    margin: 0 auto 8px auto !important;
    position: relative !important;
    overflow: visible !important;
  }

  #rtStage{
    position: absolute !important;
    inset: 0 !important;
    transform: none !important;
    transform-origin: 0 0 !important;
    will-change: auto !important;
  }

  #rtStage .table,
  .table{
    position: absolute !important;
    inset: auto !important;
    left: 50% !important;
    top: 50% !important;
    margin: 0 !important;
    transform: translate(-50%, -50%) scale(0.72) !important;
    transform-origin: center center !important;
    zoom: normal !important;
  }

  .underTable,
  .side{
    overflow: visible !important;
  }
}
</style>

<!-- ═══════════════════════════════════════════════════════════════════════
     SESSION 3 HTML — DASHBOARD · SHARE · RAG
     ═══════════════════════════════════════════════════════════════════════ -->

<!-- Dashboard Modal -->
<div id="dashboardModal" style="display:none;position:fixed;inset:0;z-index:99990;background:rgba(0,0,0,.78);backdrop-filter:blur(5px);align-items:center;justify-content:center;" onclick="if(event.target===this)saCloseDashboard()">
  <div style="background:rgba(10,14,30,.98);border:1px solid rgba(42,58,106,.9);border-radius:18px;width:min(860px,96vw);max-height:90vh;display:flex;flex-direction:column;overflow:hidden;box-shadow:0 24px 80px rgba(0,0,0,.7);">
    <div style="display:flex;align-items:center;justify-content:space-between;padding:14px 20px;border-bottom:1px solid rgba(42,58,106,.6);flex-shrink:0;">
      <span style="font-weight:700;font-size:15px;color:#c4b5fd;">📊 Operator Dashboard</span>
      <button onclick="saCloseDashboard()" style="background:rgba(180,30,60,.3);border:1px solid rgba(239,68,68,.4);color:#fca5a5;border-radius:7px;padding:4px 12px;font-size:12px;cursor:pointer;">✕ Close</button>
    </div>
    <div id="dashboardBody" style="flex:1;overflow-y:auto;padding:20px;"></div>
  </div>
</div>

<!-- Share Link Modal -->
<div id="shareModal" style="display:none;position:fixed;inset:0;z-index:99991;background:rgba(0,0,0,.78);backdrop-filter:blur(5px);align-items:center;justify-content:center;" onclick="if(event.target===this)saCloseShare()">
  <div style="background:rgba(10,14,30,.98);border:1px solid rgba(42,58,106,.9);border-radius:18px;width:min(540px,94vw);display:flex;flex-direction:column;overflow:hidden;box-shadow:0 24px 80px rgba(0,0,0,.7);">
    <div style="display:flex;align-items:center;justify-content:space-between;padding:14px 20px;border-bottom:1px solid rgba(42,58,106,.6);">
      <span style="font-weight:700;font-size:15px;color:#c4b5fd;">🔗 Share Conversation</span>
      <button onclick="saCloseShare()" style="background:rgba(180,30,60,.3);border:1px solid rgba(239,68,68,.4);color:#fca5a5;border-radius:7px;padding:4px 12px;font-size:12px;cursor:pointer;">✕ Close</button>
    </div>
    <div style="padding:20px;">
      <div class="tiny" style="margin-bottom:12px;opacity:.7;line-height:1.6;">Creates a read-only public link to this conversation. Anyone with the link can view it.</div>
      <div id="shareUrlArea" style="display:none;margin-bottom:14px;">
        <code id="shareUrlText" style="display:block;background:rgba(0,0,0,.3);border:1px solid rgba(42,58,106,.6);border-radius:8px;padding:10px 12px;font-size:12px;word-break:break-all;color:#a5b4fc;margin-bottom:8px;"></code>
        <button onclick="navigator.clipboard.writeText(document.getElementById('shareUrlText').innerText).then(()=>showToast('Copied'))" class="btn btnMini" style="width:100%;">📋 Copy Link</button>
      </div>
      <button id="createShareBtn" onclick="saCreateShare()" class="btn btnPrimary" style="width:100%;">Generate Share Link</button>
      <div id="shareStatus" class="tiny" style="margin-top:8px;opacity:.7;"></div>
    </div>
  </div>
</div>

<!-- RAG Index Modal -->
<div id="ragModal" style="display:none;position:fixed;inset:0;z-index:99991;background:rgba(0,0,0,.78);backdrop-filter:blur(5px);align-items:center;justify-content:center;" onclick="if(event.target===this)saCloseRag()">
  <div style="background:rgba(10,14,30,.98);border:1px solid rgba(42,58,106,.9);border-radius:18px;width:min(540px,94vw);display:flex;flex-direction:column;overflow:hidden;box-shadow:0 24px 80px rgba(0,0,0,.7);">
    <div style="display:flex;align-items:center;justify-content:space-between;padding:14px 20px;border-bottom:1px solid rgba(42,58,106,.6);">
      <span style="font-weight:700;font-size:15px;color:#c4b5fd;">🔬 Knowledge Base (RAG)</span>
      <button onclick="saCloseRag()" style="background:rgba(180,30,60,.3);border:1px solid rgba(239,68,68,.4);color:#fca5a5;border-radius:7px;padding:4px 12px;font-size:12px;cursor:pointer;">✕ Close</button>
    </div>
    <div style="padding:20px;">
      <div class="tiny" style="margin-bottom:14px;opacity:.7;line-height:1.6;">Upload a document and index it. Teammates will automatically search it when answering questions. Great for SOPs, contracts, product docs, and research.</div>
      <input type="file" id="ragFileInput" accept=".txt,.md,.csv,.json,.pdf" style="display:none" />
      <button onclick="document.getElementById('ragFileInput').click()" class="btn" style="width:100%;margin-bottom:10px;">📂 Choose Document</button>
      <div id="ragSelectedFile" class="tiny" style="opacity:.6;margin-bottom:10px;"></div>
      <button id="ragIndexBtn" onclick="saIndexRagFile()" class="btn btnPrimary" style="width:100%;margin-bottom:10px;">⚡ Index Document</button>
      <div id="ragStatus" class="tiny" style="opacity:.7;"></div>
      <div style="margin-top:14px;border-top:1px solid rgba(42,58,106,.4);padding-top:14px;">
        <div style="font-size:11px;opacity:.5;letter-spacing:.05em;margin-bottom:8px;">INDEXED DOCUMENTS</div>
        <div id="ragDocList" class="tiny" style="opacity:.7;">Loading…</div>
      </div>
    </div>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════════════════
     SESSION 2 HTML — WEBHOOKS MANAGER MODAL
     ═══════════════════════════════════════════════════════════════════════ -->
</div>

<style>
/* Tool call badge */
.sa-tool-badge {
  display:inline-flex; align-items:center; gap:4px;
  font-size:10px; padding:2px 7px; border-radius:5px;
  background:rgba(16,185,129,.12); color:#6ee7b7;
  border:1px solid rgba(16,185,129,.3); margin-top:5px; margin-right:4px;
  font-family:monospace;
}
/* Shared memory pill items */
.sa-mem-item {
  padding:4px 8px; margin:3px 0; font-size:12px;
  background:rgba(99,102,241,.1); border-left:2px solid rgba(99,102,241,.5);
  border-radius:0 6px 6px 0; color:rgba(196,181,253,.9); line-height:1.5;
}

</style>

}
</style>

<style>
/* RAG pill */
.sa-rag-pill {
  font-size:10px; padding:2px 7px; border-radius:5px;
  background:rgba(16,185,129,.12); color:#6ee7b7;
  border:1px solid rgba(16,185,129,.3); cursor:pointer; display:inline-flex; align-items:center;
}
/* Dashboard stat cards */
.sa-stat-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:10px; margin-bottom:18px; }
.sa-stat-card { background:rgba(30,42,74,.7); border:1px solid rgba(42,58,106,.6); border-radius:10px; padding:12px 14px; text-align:center; }
.sa-stat-num  { font-size:26px; font-weight:700; color:#c4b5fd; }
.sa-stat-lbl  { font-size:11px; color:rgba(182,196,255,.6); margin-top:3px; }
.sa-dash-section { margin-bottom:18px; }
.sa-dash-section h3 { font-size:12px; opacity:.5; letter-spacing:.06em; margin-bottom:8px; }
.sa-dash-row { display:flex; align-items:center; justify-content:space-between; padding:7px 10px; border-radius:8px; background:rgba(11,16,36,.7); border:1px solid rgba(42,58,106,.4); margin-bottom:5px; font-size:12px; }
</style>

<script>
/* ─────────────────────────────────────────────────────────────────────────────
   SESSION 3 — DASHBOARD · BRANCHING · EXPORT/SHARE · RAG
   ───────────────────────────────────────────────────────────────────────────── */
(function(){
  function _e(s){ const d=document.createElement("div"); d.innerText=String(s||""); return d.innerHTML; }
  function now_short(){ return new Date().toISOString().slice(0,16).replace("T"," "); }

  /* ── 1. DASHBOARD ─────────────────────────────────────────────────────────── */
  window.saOpenDashboard = async function saOpenDashboard(){
    const modal = document.getElementById("dashboardModal");
    if(!modal) return;
    modal.style.display = "flex";
    document.body.style.overflow = "hidden";
    const body = document.getElementById("dashboardBody");
    if(body) body.innerHTML = '<div class="tiny" style="opacity:.5;padding:20px;">Loading dashboard…</div>';
    try{
      const r = await fetch("/api/dashboard"); const d = await r.json();
      if(!d.ok || !body) return;
      const s   = d.stats   || {};
      const act = s.activity || {}; const crm  = s.crm  || {};
      const rag   = s.rag  || {};
      const smem= s.shared_memory || {};
      body.innerHTML = `
        <div class="sa-stat-grid">
          <div class="sa-stat-card"><div class="sa-stat-num">${act.total_actions||0}</div><div class="sa-stat-lbl">AI Actions</div></div>
          <div class="sa-stat-card"><div class="sa-stat-num">${crm.total_clients||0}</div><div class="sa-stat-lbl">CRM Contacts</div></div>
          <div class="sa-stat-card"><div class="sa-stat-num">${rag.total_docs||0}</div><div class="sa-stat-lbl">Knowledge Docs</div></div>
          <div class="sa-stat-card"><div class="sa-stat-num">${rag.total_chunks||0}</div><div class="sa-stat-lbl">Knowledge Chunks</div></div>
        </div>
        <div class="sa-dash-section">
          <h3>TOP TEAMMATES BY ACTIVITY</h3>
          ${(act.top_teammates||[]).map(t=>`<div class="sa-dash-row"><span>${_e(t.name)}</span><span style="color:#c4b5fd;font-weight:600;">${t.count} actions</span></div>`).join("")||'<div class="tiny" style="opacity:.4;">No activity yet.</div>'}
        </div>
        <div class="sa-dash-section">
          <h3>CRM PIPELINE</h3>
          ${Object.entries(crm.stages||{}).map(([st,cnt])=>`<div class="sa-dash-row"><span>${_e(st)}</span><span style="color:#a5b4fc;">${cnt}</span></div>`).join("")||'<div class="tiny" style="opacity:.4;">No CRM data.</div>'}
        </div>

        <div class="sa-dash-section">
          <h3>SHARED TEAM MEMORY</h3>
          <div class="sa-dash-row"><span>Facts</span><span style="color:#a5b4fc;">${smem.facts||0}</span></div>
          <div class="sa-dash-row"><span>Decisions</span><span style="color:#a5b4fc;">${smem.decisions||0}</span></div>
          <div class="sa-dash-row"><span>Open loops</span><span style="color:#a5b4fc;">${smem.open_loops||0}</span></div>
        </div>
        <div class="sa-dash-section">
          <h3>KNOWLEDGE BASE (RAG)</h3>
          <div class="sa-dash-row"><span>Documents indexed</span><span style="color:#a5b4fc;">${rag.total_docs||0}</span></div>
          <div class="sa-dash-row"><span>Text chunks stored</span><span style="color:#a5b4fc;">${rag.total_chunks||0}</span></div>
          <div style="margin-top:8px;"><button onclick="saOpenRag()" class="btn btnMini" style="width:100%;">🔬 Manage Knowledge Base</button></div>
        </div>
        <div class="sa-dash-section">
          <h3>RECENT ERRORS</h3>
          ${(act.recent||[]).filter(e=>e.status==="error").slice(0,4).map(e=>`<div class="sa-dash-row" style="border-color:rgba(239,68,68,.3);"><span style="color:#fca5a5;">${_e(e.action)}</span><span class="tiny">${(e.ts||"").slice(0,16)}</span></div>`).join("")||'<div class="tiny" style="opacity:.4;">No errors — all clear.</div>'}
        </div>
        <div class="tiny" style="opacity:.3;text-align:right;margin-top:10px;">Generated ${(d.generated_at||"").slice(0,16).replace("T"," ")} UTC</div>`;
    }catch(err){
      const b2=document.getElementById("dashboardBody");
      if(b2) b2.innerHTML=`<div class="tiny" style="color:#fca5a5;padding:20px;">Load failed: ${_e((err||{}).message||err)}</div>`;
    }
  };
  window.saCloseDashboard = function(){ const m=document.getElementById("dashboardModal"); if(m)m.style.display="none"; document.body.style.overflow=""; };

  /* ── 2. THREAD ACTIONS TOOLBAR ────────────────────────────────────────────── */
  (function patchMarkActiveSeat(){
    const orig = window.markActiveSeat;
    if(typeof orig!=="function"){ setTimeout(patchMarkActiveSeat,300); return; }
    window.markActiveSeat = function(name){
      orig.apply(this, arguments);
      try{
        const tb = document.getElementById("threadActionsRow");
        if(tb) tb.style.display = name ? "flex" : "none";
        if(name) saLoadBranches(name);
      }catch(_){}
    };
  })();

  /* ── 3. BRANCHING ─────────────────────────────────────────────────────────── */
  window.saLoadBranches = async function saLoadBranches(name){
    const sel = document.getElementById("branchSelector");
    if(!sel || !name) return;
    try{
      const r = await fetch("/api/thread/"+encodeURIComponent(name)+"/branches");
      const d = await r.json();
      sel.innerHTML = '<option value="">Snapshots…</option>' +
        (d.branches||[]).map(b=>`<option value="${_e(b.id)}">${_e(b.label)} (${b.msg_count})</option>`).join("");
    }catch(_){}
  };

  document.addEventListener("DOMContentLoaded", function(){

    /* Snapshot button */
    const snapBtn = document.getElementById("branchSnapshotBtn");
    if(snapBtn) snapBtn.addEventListener("click", async function(){
      const seat = window.selectedSeat;
      if(!seat){ if(typeof showToast==="function") showToast("Select a teammate first","error"); return; }
      const label = prompt("Name this snapshot (optional):", now_short()) || "";
      try{
        const r = await fetch("/api/thread/"+encodeURIComponent(seat)+"/snapshot",{
          method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({label})
        });
        const d = await r.json();
        if(!d.ok){ if(typeof showToast==="function") showToast(d.error||"Snapshot failed","error"); return; }
        if(typeof showToast==="function") showToast("Snapshot saved: "+d.label);
        saLoadBranches(seat);
      }catch(e){ if(typeof showToast==="function") showToast("Error: "+((e||{}).message||e),"error"); }
    });

    /* Branch restore selector */
    const branchSel = document.getElementById("branchSelector");
    if(branchSel) branchSel.addEventListener("change", async function(){
      const bid = this.value; if(!bid) return;
      const seat = window.selectedSeat; if(!seat) return;
      if(!confirm("Restore this snapshot? Current conversation will be replaced.")){ this.value=""; return; }
      try{
        const r = await fetch("/api/thread/"+encodeURIComponent(seat)+"/restore/"+encodeURIComponent(bid),{method:"POST"});
        const d = await r.json();
        if(!d.ok){ if(typeof showToast==="function") showToast(d.error||"Restore failed","error"); return; }
        if(typeof showToast==="function") showToast("Restored: "+d.label+" ("+d.msg_count+" msgs)");
        if(typeof refreshThread==="function") await refreshThread();
        this.value="";
      }catch(e){ if(typeof showToast==="function") showToast("Error: "+((e||{}).message||e),"error"); this.value=""; }
    });

    /* Export button */
    const exportBtn = document.getElementById("exportThreadBtn");
    if(exportBtn) exportBtn.addEventListener("click", function(){
      const seat = window.selectedSeat;
      if(!seat){ if(typeof showToast==="function") showToast("Select a teammate first","error"); return; }
      window.open("/api/export/thread/"+encodeURIComponent(seat),"_blank");
    });

    /* Share button */
    const shareBtn = document.getElementById("shareThreadBtn");
    if(shareBtn) shareBtn.addEventListener("click", function(){
      const seat = window.selectedSeat;
      if(!seat){ if(typeof showToast==="function") showToast("Select a teammate first","error"); return; }
      saOpenShareModal();
    });

    /* RAG pill click */
    const ragPill = document.getElementById("ragIndexStatus");
    if(ragPill) ragPill.addEventListener("click", saOpenRag);

    /* RAG file picker */
    const ragInput = document.getElementById("ragFileInput");
    if(ragInput) ragInput.addEventListener("change", function(){
      const lbl = document.getElementById("ragSelectedFile");
      if(lbl) lbl.innerText = this.files[0] ? this.files[0].name : "";
    });

    /* Check if user has RAG docs → show pill */
    fetch("/api/rag/docs").then(r=>r.json()).then(d=>{
      const pill = document.getElementById("ragIndexStatus");
      if(pill) pill.style.display = (d.docs && d.docs.length) ? "inline-flex" : "none";
    }).catch(()=>{});
  });

  /* ── 4. EXPORT/SHARE ──────────────────────────────────────────────────────── */
  window.saOpenShareModal = function(){
    const m=document.getElementById("shareModal"); if(!m) return;
    m.style.display="flex"; document.body.style.overflow="hidden";
    const ua=document.getElementById("shareUrlArea"), st=document.getElementById("shareStatus");
    if(ua) ua.style.display="none"; if(st) st.innerText="";
  };
  window.saCloseShare = function(){ const m=document.getElementById("shareModal"); if(m)m.style.display="none"; document.body.style.overflow=""; };

  window.saCreateShare = async function saCreateShare(){
    const seat=window.selectedSeat;
    if(!seat){ if(typeof showToast==="function") showToast("Select a teammate first","error"); return; }
    const st=document.getElementById("shareStatus");
    if(st) st.innerText="Creating link…";
    try{
      const r=await fetch("/api/share",{method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({teammate:seat,title:"Conversation with "+seat})});
      const d=await r.json();
      if(!d.ok){ if(st) st.innerText=d.error||"Failed"; return; }
      const ut=document.getElementById("shareUrlText"), ua=document.getElementById("shareUrlArea");
      if(ut) ut.innerText=d.url; if(ua) ua.style.display="block";
      if(st) st.innerText="Link ready — anyone with it can view this conversation.";
    }catch(e){ if(st) st.innerText="Error: "+((e||{}).message||e); }
  };

  /* ── 5. RAG MANAGER ───────────────────────────────────────────────────────── */
  window.saOpenRag = async function(){ const m=document.getElementById("ragModal"); if(!m) return; m.style.display="flex"; document.body.style.overflow="hidden"; await saLoadRagDocs(); };
  window.saCloseRag = function(){ const m=document.getElementById("ragModal"); if(m)m.style.display="none"; document.body.style.overflow=""; };

  window.saIndexRagFile = async function saIndexRagFile(){
    const fi=document.getElementById("ragFileInput"), st=document.getElementById("ragStatus");
    const file=fi&&fi.files[0];
    if(!file){ if(st) st.innerText="Choose a file first."; return; }
    if(st) st.innerText="Uploading…";
    try{
      const fd=new FormData(); fd.append("file",file);
      const up=await fetch("/api/upload",{method:"POST",body:fd});
      const upd=await up.json();
      if(!upd.ok){ if(st) st.innerText=upd.error||"Upload failed"; return; }
      if(st) st.innerText="Indexing (10–30 seconds)…";
      const ix=await fetch("/api/rag/index",{method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({file_id:upd.file.id,label:file.name})});
      const ixd=await ix.json();
      if(!ixd.ok){ if(st) st.innerText=ixd.error||"Indexing failed"; return; }
      if(st) st.innerText=`Indexed ${ixd.chunks} chunks. Teammates will search this automatically.`;
      const pill=document.getElementById("ragIndexStatus"); if(pill) pill.style.display="inline-flex";
      if(fi) fi.value="";
      const lbl=document.getElementById("ragSelectedFile"); if(lbl) lbl.innerText="";
      await saLoadRagDocs();
    }catch(e){ if(st) st.innerText="Error: "+((e||{}).message||e); }
  };

  window.saLoadRagDocs = async function saLoadRagDocs(){
    const list=document.getElementById("ragDocList"); if(!list) return;
    try{
      const r=await fetch("/api/rag/docs"); const d=await r.json();
      const docs=d.docs||[];
      if(!docs.length){ list.innerHTML='<span style="opacity:.4;">No documents indexed yet.</span>'; return; }
      list.innerHTML=docs.map(doc=>`
        <div style="display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:1px solid rgba(42,58,106,.3);">
          <span>${_e(doc.label||doc.filename)} <span style="opacity:.4;">(${doc.chunks||0} chunks)</span></span>
          <button onclick="saDeleteRagDoc('${_e(doc.doc_id)}')" style="background:rgba(180,30,60,.3);border:1px solid rgba(239,68,68,.4);color:#fca5a5;border-radius:5px;padding:2px 7px;font-size:10px;cursor:pointer;">Remove</button>
        </div>`).join("");
    }catch(e){ list.innerHTML='<span style="color:#fca5a5;">Load failed</span>'; }
  };

  window.saDeleteRagDoc = async function saDeleteRagDoc(doc_id){
    if(!confirm("Remove this document from the knowledge base?")) return;
    try{
      const r=await fetch("/api/rag/delete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({doc_id})});
      const d=await r.json();
      if(typeof showToast==="function") showToast(d.ok?"Removed":d.error||"Error");
      await saLoadRagDocs();
      const docsR=await fetch("/api/rag/docs").then(x=>x.json());
      const pill=document.getElementById("ragIndexStatus");
      if(pill) pill.style.display=(docsR.docs&&docsR.docs.length)?"inline-flex":"none";
    }catch(e){ if(typeof showToast==="function") showToast("Error: "+((e||{}).message||e),"error"); }
  };

})();
</script>

<script>
/* ─────────────────────────────────────────────────────────────────────────────
   SESSION 2 — SHARED MEMORY · TOOL CALLS · WEBHOOKS
   ───────────────────────────────────────────────────────────────────────────── */
(function(){

  /* ── 1. SHARED TEAM MEMORY PANEL ──────────────────────────────────────────── */
  function renderSharedMemory(smem){
    const card = document.getElementById("sharedMemoryCard");
    const body = document.getElementById("sharedMemoryBody");
    if(!card || !body) return;
    const facts      = smem.facts      || [];
    const decisions  = smem.decisions  || [];
    const open_loops = smem.open_loops || [];
    if(!facts.length && !decisions.length && !open_loops.length){
      card.style.display = "none";
      return;
    }
    card.style.display = "block";
    let html = "";
    if(facts.length){
      html += `<div style="font-size:10px;opacity:.5;letter-spacing:.05em;margin-bottom:4px;">FACTS</div>`;
      facts.forEach(f => { html += `<div class="sa-mem-item">📌 ${_saEsc(f)}</div>`; });
    }
    if(decisions.length){
      html += `<div style="font-size:10px;opacity:.5;letter-spacing:.05em;margin:8px 0 4px;">DECISIONS</div>`;
      decisions.forEach(d => { html += `<div class="sa-mem-item">✅ ${_saEsc(d)}</div>`; });
    }
    if(open_loops.length){
      html += `<div style="font-size:10px;opacity:.5;letter-spacing:.05em;margin:8px 0 4px;">OPEN LOOPS</div>`;
      open_loops.forEach(o => { html += `<div class="sa-mem-item">🔄 ${_saEsc(o)}</div>`; });
    }
    const ts = smem.updated_at ? (" · " + smem.updated_at.slice(0,16).replace("T"," ")) : "";
    html += `<div style="font-size:10px;opacity:.4;margin-top:8px;">Extracted automatically after group sessions${ts}</div>`;
    body.innerHTML = html;
  }

  async function loadSharedMemory(){
    try{
      const r = await fetch("/api/os/shared_memory");
      const d = await r.json();
      if(d.ok) renderSharedMemory(d.shared_memory || {});
    }catch(_){}
  }

  // Clear button
  document.addEventListener("DOMContentLoaded", function(){
    const clrBtn = document.getElementById("clearSharedMemoryBtn");
    if(clrBtn) clrBtn.addEventListener("click", async function(){
      try{
        await fetch("/api/os/shared_memory/clear", {method:"POST"});
        const card = document.getElementById("sharedMemoryCard");
        if(card) card.style.display = "none";
        if(typeof showToast==="function") showToast("Shared memory cleared");
      }catch(e){}
    });
    loadSharedMemory();
  });

  // Poll after convene so the panel updates automatically
  (function patchConveneAll(){
    const orig = window.conveneAll;
    if(typeof orig !== "function"){ setTimeout(patchConveneAll, 400); return; }
    window.conveneAll = async function(){
      await orig.apply(this, arguments);
      setTimeout(loadSharedMemory, 3500);  // wait for async extraction
    };
  })();

  /* ── 2. TOOL-CALL BADGES ON MESSAGES ──────────────────────────────────────── */
  // Patch sendFollow / followup response to show tool badges
  (function patchSendFollowForTools(){
    const origSendFollow = window.sendFollow;
    if(typeof origSendFollow !== "function"){ setTimeout(patchSendFollowForTools, 400); return; }
    window.sendFollow = async function(){
      // We intercept the response before calling the original by
      // wrapping the fetch. We do this by patching _showToolBadges
      // after any followup completes via a MutationObserver on #thread.
      await origSendFollow.apply(this, arguments);
    };
  })();

  // After every thread render, check the last followup response for tool_calls
  // We store the last tool log on window and attach badges in renderThread patch
  window._saLastToolLog = [];

  // Patch fetch globally to capture tool_calls from /api/followup responses
  (function patchFetchForTools(){
    const origFetch = window.fetch;
    window.fetch = async function(url, opts){
      const res = await origFetch.apply(this, arguments);
      try{
        const u = (typeof url === "string") ? url : (url.url || "");
        if(u === "/api/followup" && opts && opts.method === "POST"){
          const clone = res.clone();
          clone.json().then(function(d){
            if(d && d.ok && Array.isArray(d.tool_calls) && d.tool_calls.length){
              window._saLastToolLog = d.tool_calls;
              _attachToolBadgesToLastMsg(d.tool_calls);
            }
          }).catch(()=>{});
        }
      }catch(_){}
      return res;
    };
  })();

  function _attachToolBadgesToLastMsg(toolLog){
    try{
      const thread = document.getElementById("thread");
      if(!thread) return;
      const msgs = thread.querySelectorAll(".msg.assistant");
      const last = msgs[msgs.length-1];
      if(!last || last._saToolsWired) return;
      last._saToolsWired = true;
      const wrap = document.createElement("div");
      wrap.style.marginTop = "6px";
      toolLog.forEach(function(tc){
        const badge = document.createElement("span");
        badge.className = "sa-tool-badge";
        badge.title = "Args: " + JSON.stringify(tc.args||{});
        badge.textContent = "⚙ " + tc.tool;
        wrap.appendChild(badge);
      });
      last.appendChild(wrap);
    }catch(_){}
  }

  // Call on load
  if(document.readyState === "loading"){
    document.addEventListener("DOMContentLoaded", loadSharedMemory);
  } else {
    loadSharedMemory();
  }

})();
</script>

<!-- ═══════════════════════════════════════════════════════════════════════
     SESSION 1 UPGRADES — STREAMING · MULTI-MODEL · TTS
     ═══════════════════════════════════════════════════════════════════════ -->
<style>
/* Stream cursor blink */
@keyframes sa-blink { 0%,100%{opacity:1} 50%{opacity:0} }
.sa-cursor { display:inline-block; animation:sa-blink .7s step-start infinite; color:#a78bfa; margin-left:1px; font-size:.9em; }
/* Stream mode button active */
.sa-stream-on { border-color:rgba(99,102,241,.85) !important; background:rgba(99,102,241,.18) !important; color:#c4b5fd !important; }
/* TTS speaker button */
.sa-tts-btn {
  display:inline-flex; align-items:center; justify-content:center;
  background:rgba(42,58,106,.5); border:1px solid rgba(42,58,106,.7);
  color:rgba(165,180,252,.75); border-radius:8px; padding:3px 7px;
  font-size:11px; cursor:pointer; margin-top:6px; gap:4px;
  transition:background .15s, color .15s;
}
.sa-tts-btn:hover { background:rgba(99,102,241,.25); color:#c4b5fd; }
.sa-tts-btn.sa-playing { border-color:rgba(99,102,241,.8); color:#c4b5fd; animation:sa-blink .9s ease-in-out infinite; }
/* Model badge on seat cards */
.sa-model-badge {
  font-size:9px; padding:1px 5px; border-radius:5px;
  background:rgba(99,102,241,.22); color:#a5b4fc;
  border:1px solid rgba(99,102,241,.35); display:inline-block;
  margin-left:4px; vertical-align:middle;
}
</style>

<script>
/* ─────────────────────────────────────────────────────────────────────────────
   STREAMING MODE
   ───────────────────────────────────────────────────────────────────────────── */
(function(){
  // ── state ──
  let streamMode = localStorage.getItem("sa_stream_mode") !== "off";
  let _currentTtsAudio = null;

  // ── helpers ──
  function _esc(s){ const d=document.createElement("div"); d.innerText=String(s||""); return d.innerHTML; }
  function _tm(name){ try{ const r=window._saStateCache; return ((r&&r.installed)||{})[name]||{}; }catch(e){ return{}; } }

  // ── wire stream toggle button ──
  function initStreamToggle(){
    const btn = document.getElementById("streamToggleBtn");
    if(!btn) return;
    function refresh(){
      if(streamMode){
        btn.classList.add("sa-stream-on");
        btn.title = "Streaming ON — click to disable";
      } else {
        btn.classList.remove("sa-stream-on");
        btn.title = "Streaming OFF — click to enable real-time token streaming";
      }
    }
    refresh();
    btn.addEventListener("click", function(){
      streamMode = !streamMode;
      localStorage.setItem("sa_stream_mode", streamMode ? "on" : "off");
      refresh();
      if(typeof showToast==="function") showToast(streamMode ? "⚡ Streaming ON" : "Streaming OFF");
    });
  }

  // ── cache state for model badge reads ──
  (function patchLoadState(){
    const orig = window.loadState;
    if(typeof orig !== "function") return;
    window.loadState = async function(){
      const result = await orig.apply(this, arguments);
      try{
        const r = await fetch("/api/state"); const d = await r.json();
        if(d.ok) window._saStateCache = d;
      }catch(_){}
      return result;
    };
  })();

  /* ─── TTS ─────────────────────────────────────────────────────────────────── */
  window.saTtsSpeak = async function saTtsSpeak(text, voice, btn){
    if(!text) return;
    // Stop any playing audio
    if(_currentTtsAudio){ _currentTtsAudio.pause(); _currentTtsAudio=null; }
    if(btn){ btn.classList.add("sa-playing"); btn.textContent="⏹ Stop"; }

    // If called again while playing, just stop
    let stopped = false;
    if(btn){ btn._saTtsStop = ()=>{ stopped=true; if(_currentTtsAudio){_currentTtsAudio.pause();_currentTtsAudio=null;} btn.classList.remove("sa-playing"); btn.textContent="🔊 Speak"; btn._saTtsStop=null; }; }

    try{
      const resp = await fetch("/api/tts",{
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({text: text.slice(0,2000), voice: voice||"alloy"})
      });
      if(!resp.ok){ throw new Error("TTS request failed"); }
      const blob = await resp.blob();
      const url  = URL.createObjectURL(blob);
      const audio = new Audio(url);
      _currentTtsAudio = audio;
      audio.onended = ()=>{
        URL.revokeObjectURL(url); _currentTtsAudio=null;
        if(btn){ btn.classList.remove("sa-playing"); btn.textContent="🔊 Speak"; btn._saTtsStop=null; }
      };
      audio.onerror = ()=>{
        URL.revokeObjectURL(url); _currentTtsAudio=null;
        if(btn){ btn.classList.remove("sa-playing"); btn.textContent="🔊 Speak"; }
      };
      if(!stopped) audio.play();
    }catch(e){
      if(btn){ btn.classList.remove("sa-playing"); btn.textContent="🔊 Speak"; }
      if(typeof showToast==="function") showToast("TTS error: "+(e.message||"unknown"),"error");
    }
  };

  /* Attach a 🔊 button to a rendered assistant message div */
  window.addTtsButton = function addTtsButton(msgDiv, text, voice){
    if(!msgDiv || !text) return;
    if(msgDiv._saTtsWired) return;
    msgDiv._saTtsWired = true;
    const btn = document.createElement("button");
    btn.className = "sa-tts-btn";
    btn.textContent = "🔊 Speak";
    btn.title = "Read this response aloud";
    btn.addEventListener("click", function(e){
      e.stopPropagation();
      if(btn._saTtsStop){ btn._saTtsStop(); return; }
      saTtsSpeak(text, voice, btn);
    });
    msgDiv.appendChild(btn);
  };

  /* Patch renderThread to add TTS buttons to every assistant message */
  (function patchRenderThread(){
    const orig = window.renderThread;
    if(typeof orig !== "function"){ setTimeout(patchRenderThread, 300); return; }
    window.renderThread = function(msgs, imageState){
      orig.apply(this, arguments);
      try{
        const seat = window.selectedSeat || "";
        const tm   = _tm(seat);
        const voice = tm.tts_voice || "alloy";
        const thread = document.getElementById("thread");
        if(!thread) return;
        thread.querySelectorAll(".msg.assistant").forEach(function(div){
          if(div._saTtsWired) return;
          // Get text content — skip image messages
          const contentEl = div.querySelector("div:not(.who):not(.actions):not(.sa-tts-btn)");
          const raw = contentEl ? (contentEl.innerText||"").trim() : "";
          if(raw && raw.length > 10 && !raw.startsWith("[Image")) addTtsButton(div, raw, voice);
        });
      }catch(_){}
    };
  })();

  /* ─── STREAMING SEND ──────────────────────────────────────────────────────── */
  async function sendFollowStream(){
    const seat = window.selectedSeat;
    if(!seat){ if(typeof showModal==="function") showModal("No seat selected","Click a teammate card first."); return; }
    const msgEl = document.getElementById("followMsg");
    const msg = (msgEl ? msgEl.value : "").trim();
    if(!msg){ if(typeof showModal==="function") showModal("Missing message","Type a message."); return; }

    const dmFileIds = window.dmFileIds || [];
    const lightingOn = !!window.lightingModeOn;

    if(typeof setSeatLive==="function") setSeatLive(seat,"thinking");
    if(typeof setOpStatus==="function") setOpStatus("Streaming…");

    const threadEl = document.getElementById("thread");

    // Append user bubble immediately
    const userDiv = document.createElement("div");
    userDiv.className = "msg user";
    const userWho = document.createElement("div"); userWho.className="who"; userWho.innerText="You";
    const userBody = document.createElement("div"); userBody.innerText=msg;
    userDiv.appendChild(userWho); userDiv.appendChild(userBody);
    threadEl.appendChild(userDiv);

    // Append assistant streaming bubble
    const aDiv = document.createElement("div"); aDiv.className="msg assistant";
    const aWho = document.createElement("div"); aWho.className="who"; aWho.innerText=seat;
    const aBody = document.createElement("div");
    const aCursor = document.createElement("span"); aCursor.className="sa-cursor"; aCursor.textContent="▋";
    aBody.appendChild(aCursor);
    aDiv.appendChild(aWho); aDiv.appendChild(aBody);
    threadEl.appendChild(aDiv);
    threadEl.scrollTop = threadEl.scrollHeight;

    if(msgEl) msgEl.value="";
    let fullText = "";

    try{
      const response = await fetch("/api/followup/stream",{
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({name:seat, message:msg, file_ids:dmFileIds, lighting_mode:lightingOn})
      });

      if(!response.ok || !response.body){
        const errData = await response.json().catch(()=>({error:"Stream unavailable"}));
        throw new Error(errData.error||"Stream unavailable");
      }

      const reader  = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while(true){
        const {done, value} = await reader.read();
        if(done) break;
        buffer += decoder.decode(value,{stream:true});
        const lines = buffer.split("\n");
        buffer = lines.pop(); // keep incomplete line

        for(const line of lines){
          if(!line.startsWith("data: ")) continue;
          let parsed;
          try{ parsed = JSON.parse(line.slice(6)); }catch(_){ continue; }

          if(parsed.token){
            fullText += parsed.token;
            aBody.innerText = fullText;
            aBody.appendChild(aCursor);
            threadEl.scrollTop = threadEl.scrollHeight;
          }
          if(parsed.error){ throw new Error(parsed.error); }
          if(parsed.done){
            aCursor.remove();
            window.lastSeatAssistantText = fullText;
            if(typeof setSeatLive==="function") setSeatLive(seat,"done");
            if(typeof setOpStatus==="function") setOpStatus("Complete");
            if(parsed.email_draft && typeof applyEmailDraft==="function") applyEmailDraft(parsed.email_draft, seat);
            if(window.dmFileIds){ window.dmFileIds=[]; }
            if(typeof renderAttachList==="function") renderAttachList("dmAttachList",[]);
            // Wire TTS + click-to-expand
            const tm = _tm(seat);
            addTtsButton(aDiv, fullText, tm.tts_voice||"alloy");
            if(typeof saWireThreadClicks==="function") setTimeout(saWireThreadClicks,50);
            try{ if(window.onboardingRefresh) await window.onboardingRefresh(); }catch(_){}
          }
        }
      }
    }catch(err){
      aCursor.remove();
      aBody.innerText = (fullText || "") + (fullText ? "\n\n" : "") + "[Stream error: "+(err.message||"unknown")+"]";
      if(typeof setSeatLive==="function") setSeatLive(seat,"waiting");
      if(typeof setOpStatus==="function") setOpStatus("Error");
    }
  }

  /* Patch the existing sendFollow to route through stream when mode is ON */
  function patchSendFollow(){
    const origBtn = document.getElementById("sendFollow");
    if(!origBtn){ setTimeout(patchSendFollow,200); return; }

    origBtn.addEventListener("click", async function(e){
      if(!streamMode) return; // let original handler fire normally
      e.stopImmediatePropagation();
      await sendFollowStream();
    }, true); // capture phase fires before original listener

    // Also intercept Enter key in followMsg
    const followMsg = document.getElementById("followMsg");
    if(followMsg){
      followMsg.addEventListener("keydown", function(e){
        if(e.key==="Enter" && !e.shiftKey && streamMode){
          e.preventDefault();
          e.stopImmediatePropagation();
          sendFollowStream();
        }
      }, true);
    }
  }

  /* ─── INIT ────────────────────────────────────────────────────────────────── */
  document.addEventListener("DOMContentLoaded", function(){
    initStreamToggle();
    patchSendFollow();
    // Also try after a small delay in case the app JS runs late
    setTimeout(function(){ initStreamToggle(); patchSendFollow(); }, 600);
  });
  // Fallback if DOMContentLoaded already fired
  if(document.readyState !== "loading"){
    setTimeout(function(){ initStreamToggle(); patchSendFollow(); }, 100);
  }
})();
</script>

</body>
</html>
"""

@app.get("/")
def index():
    return render_template_string(HTML, app_title=APP_TITLE, model=MODEL)









@app.route("/api/clients", methods=["GET"])
def api_clients_list():
    username = _get_session_username()
    data = _load_clients(username)
    # return list
    out = []
    for cid, c in (data.get("clients") or {}).items():
        if isinstance(c, dict):
            item = dict(c)
            item.setdefault("id", cid)
            out.append(item)
    out.sort(key=lambda x: (x.get("name") or "").lower())
    return jsonify({"ok": True, "active_client_id": data.get("active_client_id",""), "clients": out})

@app.route("/api/clients/active", methods=["GET"])
def api_clients_active():
    username = _get_session_username()
    c = _get_active_client(username)
    return jsonify({"ok": True, "client": c})

@app.route("/api/clients/active", methods=["POST"])
def api_clients_set_active():
    username = _get_session_username()
    payload = request.get_json(silent=True) or {}
    cid = (payload.get("client_id") or "").strip()
    data = _load_clients(username)
    if cid and cid not in (data.get("clients") or {}):
        return jsonify({"ok": False, "error": "Client not found"}), 404
    data["active_client_id"] = cid
    _save_clients(username, data)
    return jsonify({"ok": True, "active_client_id": cid})

@app.route("/api/clients", methods=["POST"])
def api_clients_create():
    username = _get_session_username()
    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "Name is required"}), 400
    data = _load_clients(username)
    cid = _new_client_id()
    now = datetime.utcnow().isoformat() + "Z"
    client = {
        "id": cid,
        "name": name,
        "company": (payload.get("company") or "").strip(),
        "email": (payload.get("email") or "").strip(),
        "tags": (payload.get("tags") or "").strip(),
        "notes": (payload.get("notes") or "").strip(),
        "last_summary": (payload.get("last_summary") or "").strip(),
        "updated_at": now,
    }
    data["clients"][cid] = client
    # auto-activate if none
    if not (data.get("active_client_id") or "").strip():
        data["active_client_id"] = cid
    _save_clients(username, data)
    return jsonify({"ok": True, "client": client, "active_client_id": data.get("active_client_id","")})

@app.route("/api/clients/<client_id>", methods=["POST"])
def api_clients_update(client_id):
    username = _get_session_username()
    payload = request.get_json(silent=True) or {}
    data = _load_clients(username)
    clients = data.get("clients") or {}
    if client_id not in clients or not isinstance(clients[client_id], dict):
        return jsonify({"ok": False, "error": "Client not found"}), 404
    c = clients[client_id]
    for k in ["name","company","email","tags","notes","last_summary"]:
        if k in payload:
            c[k] = (payload.get(k) or "").strip()
    c["updated_at"] = datetime.utcnow().isoformat() + "Z"
    clients[client_id] = c
    data["clients"] = clients
    _save_clients(username, data)
    c2 = dict(c); c2.setdefault("id", client_id)
    return jsonify({"ok": True, "client": c2})

@app.route("/api/clients/<client_id>", methods=["DELETE"])
def api_clients_delete(client_id):
    username = _get_session_username()
    data = _load_clients(username)
    clients = data.get("clients") or {}
    if client_id in clients:
        clients.pop(client_id, None)
    if data.get("active_client_id") == client_id:
        data["active_client_id"] = ""
    data["clients"] = clients
    _save_clients(username, data)
    return jsonify({"ok": True})





# =========================
# CRM COMMAND CENTER (Full CRM Mode) - additive v1
# =========================
#
# This module extends Client Memory Profiles into a full CRM:
# - Clients with pipeline stages, tags, custom fields
# - Tasks + reminders
# - Broadcast email (SMS placeholder)
# - Sequences (nurture automation) driven by tick() without background workers
# - Calendar event creation (Google Calendar OAuth)
#
# Design constraints:
# - Additive only: does not break existing /api/clients endpoints
# - Storage is per-user JSON in DATA/crm/<user>.json
# - Safe defaults and migration from existing clients store if CRM store is empty

CRM_DIR = DATA / "crm"
CRM_DIR.mkdir(parents=True, exist_ok=True)

def _crm_path_for_user(username: str) -> Path:
    safe = _safe_name(username or "anon")
    return CRM_DIR / f"{safe}.json"

def _default_pipeline_stages() -> List[str]:
    return ["Lead", "Conversation", "Interested", "Call booked", "Client", "VIP", "Past client", "Cold"]

def _crm_default_state() -> Dict[str, Any]:
    return {
        "version": "crm_v1",
        "updated_at": None,
        "clients": {},          # id -> client dict
        "pipeline": {"stages": _default_pipeline_stages()},
        "tasks": {},            # id -> task dict
        "sequences": {},        # id -> sequence dict
        "enrollments": {},      # id -> enrollment dict
        "messages": [],         # recent message log (bounded)
        "settings": {
            "sms": {"provider": "", "twilio_sid": "", "twilio_token": "", "twilio_from": ""},
        },
    }

def _crm_load(username: str) -> Dict[str, Any]:
    path = _crm_path_for_user(username)
    data = load_json(path, _crm_default_state())
    if not isinstance(data, dict):
        data = _crm_default_state()
    data.setdefault("clients", {})
    data.setdefault("pipeline", {"stages": _default_pipeline_stages()})
    data.setdefault("tasks", {})
    data.setdefault("sequences", {})
    data.setdefault("enrollments", {})
    data.setdefault("messages", [])
    data.setdefault("settings", {"sms": {"provider": "", "twilio_sid": "", "twilio_token": "", "twilio_from": ""}})
    # self-heal pipeline
    if not isinstance(data.get("pipeline"), dict):
        data["pipeline"] = {"stages": _default_pipeline_stages()}
    if not isinstance((data["pipeline"].get("stages")), list) or not data["pipeline"]["stages"]:
        data["pipeline"]["stages"] = _default_pipeline_stages()
    # coerce maps
    for k in ["clients", "tasks", "sequences", "enrollments"]:
        if not isinstance(data.get(k), dict):
            data[k] = {}
    if not isinstance(data.get("messages"), list):
        data["messages"] = []
    return data

def _crm_save(username: str, data: Dict[str, Any]) -> None:
    data = data or {}
    data["updated_at"] = now_iso()
    # bound messages log
    try:
        msgs = data.get("messages") or []
        if isinstance(msgs, list) and len(msgs) > 500:
            data["messages"] = msgs[-500:]
    except Exception:
        pass
    save_json(_crm_path_for_user(username), data)

def _crm_new_id(prefix: str) -> str:
    prefix = re.sub(r"[^a-zA-Z0-9_]+", "_", (prefix or "x"))
    return f"{prefix}_{uuid.uuid4().hex[:10]}"

def _crm_migrate_from_client_memory_if_empty(username: str) -> None:
    """Best-effort migration: if CRM has no clients but legacy client memory has clients, import them."""
    try:
        crm = _crm_load(username)
        if (crm.get("clients") or {}):
            return
        legacy = _load_clients(username)
        legacy_clients = legacy.get("clients") or {}
        if not isinstance(legacy_clients, dict) or not legacy_clients:
            return
        out = {}
        for cid, c in legacy_clients.items():
            if not isinstance(c, dict):
                continue
            new_id = cid if cid else _crm_new_id("c")
            tags = c.get("tags") or ""
            tags_list = [t.strip() for t in str(tags).split(",") if t.strip()]
            out[new_id] = {
                "id": new_id,
                "name": (c.get("name") or "").strip(),
                "company": (c.get("company") or "").strip(),
                "email": (c.get("email") or "").strip(),
                "phone": "",
                "tags": tags_list,
                "status": "lead",
                "pipeline_stage": "Lead",
                "last_contact": "",
                "next_followup": "",
                "notes": (c.get("notes") or "").strip(),
                "last_summary": (c.get("last_summary") or "").strip(),
                "custom_fields": {},
                "created_at": c.get("updated_at") or now_iso(),
                "updated_at": c.get("updated_at") or now_iso(),
            }
        crm["clients"] = out
        _crm_save(username, crm)
    except Exception:
        return

def _crm_client_matches_filter(c: Dict[str, Any], filt: Dict[str, Any]) -> bool:
    if not isinstance(c, dict):
        return False
    tags = c.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    tags = [str(t).strip() for t in (tags or []) if str(t).strip()]
    stage = (c.get("pipeline_stage") or "").strip()
    status = (c.get("status") or "").strip()
    need_tag = (filt.get("tag") or "").strip()
    need_stage = (filt.get("stage") or "").strip()
    need_status = (filt.get("status") or "").strip()
    ids = filt.get("ids") or []
    if ids and c.get("id") not in ids:
        return False
    if need_tag and (need_tag not in tags):
        return False
    if need_stage and stage != need_stage:
        return False
    if need_status and status != need_status:
        return False
    return True

def _crm_log_message(username: str, rec: Dict[str, Any]) -> None:
    try:
        crm = _crm_load(username)
        crm.setdefault("messages", [])
        rec = rec or {}
        rec.setdefault("ts", now_iso())
        crm["messages"].append(rec)
        _crm_save(username, crm)
    except Exception:
        pass

def _crm_send_email_to(u: Dict[str, Any], to_addr: str, subject: str, body: str, from_name: str = "") -> Tuple[bool, str, str]:
    """Returns (ok, provider, error)."""
    cap = _email_capability_for_user(u)
    try:
        if cap.get("gmail_connected"):
            access_token, reason = _gmail_creds_for_user(u)
            if not access_token:
                return False, "gmail_oauth", reason or "Gmail not connected."
            _gmail_send_message(access_token, to_addr=to_addr, subject=subject, body=body, from_name=from_name or _user_smtp_settings(u).get("from_name",""))
            return True, "gmail_oauth", ""
        ready, reason = smtp_ready_for_user(u)
        if not ready:
            return False, "smtp", reason or "SMTP not connected."
        s = _user_smtp_settings(u)
        host = s["host"]; port = s["port"]
        user = s["user"] or SMTP_USER
        password = s["pass"] or SMTP_PASS
        fn = from_name or s["from_name"]
        if not user or not password:
            return False, "smtp", "Missing SMTP credentials."
        send_email_smtp_with_creds(to_addr=to_addr, subject=subject, body=body, host=host, port=port, user=user, password=password, from_name=fn)
        return True, "smtp", ""
    except Exception as e:
        return False, "email", str(e)

def _crm_try_send_sms(username: str, to_phone: str, body: str) -> Tuple[bool, str]:
    """SMS placeholder. Supports Twilio via env or CRM settings when provided."""
    # No hard dependency. Only works if configured.
    try:
        crm = _crm_load(username)
        sms = ((crm.get("settings") or {}).get("sms") or {})
        provider = (sms.get("provider") or os.getenv("SMS_PROVIDER","")).strip().lower()
        if provider != "twilio":
            return False, "SMS not configured. Set provider to 'twilio' in CRM settings."
        sid = (sms.get("twilio_sid") or os.getenv("TWILIO_SID","")).strip()
        token = (sms.get("twilio_token") or os.getenv("TWILIO_TOKEN","")).strip()
        from_num = (sms.get("twilio_from") or os.getenv("TWILIO_FROM","")).strip()
        if not sid or not token or not from_num:
            return False, "Twilio missing SID/TOKEN/FROM."
        import requests
        url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
        r = requests.post(url, data={"To": to_phone, "From": from_num, "Body": body}, auth=(sid, token), timeout=20)
        if r.status_code >= 400:
            return False, f"Twilio error: {r.text}"
        return True, ""
    except Exception as e:
        return False, str(e)



@app.get("/api/crm/settings/sms")
def api_crm_sms_settings_get():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    crm = _crm_load(uname)
    sms = ((crm.get("settings") or {}).get("sms") or {})
    safe = {
        "provider": sms.get("provider", "twilio"),
        "twilio_sid": sms.get("twilio_sid", ""),
        "twilio_from": sms.get("twilio_from", ""),
        "twilio_token": ""  # user can re-enter to update
    }
    return jsonify({"ok": True, "sms": safe})
@app.get("/api/settings/sms")
def api_settings_sms_get():
    return api_crm_sms_settings_get()


@app.post("/api/crm/settings/sms")
def api_crm_sms_settings_set():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(silent=True) or {}
    provider = (payload.get("provider") or "twilio").strip().lower()
    sid = (payload.get("twilio_sid") or "").strip()
    token = (payload.get("twilio_token") or "").strip()
    from_num = (payload.get("twilio_from") or "").strip()

    crm = _crm_load(uname)
    crm.setdefault("settings", {})
    crm["settings"].setdefault("sms", {})
    sms = crm["settings"]["sms"]
    sms["provider"] = provider

    if sid:
        sms["twilio_sid"] = sid
    if from_num:
        sms["twilio_from"] = from_num
    if token:
        sms["twilio_token"] = token

    _crm_save(uname, crm)
    return jsonify({"ok": True})
@app.post("/api/settings/sms")
def api_settings_sms_set():
    return api_crm_sms_settings_set()


@app.post("/api/crm/settings/sms/test")
def api_crm_sms_settings_test():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(silent=True) or {}
    to_phone = (payload.get("to") or "").strip()
    body = (payload.get("body") or "Test message from Simply Agentic AI").strip()
    if not to_phone:
        return jsonify({"ok": False, "error": "Missing 'to' phone"}), 400
    ok_send, err = _crm_try_send_sms(uname, to_phone, body)
    return jsonify({"ok": bool(ok_send), "error": err})



def _crm_tick_once() -> None:
    """Run due CRM automations (tasks reminders, sequences enrollments). Safe, bounded work."""
    # Called by /api/action_stack_schedules/tick
    max_sends = 40  # hard cap per tick across all users
    sends_done = 0
    now_utc = datetime.utcnow()

    for user_path in CRM_DIR.glob("*.json"):
        if sends_done >= max_sends:
            break
        username = user_path.stem or "anon"
        try:
            crm = load_json(user_path, _crm_default_state())
            if not isinstance(crm, dict):
                continue
            enroll = crm.get("enrollments") or {}
            seqs = crm.get("sequences") or {}
            clients = crm.get("clients") or {}
            changed = False

            # Process due enrollments (email only; sms optional)
            for eid, e in list(enroll.items()):
                if sends_done >= max_sends:
                    break
                if not isinstance(e, dict):
                    continue
                status = (e.get("status") or "active").strip().lower()
                if status != "active":
                    continue
                next_due = (e.get("next_due") or "").strip()
                if not next_due:
                    continue
                try:
                    due_dt = datetime.fromisoformat(next_due.replace("Z",""))
                except Exception:
                    due_dt = None
                if not due_dt or now_utc < due_dt:
                    continue

                seq_id = (e.get("sequence_id") or "").strip()
                client_id = (e.get("client_id") or "").strip()
                step_i = int(e.get("step_index") or 0)

                seq = seqs.get(seq_id) if isinstance(seqs, dict) else None
                c = clients.get(client_id) if isinstance(clients, dict) else None
                if not isinstance(seq, dict) or not isinstance(c, dict):
                    e["status"] = "stopped"
                    enroll[eid] = e
                    changed = True
                    continue

                steps = seq.get("steps") or []
                if not isinstance(steps, list) or step_i >= len(steps):
                    e["status"] = "complete"
                    enroll[eid] = e
                    changed = True
                    continue

                step = steps[step_i] if isinstance(steps[step_i], dict) else {}
                channel = (step.get("channel") or "email").strip().lower()
                subj_t = (step.get("subject") or "").strip()
                body_t = (step.get("body") or "").strip()
                delay_days = int(step.get("delay_days") or 0)

                # Render templates
                ctx = {
                    "name": c.get("name",""),
                    "company": c.get("company",""),
                    "email": c.get("email",""),
                    "phone": c.get("phone",""),
                    "stage": c.get("pipeline_stage",""),
                }
                subj = _safe_render(subj_t, ctx) if subj_t else ""
                body = _safe_render(body_t, ctx) if body_t else ""

                ok_send = False
                provider = ""
                err = ""

                # Get a user record for provider creds if possible
                users_db = load_users()
                urec = (users_db.get("users") or {}).get(username)
                if not isinstance(urec, dict):
                    urec = current_user() if (current_user() and (current_user().get("username")==username)) else None

                if channel == "sms":
                    phone = (c.get("phone") or "").strip()
                    if phone and body:
                        ok_send, err = _crm_try_send_sms(username, phone, body)
                        provider = "sms"
                    else:
                        ok_send = False
                        err = "Missing phone/body."
                        provider = "sms"
                else:
                    to_addr = (c.get("email") or "").strip()
                    if to_addr and EMAIL_RE.match(to_addr) and body:
                        if isinstance(urec, dict):
                            ok_send, provider, err = _crm_send_email_to(urec, to_addr, subj or (seq.get("default_subject") or "Update"), body)
                        else:
                            ok_send = False
                            provider = "email"
                            err = "User record not available for email credentials."
                    else:
                        ok_send = False
                        provider = "email"
                        err = "Missing/invalid email or empty body."

                # Log message
                try:
                    crm.setdefault("messages", [])
                    crm["messages"].append({
                        "ts": now_iso(),
                        "type": "sequence_step",
                        "sequence_id": seq_id,
                        "enrollment_id": eid,
                        "client_id": client_id,
                        "step_index": step_i,
                        "channel": channel,
                        "provider": provider,
                        "ok": bool(ok_send),
                        "error": err,
                        "subject": subj,
                    })
                    if len(crm["messages"]) > 500:
                        crm["messages"] = crm["messages"][-500:]
                except Exception:
                    pass

                # Advance
                if ok_send:
                    sends_done += 1
                    e["step_index"] = step_i + 1
                    if (step_i + 1) >= len(steps):
                        e["status"] = "complete"
                        e["next_due"] = ""
                    else:
                        e["next_due"] = (now_utc + timedelta(days=max(0, delay_days))).isoformat() + "Z"
                    enroll[eid] = e
                    changed = True
                else:
                    # backoff 1 day to avoid hammering
                    e["next_due"] = (now_utc + timedelta(days=1)).isoformat() + "Z"
                    enroll[eid] = e
                    changed = True

            if changed:
                crm["enrollments"] = enroll
                save_json(user_path, crm)

        except Exception:
            continue

# ---- CRM APIs ----
@app.post("/api/settings/sms/test")
def api_settings_sms_test():
    return api_crm_sms_settings_test()


@app.get("/api/crm/state")
def api_crm_state():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    _crm_migrate_from_client_memory_if_empty(uname)
    crm = _crm_load(uname)
    return jsonify({"ok": True, "pipeline": crm.get("pipeline") or {}, "counts": {
        "clients": len(crm.get("clients") or {}),
        "tasks": len(crm.get("tasks") or {}),
        "sequences": len(crm.get("sequences") or {}),
        "enrollments": len(crm.get("enrollments") or {}),
    }})

@app.get("/api/crm/clients")
def api_crm_clients_list():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    _crm_migrate_from_client_memory_if_empty(uname)
    crm = _crm_load(uname)
    clients = list((crm.get("clients") or {}).values())
    # sort by updated_at desc
    def _ts(x):
        try:
            return str(x.get("updated_at") or "")
        except Exception:
            return ""
    clients.sort(key=_ts, reverse=True)
    return jsonify({"ok": True, "clients": clients, "pipeline": crm.get("pipeline") or {}})

@app.post("/api/crm/clients")
def api_crm_clients_create():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "Name is required"}), 400
    crm = _crm_load(uname)
    cid = _crm_new_id("c")
    now = now_iso()
    tags_in = payload.get("tags") or []
    if isinstance(tags_in, str):
        tags = [t.strip() for t in tags_in.split(",") if t.strip()]
    elif isinstance(tags_in, list):
        tags = [str(t).strip() for t in tags_in if str(t).strip()]
    else:
        tags = []
    stage = (payload.get("pipeline_stage") or "Lead").strip()
    if stage not in (crm.get("pipeline",{}).get("stages") or []):
        stage = "Lead"
    client = {
        "id": cid,
        "name": name,
        "company": (payload.get("company") or "").strip(),
        "email": (payload.get("email") or "").strip(),
        "phone": (payload.get("phone") or "").strip(),
        "tags": tags,
        "status": (payload.get("status") or "lead").strip(),
        "pipeline_stage": stage,
        "last_contact": (payload.get("last_contact") or "").strip(),
        "next_followup": (payload.get("next_followup") or "").strip(),
        "notes": (payload.get("notes") or "").strip(),
        "last_summary": (payload.get("last_summary") or "").strip(),
        "custom_fields": payload.get("custom_fields") if isinstance(payload.get("custom_fields"), dict) else {},
        "created_at": now,
        "updated_at": now,
    }
    try:
        client = _crm_enrich_client_record(client)
    except Exception:
        pass  # enrichment is best-effort
    try:
        client = _crm_apply_pipeline_rules(uname, client)
    except Exception:
        pass  # rules are best-effort
    try:
        crm["clients"][cid] = client
        _crm_save(uname, crm)
    except Exception as _save_err:
        return jsonify({"ok": False, "error": f"Storage error: {_save_err}"}), 500
    return jsonify({"ok": True, "client": client})

@app.post("/api/crm/clients/<client_id>")
def api_crm_clients_update(client_id: str):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(silent=True) or {}
    crm = _crm_load(uname)
    clients = crm.get("clients") or {}
    if client_id not in clients or not isinstance(clients[client_id], dict):
        return jsonify({"ok": False, "error": "Client not found"}), 404
    c = clients[client_id]
    for k in ["name","company","email","phone","status","last_contact","next_followup","notes","last_summary"]:
        if k in payload:
            c[k] = (payload.get(k) or "").strip()
    if "pipeline_stage" in payload:
        stage = (payload.get("pipeline_stage") or "").strip()
        if stage and stage in (crm.get("pipeline",{}).get("stages") or []):
            c["pipeline_stage"] = stage
    if "tags" in payload:
        tags_in = payload.get("tags") or []
        if isinstance(tags_in, str):
            c["tags"] = [t.strip() for t in tags_in.split(",") if t.strip()]
        elif isinstance(tags_in, list):
            c["tags"] = [str(t).strip() for t in tags_in if str(t).strip()]
    if "custom_fields" in payload and isinstance(payload.get("custom_fields"), dict):
        c["custom_fields"] = payload.get("custom_fields") or {}
    c["updated_at"] = now_iso()
    c = _crm_enrich_client_record(c)
    c = _crm_apply_pipeline_rules(uname, c)
    clients[client_id] = c
    crm["clients"] = clients
    _crm_save(uname, crm)
    return jsonify({"ok": True, "client": c})

@app.delete("/api/crm/clients/<client_id>")
def api_crm_clients_delete(client_id: str):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    crm = _crm_load(uname)
    clients = crm.get("clients") or {}
    clients.pop(client_id, None)
    crm["clients"] = clients
    _crm_save(uname, crm)
    return jsonify({"ok": True})

@app.post("/api/crm/clients/import_csv")
def api_crm_clients_import_csv():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(silent=True) or {}
    csv_text = (payload.get("csv_text") or "")
    if not csv_text.strip():
        return jsonify({"ok": False, "error": "CSV text is required"}), 400

    import csv
    from io import StringIO

    crm = _crm_load(uname)
    stages = crm.get("pipeline", {}).get("stages") or ["Lead"]
    default_stage = stages[0] if stages else "Lead"
    imported = 0
    skipped = 0

    def pick(row, *names):
        lowered = {str(k).strip().lower(): v for k, v in row.items()}
        for name in names:
            val = lowered.get(name)
            if val is not None and str(val).strip():
                return str(val).strip()
        return ""

    try:
        reader = csv.DictReader(StringIO(csv_text))
        if not reader.fieldnames:
            return jsonify({"ok": False, "error": "CSV must include a header row"}), 400
        for row in reader:
            if not isinstance(row, dict):
                skipped += 1
                continue
            name = pick(row, "name", "full name", "fullname", "contact", "client", "prospect")
            email = pick(row, "email", "email address", "e-mail")
            phone = pick(row, "phone", "phone number", "mobile", "cell")
            company = pick(row, "company", "brokerage", "business")
            notes = pick(row, "notes", "note", "source")
            stage = pick(row, "pipeline_stage", "pipeline stage", "stage") or default_stage
            if stage not in stages:
                stage = default_stage
            if not name and not email and not phone:
                skipped += 1
                continue
            if not name:
                name = email or phone or "Imported prospect"
            now = now_iso()
            cid = _crm_new_id("c")
            crm.setdefault("clients", {})[cid] = {
                "id": cid,
                "name": name,
                "company": company,
                "email": email,
                "phone": phone,
                "tags": [],
                "status": "lead",
                "pipeline_stage": stage,
                "last_contact": "",
                "next_followup": "",
                "notes": notes,
                "last_summary": "",
                "custom_fields": {},
                "created_at": now,
                "updated_at": now,
            }
            imported += 1
    except Exception as e:
        return jsonify({"ok": False, "error": f"CSV import failed: {e}"}), 400

    _crm_save(uname, crm)
    return jsonify({"ok": True, "imported": imported, "skipped": skipped, "total_clients": len(crm.get("clients") or {})})


@app.post("/api/crm/pipeline")
def api_crm_pipeline_set():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(silent=True) or {}
    stages = payload.get("stages")
    if isinstance(stages, str):
        stages = [s.strip() for s in stages.splitlines() if s.strip()]
    if not isinstance(stages, list) or not stages:
        return jsonify({"ok": False, "error": "Stages are required"}), 400
    stages = [str(s).strip() for s in stages if str(s).strip()]
    stages = stages[:40]
    crm = _crm_load(uname)
    crm["pipeline"] = {"stages": stages}
    _crm_save(uname, crm)
    return jsonify({"ok": True, "pipeline": crm["pipeline"]})

@app.post("/api/crm/broadcast/email")
def api_crm_broadcast_email():
    """
    Bulk email sender for CRM.
    Supports:
      - payload.filter = {tag, stage, status, ids}
      - OR UI-friendly keys: all/tag/stage/status/client_ids
      - payload.dry_run = true (no sends, returns count only)
    Returns: {ok, count, sent, failed, results}
    """
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"

    payload = request.get_json(silent=True) or {}
    subject = (payload.get("subject") or "").strip()
    body_t = (payload.get("body") or "").strip()
    dry_run = bool(payload.get("dry_run"))

    if not subject or not body_t:
        return jsonify({"ok": False, "error": "Missing subject or body"}), 400

    # Accept either {filter:{...}} or direct UI keys.
    filt = payload.get("filter") or {}
    if not isinstance(filt, dict):
        filt = {}

    # UI keys override / fill filter when present.
    if payload.get("tag"):
        filt["tag"] = str(payload.get("tag") or "").strip()
    if payload.get("stage"):
        filt["stage"] = str(payload.get("stage") or "").strip()
    if payload.get("status"):
        filt["status"] = str(payload.get("status") or "").strip()
    if payload.get("client_ids"):
        ids = payload.get("client_ids") or []
        if isinstance(ids, str):
            ids = [x.strip() for x in ids.split(",") if x.strip()]
        if isinstance(ids, list):
            filt["ids"] = [str(x).strip() for x in ids if str(x).strip()]

    try:
        crm = _crm_load(uname)
        clients = list((crm.get("clients") or {}).values())
        recipients = [c for c in clients if _crm_client_matches_filter(c, filt)]

        # safety cap
        if len(recipients) > 250:
            return jsonify({"ok": False, "error": "Too many recipients (cap 250). Narrow your filter."}), 400

        if dry_run:
            return jsonify({"ok": True, "count": len(recipients), "sent": 0, "failed": 0, "results": []})

        sent = 0
        failed = 0
        results = []
        from_name = (_user_smtp_settings(u).get("from_name", "") or "").strip()

        for c in recipients:
            to_addr = (c.get("email") or "").strip()
            if not to_addr or (not EMAIL_RE.match(to_addr)):
                failed += 1
                results.append({"client_id": c.get("id", ""), "ok": False, "error": "Missing/invalid email"})
                continue

            ctx = {"name": c.get("name", ""), "company": c.get("company", "")}
            body = _safe_render(body_t, ctx)

            ok, provider, err = _crm_send_email_to(
                u, to_addr, subject, body,
                from_name=from_name
            )
            if ok:
                sent += 1
            else:
                failed += 1
            results.append({"client_id": c.get("id", ""), "ok": bool(ok), "provider": provider, "error": err})

        _crm_log_message(uname, {"type": "broadcast_email", "subject": subject, "filter": filt, "sent": sent, "failed": failed})
        return jsonify({"ok": True, "count": len(recipients), "sent": sent, "failed": failed, "results": results})

    except Exception as e:
        # Never 500 the UI; return a clear error.
        return jsonify({"ok": False, "error": str(e) or "Broadcast failed"}), 500

@app.post("/api/crm/broadcast/sms")
def api_crm_broadcast_sms():
    """Bulk SMS sender for CRM (Twilio only when configured)."""
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"

    payload = request.get_json(silent=True) or {}
    body_t = (payload.get("body") or "").strip()
    dry_run = bool(payload.get("dry_run"))

    if not body_t:
        return jsonify({"ok": False, "error": "Missing body"}), 400

    filt = payload.get("filter") or {}
    if not isinstance(filt, dict):
        filt = {}

    if payload.get("tag"):
        filt["tag"] = str(payload.get("tag") or "").strip()
    if payload.get("stage"):
        filt["stage"] = str(payload.get("stage") or "").strip()
    if payload.get("status"):
        filt["status"] = str(payload.get("status") or "").strip()
    if payload.get("client_ids"):
        ids = payload.get("client_ids") or []
        if isinstance(ids, str):
            ids = [x.strip() for x in ids.split(",") if x.strip()]
        if isinstance(ids, list):
            filt["ids"] = [str(x).strip() for x in ids if str(x).strip()]

    try:
        crm = _crm_load(uname)
        clients = list((crm.get("clients") or {}).values())
        recipients = [c for c in clients if _crm_client_matches_filter(c, filt)]

        if len(recipients) > 250:
            return jsonify({"ok": False, "error": "Too many recipients (cap 250). Narrow your filter."}), 400

        if dry_run:
            return jsonify({"ok": True, "count": len(recipients), "sent": 0, "failed": 0, "results": []})

        sent = 0
        failed = 0
        results = []

        for c in recipients:
            phone = (c.get("phone") or "").strip()
            if not phone:
                failed += 1
                results.append({"client_id": c.get("id",""), "ok": False, "error": "Missing phone"})
                continue

            ctx = {"name": c.get("name", ""), "company": c.get("company", "")}
            body = _safe_render(body_t, ctx)

            ok_send, err = _crm_try_send_sms(uname, phone, body)
            if ok_send:
                sent += 1
            else:
                failed += 1
            results.append({"client_id": c.get("id",""), "ok": bool(ok_send), "error": err})

        _crm_log_message(uname, {"type": "broadcast_sms", "filter": filt, "sent": sent, "failed": failed})
        return jsonify({"ok": True, "count": len(recipients), "sent": sent, "failed": failed, "results": results})

    except Exception as e:
        return jsonify({"ok": False, "error": str(e) or "Broadcast failed"}), 500




@app.post("/api/crm/tasks")
def api_crm_task_create():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(silent=True) or {}
    title = (payload.get("title") or "").strip()
    if not title:
        return jsonify({"ok": False, "error": "Title is required"}), 400
    due = (payload.get("due") or "").strip()  # ISO string
    crm = _crm_load(uname)
    tid = _crm_new_id("t")
    task = {
        "id": tid,
        "title": title,
        "client_id": (payload.get("client_id") or "").strip(),
        "status": (payload.get("status") or "open").strip(),
        "priority": (payload.get("priority") or "normal").strip(),
        "due": due,
        "notes": (payload.get("notes") or "").strip(),
        "created_at": now_iso(),
        "updated_at": now_iso(),
    }
    crm["tasks"][tid] = task
    _crm_save(uname, crm)
    return jsonify({"ok": True, "task": task})

@app.get("/api/crm/tasks")
def api_crm_tasks_list():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    crm = _crm_load(uname)
    tasks = list((crm.get("tasks") or {}).values())
    status = (request.args.get("status") or "").strip()
    if status:
        tasks = [t for t in tasks if (t.get("status") or "") == status]
    # sort due asc then created desc
    def _key(t):
        return (t.get("due") or "9999", t.get("created_at") or "")
    tasks.sort(key=_key)
    return jsonify({"ok": True, "tasks": tasks})

@app.post("/api/crm/tasks/<task_id>")
def api_crm_task_update(task_id: str):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(silent=True) or {}
    crm = _crm_load(uname)
    tasks = crm.get("tasks") or {}
    if task_id not in tasks or not isinstance(tasks[task_id], dict):
        return jsonify({"ok": False, "error": "Task not found"}), 404
    t = tasks[task_id]
    for k in ["title","client_id","status","priority","due","notes"]:
        if k in payload:
            t[k] = (payload.get(k) or "").strip()
    t["updated_at"] = now_iso()
    tasks[task_id] = t
    crm["tasks"] = tasks
    _crm_save(uname, crm)
    return jsonify({"ok": True, "task": t})

@app.delete("/api/crm/tasks/<task_id>")
def api_crm_task_delete(task_id: str):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    crm = _crm_load(uname)
    tasks = crm.get("tasks") or {}
    tasks.pop(task_id, None)
    crm["tasks"] = tasks
    _crm_save(uname, crm)
    return jsonify({"ok": True})

@app.post("/api/crm/sequences")
def api_crm_sequence_create():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "Name is required"}), 400
    steps = payload.get("steps") or []
    if isinstance(steps, str):
        # allow a simple newline format: each line "delay_days|email|Subject|Body"
        parsed = []
        for ln in steps.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            parts = ln.split("|")
            if len(parts) >= 4:
                parsed.append({"delay_days": int(parts[0] or 0), "channel": parts[1].strip() or "email", "subject": parts[2].strip(), "body": "|".join(parts[3:]).strip()})
        steps = parsed
    if not isinstance(steps, list) or not steps:
        return jsonify({"ok": False, "error": "At least one step is required"}), 400
    clean_steps = []
    for st in steps[:25]:
        if not isinstance(st, dict):
            continue
        clean_steps.append({
            "delay_days": int(st.get("delay_days") or 0),
            "channel": (st.get("channel") or "email").strip().lower(),
            "subject": (st.get("subject") or "").strip(),
            "body": (st.get("body") or "").strip(),
        })
    if not clean_steps:
        return jsonify({"ok": False, "error": "Invalid steps"}), 400

    crm = _crm_load(uname)
    sid = _crm_new_id("seq")
    seq = {
        "id": sid,
        "name": name,
        "default_subject": (payload.get("default_subject") or "").strip(),
        "steps": clean_steps,
        "created_at": now_iso(),
        "updated_at": now_iso(),
    }
    crm["sequences"][sid] = seq
    _crm_save(uname, crm)
    return jsonify({"ok": True, "sequence": seq})

@app.get("/api/crm/sequences")
def api_crm_sequences_list():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    crm = _crm_load(uname)
    seqs = list((crm.get("sequences") or {}).values())
    seqs.sort(key=lambda s: (s.get("updated_at") or ""), reverse=True)
    return jsonify({"ok": True, "sequences": seqs, "enrollments": list((crm.get("enrollments") or {}).values())})

@app.post("/api/crm/enroll")
def api_crm_enroll_client():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(silent=True) or {}
    client_id = (payload.get("client_id") or "").strip()
    seq_id = (payload.get("sequence_id") or "").strip()
    if not client_id or not seq_id:
        return jsonify({"ok": False, "error": "Missing client_id or sequence_id"}), 400
    crm = _crm_load(uname)
    if client_id not in (crm.get("clients") or {}):
        return jsonify({"ok": False, "error": "Client not found"}), 404
    if seq_id not in (crm.get("sequences") or {}):
        return jsonify({"ok": False, "error": "Sequence not found"}), 404
    eid = _crm_new_id("enr")
    now = datetime.utcnow().isoformat() + "Z"
    enrollment = {
        "id": eid,
        "client_id": client_id,
        "sequence_id": seq_id,
        "status": "active",
        "step_index": 0,
        "next_due": now,
        "created_at": now,
        "updated_at": now,
    }
    crm["enrollments"][eid] = enrollment
    _crm_save(uname, crm)
    return jsonify({"ok": True, "enrollment": enrollment})

@app.post("/api/crm/calendar/create_event")
def api_crm_calendar_create_event():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    payload = request.get_json(silent=True) or {}
    title = (payload.get("title") or "").strip()
    start_iso = (payload.get("start_iso") or "").strip()
    end_iso = (payload.get("end_iso") or "").strip()
    timezone = (payload.get("timezone") or "America/New_York").strip()
    if not title or not start_iso or not end_iso:
        return jsonify({"ok": False, "error": "Missing title/start_iso/end_iso"}), 400
    access_token, reason = _calendar_creds_for_user(u)
    if not access_token:
        return jsonify({"ok": False, "error": reason}), 400
    try:
        event = _calendar_create_event(access_token, title=title, start_iso=start_iso, end_iso=end_iso, timezone=timezone, attendees=payload.get("attendees") or [], description=(payload.get("description") or ""), location=(payload.get("location") or ""))
        return jsonify({"ok": True, "event": event})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/passes/run", methods=["POST"])
def api_passes_run():
    username = _get_session_username()
    payload = request.get_json(silent=True) or {}
    pass_name = (payload.get("pass") or "").strip().lower()
    seat = (payload.get("seat") or "").strip()
    text_in = payload.get("text") or ""
    if not isinstance(text_in, str):
        text_in = str(text_in)

    allowed = {"risk", "scale", "failure", "assumptions", "constraints", "optimize"}
    if pass_name not in allowed:
        return jsonify({"ok": False, "error": "Unknown pass"}), 400

    # Guardrails: keep request size reasonable
    if len(text_in.encode("utf-8", errors="ignore")) > 200_000:
        # Trim from the front so we keep the most recent parts
        text_in = text_in[-180_000:]

    profile = _load_operator_profile(username)
    operator_ctx = (
        f"Operator display name: {(profile.get('display_name') or 'Operator').strip()}\n"
        f"Business: {(profile.get('business') or '').strip()}\n"
        f"Offers: {(profile.get('offers') or '').strip()}\n"
        f"Audience: {(profile.get('audience') or '').strip()}\n"
        f"Goals: {(profile.get('goals') or '').strip()}\n"
        f"Constraints: {(profile.get('constraints') or '').strip()}\n"
        f"Tone rules: {(profile.get('tone_rules') or '').strip()}\n"
    ).strip()

    base_system = (
        "You are a tactical analysis engine inside an agentic command center. "
        "You run fast, practical analysis passes on the provided text. "
        "Be concrete and operator-ready. No fluff. "
        "Do not invent facts. If something is unknown, say so plainly. "
        "Use short headings and bullets. Avoid long preambles. "
        "Do not use em dashes."
    )

    pass_instructions = {
        "risk": (
            "RISK ASSESSMENT. Identify the top risks in executing the plan or advice in the text. "
            "Include: Risk level (Low, Medium, High), risk categories, and mitigations. "
            "End with Stop conditions: 2 to 4 conditions where the operator should pause before proceeding."
        ),
        "scale": (
            "SCALABILITY RANKING. Score scalability from 1 to 10. "
            "Name the primary bottleneck and the first thing that breaks when volume doubles. "
            "Give 3 scale levers that reduce operator time or increase throughput."
        ),
        "failure": (
            "FAILURE SIMULATOR. Produce 5 realistic failure scenarios. "
            "For each: Failure mode, early warning signal, prevention, recovery step. "
            "Prioritize the most likely failures first."
        ),
        "assumptions": (
            "ASSUMPTION SCAN. List key assumptions implied by the text. "
            "For each: assumption, confidence (High, Medium, Low), and the fastest validation test."
        ),
        "constraints": (
            "CONSTRAINT SCAN. Identify constraints and dependencies. "
            "Classify each as People, Time, Tools, Data, Policy, or Market. "
            "For each: why it is a constraint and one practical workaround."
        ),
        "optimize": (
            "OPTIMIZATION PASS. Rewrite the plan or output into a clearer, higher leverage version. "
            "Preserve intent. Reduce steps. Remove redundancy. "
            "End with: Next 3 actions the operator should take."
        ),
    }

    system = base_system + "\n\n" + "Operator context:\n" + operator_ctx + "\n\n" + pass_instructions[pass_name]
    user_msg = f"Seat: {seat or 'N/A'}\n\nTEXT TO ANALYZE:\n{text_in}"

    try:
        result = call_llm(system, [{"role": "user", "content": user_msg}], temperature=0.2)
        return jsonify({"ok": True, "result": result})
    except Exception as e:
        code, msg = _classify_openai_error(e)
        return jsonify({"ok": False, "error": msg}), code


def _load_operator_profile(username: str) -> Dict[str, Any]:
    """Per-user operator profile teammates can reference."""
    try:
        OPERATOR_PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    path = OPERATOR_PROFILE_DIR / f"{(username or 'anon')}.json"
    if not path.exists():
        return {
            "display_name": "Operator",
            "business": "",
            "offers": "",
            "audience": "",
            "goals": "",
            "constraints": "",
            "tone_rules": "",
            "notes": "",
            "updated_at": ""
        }
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {
            "display_name": "Operator",
            "business": "",
            "offers": "",
            "audience": "",
            "goals": "",
            "constraints": "",
            "tone_rules": "",
            "notes": "",
            "updated_at": ""
        }

def _save_operator_profile(username: str, profile: Dict[str, Any]) -> None:
    try:
        OPERATOR_PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    now = datetime.utcnow().isoformat() + "Z"
    profile = dict(profile or {})
    profile["updated_at"] = now
    path = OPERATOR_PROFILE_DIR / f"{(username or 'anon')}.json"
    path.write_text(json.dumps(profile, ensure_ascii=False, indent=2), encoding="utf-8")


# =========================
# CRM WOW FEATURES (Lead Lab / Social Studio / Offer Builder / Playbooks)
# =========================

def _crm_extract_domain(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"^https?://", "", s)
    s = re.sub(r"^www\.", "", s)
    s = s.split("/")[0].strip()
    return s

def _crm_name_bits(name: str) -> Tuple[str, str]:
    bits = [x for x in re.split(r"\s+", (name or "").strip()) if x]
    if not bits:
        return ("", "")
    first = re.sub(r"[^a-z]", "", bits[0].lower())
    last = re.sub(r"[^a-z]", "", bits[-1].lower()) if len(bits) > 1 else ""
    return first, last

def _crm_email_candidates(name: str, domain: str) -> List[Dict[str, Any]]:
    domain = _crm_extract_domain(domain)
    if not domain:
        return []
    first, last = _crm_name_bits(name)
    if not first and not last:
        first = "hello"
    fi = first[:1]
    li = last[:1]
    vals = []
    def add(local: str, score: float):
        if local:
            vals.append({"email": f"{local}@{domain}", "confidence": round(float(score), 2), "status": "estimated"})
    add(first, 0.62)
    add(f"{first}.{last}" if first and last else "", 0.76)
    add(f"{fi}{last}" if fi and last else "", 0.71)
    add(f"{first}{li}" if first and li else "", 0.66)
    add("hello", 0.48)
    add("info", 0.42)
    out = []
    seen = set()
    for row in sorted(vals, key=lambda x: x["confidence"], reverse=True):
        email = row["email"]
        if email in seen:
            continue
        seen.add(email)
        out.append(row)
    return out

def _crm_parse_lead_source_rows(source_text: str) -> List[Dict[str, Any]]:
    rows = []
    for raw in (source_text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if "|" in line:
            parts = [p.strip() for p in line.split("|")]
        else:
            parts = [p.strip() for p in re.split(r",|\t", line)]
        parts = [p for p in parts if p]
        item = {"name": "", "company": "", "domain": "", "title": "", "notes": ""}
        if len(parts) == 1:
            item["company"] = parts[0]
        elif len(parts) == 2:
            item["company"], item["domain"] = parts[0], parts[1]
        elif len(parts) == 3:
            item["name"], item["company"], item["domain"] = parts[0], parts[1], parts[2]
        else:
            item["name"], item["company"], item["domain"], item["title"] = parts[0], parts[1], parts[2], parts[3]
            if len(parts) > 4:
                item["notes"] = " | ".join(parts[4:])
        rows.append(item)
    return rows

def _crm_llm_or_fallback(system: str, prompt: str, fallback: str) -> str:
    try:
        reply = call_llm(system, [{"role": "user", "content": prompt}], temperature=0.7)
        reply = (reply or "").strip()
        if reply:
            return reply
    except Exception:
        pass
    return fallback


def _crm_extract_json_block(text: str) -> str:
    s = (text or '').strip()
    if not s:
        return ''
    m = re.search(r"```(?:json)?\s*([\s\S]*?)```", s, flags=re.I)
    if m:
        s = m.group(1).strip()
    start = s.find('[')
    end = s.rfind(']')
    if start != -1 and end != -1 and end > start:
        return s[start:end+1]
    start = s.find('{')
    end = s.rfind('}')
    if start != -1 and end != -1 and end > start:
        return s[start:end+1]
    return s


def _crm_response_text(resp: Any) -> str:
    try:
        txt = resp.choices[0].message.content
        if isinstance(txt, str) and txt.strip():
            return txt.strip()
    except Exception:
        pass
    try:
        txt = getattr(resp, 'output_text', None)
        if isinstance(txt, str) and txt.strip():
            return txt.strip()
    except Exception:
        pass
    try:
        data = resp.model_dump() if hasattr(resp, 'model_dump') else resp
    except Exception:
        data = resp
    parts: List[str] = []
    try:
        outputs = (data or {}).get('output') or []
        for item in outputs:
            for c in (item.get('content') or []):
                if isinstance(c, dict):
                    if c.get('type') in ('output_text', 'text') and c.get('text'):
                        parts.append(str(c.get('text')))
                    elif c.get('type') == 'message' and c.get('content'):
                        for inner in (c.get('content') or []):
                            if isinstance(inner, dict) and inner.get('text'):
                                parts.append(str(inner.get('text')))
    except Exception:
        pass
    return '\n'.join([p for p in parts if p]).strip()


def _crm_openai_web_search(query: str, niche: str, location: str, max_results: int = 12) -> List[Dict[str, Any]]:
    """Use OpenAI web search to find likely prospect businesses.

    Returns lightweight candidate rows that are later validated against public pages.
    This is additive: if the user's key or model does not support web search, we quietly fall back.
    """
    query = (query or '').strip()
    if not query:
        return []
    try:
        client = get_openai_client()
    except Exception:
        return []

    model = os.getenv('LEAD_LAB_WEB_MODEL', 'gpt-4o-mini')
    system = (
        'You are a precise B2B lead researcher. Use web search. Find real businesses that match the request. '
        'Return ONLY a JSON array. Each item must be an object with keys: '
        'name, company, website, phone, email, notes. '
        'Only include likely real prospects, not search engines, portals, directories, marketplaces, social networks, review sites, or aggregators. '
        'Prefer official business websites. If email or phone is unknown, use an empty string. '
        f'Return at most {max(1, min(25, int(max_results or 12)))} items.'
    )
    user = (
        f'Niche: {niche or "businesses"}\n'
        f'Location: {location or "target area"}\n'
        f'Search query: {query}\n'
        'Requirements: prioritize official websites and businesses clearly serving the niche and location. '
        'Do not invent contact details. Return JSON only.'
    )

    try:
        resp = client.chat.completions.create(
            model=os.getenv('LEAD_LAB_WEB_MODEL', 'gpt-4o-mini'),
            messages=[
                {'role': 'system', 'content': system},
                {'role': 'user', 'content': user},
            ],
            temperature=0.1,
            timeout=45,
        )
    except Exception:
        # Older SDKs / unsupported accounts should not break Lead Lab.
        return []

    txt = _crm_response_text(resp)
    raw = _crm_extract_json_block(txt)
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except Exception:
        return []
    if isinstance(data, dict):
        data = data.get('items') or data.get('results') or []
    if not isinstance(data, list):
        return []

    out: List[Dict[str, Any]] = []
    seen = set()
    for row in data:
        if not isinstance(row, dict):
            continue
        website = (row.get('website') or row.get('url') or '').strip()
        phone = _crm_clean_phone(row.get('phone') or '')
        email = (row.get('email') or '').strip().lower()
        domain = _crm_extract_domain(urlparse(website).netloc or website)
        if not domain or _crm_is_blocked_domain(domain):
            continue
        key = domain.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append({
            'url': website if website.startswith('http') else ('https://' + domain),
            'title': (row.get('company') or row.get('name') or domain).strip(),
            'domain': domain,
            'snippet': (row.get('notes') or '').strip(),
            'name_hint': (row.get('name') or '').strip(),
            'company_hint': (row.get('company') or '').strip(),
            'phone_hint': phone,
            'email_hint': email,
        })
        if len(out) >= max_results:
            break
    return out

_CRM_SEARCH_BLOCKED_DOMAINS = {
    "duckduckgo.com", "google.com", "bing.com", "yahoo.com", "search.brave.com",
    "facebook.com", "instagram.com", "x.com", "twitter.com", "linkedin.com", "youtube.com",
    "realtor.com", "zillow.com", "trulia.com", "redfin.com", "homes.com", "movoto.com",
    "yelp.com", "yellowpages.com", "mapquest.com", "maps.apple.com",
    "whitepages.com", "angi.com", "angieslist.com", "thumbtack.com", "houzz.com",
    "homeadvisor.com", "bbb.org", "superpages.com", "manta.com", "alignable.com",
    "indeed.com", "glassdoor.com", "craigslist.org", "tripadvisor.com",
    "wikipedia.org", "reddit.com", "quora.com", "amazonaws.com",
}
_CRM_STATE_CITY_MAP = {
    "new jersey": ["Newark, NJ", "Jersey City, NJ", "Paterson, NJ", "Elizabeth, NJ", "Edison, NJ", "Woodbridge, NJ", "Toms River, NJ", "Trenton, NJ", "Clifton, NJ", "Hoboken, NJ", "Princeton, NJ", "Cherry Hill, NJ", "Morristown, NJ", "Westfield, NJ", "Summit, NJ", "Montclair, NJ", "Middletown, NJ", "Bridgewater, NJ", "Paramus, NJ", "Hackensack, NJ", "Bergen County, NJ", "Monmouth County, NJ", "Ocean County, NJ", "Essex County, NJ"],
    "nj": ["Newark, NJ", "Jersey City, NJ", "Paterson, NJ", "Elizabeth, NJ", "Edison, NJ", "Woodbridge, NJ", "Toms River, NJ", "Trenton, NJ", "Clifton, NJ", "Hoboken, NJ", "Princeton, NJ", "Cherry Hill, NJ", "Morristown, NJ", "Westfield, NJ", "Summit, NJ", "Montclair, NJ", "Middletown, NJ", "Bridgewater, NJ", "Paramus, NJ", "Hackensack, NJ", "Bergen County, NJ", "Monmouth County, NJ", "Ocean County, NJ", "Essex County, NJ"],
}
_CRM_BAD_PERSON_WORDS = {"realty", "realtor", "realtors", "estate", "homes", "home", "properties", "property", "group", "team", "broker", "brokerage", "real", "contact", "about", "welcome", "new", "jersey", "nj", "duckduckgo", "search"}


def _crm_is_blocked_domain(domain: str) -> bool:
    d = _crm_extract_domain(domain)
    if not d:
        return True
    for item in _CRM_SEARCH_BLOCKED_DOMAINS:
        if d == item or d.endswith("." + item):
            return True
    return False


def _crm_clean_phone(phone: str) -> str:
    digits = re.sub(r"\D", "", phone or "")
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    if len(digits) == 10:
        return f"({digits[:3]}) {digits[3:6]}-{digits[6:]}"
    return (phone or "").strip()


def _crm_extract_emails_from_text(text: str) -> List[str]:
    vals = re.findall(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", text or "", flags=re.I)
    out = []
    seen = set()
    for e in vals:
        e = e.strip(" .,;:>)]}\"'\n\r\t").lower()
        if any(x in e for x in ["example.com", ".png", ".jpg", ".jpeg", ".gif", ".webp", "sentry.io"]):
            continue
        if e not in seen:
            seen.add(e)
            out.append(e)
    return out


def _crm_extract_phones_from_text(text: str) -> List[str]:
    vals = re.findall(r"(?:\+?1[\s\-.]?)?(?:\(?\d{3}\)?[\s\-.]?)\d{3}[\s\-.]?\d{4}", text or "")
    out = []
    seen = set()
    for v in vals:
        c = _crm_clean_phone(v)
        digits = re.sub(r"\D", "", c)
        if len(digits) == 10 and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _crm_best_person_name(candidates: List[str], company: str = "") -> str:
    company_words = set(re.findall(r"[a-z]+", (company or "").lower()))
    for raw in candidates:
        val = re.sub(r"\s+", " ", (raw or "").strip(" |,-"))
        if not val:
            continue
        parts = [p for p in re.split(r"\s+", val) if p]
        if len(parts) < 2 or len(parts) > 4:
            continue
        bad = False
        clean_parts = []
        for p in parts:
            letters = re.sub(r"[^A-Za-z]", "", p)
            if not letters:
                bad = True
                break
            low = letters.lower()
            if low in _CRM_BAD_PERSON_WORDS or low in company_words:
                bad = True
                break
            if not letters[0].isupper() and not p[:1].isupper():
                bad = True
                break
            clean_parts.append(letters.capitalize())
        if bad:
            continue
        joined = " ".join(clean_parts)
        if len(joined) >= 5:
            return joined
    return ""


def _crm_guess_company(title: str, domain: str) -> str:
    title = re.sub(r"\s+", " ", (title or "").strip())
    if title:
        for piece in re.split(r"\||•|-|—|–", title):
            piece = piece.strip()
            if not piece:
                continue
            words = set(re.findall(r"[a-z]+", piece.lower()))
            if words & {"contact", "about", "search", "duckduckgo", "google", "bing"}:
                continue
            if len(piece) >= 3:
                return piece[:140]
    d = _crm_extract_domain(domain)
    if not d:
        return ""
    stem = d.split(".")[0].replace("-", " ").replace("_", " ").strip()
    return stem.title()


def _crm_fetch_text_url(url: str, timeout: int = 8) -> Tuple[str, str]:
    try:
        import requests
        headers = {"User-Agent": "Mozilla/5.0 (compatible; SimplyAgenticLeadLab/1.0; +https://example.com)"}
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        ctype = (r.headers.get("Content-Type") or "").lower()
        if r.status_code >= 400:
            return "", r.url or url
        if "text/html" not in ctype and "application/xhtml+xml" not in ctype and ctype:
            return "", r.url or url
        return r.text or "", r.url or url
    except Exception:
        return "", url


def _crm_same_domain(url_a: str, url_b: str) -> bool:
    da = _crm_extract_domain(urlparse(url_a).netloc or url_a)
    db = _crm_extract_domain(urlparse(url_b).netloc or url_b)
    return bool(da and db and da == db)


def _crm_find_contact_links(html: str, base_url: str) -> List[str]:
    out = []
    seen = set()
    if not html:
        return out
    if BeautifulSoup is not None:
        try:
            soup = BeautifulSoup(html, "html.parser")
            for a in soup.find_all("a", href=True):
                href = (a.get("href") or "").strip()
                label = " ".join([a.get_text(" ", strip=True), href]).lower()
                if not any(k in label for k in ["contact", "about", "agent", "team", "staff", "bio"]):
                    continue
                full = urljoin(base_url, href)
                if full.startswith("mailto:") or full.startswith("tel:"):
                    continue
                if not _crm_same_domain(full, base_url):
                    continue
                if full not in seen:
                    seen.add(full)
                    out.append(full)
        except Exception:
            pass
    return out[:3]


def _crm_parse_page_signals(html: str, url: str, niche: str, location: str) -> Dict[str, Any]:
    title = ""
    headings = []
    visible_text = re.sub(r"<script.*?</script>|<style.*?</style>", " ", html or "", flags=re.I | re.S)
    visible_text = re.sub(r"<[^>]+>", " ", visible_text)
    visible_text = re.sub(r"\s+", " ", visible_text).strip()
    if BeautifulSoup is not None and html:
        try:
            soup = BeautifulSoup(html, "html.parser")
            if soup.title and soup.title.string:
                title = soup.title.string.strip()
            if not title:
                og = soup.find("meta", attrs={"property": "og:title"}) or soup.find("meta", attrs={"name": "title"})
                if og and og.get("content"):
                    title = og.get("content").strip()
            headings = [x.get_text(" ", strip=True) for x in soup.find_all(["h1", "h2"], limit=8)]
        except Exception:
            pass
    emails = _crm_extract_emails_from_text((html or "") + "\n" + visible_text)
    phones = _crm_extract_phones_from_text((html or "") + "\n" + visible_text)
    company = _crm_guess_company(title or (headings[0] if headings else ""), url)
    person_name = _crm_best_person_name(([title] if title else []) + headings, company=company)
    text_l = (title + " " + " ".join(headings) + " " + visible_text[:5000]).lower()
    niche_hit = bool(niche and all(tok in text_l for tok in [t for t in re.findall(r"[a-z0-9]+", niche.lower())[:2]])) or any(k in text_l for k in ["realtor", "real estate", "broker", "brokerage", "homes for sale", "properties"]) 
    location_hit = bool(location and any(tok in text_l for tok in re.findall(r"[a-z0-9]+", location.lower())[:2]))
    return {
        "title": title,
        "headings": headings,
        "visible_text": visible_text,
        "emails": emails,
        "phones": phones,
        "company": company,
        "name": person_name,
        "niche_hit": bool(niche_hit),
        "location_hit": bool(location_hit),
    }


def _crm_merge_email_candidates(public_emails: List[str], name: str, domain: str) -> List[Dict[str, Any]]:
    out = []
    seen = set()
    for e in public_emails[:5]:
        if e not in seen:
            seen.add(e)
            out.append({"email": e, "confidence": 0.97, "status": "public"})
    for row in _crm_email_candidates(name, domain):
        if row.get("email") not in seen:
            seen.add(row.get("email"))
            out.append(row)
    return out[:5]


def _crm_score_candidate(candidate: Dict[str, Any], niche: str, location: str) -> int:
    score = 35
    if candidate.get("website"):
        score += 10
    if candidate.get("phone"):
        score += 18
    public_emails = [x for x in (candidate.get("email_candidates") or []) if x.get("status") == "public"]
    if public_emails:
        score += 25
    if candidate.get("name") and candidate.get("name") != candidate.get("company"):
        score += 12
    if candidate.get("niche_hit"):
        score += 8
    if candidate.get("location_hit"):
        score += 8
    if niche and any(tok in (candidate.get("notes") or "").lower() for tok in re.findall(r"[a-z0-9]+", niche.lower())[:2]):
        score += 5
    return max(1, min(99, score))


def _crm_ddg_search(query: str, max_results: int = 12) -> List[Dict[str, str]]:
    try:
        import requests
        headers = {"User-Agent": "Mozilla/5.0 (compatible; SimplyAgenticLeadLab/1.0; +https://example.com)"}
        r = requests.post("https://html.duckduckgo.com/html/", data={"q": query}, headers=headers, timeout=18)
        html = r.text or ""
    except Exception:
        return []
    out = []
    seen = set()
    if BeautifulSoup is not None and html:
        try:
            soup = BeautifulSoup(html, "html.parser")
            for a in soup.select("a.result__a"):
                href = (a.get("href") or "").strip()
                title = a.get_text(" ", strip=True)
                if not href:
                    continue
                href = unquote(href)
                if href.startswith("//"):
                    href = "https:" + href
                if href.startswith("/") and "uddg=" in href:
                    m = re.search(r"uddg=([^&]+)", href)
                    if m:
                        href = unquote(m.group(1))
                domain = _crm_extract_domain(urlparse(href).netloc or href)
                if not href.startswith("http") or _crm_is_blocked_domain(domain):
                    continue
                if domain in seen:
                    continue
                seen.add(domain)
                out.append({"url": href, "title": title, "domain": domain})
                if len(out) >= max_results:
                    break
        except Exception:
            pass
    return out


def _crm_build_queries(niche: str, location: str, lead_count: int, search_mode: str) -> List[str]:
    niche = (niche or "businesses").strip()
    location = (location or "United States").strip()
    mode = (search_mode or "balanced").strip().lower()
    locations = [location]
    loc_key = location.strip().lower()
    if loc_key in _CRM_STATE_CITY_MAP:
        extra = _CRM_STATE_CITY_MAP[loc_key]
        if mode == "precision":
            locations.extend(extra[:4])
        elif mode == "broad":
            locations.extend(extra[:12])
        else:
            locations.extend(extra[:8])
    _is_realty = bool(re.search(r'real.?estate|realtor|broker|realty', niche, flags=re.I))
    templates = ['{niche} in {loc} contact', '{loc} {niche} office', '{loc} {niche} team', '{loc} {niche} website']
    if _is_realty:
        templates += ['{loc} {niche} realtor broker', '{loc} {niche} real estate agent']
    queries = []
    seen = set()
    for loc in locations:
        for tpl in templates:
            q = tpl.format(niche=niche, loc=loc).strip()
            if q.lower() not in seen:
                seen.add(q.lower())
                queries.append(q)
    max_q = 8 if mode == "precision" else (14 if mode == "balanced" else 20)
    return queries[:max_q]


def _crm_enrich_result(result: Dict[str, str], niche: str, location: str, query: str) -> Optional[Dict[str, Any]]:
    url = result.get("url") or ""
    domain = result.get("domain") or _crm_extract_domain(urlparse(url).netloc or url)
    if not url or _crm_is_blocked_domain(domain):
        return None
    html, final_url = _crm_fetch_text_url(url)
    website = f"https://{_crm_extract_domain(urlparse(final_url or url).netloc or final_url or url)}" if (final_url or url) else (f"https://{domain}" if domain else "")
    hint_name = (result.get('name_hint') or '').strip()
    hint_company = (result.get('company_hint') or '').strip()
    hint_phone = _crm_clean_phone(result.get('phone_hint') or '')
    hint_email = (result.get('email_hint') or '').strip().lower()

    if not html:
        candidate = _crm_fallback_candidate_from_result(result, niche, location, query)
        if not candidate:
            return None
        if hint_name and (candidate.get('name') == candidate.get('company') or not candidate.get('name')):
            candidate['name'] = hint_name
        if hint_company:
            candidate['company'] = hint_company
        if hint_phone and not candidate.get('phone'):
            candidate['phone'] = hint_phone
        if hint_email and not candidate.get('email'):
            candidate['email'] = hint_email
        candidate['website'] = website or candidate.get('website') or ''
        candidate['email_candidates'] = _crm_merge_email_candidates(([hint_email] if hint_email else []), candidate.get('name') or candidate.get('company') or '', domain)
        candidate['score'] = max(candidate.get('score') or 0, _crm_score_candidate(candidate, niche, location))
        return candidate

    signals = _crm_parse_page_signals(html, final_url, niche, location)
    emails = list(signals.get("emails") or [])
    phones = list(signals.get("phones") or [])
    if hint_email and hint_email not in emails:
        emails.insert(0, hint_email)
    if hint_phone and hint_phone not in phones:
        phones.insert(0, hint_phone)
    for link in _crm_find_contact_links(html, final_url):
        sub_html, _ = _crm_fetch_text_url(link)
        if not sub_html:
            continue
        sub = _crm_parse_page_signals(sub_html, link, niche, location)
        for e in sub.get("emails") or []:
            if e not in emails:
                emails.append(e)
        for p in sub.get("phones") or []:
            if p not in phones:
                phones.append(p)
        if not signals.get("name") and sub.get("name"):
            signals["name"] = sub.get("name")
        if not signals.get("company") and sub.get("company"):
            signals["company"] = sub.get("company")
        signals["niche_hit"] = signals.get("niche_hit") or sub.get("niche_hit")
        signals["location_hit"] = signals.get("location_hit") or sub.get("location_hit")
    name = signals.get("name") or hint_name or ""
    company = signals.get("company") or hint_company or _crm_guess_company(result.get("title") or "", domain)
    title = "Realtor" if re.search(r"real estate|realtor|broker", niche or "", flags=re.I) else "Contact"
    email_candidates = _crm_merge_email_candidates(emails, name or company, domain)
    candidate = {
        "name": name or company,
        "company": company,
        "title": title,
        "domain": domain,
        "website": website,
        "phone": phones[0] if phones else "",
        "email": emails[0] if emails else "",
        "email_candidates": email_candidates,
        "niche_hit": bool(signals.get("niche_hit")),
        "location_hit": bool(signals.get("location_hit")),
        "notes": f"Found from public web search for {niche or 'lead'} in {location or 'target area'}. Source query: {query}",
        "source_query": query,
    }
    candidate["score"] = _crm_score_candidate(candidate, niche, location)
    if candidate["score"] < 40:
        return None
    return candidate


def _crm_items_from_rows(rows: List[Dict[str, Any]], niche: str, location: str) -> List[Dict[str, Any]]:
    items = []
    for row in rows[:200]:
        domain = _crm_extract_domain(row.get("domain") or row.get("company") or "")
        name = (row.get("name") or "").strip()
        company = (row.get("company") or "").strip() or (domain.split(".")[0].replace("-", " ").title() if domain else "")
        title = (row.get("title") or "").strip() or ("Realtor" if re.search(r"real estate|realtor|broker", niche or "", flags=re.I) else "Contact")
        if not name and company:
            name = company
        email_candidates = _crm_email_candidates(name, domain)
        item = {
            "name": name,
            "company": company,
            "title": title,
            "domain": domain,
            "website": f"https://{domain}" if domain else "",
            "phone": "",
            "email": ((email_candidates[0] or {}).get("email") if email_candidates else "") or "",
            "email_candidates": email_candidates,
            "niche_hit": True,
            "location_hit": bool(location),
            "notes": (row.get("notes") or "") + (f"\nSeed row for {niche} in {location}." if niche or location else "\nSeed row."),
            "source_query": "seed rows",
        }
        item["score"] = _crm_score_candidate(item, niche, location)
        items.append(item)
    return items


def _crm_bing_search(query: str, max_results: int = 12) -> List[Dict[str, str]]:
    try:
        import requests
        from urllib.parse import quote_plus
        headers = {"User-Agent": "Mozilla/5.0 (compatible; SimplyAgenticLeadLab/1.0; +https://example.com)"}
        url = "https://www.bing.com/search?q=" + quote_plus(query)
        r = requests.get(url, headers=headers, timeout=18)
        html = r.text or ""
    except Exception:
        return []
    out, seen = [], set()
    if BeautifulSoup is None or not html:
        return out
    try:
        soup = BeautifulSoup(html, "html.parser")
        for li in soup.select("li.b_algo"):
            a = li.select_one("h2 a") or li.select_one("a")
            if not a:
                continue
            href = (a.get("href") or "").strip()
            title = a.get_text(" ", strip=True)
            snippet_el = li.select_one(".b_caption p") or li.select_one("p")
            snippet = snippet_el.get_text(" ", strip=True) if snippet_el else ""
            domain = _crm_extract_domain(urlparse(href).netloc or href)
            if not href.startswith("http") or not domain or _crm_is_blocked_domain(domain) or domain in seen:
                continue
            seen.add(domain)
            out.append({"url": href, "title": title, "domain": domain, "snippet": snippet})
            if len(out) >= max_results:
                break
    except Exception:
        return out
    return out


def _crm_public_search(query: str, max_results: int = 18, niche: str = "", location: str = "") -> List[Dict[str, str]]:
    merged, seen = [], set()
    search_fns = [lambda q, max_results=max_results: _crm_openai_web_search(q, niche=niche, location=location, max_results=max_results)]
    search_fns.extend([_crm_bing_search, _crm_ddg_search])
    for fn in search_fns:
        try:
            rows = fn(query, max_results=max_results)
        except TypeError:
            try:
                rows = fn(query)
            except Exception:
                rows = []
        except Exception:
            rows = []
        for row in rows:
            dom = row.get("domain") or ""
            if not dom or dom in seen or _crm_is_blocked_domain(dom):
                continue
            seen.add(dom)
            merged.append(row)
            if len(merged) >= max_results:
                return merged
    return merged


def _crm_parse_specific_areas(val: str) -> List[str]:
    raw = re.split(r"[\n,;|]+", val or "")
    out, seen = [], set()
    for x in raw:
        s = re.sub(r"\s+", " ", (x or "").strip())
        if not s:
            continue
        k = s.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(s)
    return out[:30]


def _crm_build_queries_v2(niche: str, location: str, lead_count: int, search_mode: str, specific_areas: Optional[List[str]] = None) -> List[str]:
    niche = (niche or "businesses").strip()
    location = (location or "United States").strip()
    mode = (search_mode or "balanced").strip().lower()
    locations = []
    if specific_areas:
        locations.extend([x for x in specific_areas if x])
    if location:
        locations.append(location)
    loc_key = location.strip().lower()
    if loc_key in _CRM_STATE_CITY_MAP:
        extra = _CRM_STATE_CITY_MAP[loc_key]
        locations.extend(extra[:4] if mode == "precision" else extra[:10] if mode == "balanced" else extra[:16])
    # de-dupe while preserving order
    deduped, seen = [], set()
    for loc in locations:
        lk = loc.lower()
        if lk not in seen:
            seen.add(lk); deduped.append(loc)
    locations = deduped or [location]
    realtorish = bool(re.search(r"real estate|realtor|broker", niche, flags=re.I))
    templates = [
        '{niche} in {loc}',
        '{loc} {niche}',
        '{niche} {loc} contact',
        '{loc} {niche} office',
        '{loc} {niche} team',
    ]
    if realtorish:
        templates.extend([
            '{loc} realtor',
            '{loc} real estate agent',
            '{loc} real estate broker',
            '{loc} realty group',
            '{loc} homes real estate',
        ])
    queries, seen_q = [], set()
    for loc in locations:
        for tpl in templates:
            q = re.sub(r"\s+", " ", tpl.format(niche=niche, loc=loc)).strip()
            key = q.lower()
            if key in seen_q:
                continue
            seen_q.add(key)
            queries.append(q)
    max_q = 10 if mode == "precision" else (18 if mode == "balanced" else 28)
    return queries[:max_q]


def _crm_fallback_candidate_from_result(result: Dict[str, str], niche: str, location: str, query: str) -> Optional[Dict[str, Any]]:
    domain = result.get("domain") or _crm_extract_domain(urlparse(result.get("url") or "").netloc or result.get("url") or "")
    if not domain or _crm_is_blocked_domain(domain):
        return None
    title = (result.get("title") or "").strip()
    snippet = (result.get("snippet") or "").strip()
    company = _crm_guess_company(title, domain)
    name = _crm_best_person_name([title], company=company)
    notes = f"Found from public web search for {niche or 'lead'} in {location or 'target area'}. Source query: {query}. {snippet}".strip()
    candidate = {
        "name": name or company or domain.split('.')[0].title(),
        "company": company or domain.split('.')[0].title(),
        "title": "Realtor" if re.search(r"real estate|realtor|broker", niche or "", flags=re.I) else "Contact",
        "domain": domain,
        "website": result.get("url") or (f"https://{domain}"),
        "phone": "",
        "email": "",
        "email_candidates": _crm_email_candidates(name or company or domain, domain),
        "niche_hit": True,
        "location_hit": bool(location),
        "notes": notes,
        "source_query": query,
    }
    candidate["score"] = max(40, _crm_score_candidate(candidate, niche, location) - 10)
    return candidate


def _crm_make_lead_from_search_row(row: Dict[str, Any], niche: str, location: str, query: str, min_score: int = 40) -> Optional[Dict[str, Any]]:
    if not isinstance(row, dict):
        return None
    domain = _crm_extract_domain(row.get('domain') or urlparse(row.get('url') or '').netloc or row.get('url') or '')
    if not domain or _crm_is_blocked_domain(domain):
        return None
    website = (row.get('url') or '').strip()
    if not website:
        website = 'https://' + domain
    elif not website.startswith('http'):
        website = 'https://' + domain
    company = (row.get('company_hint') or row.get('title') or '').strip()
    if not company:
        company = _crm_guess_company(row.get('title') or '', domain) or domain.split('.')[0].replace('-', ' ').title()
    name = (row.get('name_hint') or '').strip()
    if not name:
        name = _crm_best_person_name([row.get('title') or '', row.get('snippet') or ''], company=company)
    phone = _crm_clean_phone(row.get('phone_hint') or row.get('phone') or '')
    public_email = ((row.get('email_hint') or row.get('email') or '')).strip().lower()
    email_candidates = _crm_merge_email_candidates(([public_email] if public_email else []), name or company, domain)
    title = 'Realtor' if re.search(r'real estate|realtor|broker', niche or '', flags=re.I) else 'Contact'
    notes = (row.get('snippet') or '').strip()
    score = 55
    if row.get('name_hint'):
        score += 8
    if phone:
        score += 12
    if public_email:
        score += 12
    if any(x.get('status') == 'public' for x in email_candidates):
        score += 6
    if location:
        score += 3
    score = max(int(min_score or 40), min(96, score))
    return {
        'name': name or company,
        'company': company,
        'title': title,
        'domain': domain,
        'website': website,
        'phone': phone,
        'email': public_email,
        'email_candidates': email_candidates,
        'score': score,
        'confidence': score,
        'niche_hit': True,
        'location_hit': bool(location),
        'notes': notes or f'Public web lead for {niche or "business"} in {location or "target area"}',
        'source_query': query,
    }


def _crm_discover_public_leads(niche: str, location: str, lead_count: int, search_mode: str, existing_domains: Optional[set] = None, specific_areas: Optional[List[str]] = None, require_contact: str = "any", min_score: int = 40) -> List[Dict[str, Any]]:
    queries = _crm_build_queries_v2(niche, location, lead_count, search_mode, specific_areas=specific_areas)
    seen_domains = set([_crm_extract_domain(x) for x in (existing_domains or set()) if x])
    out: List[Dict[str, Any]] = []
    raw_results: List[Dict[str, Any]] = []
    per_query = 8 if (search_mode or 'balanced').lower() == 'precision' else 12 if (search_mode or 'balanced').lower() == 'balanced' else 16

    def include_item(item: Optional[Dict[str, Any]]) -> bool:
        if not item:
            return False
        dom = (item.get('domain') or '').strip().lower()
        if not dom or dom in seen_domains:
            return False
        has_phone = bool((item.get('phone') or '').strip())
        public_email = bool((item.get('email') or '').strip())
        any_email = public_email or bool(item.get('email_candidates') or [])
        if require_contact == 'phone' and not has_phone:
            return False
        if require_contact == 'email' and not any_email:
            return False
        if require_contact == 'phone_or_email' and not (has_phone or any_email):
            return False
        if (item.get('score') or 0) < int(min_score or 40):
            return False
        seen_domains.add(dom)
        out.append(item)
        return True

    # Pass 1: fast lead creation from search results, prioritizing OpenAI web search hints and official sites.
    for q in queries:
        rows = _crm_public_search(q, max_results=per_query, niche=niche, location=location)
        for row in rows:
            dom = _crm_extract_domain(row.get('domain') or urlparse(row.get('url') or '').netloc or row.get('url') or '')
            if not dom or dom in seen_domains or _crm_is_blocked_domain(dom):
                continue
            row['query'] = q
            raw_results.append(row)
            item = _crm_make_lead_from_search_row(row, niche, location, q, min_score=max(35, int(min_score or 40) - 5))
            include_item(item)
            if len(out) >= lead_count:
                break
        if len(out) >= lead_count:
            break

    # Pass 2: enrich a small subset only, to keep the route fast and avoid server/proxy timeouts.
    if len(out) < lead_count and raw_results:
        enrich_pool = raw_results[:max(lead_count * 2, 12)]
        max_workers = 4
        try:
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                future_map = {ex.submit(_crm_enrich_result, row, niche, location, row.get('query') or ''): row for row in enrich_pool}
                for fut in as_completed(future_map, timeout=55):
                    row = future_map.get(fut) or {}
                    try:
                        item = fut.result(timeout=0)
                    except Exception:
                        item = _crm_make_lead_from_search_row(row, niche, location, row.get('query') or '', min_score=max(35, int(min_score or 40) - 5))
                    include_item(item)
                    if len(out) >= lead_count:
                        break
        except Exception:
            pass

    # Pass 3: deterministic fallback rows from raw results so the user always gets a usable list.
    if len(out) < lead_count:
        for row in raw_results:
            item = _crm_fallback_candidate_from_result(row, niche, location, row.get('query') or '') or _crm_make_lead_from_search_row(row, niche, location, row.get('query') or '', min_score=max(35, int(min_score or 40) - 5))
            if include_item(item) and len(out) >= lead_count:
                break

    out.sort(key=lambda x: ((1 if x.get('phone') else 0) + (1 if (x.get('email') or x.get('email_candidates')) else 0), x.get('score') or 0), reverse=True)
    return out[:lead_count]


@app.post("/api/crm/lead_lab")
def api_crm_lead_lab():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    try:
        payload = request.get_json(silent=True) or {}
        niche = (payload.get("niche") or "").strip()
        location = (payload.get("location") or "").strip()
        source_text = (payload.get("source_text") or "").strip()
        specific_areas = _crm_parse_specific_areas(payload.get("specific_areas") or "")
        search_mode = (payload.get("search_mode") or "balanced").strip().lower()
        require_contact = (payload.get("require_contact") or "phone_or_email").strip().lower()
        try:
            lead_count = int(payload.get("lead_count") or 25)
        except Exception:
            lead_count = 25
        try:
            min_score = int(payload.get("min_score") or 40)
        except Exception:
            min_score = 40
        lead_count = max(1, min(100, lead_count))
        min_score = max(20, min(90, min_score))
        if not niche and not location and not source_text and not specific_areas:
            return jsonify({"ok": False, "error": "Add a niche, location, or specific areas to search"}), 400

        items: List[Dict[str, Any]] = []
        existing_domains = set()
        if source_text:
            try:
                parsed = _crm_parse_lead_source_rows(source_text) or []
                seed_items = _crm_items_from_rows(parsed, niche, location) or []
            except Exception:
                seed_items = []
            for item in (seed_items or []):
                dom = item.get("domain") or ""
                if dom:
                    existing_domains.add(dom)
            items.extend(seed_items or [])

        remaining = max(0, lead_count - len(items))
        if remaining > 0:
            discovered = _crm_discover_public_leads(
                niche, location, remaining, search_mode, existing_domains=existing_domains,
                specific_areas=specific_areas, require_contact=require_contact, min_score=min_score
            )
            items.extend(discovered or [])

        # OpenAI-first top-off so the user still gets a complete list when scraping is thin.
        final: List[Dict[str, Any]] = []
        seen = set()
        for item in items:
            dom = (item.get("domain") or "").strip().lower()
            key = dom or ((item.get("website") or item.get("company") or item.get("name") or "").strip().lower())
            if not key or key in seen:
                continue
            seen.add(key)
            final.append(item)
            if len(final) >= lead_count:
                break

        if len(final) < lead_count:
            need = max(0, lead_count - len(final))
            ai_queries = _crm_build_queries_v2(niche, location, lead_count, 'broad' if search_mode != 'broad' else search_mode, specific_areas=specific_areas)[:12]
            for q in ai_queries:
                if len(final) >= lead_count:
                    break
                try:
                    rows = _crm_openai_web_search(q, niche, location, max_results=max(need * 2, 8))
                except Exception as ai_err:
                    append_log('crm_lead_lab_ai_query_error', {'error': str(ai_err), 'query': q, 'at': now_iso()})
                    rows = []
                for row in rows:
                    item = _crm_make_lead_from_search_row(row, niche, location, q, min_score=max(35, min_score - 5))
                    if not item:
                        continue
                    dom = (item.get('domain') or '').strip().lower()
                    key = dom or ((item.get('website') or item.get('company') or item.get('name') or '').strip().lower())
                    if not key or key in seen:
                        continue
                    seen.add(key)
                    final.append(item)
                    if len(final) >= lead_count:
                        break

        warning = ""
        if not final:
            warning = "No public leads were found for that exact search. Try Broad mode or add specific areas."
        elif len(final) < lead_count:
            warning = f"Built {len(final)} leads from public web signals for this search."

        resp = jsonify({"ok": True, "items": final[:lead_count], "count": min(len(final), lead_count), "warning": warning})
        resp.headers['Cache-Control'] = 'no-store'
        return resp
    except Exception as e:
        try:
            append_log("crm_lead_lab_error", {"error": str(e), "at": now_iso()})
        except Exception:
            pass
        resp = jsonify({"ok": False, "error": f"Lead Lab server error: {str(e)}"})
        resp.headers['Cache-Control'] = 'no-store'
        return resp, 500

@app.post("/api/crm/social_studio")
def api_crm_social_studio():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    payload = request.get_json(silent=True) or {}
    platform = (payload.get("platform") or "Facebook").strip()
    asset_type = (payload.get("asset_type") or "content_pack").strip()
    audience = (payload.get("audience") or "entrepreneurs").strip()
    offer = (payload.get("offer") or "").strip()
    if not offer:
        return jsonify({"ok": False, "error": "Add your offer or angle"}), 400

    system = "You create practical, high-performing social media assets for entrepreneurs. Use clean formatting with headings and bullets."
    prompt = f"Platform: {platform}\nAsset type: {asset_type}\nAudience: {audience}\nOffer/angle: {offer}\n\nGenerate a useful asset pack."
    fallback = (
        f"Content pack for {platform}\n"
        f"- Hook: The fastest way to lose good leads is to sound like everyone else.\n"
        f"- Hook: Most entrepreneurs do not need more content. They need content that moves conversations forward.\n"
        f"- Hook: If your audience is watching but not replying, your message is too broad.\n\n"
        f"Comments\n"
        f"- Curious what part of this feels hardest right now?\n"
        f"- This is the part most people skip, and it costs them momentum.\n"
        f"- Strong angle here. I would tighten the promise and make the next step clearer.\n\n"
        f"DM openers\n"
        f"- Hey, I saw you work with {audience}. Quick question: what are you doing right now to turn attention into actual conversations?\n"
        f"- You probably do not need another tactic. You likely need a cleaner system around {offer}.\n\n"
        f"CTA ideas\n"
        f"- Want the exact workflow? Comment \"system\".\n"
        f"- If this is relevant to your business, message me and I will show you the simple version."
    )
    output = _crm_llm_or_fallback(system, prompt, fallback)
    return jsonify({"ok": True, "output": output})

@app.post("/api/crm/offer_builder")
def api_crm_offer_builder():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    payload = request.get_json(silent=True) or {}
    audience = (payload.get("audience") or "").strip()
    result = (payload.get("result") or "").strip()
    method = (payload.get("method") or "").strip()
    if not audience or not result or not method:
        return jsonify({"ok": False, "error": "Audience, result, and method are required"}), 400

    system = "You are an offer strategist. Build clear, practical offers with concise sections."
    prompt = f"Audience: {audience}\nResult: {result}\nMethod: {method}\n\nBuild an offer statement, promise, bullets, CTA, and short DM pitch."
    fallback = (
        f"Offer statement\n"
        f"We help {audience} {result} using a simple, guided system built around {method}.\n\n"
        f"Core promise\n"
        f"- Faster clarity\n"
        f"- Less guesswork\n"
        f"- More consistent execution\n\n"
        f"Why it stands out\n"
        f"- Done with you structure instead of generic advice\n"
        f"- Clear next steps instead of random tactics\n"
        f"- Built for speed and consistency\n\n"
        f"CTA\n"
        f"- If you want to see whether this fits your business, message me \"offer\".\n\n"
        f"DM pitch\n"
        f"- I help {audience} {result}. The difference is the process: {method}. If you want, I can show you the clean version."
    )
    output = _crm_llm_or_fallback(system, prompt, fallback)
    return jsonify({"ok": True, "output": output})

@app.post("/api/crm/playbooks")
def api_crm_playbooks():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    payload = request.get_json(silent=True) or {}
    goal = (payload.get("goal") or "get_clients").strip()
    timeline = (payload.get("timeline") or "30 days").strip()
    context = (payload.get("context") or "").strip()
    system = "You create crisp business growth playbooks. Return a practical sequence of steps with short explanations."
    prompt = f"Goal: {goal}\nTimeline: {timeline}\nContext: {context}\n\nGenerate a step-by-step playbook."
    fallback = (
        f"Playbook for {goal.replace('_',' ')}\n"
        f"Step 1\n- Clarify your offer and the one audience you are speaking to.\n"
        f"Step 2\n- Publish three authority posts that surface the real problem your audience feels.\n"
        f"Step 3\n- Start daily conversations with people already engaging around that problem.\n"
        f"Step 4\n- Capture interested leads into your pipeline and tag them by readiness.\n"
        f"Step 5\n- Follow up with one useful message and one clear call to action.\n"
        f"Step 6\n- Review what converted, refine the message, and repeat for {timeline}."
    )
    output = _crm_llm_or_fallback(system, prompt, fallback)
    return jsonify({"ok": True, "output": output})


@app.errorhandler(Exception)
def _handle_exception(e):
    try:
        code = getattr(e, "code", 500) or 500
        try:
            path = request.path or ""
        except Exception:
            path = ""
        if path.startswith("/api/"):
            resp = jsonify({"ok": False, "error": str(e) or "Internal server error"})
            resp.headers["Content-Type"] = "application/json"
            resp.headers["Cache-Control"] = "no-store"
            return resp, code
    except Exception:
        pass
    raise e

@app.errorhandler(404)
def _handle_404(e):
    try:
        if (request.path or "").startswith("/api/"):
            return jsonify({"ok": False, "error": "Endpoint not found"}), 404
    except Exception:
        pass
    return "<h1>404 Not Found</h1>", 404

@app.errorhandler(500)
def _handle_500(e):
    try:
        if (request.path or "").startswith("/api/"):
            return jsonify({"ok": False, "error": "Internal server error"}), 500
    except Exception:
        pass
    return "<h1>500 Internal Server Error</h1>", 500



# === Additive Patch: Move Diagnostics Panel Into Settings ===
ADD_DIAG_PATCH = r'''
<script>
document.addEventListener("DOMContentLoaded", function(){

  const diag = document.getElementById("diagOverlay");
  if(!diag) return;

  diag.style.position = "static";
  diag.style.bottom = "auto";
  diag.style.left = "auto";
  diag.style.right = "auto";
  diag.style.width = "100%";
  diag.style.marginTop = "12px";

  const targets = [
    document.getElementById("settingsPanel"),
    document.getElementById("settingsTab"),
    document.querySelector('[data-panel="settings"]'),
    document.querySelector('.settings-panel')
  ].filter(Boolean);

  if(targets.length){
    targets[0].appendChild(diag);
  }

});
</script>
'''



# === Additive Patch v8: UX polish (voice ring, idle breath, spotlight, autoscroll, remember seat) + Diagnostics moved into Settings ===
ADD_UI_POLISH_V8 = r'''
<style>
  /* --- v8 Gold trim reinforcement on primary console buttons --- */
  .btn, .btnMini {
    box-shadow:
      0 0 0 1px rgba(214, 176, 92, 0.35) inset,
      0 0 18px rgba(214, 176, 92, 0.10),
      0 10px 30px rgba(0,0,0,0.35);
  }
  .btnPrimary {
    box-shadow:
      0 0 0 1px rgba(214, 176, 92, 0.50) inset,
      0 0 26px rgba(214, 176, 92, 0.16),
      0 12px 36px rgba(0,0,0,0.40);
  }

  /* --- v8 Spotlight dimming for non-active seats --- */
  .seat.is-dimmed {
    opacity: 0.38;
    transform: scale(0.985);
    filter: saturate(0.85) contrast(0.95);
    transition: opacity .18s ease, transform .18s ease, filter .18s ease;
  }
  .seat.is-active {
    opacity: 1;
    transform: scale(1);
    filter: none;
  }

  /* --- v8 Voice indicator ring on active seat --- */
  .seat.is-speaking::before {
    content: "";
    position: absolute;
    inset: -10px;
    border-radius: 22px;
    pointer-events: none;
    background: radial-gradient(circle at 30% 30%, rgba(214,176,92,0.35), rgba(128,90,255,0.18), rgba(0,0,0,0));
    box-shadow:
      0 0 0 1px rgba(214,176,92,0.55) inset,
      0 0 28px rgba(214,176,92,0.22),
      0 0 34px rgba(128,90,255,0.18);
    animation: v8PulseRing 1.25s ease-in-out infinite;
  }
  @keyframes v8PulseRing {
    0% { transform: scale(0.98); opacity: 0.55; }
    50% { transform: scale(1.02); opacity: 1; }
    100% { transform: scale(0.98); opacity: 0.55; }
  }

  /* --- v8 Idle breathing on the table stage --- */
  #rtStage.v8-idle-breath {
    animation: v8Breath 4.8s ease-in-out infinite;
    transform-origin: 50% 50%;
  }
  @keyframes v8Breath {
    0% { transform: translate(var(--rt-shift-x, 0px), var(--rt-shift-y, 0px)) scale(var(--rt-scale, 1)); filter: saturate(1) brightness(1); }
    50% { transform: translate(var(--rt-shift-x, 0px), var(--rt-shift-y, 0px)) scale(calc(var(--rt-scale, 1) * 1.008)); filter: saturate(1.03) brightness(1.02); }
    100% { transform: translate(var(--rt-shift-x, 0px), var(--rt-shift-y, 0px)) scale(var(--rt-scale, 1)); filter: saturate(1) brightness(1); }
  }

  /* --- v8 Ensure no horizontal clipping in mobile webviews --- */
  html, body { overflow-x: hidden; max-width: 100%; }
  .panel, .card, .modal, .wrap, #app, #root, #main, #content { max-width: 100%; }

  /* --- v8 Lock-friendly scrolling: when locked, allow vertical scroll gestures --- */
  body.v8-table-locked #tableViewport,
  body.v8-table-locked #tableWrap,
  body.v8-table-locked #rtStage {
    touch-action: pan-y !important;
  }
</style>

<script>
(function(){
  // -----------------------------
  // v8: Utilities
  // -----------------------------
  const V8_LAST_SEAT_KEY = "round_table_last_selected_seat_v1";
  const V8_IDLE_AFTER_MS = 9000;

  function $(id){ return document.getElementById(id); }
  function q(sel, root){ return (root||document).querySelector(sel); }
  function qa(sel, root){ return Array.from((root||document).querySelectorAll(sel)); }

  function safeSetLS(k,v){ try{ localStorage.setItem(k,v); }catch(_){ } }
  function safeGetLS(k){ try{ return localStorage.getItem(k) || ""; }catch(_){ return ""; } }

  function isElementVisible(el){
    if(!el) return false;
    const style = window.getComputedStyle(el);
    if(style.display === "none" || style.visibility === "hidden" || style.opacity === "0") return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  }

  // -----------------------------
  // v8: Move Diagnostics into Settings (no bottom overlay)
  // -----------------------------
  function moveDiagnosticsIntoSettings(){
    const diag = $("diagOverlay");
    if(!diag) return;
    // remove "bottom overlay" feel if any CSS remains
    diag.style.position = "static";
    diag.style.bottom = "auto";
    diag.style.left = "auto";
    diag.style.right = "auto";
    diag.style.width = "100%";
    diag.style.marginTop = "14px";

    // prefer settingsForm which exists in this app
    const settingsForm = $("settingsForm");
    if(!settingsForm) return;

    // Create a small section header if it doesn't exist
    let hdr = $("v8DiagHdr");
    if(!hdr){
      hdr = document.createElement("div");
      hdr.id = "v8DiagHdr";
      hdr.style.marginTop = "16px";
      hdr.style.paddingTop = "12px";
      hdr.style.borderTop = "1px solid rgba(214,176,92,0.22)";
      hdr.innerHTML = '<div class="tiny" style="letter-spacing:.08em; text-transform:uppercase; opacity:.85;">System Diagnostics</div>';
      settingsForm.appendChild(hdr);
    }
    settingsForm.appendChild(diag);
  }

  // -----------------------------
  // v8: Remember last selected teammate
  // -----------------------------
  function installRememberSeatHooks(){
    // We wrap selectSeat if it exists
    const fn = window.selectSeat;
    if(typeof fn !== "function") return;
    if(fn.__v8wrapped) return;

    const wrapped = async function(name){
      safeSetLS(V8_LAST_SEAT_KEY, String(name||""));
      return await fn.apply(this, arguments);
    };
    wrapped.__v8wrapped = true;
    window.selectSeat = wrapped;
  }

  async function restoreLastSeatAfterRender(){
    const last = safeGetLS(V8_LAST_SEAT_KEY);
    if(!last) return;
    // only restore if seat exists
    const seatEl = document.querySelector('.seat[data-name="' + CSS.escape(last) + '"]');
    if(!seatEl) return;
    try{
      if(typeof window.selectSeat === "function"){
        await window.selectSeat(last);
      }else if(typeof window.forceSeatSelectUI === "function"){
        window.forceSeatSelectUI(last);
      }
    }catch(_){}
  }

  // -----------------------------
  // v8: Spotlight dim non-active seats
  // -----------------------------
  function installSpotlightDimming(){
    const fn = window.markActiveSeat;
    if(typeof fn !== "function") return;
    if(fn.__v8wrapped) return;

    const wrapped = function(){
      const res = fn.apply(this, arguments);

      // Determine active seat name by reading selectedSeat if present
      let activeName = "";
      try{ activeName = window.selectedSeat || ""; }catch(_){ activeName = ""; }

      const seats = qa(".seat[data-name]");
      seats.forEach(el => {
        const nm = el.getAttribute("data-name") || "";
        const isActive = activeName && nm === activeName;
        el.classList.toggle("is-active", !!isActive);
        el.classList.toggle("is-dimmed", !!(activeName && !isActive));
      });

      return res;
    };
    wrapped.__v8wrapped = true;
    window.markActiveSeat = wrapped;
  }

  // -----------------------------
  // v8: Voice indicator ring + Dictation fill + Name switching helper
  // -----------------------------
  let v8SpeechActive = false;
  let v8IdleTimer = null;
  let v8LastInteractionTs = Date.now();

  function setSpeaking(on){
    v8SpeechActive = !!on;
    let activeName = "";
    try{ activeName = window.selectedSeat || ""; }catch(_){ activeName = ""; }
    if(!activeName) return;
    const el = document.querySelector('.seat[data-name="' + CSS.escape(activeName) + '"]');
    if(!el) return;
    el.classList.toggle("is-speaking", v8SpeechActive);
  }

  function getDictationTarget(){
    // If group console prompt is visible, prefer it; else followMsg.
    const op = $("opPrompt");
    const dm = $("followMsg");

    if(op && isElementVisible(op)) return op;
    if(dm && isElementVisible(dm)) return dm;
    return dm || op || null;
  }

  function appendDictation(text){
    const t = getDictationTarget();
    if(!t) return;
    const existing = (t.value || "");
    const space = existing && !existing.endsWith(" ") ? " " : "";
    t.value = existing + space + text;
    try{ t.focus(); }catch(_){}
  }

  function trySelectByNameSpoken(transcript){
    // If user says a teammate name, switch seats
    const s = (transcript || "").toLowerCase().trim();
    if(!s) return false;

    // Collect known seat names
    const seats = qa(".seat[data-name]").map(el => el.getAttribute("data-name"));
    if(!seats.length) return false;

    // Basic match: if transcript contains the seat name as a whole word-ish
    for(const name of seats){
      const n = (name || "").toLowerCase();
      if(!n) continue;
      // Allow "hey alex" or "alex"
      if(s === n || s.includes(" " + n + " ") || s.startsWith(n + " ") || s.endsWith(" " + n) || s.includes(n)){
        // Switch seat + force glow pulse if available
        try{
          if(typeof window.selectSeat === "function"){
            window.selectSeat(name);
          }else if(typeof window.forceSeatSelectUI === "function"){
            window.forceSeatSelectUI(name);
          }
          if(typeof window.forceSeatSelectUI === "function"){
            window.forceSeatSelectUI(name);
          }
        }catch(_){}
        return true;
      }
    }
    return false;
  }

  function installVoiceHooks(){
    // Wrap startRecognition if present (your code uses a wrapper around SpeechRecognition)
    const startFn = window.startRecognition;
    const stopFn = window.stopRecognition;

    if(typeof startFn === "function" && !startFn.__v8wrapped){
      const wrappedStart = async function(){
        setSpeaking(true);
        try{ return await startFn.apply(this, arguments); }
        finally{
          // speaking state is cleared by stop / end too, but this ensures we never "stick" on errors
          // do not clear immediately here
        }
      };
      wrappedStart.__v8wrapped = true;
      window.startRecognition = wrappedStart;
    }

    if(typeof stopFn === "function" && !stopFn.__v8wrapped){
      const wrappedStop = async function(){
        setSpeaking(false);
        return await stopFn.apply(this, arguments);
      };
      wrappedStop.__v8wrapped = true;
      window.stopRecognition = wrappedStop;
    }

    // If your recognition instance is globally exposed, hook its events safely
    try{
      const rec = window.recognition || window._recognition || null;
      if(rec && !rec.__v8events){
        rec.addEventListener("start", () => setSpeaking(true));
        rec.addEventListener("end", () => setSpeaking(false));
        rec.addEventListener("error", () => setSpeaking(false));
        rec.__v8events = true;
      }
    }catch(_){}

    // Wrap your transcript handler if present
    const handler = window.onVoiceTranscript;
    if(typeof handler === "function" && !handler.__v8wrapped){
      const wrapped = function(text, meta){
        try{
          const t = String(text||"").trim();
          if(t){
            // 1) try name switching
            const switched = trySelectByNameSpoken(t);
            // 2) always fill prompt box if not just a name switch OR meta requests it
            if(!switched || (meta && meta.forceFill)){
              appendDictation(t);
            }
          }
        }catch(_){}
        return handler.apply(this, arguments);
      };
      wrapped.__v8wrapped = true;
      window.onVoiceTranscript = wrapped;
    }
  }

  // -----------------------------
  // v8: Auto-scroll thread areas when new content arrives
  // -----------------------------
  function installAutoScroll(){
    const thread = $("thread");
    if(thread && !thread.__v8obs){
      const obs = new MutationObserver(() => {
        // Only autoscroll if user is already near bottom
        const nearBottom = (thread.scrollHeight - (thread.scrollTop + thread.clientHeight)) < 140;
        if(nearBottom){
          thread.scrollTop = thread.scrollHeight;
        }
      });
      obs.observe(thread, { childList:true, subtree:true });
      thread.__v8obs = true;
    }

    const group = $("groupRepliesList") || $("groupReplies") || null;
    if(group && !group.__v8obs){
      const obs2 = new MutationObserver(() => {
        const nearBottom = (group.scrollHeight - (group.scrollTop + group.clientHeight)) < 140;
        if(nearBottom){
          group.scrollTop = group.scrollHeight;
        }
      });
      obs2.observe(group, { childList:true, subtree:true });
      group.__v8obs = true;
    }
  }

  // -----------------------------
  // v8: Idle breathing controller
  // -----------------------------
  function markInteraction(){
    v8LastInteractionTs = Date.now();
    const stage = $("rtStage");
    if(stage) stage.classList.remove("v8-idle-breath");
    if(v8IdleTimer) clearTimeout(v8IdleTimer);
    v8IdleTimer = setTimeout(() => {
      const stage2 = $("rtStage");
      if(!stage2) return;
      // Only breathe if not speaking and no recent interaction
      if(!v8SpeechActive && (Date.now() - v8LastInteractionTs) >= V8_IDLE_AFTER_MS){
        stage2.classList.add("v8-idle-breath");
      }
    }, V8_IDLE_AFTER_MS + 250);
  }

  function installIdleBreath(){
    ["pointerdown","touchstart","wheel","keydown","scroll"].forEach(ev => {
      window.addEventListener(ev, markInteraction, {passive:true});
    });
    markInteraction();
  }

  // -----------------------------
  // v8: Table lock should really lock panning/zoom gestures, but keep scroll
  // -----------------------------
  function installLockBehavior(){
    const lockBtn = $("tableLockBtn");
    if(!lockBtn) return;

    function applyLockedUI(isLocked){
      document.body.classList.toggle("v8-table-locked", !!isLocked);
      lockBtn.textContent = isLocked ? "🔒" : "🔓";
      lockBtn.title = isLocked ? "Table locked (scroll page)" : "Table unlocked (pan/zoom table)";
    }

    // Preserve any existing lock behavior, but ensure we also toggle the body class
    let locked = true;
    try{
      locked = (document.body.classList.contains("v8-table-locked"));
    }catch(_){ locked = true; }

    applyLockedUI(locked);

    lockBtn.addEventListener("click", function(){
      locked = !document.body.classList.contains("v8-table-locked");
      applyLockedUI(locked);
    });
  }

  // -----------------------------
  // v8: Bootstrap
  // -----------------------------
  document.addEventListener("DOMContentLoaded", function(){
    try{ moveDiagnosticsIntoSettings(); }catch(_){}

    try{ installRememberSeatHooks(); }catch(_){}
    try{ installSpotlightDimming(); }catch(_){}
    try{ installVoiceHooks(); }catch(_){}
    try{ installAutoScroll(); }catch(_){}
    try{ installIdleBreath(); }catch(_){}
    try{ installLockBehavior(); }catch(_){}

    // Restore seat after table render; retry a few times in case render is async.
    let tries = 0;
    const timer = setInterval(async () => {
      tries++;
      try{ await restoreLastSeatAfterRender(); }catch(_){}
      // stop once seat exists or tries exhausted
      const last = safeGetLS(V8_LAST_SEAT_KEY);
      const exists = last && document.querySelector('.seat[data-name="' + CSS.escape(last) + '"]');
      if(exists || tries >= 14) clearInterval(timer);
    }, 250);
  });
})();


</script>
'''





# =========================
# OS LAYER V2 (additive, non-breaking)
# =========================
OS_DIR = DATA / "os_state"
OS_DIR.mkdir(parents=True, exist_ok=True)

STACK_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "lead_followup": {
        "name": "lead_followup",
        "title": "Lead Follow Up",
        "description": "Follow up with a lead, save memory, and route to Sunshine if needed.",
        "steps": [
            {"type": "prompt", "label": "Draft follow up", "prompt": "Draft a high-trust follow-up for {{input}}."},
            {"type": "save_memory", "label": "Save last follow up", "key": "last_followup", "prompt": "{{last}}"},
            {"type": "route", "label": "Sales polish", "to_teammate": "Sunshine", "prompt": "Improve this for ethical sales clarity without pressure:\n\n{{last}}"}
        ]
    },
    "client_onboarding": {
        "name": "client_onboarding",
        "title": "Client Onboarding",
        "description": "Welcome a new client, gather constraints, and create next steps.",
        "steps": [
            {"type": "prompt", "label": "Welcome email", "prompt": "Write a clean welcome and onboarding note for {{input}}."},
            {"type": "route", "label": "Clarify scope", "to_teammate": "Alex", "prompt": "Turn this into an onboarding checklist with next steps:\n\n{{last}}"},
            {"type": "save_memory", "label": "Save onboarding plan", "key": "onboarding_plan", "prompt": "{{last}}"}
        ]
    },
    "content_pipeline": {
        "name": "content_pipeline",
        "title": "Content Pipeline",
        "description": "Generate strategy, copy, and creative direction in one sequence.",
        "steps": [
            {"type": "route", "label": "Strategy", "to_teammate": "Alex", "prompt": "Create a content strategy for: {{input}}"},
            {"type": "route", "label": "Copy", "to_teammate": "Willow", "prompt": "Write the post copy from this strategy:\n\n{{last}}"},
            {"type": "route", "label": "Creative", "to_teammate": "Luna", "prompt": "Create the visual direction for this content:\n\n{{step2.output}}"}
        ]
    },
    "lead_to_outreach": {
        "name": "lead_to_outreach",
        "title": "Lead To Outreach",
        "description": "Find leads, score them, and draft the first outreach.",
        "steps": [
            {"type": "route", "label": "Research", "to_teammate": "Ava", "prompt": "Research a clean lead profile for: {{input}}"},
            {"type": "route", "label": "Offer angle", "to_teammate": "Alex", "prompt": "Create the best angle for this lead:\n\n{{last}}"},
            {"type": "route", "label": "Outreach", "to_teammate": "Sunshine", "prompt": "Write the first outreach based on this:\n\n{{step2.output}}"}
        ]
    },
}


def _os_path_for_user(username: str) -> Path:
    return OS_DIR / f"{_safe_name(username or 'anon')}.json"


def _os_default_state() -> Dict[str, Any]:
    return {
        "version": "os_v2",
        "updated_at": None,
        "mode": "operator",
        "session_objective": {"title": "", "context": "", "updated_at": None},
        "session_state": {"mode": "", "stage": "", "goal": "", "constraints": [], "updated_at": None},
        "memory": {
            "operator": {},
            "clients": {},
            "leads": {},
            "campaigns": {},
            "conversations": {},
            "global_notes": []
        },
        "tool_preferences": {},
        "pipeline_rules": [
            {"id": "reply_to_interested", "name": "Reply => Interested", "trigger": "has_recent_reply", "action": "set_stage", "value": "Interested", "enabled": True},
            {"id": "booked_to_call", "name": "Call Booked Tag", "trigger": "tag_present", "match": "booked", "action": "set_stage", "value": "Call booked", "enabled": True},
            {"id": "vip_tag_to_vip", "name": "VIP Tag => VIP", "trigger": "tag_present", "match": "vip", "action": "set_stage", "value": "VIP", "enabled": True},
        ],
        "session_log": [],
        "error_log": [],
        "execution_timeline": []
    }


def _os_load(username: str) -> Dict[str, Any]:
    data = load_json(_os_path_for_user(username), _os_default_state())
    if not isinstance(data, dict):
        data = _os_default_state()
    base = _os_default_state()
    for k, v in base.items():
        data.setdefault(k, v)
    if not isinstance(data.get("memory"), dict):
        data["memory"] = base["memory"]
    for mk, mv in base["memory"].items():
        data["memory"].setdefault(mk, mv)
    if not isinstance(data.get("pipeline_rules"), list):
        data["pipeline_rules"] = list(base["pipeline_rules"])
    if not isinstance(data.get("session_log"), list):
        data["session_log"] = []
    if not isinstance(data.get("error_log"), list):
        data["error_log"] = []
    if not isinstance(data.get("execution_timeline"), list):
        data["execution_timeline"] = []
    return data


def _os_save(username: str, data: Dict[str, Any]) -> None:
    data = data or {}
    data["updated_at"] = now_iso()
    for k in ["session_log", "error_log", "execution_timeline"]:
        try:
            if isinstance(data.get(k), list) and len(data[k]) > 500:
                data[k] = data[k][-500:]
        except Exception:
            pass
    save_json(_os_path_for_user(username), data)


def _os_log(username: str, kind: str, payload: Dict[str, Any]) -> None:
    try:
        osd = _os_load(username)
        rec = {"id": uuid.uuid4().hex[:10], "kind": kind, "at": now_iso(), "payload": payload or {}}
        osd.setdefault("session_log", []).append(rec)
        osd.setdefault("execution_timeline", []).append(rec)
        _os_save(username, osd)
    except Exception:
        pass


def _os_log_error(username: str, where: str, error: str, extra: Optional[Dict[str, Any]] = None) -> None:
    try:
        osd = _os_load(username)
        osd.setdefault("error_log", []).append({"id": uuid.uuid4().hex[:10], "where": where, "error": error, "extra": extra or {}, "at": now_iso()})
        _os_save(username, osd)
    except Exception:
        pass


def _safe_json_loads(text: str, fallback: Dict[str, Any]) -> Dict[str, Any]:
    try:
        val = json.loads((text or "").strip())
        if isinstance(val, dict):
            return val
    except Exception:
        pass
    return fallback


def _os_session_context(username: str) -> Dict[str, Any]:
    osd = _os_load(username)
    return {
        "objective": (osd.get("session_objective") or {}),
        "state": (osd.get("session_state") or {}),
        "mode": (osd.get("mode") or "operator"),
    }


def _os_tool_candidates() -> List[str]:
    return [
        "round_table",
        "lead_lab",
        "crm_clients",
        "crm_pipeline",
        "crm_broadcast",
        "calendar",
        "social_studio",
        "offer_builder",
        "growth_playbook",
        "action_stacks",
        "image_library",
        "email_console",
    ]


def _os_route_query(username: str, query: str) -> Dict[str, Any]:
    q = (query or "").strip()
    if not q:
        return {"intent": "unknown", "module": "round_table", "plan": "Ask for a clear goal.", "next_action": "Type a clearer command."}
    objective = ((_os_load(username).get("session_objective") or {}).get("title") or "").strip()
    system = (
        "You are an intent router for an AI operator OS. "
        "Classify the user's request, choose the best module, and return strict JSON. "
        "Modules: " + ", ".join(_os_tool_candidates()) + ". "
        "Keys: intent, module, plan, next_action, confidence, prefill_objective."
    )
    user = json.dumps({"query": q, "objective": objective}, ensure_ascii=False)
    fallback = {
        "intent": "general_execution",
        "module": "round_table",
        "plan": "Use the round table to clarify and execute the request.",
        "next_action": "Send the request to the round table.",
        "confidence": 0.55,
        "prefill_objective": q[:140],
    }
    try:
        raw = call_llm(system, [{"role": "user", "content": user}], temperature=0.15)
        out = _safe_json_loads(raw, fallback)
        if out.get("module") not in _os_tool_candidates():
            out["module"] = fallback["module"]
        return out
    except Exception as e:
        _os_log_error(username, "intent_route", str(e), {"query": q})
        return fallback


def _crm_extract_first_name(name: str) -> str:
    name = (name or "").strip()
    if not name:
        return ""
    return re.split(r"\s+", name)[0].strip()


def _crm_compute_lead_score(client: Dict[str, Any]) -> int:
    score = 0
    if (client.get("name") or "").strip(): score += 10
    if (client.get("email") or "").strip(): score += 20
    if (client.get("phone") or "").strip(): score += 20
    if (client.get("company") or "").strip(): score += 10
    if (client.get("notes") or "").strip(): score += 5
    tags = client.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    score += min(15, 3 * len(tags))
    status = (client.get("status") or "").strip().lower()
    if status in ("vip", "active"): score += 10
    stage = (client.get("pipeline_stage") or "").strip().lower()
    if stage in ("interested", "call booked", "client", "vip"): score += 10
    return max(0, min(100, score))


def _crm_enrich_client_record(client: Dict[str, Any]) -> Dict[str, Any]:
    c = dict(client or {})
    cf = dict(c.get("custom_fields") or {})
    email = (c.get("email") or "").strip()
    website = (c.get("company_website") or cf.get("website") or "").strip()
    domain = ""
    try:
        if website:
            domain = _crm_extract_domain(website)
        elif email and "@" in email:
            domain = email.split("@", 1)[1].strip().lower()
    except Exception:
        domain = ""
    if domain:
        cf["domain"] = domain
        if not c.get("company"):
            guessed = domain.split(".")[0].replace("-", " ").replace("_", " ").title()
            if guessed:
                c["company"] = guessed
    c["lead_score"] = _crm_compute_lead_score(c)
    c["first_name"] = _crm_extract_first_name(c.get("name") or "")
    c["custom_fields"] = cf
    return c


def _crm_append_conversation(username: str, client_id: str, rec: Dict[str, Any]) -> None:
    if not client_id:
        return
    crm = _crm_load(username)
    clients = crm.get("clients") or {}
    c = clients.get(client_id)
    if not isinstance(c, dict):
        return
    cf = c.get("custom_fields") or {}
    conv = cf.get("conversation") or []
    if not isinstance(conv, list):
        conv = []
    item = {
        "id": uuid.uuid4().hex[:10],
        "at": now_iso(),
        "channel": (rec.get("channel") or "note").strip(),
        "direction": (rec.get("direction") or "system").strip(),
        "subject": (rec.get("subject") or "").strip(),
        "body": (rec.get("body") or "").strip(),
        "meta": rec.get("meta") if isinstance(rec.get("meta"), dict) else {},
    }
    conv.append(item)
    if len(conv) > 200:
        conv = conv[-200:]
    cf["conversation"] = conv
    c["custom_fields"] = cf
    c["updated_at"] = now_iso()
    clients[client_id] = c
    crm["clients"] = clients
    _crm_save(username, crm)


def _crm_apply_pipeline_rules(username: str, client: Dict[str, Any]) -> Dict[str, Any]:
    c = dict(client or {})
    osd = _os_load(username)
    rules = osd.get("pipeline_rules") or []
    tags = c.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    conv = (((c.get("custom_fields") or {}).get("conversation")) or [])
    has_recent_reply = False
    try:
        if conv:
            last = conv[-1]
            has_recent_reply = (last.get("direction") == "inbound")
    except Exception:
        has_recent_reply = False
    for r in rules:
        if not isinstance(r, dict) or not r.get("enabled", True):
            continue
        trig = (r.get("trigger") or "").strip()
        if trig == "has_recent_reply" and has_recent_reply and (r.get("action") == "set_stage"):
            c["pipeline_stage"] = (r.get("value") or c.get("pipeline_stage") or "Lead").strip()
        elif trig == "tag_present" and (r.get("match") or "") in tags and (r.get("action") == "set_stage"):
            c["pipeline_stage"] = (r.get("value") or c.get("pipeline_stage") or "Lead").strip()
    return c


def _next_followup_suggestion(client: Dict[str, Any]) -> str:
    stage = (client.get("pipeline_stage") or "Lead").strip().lower()
    if stage == "lead":
        return "Send a first value-led outreach."
    if stage == "conversation":
        return "Reply with one clear next step."
    if stage == "interested":
        return "Offer a call or direct path forward."
    if stage == "call booked":
        return "Send confirmation and prep notes."
    if stage in ("client", "vip"):
        return "Deliver value and identify expansion opportunity."
    return "Review the client and decide the cleanest next move."


# -------- Action Stack engine upgrades (conditional logic, retries, fallback, timeline) --------
def _normalize_steps(steps: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if isinstance(steps, list):
        for s in steps:
            if not isinstance(s, dict):
                continue
            typ = (s.get("type") or "").strip().lower()
            if typ not in ("prompt", "ask_user", "wait", "save_memory", "route", "branch"):
                typ = "prompt"
            out.append({
                "type": typ,
                "label": (s.get("label") or "").strip()[:80],
                "prompt": (s.get("prompt") or ""),
                "seconds": int(s.get("seconds") or 0),
                "key": (s.get("key") or "").strip()[:80],
                "to_teammate": (s.get("to_teammate") or "").strip()[:64],
                "condition_contains": (s.get("condition_contains") or "").strip(),
                "goto_step": int(s.get("goto_step") or 0),
                "retries": max(0, min(3, int(s.get("retries") or 0))),
                "fallback_teammate": (s.get("fallback_teammate") or "").strip()[:64],
                "continue_on_error": bool(s.get("continue_on_error")),
            })
    return out


def _run_action_stack_engine(run: Dict[str, Any]) -> Dict[str, Any]:
    u = run.get("user") or "anon"
    steps = run.get("steps") or []
    outputs = run.get("outputs") or {}
    try:
        if (run.get("status") == "waiting") and run.get("wait_until"):
            w_dt = datetime.fromisoformat(str(run.get("wait_until")).replace("Z", ""))
            if w_dt and datetime.utcnow() < w_dt:
                _persist_run(run)
                return run
            run["status"] = "running"
            run.pop("wait_until", None)
    except Exception:
        pass

    mem = (_load_action_memory(u).get("memory") or {})
    cursor = int(run.get("cursor") or 0)
    last_output = outputs.get(str(cursor - 1), "") if cursor > 0 else ""

    def _stack_task_log(step_num: int, stype: str, output: str, extra: Optional[Dict[str, Any]] = None, status: str = "success") -> None:
        try:
            append_task_log(
                action="stack_step" if status == "success" else "stack_error",
                record={
                    "teammate": run.get("teammate", ""),
                    "stack": run.get("stack_name", ""),
                    "run_id": run.get("id", ""),
                    "step": step_num,
                    "type": stype,
                    "output": output,
                    "extra": extra or {},
                },
                teammate=run.get("teammate", ""),
                status=status,
            )
            _os_log(u, "stack_timeline", {
                "run_id": run.get("id", ""),
                "stack_name": run.get("stack_name", ""),
                "step": step_num,
                "type": stype,
                "status": status,
                "extra": extra or {},
            })
        except Exception:
            pass

    while cursor < len(steps):
        step = steps[cursor]
        stype = step.get("type", "prompt")
        ctx: Dict[str, Any] = {"input": run.get("input", ""), "last": last_output, "teammate": run.get("teammate", "")}
        for i, out in outputs.items():
            try:
                idx = int(i)
                ctx[f"step{idx+1}.output"] = out
            except Exception:
                continue
        for k, v in (mem or {}).items():
            ctx[f"memory.{k}"] = v

        if stype == "branch":
            needle = (step.get("condition_contains") or "").strip().lower()
            goto_step = int(step.get("goto_step") or 0)
            hay = str(last_output or "").lower()
            if needle and needle in hay and goto_step > 0 and goto_step <= len(steps):
                _stack_task_log(cursor + 1, "branch", f"goto {goto_step}", {"matched": needle})
                cursor = goto_step - 1
                run["cursor"] = cursor
                continue
            outputs[str(cursor)] = last_output
            cursor += 1
            run["cursor"] = cursor
            _persist_run(run)
            continue

        try:
            if stype == "ask_user":
                run["status"] = "needs_input"
                run["cursor"] = cursor
                _stack_task_log(cursor + 1, "ask_user", "", {"label": step.get("label", "")})
                _append_run_log(run, "needs_input", {"step": cursor + 1, "label": step.get("label", "")})
                _persist_run(run)
                return run
            if stype == "wait":
                secs = max(0, min(3600, int(step.get("seconds") or 0)))
                run["status"] = "waiting"
                run["cursor"] = cursor
                run["wait_until"] = (datetime.utcnow() + timedelta(seconds=secs)).isoformat() + "Z"
                _stack_task_log(cursor + 1, "wait", "", {"seconds": secs})
                _append_run_log(run, "wait", {"step": cursor + 1, "seconds": secs})
                _persist_run(run)
                return run
            if stype == "save_memory":
                key = (step.get("key") or "").strip()
                val = _safe_render(step.get("prompt") or "{{last}}", ctx)
                if key:
                    mem2 = _load_action_memory(u)
                    mem2.setdefault("memory", {})
                    mem2["memory"][key] = val
                    _save_action_memory(u, mem2)
                    mem = mem2["memory"]
                outputs[str(cursor)] = val
                last_output = val
                run["last_output"] = last_output
                _stack_task_log(cursor + 1, "save_memory", val, {"key": key})
                _append_run_log(run, "save_memory", {"step": cursor + 1, "key": key})
            else:
                retries = max(0, int(step.get("retries") or 0))
                fallback_teammate = (step.get("fallback_teammate") or "").strip()
                continue_on_error = bool(step.get("continue_on_error"))
                attempt = 0
                out = ""
                while True:
                    attempt += 1
                    try:
                        if stype == "route":
                            to_tm = (step.get("to_teammate") or "").strip()
                            p = _safe_render(step.get("prompt") or "{{last}}", ctx)
                            out = _call_teammate_prompt_for_user(u, to_tm, p)
                            _stack_task_log(cursor + 1, "route", out, {"to": to_tm, "attempt": attempt})
                            _append_run_log(run, "route", {"step": cursor + 1, "to": to_tm, "attempt": attempt})
                        else:
                            p = _safe_render(step.get("prompt") or "", ctx)
                            out = _call_teammate_prompt_for_user(u, run.get("teammate", ""), p)
                            _stack_task_log(cursor + 1, "prompt", out, {"label": step.get("label", ""), "attempt": attempt})
                            _append_run_log(run, "prompt", {"step": cursor + 1, "label": step.get("label", ""), "attempt": attempt})
                        break
                    except Exception as inner:
                        if attempt <= retries:
                            continue
                        if fallback_teammate:
                            try:
                                p = _safe_render(step.get("prompt") or "{{last}}", ctx)
                                out = _call_teammate_prompt_for_user(u, fallback_teammate, p)
                                _stack_task_log(cursor + 1, "fallback", out, {"to": fallback_teammate, "error": str(inner)})
                                break
                            except Exception as inner2:
                                if continue_on_error:
                                    out = f"[continued after error] {inner2}"
                                    _stack_task_log(cursor + 1, "continued_error", out, {"error": str(inner2)}, status="error")
                                    break
                                raise inner2
                        if continue_on_error:
                            out = f"[continued after error] {inner}"
                            _stack_task_log(cursor + 1, "continued_error", out, {"error": str(inner)}, status="error")
                            break
                        raise inner
                outputs[str(cursor)] = out
                last_output = out
                run["last_output"] = last_output
            run["outputs"] = outputs
            cursor += 1
            run["cursor"] = cursor
            run["status"] = "running"
            _persist_run(run)
        except Exception as e:
            run["status"] = "failed"
            run["error"] = str(e)
            run["cursor"] = cursor
            _stack_task_log(cursor + 1, "error", "", {"error": str(e)}, status="error")
            _append_run_log(run, "error", {"step": cursor + 1, "error": str(e)})
            _persist_run(run)
            return run

    run["status"] = "complete"
    run["cursor"] = len(steps)
    try:
        append_task_log(
            action="stack_complete",
            record={
                "teammate": run.get("teammate", ""),
                "stack": run.get("stack_name", ""),
                "run_id": run.get("id", ""),
                "steps": len(steps),
                "last_output": run.get("last_output", ""),
            },
            teammate=run.get("teammate", ""),
            status="success",
        )
        _os_log(u, "stack_complete", {"run_id": run.get("id", ""), "stack": run.get("stack_name", "")})
    except Exception:
        pass
    _append_run_log(run, "complete", {"steps": len(steps)})
    _persist_run(run)
    return run


# -------- OS endpoints --------
@app.get("/api/os/session_objective")
def api_os_session_objective_get():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    osd = _os_load(uname)
    return jsonify({"ok": True, "objective": osd.get("session_objective") or {}, "mode": osd.get("mode") or "operator"})


@app.post("/api/os/session_objective")
def api_os_session_objective_set():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(silent=True) or {}
    osd = _os_load(uname)
    osd["session_objective"] = {
        "title": (payload.get("title") or "").strip(),
        "context": (payload.get("context") or "").strip(),
        "updated_at": now_iso(),
    }
    if "mode" in payload:
        osd["mode"] = ((payload.get("mode") or "operator").strip() or "operator")
    _os_save(uname, osd)
    _os_log(uname, "session_objective", {"title": osd["session_objective"]["title"]})
    return jsonify({"ok": True, "objective": osd["session_objective"], "mode": osd.get("mode")})


@app.get("/api/os/memory")
def api_os_memory_get():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    osd = _os_load(uname)
    return jsonify({"ok": True, "memory": osd.get("memory") or {}, "session_state": osd.get("session_state") or {}, "mode": osd.get("mode") or "operator"})


@app.post("/api/os/memory")
def api_os_memory_set():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(silent=True) or {}
    osd = _os_load(uname)
    memory = osd.get("memory") or {}
    for scope in ["operator", "clients", "leads", "campaigns", "conversations"]:
        if scope in payload and isinstance(payload.get(scope), dict):
            cur = memory.get(scope) or {}
            cur.update(payload.get(scope) or {})
            memory[scope] = cur
    note = (payload.get("note") or "").strip()
    if note:
        notes = memory.get("global_notes") or []
        notes.append({"at": now_iso(), "note": note})
        if len(notes) > 100:
            notes = notes[-100:]
        memory["global_notes"] = notes
    osd["memory"] = memory
    if isinstance(payload.get("session_state"), dict):
        osd["session_state"].update(payload.get("session_state") or {})
        osd["session_state"]["updated_at"] = now_iso()
    _os_save(uname, osd)
    return jsonify({"ok": True, "memory": memory, "session_state": osd.get("session_state") or {}})


@app.post("/api/os/intent_route")
def api_os_intent_route():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(silent=True) or {}
    query = (payload.get("query") or "").strip()
    out = _os_route_query(uname, query)
    _os_log(uname, "intent_route", {"query": query, "result": out})
    return jsonify({"ok": True, **out})


@app.get("/api/os/stack_templates")
def api_os_stack_templates():
    return jsonify({"ok": True, "templates": list(STACK_TEMPLATES.values())})


@app.get("/api/os/stack_timeline/<run_id>")
def api_os_stack_timeline(run_id: str):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    runs = _load_runs(uname).get("runs") or {}
    run = runs.get(run_id)
    if not isinstance(run, dict):
        return jsonify({"ok": False, "error": "Run not found"}), 404
    return jsonify({"ok": True, "timeline": run.get("log") or [], "run": run})


@app.post("/api/os/collaborate")
def api_os_collaborate():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(silent=True) or {}
    prompt = (payload.get("prompt") or "").strip()
    debate = bool(payload.get("debate"))
    teammates = payload.get("teammates") or ["Alex", "Willow", "Sunshine"]
    if not prompt:
        return jsonify({"ok": False, "error": "Missing prompt"}), 400
    reg = load_registry()
    installed = reg.get("installed") or {}
    selected = [t for t in teammates if t in installed][:6]
    if not selected:
        return jsonify({"ok": False, "error": "No valid teammates selected"}), 400
    objective = ((_os_load(uname).get("session_objective") or {}).get("title") or "").strip()
    outputs = {}
    confidence = {}
    prev = ""
    for idx, name in enumerate(selected):
        p = prompt
        if prev:
            p += "\n\nPrevious teammate context:\n" + prev
        if objective:
            p += "\n\nCurrent session objective: " + objective
        if debate and idx > 0:
            p += "\n\nChallenge weak assumptions in the prior reasoning and strengthen what survives."
        try:
            outputs[name] = _call_teammate_prompt_for_user(uname, name, p)
            prev = outputs[name]
            confidence[name] = max(0.35, min(0.95, 0.55 + (0.08 * idx)))
        except Exception as e:
            outputs[name] = f"[error] {e}"
            confidence[name] = 0.25
    synthesis_prompt = "Synthesize these teammate outputs into one aligned answer. Include disagreement if it matters.\n\n" + json.dumps(outputs, indent=2)
    synthesis = _call_teammate_prompt_for_user(uname, "Atlis" if "Atlis" in installed else selected[0], synthesis_prompt)
    return jsonify({"ok": True, "outputs": outputs, "synthesis": synthesis, "confidence": confidence, "debate": debate})


@app.get("/api/os/next_actions")
def api_os_next_actions():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    crm = _crm_load(uname)
    osd = _os_load(uname)
    clients = list((crm.get("clients") or {}).values())
    clients.sort(key=lambda x: str(x.get("updated_at") or ""), reverse=True)
    suggestions = []
    objective = (osd.get("session_objective") or {}).get("title") or ""
    if objective:
        suggestions.append({"type": "objective", "title": "Advance the session objective", "detail": objective})
    if clients:
        hottest = sorted(clients, key=lambda x: int(x.get("lead_score") or 0), reverse=True)[:3]
        for c in hottest:
            suggestions.append({
                "type": "client",
                "client_id": c.get("id"),
                "title": f"Next move for {c.get('name') or 'client'}",
                "detail": _next_followup_suggestion(c),
                "score": int(c.get("lead_score") or 0),
            })
    tasks = list((crm.get("tasks") or {}).values())
    due = [t for t in tasks if not t.get("done")]
    due.sort(key=lambda x: str(x.get("due") or ""))
    for t in due[:3]:
        suggestions.append({"type": "task", "title": t.get("title") or "Task", "detail": t.get("due") or "No due date"})
    return jsonify({"ok": True, "suggestions": suggestions[:10]})


@app.get("/api/os/session_recap")
def api_os_session_recap():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    osd = _os_load(uname)
    log = osd.get("session_log") or []
    recent = log[-20:]
    bullets = []
    for item in recent:
        kind = item.get("kind") or "event"
        payload = item.get("payload") or {}
        if kind == "intent_route":
            bullets.append(f"Routed command '{payload.get('query','')}' to {((payload.get('result') or {}).get('module') or 'round_table')}")
        elif kind == "session_objective":
            bullets.append(f"Session objective set to: {payload.get('title','')}")
        elif kind == "stack_complete":
            bullets.append(f"Completed stack: {payload.get('stack','')}")
        else:
            bullets.append(f"{kind}: {json.dumps(payload)[:140]}")
    recap = "\n".join("- " + b for b in bullets) if bullets else "No major session events yet."
    return jsonify({"ok": True, "recap": recap, "recent": recent})


@app.post("/api/os/error_explain")
def api_os_error_explain():
    payload = request.get_json(silent=True) or {}
    err = (payload.get("error") or "").strip()
    if not err:
        return jsonify({"ok": False, "error": "Missing error text"}), 400
    hints = []
    low = err.lower()
    if "not authenticated" in low:
        hints.append("Log in again and refresh the page.")
    if "api key" in low:
        hints.append("Open Settings and verify the OpenAI API key.")
    if "smtp" in low or "gmail" in low:
        hints.append("Check email settings or reconnect Gmail.")
    if "calendar" in low:
        hints.append("Reconnect Google Calendar and try again.")
    if "twilio" in low:
        hints.append("Verify Twilio SID, token, and from number.")
    if not hints:
        hints.append("Check the relevant settings for the feature that failed and try once more.")
    return jsonify({"ok": True, "summary": err, "fixes": hints})


@app.get("/api/os/integrity_audit")
def api_os_integrity_audit():
    reg = load_registry()
    installed = reg.get("installed") or {}
    issues = []
    for name, t in installed.items():
        if not isinstance(t, dict):
            issues.append({"teammate": name, "issue": "Invalid registry entry"})
            continue
        if not (t.get("job_title") or "").strip():
            issues.append({"teammate": name, "issue": "Missing job title"})
        if not (t.get("version") or "").strip():
            issues.append({"teammate": name, "issue": "Missing version"})
        if not isinstance(t.get("responsibilities"), list):
            issues.append({"teammate": name, "issue": "Responsibilities should be a list"})
    return jsonify({"ok": True, "issues": issues, "healthy": len(issues) == 0})


@app.get("/api/os/tool_select")
def api_os_tool_select():
    q = (request.args.get("query") or "").strip()
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    out = _os_route_query(uname, q)
    return jsonify({"ok": True, "selection": out})


@app.post("/api/os/outcomes/run")
def api_os_outcomes_run():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(silent=True) or {}
    outcome = (payload.get("outcome") or "").strip().lower()
    params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
    result = {"outcome": outcome, "steps": [], "status": "ready"}
    if outcome == "get leads + dm them":
        niche = (params.get("niche") or "real estate agents").strip()
        location = (params.get("location") or "New Jersey").strip()
        leads = _crm_discover_public_leads(niche=niche, location=location, lead_count=int(params.get("lead_count") or 10), search_mode="balanced")
        result["steps"].append({"step": "lead_lab", "count": len(leads)})
        previews = []
        for lead in leads[:5]:
            prompt = f"Write a short first outreach for {lead.get('name','lead')} at {lead.get('company','their company')}."
            previews.append({"lead": lead.get("name",""), "draft": _call_teammate_prompt_for_user(uname, "Sunshine", prompt)})
        result["steps"].append({"step": "outreach_preview", "items": previews})
    elif outcome == "create content + schedule":
        topic = (params.get("topic") or "your offer").strip()
        strategy = _call_teammate_prompt_for_user(uname, "Alex", f"Create a short content plan for {topic}.")
        copy = _call_teammate_prompt_for_user(uname, "Willow", f"Write the post copy from this strategy:\n\n{strategy}")
        result["steps"].append({"step": "strategy", "text": strategy})
        result["steps"].append({"step": "copy", "text": copy})
    else:
        result["status"] = "unknown_outcome"
        result["steps"].append({"step": "hint", "text": "Try one of: get leads + dm them, create content + schedule"})
    _os_log(uname, "outcome_run", result)
    return jsonify({"ok": True, "result": result})


@app.get("/api/crm/clients/<client_id>/conversation")
def api_crm_client_conversation(client_id: str):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    crm = _crm_load(uname)
    c = (crm.get("clients") or {}).get(client_id)
    if not isinstance(c, dict):
        return jsonify({"ok": False, "error": "Client not found"}), 404
    conv = (((c.get("custom_fields") or {}).get("conversation")) or [])
    return jsonify({"ok": True, "conversation": conv, "client": c})


@app.post("/api/crm/clients/<client_id>/conversation")
def api_crm_client_conversation_add(client_id: str):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(silent=True) or {}
    _crm_append_conversation(uname, client_id, payload)
    crm = _crm_load(uname)
    c = (crm.get("clients") or {}).get(client_id) or {}
    c = _crm_apply_pipeline_rules(uname, c)
    crm["clients"][client_id] = c
    _crm_save(uname, crm)
    return jsonify({"ok": True, "client": c, "conversation": (((c.get("custom_fields") or {}).get("conversation")) or [])})


@app.get("/api/os/pipeline_rules")
def api_os_pipeline_rules_get():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    return jsonify({"ok": True, "rules": _os_load(uname).get("pipeline_rules") or []})


@app.post("/api/os/pipeline_rules")
def api_os_pipeline_rules_set():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(silent=True) or {}
    rules = payload.get("rules")
    if not isinstance(rules, list):
        return jsonify({"ok": False, "error": "rules must be a list"}), 400
    osd = _os_load(uname)
    osd["pipeline_rules"] = rules
    _os_save(uname, osd)
    return jsonify({"ok": True, "rules": rules})


# =========================
# OAUTH STATE STORE (additive safety)
# =========================
OAUTH_STATE_STORE = DATA / "oauth_states.json"

def _load_oauth_states():
    return load_json(OAUTH_STATE_STORE, {})

def _save_oauth_states(data):
    save_json(OAUTH_STATE_STORE, data)

def _store_oauth_state(state, username):
    data = _load_oauth_states()
    data[state] = {"username": username, "at": now_iso()}
    _save_oauth_states(data)

def _consume_oauth_state(state):
    data = _load_oauth_states()
    rec = data.pop(state, None)
    _save_oauth_states(data)
    return rec


# =============================================================================
# SESSION 3 UPGRADE — RAG · BRANCHING · EXPORT/SHARE · DASHBOARD
# =============================================================================

import math as _math

# ── RAG (Retrieval-Augmented Generation) ─────────────────────────────────────

RAG_DIR = DATA / "rag"
RAG_DIR.mkdir(exist_ok=True)


def _rag_index_path(username: str) -> Path:
    return RAG_DIR / f"{_safe_name(username or 'anon')}_index.jsonl"


def _rag_meta_path(username: str) -> Path:
    return RAG_DIR / f"{_safe_name(username or 'anon')}_meta.json"


def _cosine_sim(a: List[float], b: List[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na  = _math.sqrt(sum(x * x for x in a))
    nb  = _math.sqrt(sum(x * x for x in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _chunk_text(text: str, chunk_size: int = 400, overlap: int = 60) -> List[str]:
    words  = text.split()
    chunks = []
    start  = 0
    while start < len(words):
        chunks.append(" ".join(words[start: start + chunk_size]))
        start += chunk_size - overlap
    return [c for c in chunks if c.strip()]


def _embed_texts(texts: List[str], oai_client) -> List[List[float]]:
    if not texts:
        return []
    resp = oai_client.embeddings.create(model="text-embedding-3-small", input=texts)
    return [item.embedding for item in sorted(resp.data, key=lambda x: x.index)]


def _rag_load_meta(username: str) -> Dict[str, Any]:
    return load_json(_rag_meta_path(username), {"docs": {}, "updated_at": None})


def _rag_save_meta(username: str, meta: Dict[str, Any]) -> None:
    meta["updated_at"] = now_iso()
    save_json(_rag_meta_path(username), meta)


@app.post("/api/rag/index")
def api_rag_index():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname   = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(silent=True) or {}
    file_id = (payload.get("file_id") or "").strip()
    label   = (payload.get("label")   or "").strip()[:80]
    if not file_id:
        return jsonify({"ok": False, "error": "file_id required"}), 400
    rec   = get_upload_record(file_id)
    if not rec:
        return jsonify({"ok": False, "error": "File not found"}), 404
    fpath = UPLOADS_DIR / rec["relpath"] if rec.get("relpath") else None
    text  = safe_read_text_file(fpath, max_bytes=200_000) if fpath else None
    if not text:
        return jsonify({"ok": False, "error": "Cannot read file (text only, max 200KB)"}), 400
    chunks = _chunk_text(text)[:400]
    if not chunks:
        return jsonify({"ok": False, "error": "No text chunks extracted"}), 400
    try:
        oai         = get_openai_client()
        all_vectors: List[List[float]] = []
        for i in range(0, len(chunks), 96):
            all_vectors.extend(_embed_texts(chunks[i:i + 96], oai))
    except Exception as e:
        code, msg = _classify_openai_error(e)
        return jsonify({"ok": False, "error": msg}), code
    doc_id   = file_id
    idx_path = _rag_index_path(uname)
    existing: List[str] = []
    if idx_path.exists():
        for line in idx_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                if json.loads(line).get("doc_id") != doc_id:
                    existing.append(line)
            except Exception:
                pass
    new_lines = [json.dumps({"doc_id": doc_id, "chunk_idx": i, "text": c, "vec": v}, ensure_ascii=False)
                 for i, (c, v) in enumerate(zip(chunks, all_vectors))]
    idx_path.write_text("\n".join(existing + new_lines), encoding="utf-8")
    meta = _rag_load_meta(uname)
    meta.setdefault("docs", {})[doc_id] = {
        "doc_id": doc_id, "label": label or rec.get("filename", "Document"),
        "filename": rec.get("filename", ""), "chunks": len(chunks), "indexed_at": now_iso(),
    }
    _rag_save_meta(uname, meta)
    return jsonify({"ok": True, "doc_id": doc_id, "chunks": len(chunks)})


@app.get("/api/rag/docs")
def api_rag_docs():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    meta  = _rag_load_meta(uname)
    return jsonify({"ok": True, "docs": list((meta.get("docs") or {}).values())})


@app.post("/api/rag/delete")
def api_rag_delete():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname   = (u.get("username") if isinstance(u, dict) else None) or "anon"
    doc_id  = ((request.get_json(silent=True) or {}).get("doc_id") or "").strip()
    if not doc_id:
        return jsonify({"ok": False, "error": "doc_id required"}), 400
    idx_path = _rag_index_path(uname)
    if idx_path.exists():
        kept = []
        for l in idx_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                if json.loads(l).get("doc_id") != doc_id:
                    kept.append(l)
            except Exception:
                pass  # drop malformed lines rather than crashing
        idx_path.write_text("\n".join(kept), encoding="utf-8")
    meta = _rag_load_meta(uname)
    (meta.get("docs") or {}).pop(doc_id, None)
    _rag_save_meta(uname, meta)
    return jsonify({"ok": True})


def _rag_retrieve(username: str, query: str, top_k: int = 4) -> str:
    idx_path = _rag_index_path(username)
    if not idx_path.exists():
        return ""
    rows = []
    for line in idx_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            rows.append(json.loads(line))
        except Exception:
            pass
    if not rows:
        return ""
    try:
        q_vec = _embed_texts([query], get_openai_client())[0]
    except Exception:
        return ""
    scored = sorted([(r, _cosine_sim(q_vec, r["vec"])) for r in rows if r.get("vec")],
                    key=lambda x: x[1], reverse=True)
    top = [r for r, s in scored[:top_k] if s > 0.25]
    if not top:
        return ""
    parts = [f"[doc:{r.get('doc_id','')[:8]} chunk:{r.get('chunk_idx',0)}]\n{r['text']}" for r in top]
    return "\nKNOWLEDGE BASE (retrieved — use if relevant to the question):\n" + "\n\n".join(parts) + "\n"


# ── CONVERSATION BRANCHING ────────────────────────────────────────────────────

def _branches_path(teammate_name: str) -> Path:
    safe = re.sub(r"[^a-zA-Z0-9_-]+", "_", teammate_name)
    return THREADS_DIR / f"{safe}_branches.json"


def _load_branches(teammate_name: str) -> Dict[str, Any]:
    return load_json(_branches_path(teammate_name), {"branches": {}, "updated_at": None})


def _save_branches(teammate_name: str, data: Dict[str, Any]) -> None:
    data["updated_at"] = now_iso()
    save_json(_branches_path(teammate_name), data)


@app.post("/api/thread/<n>/snapshot")
def api_thread_snapshot(n: str):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    payload   = request.get_json(silent=True) or {}
    label     = (payload.get("label") or "").strip()[:60] or now_iso()[:16].replace("T", " ")
    thread    = load_thread(n)
    if not thread:
        return jsonify({"ok": False, "error": "No messages to snapshot"}), 400
    branch_id = uuid.uuid4().hex[:12]
    data      = _load_branches(n)
    data.setdefault("branches", {})[branch_id] = {
        "id": branch_id, "label": label, "created_at": now_iso(),
        "msg_count": len(thread), "thread": thread,
    }
    brs = data["branches"]
    if len(brs) > 20:
        for old in sorted(brs, key=lambda k: brs[k].get("created_at", ""))[:-20]:
            del brs[old]
    _save_branches(n, data)
    return jsonify({"ok": True, "branch_id": branch_id, "label": label})


@app.get("/api/thread/<n>/branches")
def api_thread_branches(n: str):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    data    = _load_branches(n)
    branches = sorted((data.get("branches") or {}).values(),
                      key=lambda b: str(b.get("created_at") or ""), reverse=True)
    slim = [{"id": b["id"], "label": b["label"],
             "created_at": b.get("created_at", ""), "msg_count": b.get("msg_count", 0)}
            for b in branches]
    return jsonify({"ok": True, "branches": slim})


@app.post("/api/thread/<n>/restore/<branch_id>")
def api_thread_restore(n: str, branch_id: str):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    data   = _load_branches(n)
    branch = (data.get("branches") or {}).get(branch_id)
    if not branch:
        return jsonify({"ok": False, "error": "Branch not found"}), 404
    save_thread(n, branch["thread"])
    return jsonify({"ok": True, "msg_count": len(branch["thread"]), "label": branch["label"]})


# ── EXPORT & SHARE ────────────────────────────────────────────────────────────

SHARES_PATH = DATA / "shares.json"


def _load_shares() -> Dict[str, Any]:
    return load_json(SHARES_PATH, {"shares": {}, "updated_at": None})


def _save_shares(data: Dict[str, Any]) -> None:
    data["updated_at"] = now_iso()
    save_json(SHARES_PATH, data)


def _render_thread_html(teammate: str, thread: List[Dict[str, Any]], title: str = "") -> str:
    def _esc(s: str) -> str:
        return (str(s or "")
                .replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))
    safe_title    = _esc(title or f"Conversation with {teammate}")
    safe_teammate = _esc(teammate)
    rows  = ""
    for m in thread:
        role    = m.get("role", "user")
        content = _esc(str(m.get("content") or ""))
        who     = "You" if role == "user" else safe_teammate
        bg      = "#1e2a4a" if role == "user" else "#0f1929"
        border  = "#7c3aed" if role == "user" else "#3b82f6"
        rows   += (f'<div style="margin:10px 0;padding:12px 16px;border-radius:10px;'
                   f'background:{bg};border-left:3px solid {border};">'
                   f'<div style="font-size:11px;color:#6b7280;margin-bottom:5px;">{who}</div>'
                   f'<div style="white-space:pre-wrap;line-height:1.6;">{content}</div></div>')
    return (f'<!doctype html><html><head><meta charset="utf-8"><title>{safe_title}</title>'
            f'<style>body{{margin:0;font-family:system-ui,sans-serif;background:#07090f;'
            f'color:#e2e8f0;padding:20px;max-width:780px;margin:auto;}}'
            f'h1{{font-size:18px;color:#c4b5fd;margin-bottom:4px;}}'
            f'.meta{{font-size:12px;color:#6b7280;margin-bottom:20px;}}</style></head><body>'
            f'<h1>{safe_title}</h1>'
            f'<div class="meta">Exported {now_iso()[:10]} · {len(thread)} messages</div>'
            f'{rows}</body></html>')


@app.get("/api/export/thread/<n>")
def api_export_thread(n: str):
    from flask import Response
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    thread = load_thread(n)
    if not thread:
        return jsonify({"ok": False, "error": "No messages to export"}), 400
    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", n)[:40]
    return Response(_render_thread_html(n, thread), mimetype="text/html",
                    headers={"Content-Disposition": f"attachment; filename={safe_name}_conversation.html"})


@app.post("/api/share")
def api_share_create():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname    = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload  = request.get_json(silent=True) or {}
    teammate = (payload.get("teammate") or "").strip()
    if not teammate:
        return jsonify({"ok": False, "error": "teammate required"}), 400
    thread = load_thread(teammate)
    if not thread:
        return jsonify({"ok": False, "error": "No messages to share"}), 400
    token = secrets.token_urlsafe(20)
    title = (payload.get("title") or f"Conversation with {teammate}").strip()[:120]
    data  = _load_shares()
    data.setdefault("shares", {})[token] = {
        "token": token, "teammate": teammate, "title": title, "owner": uname,
        "created_at": now_iso(), "views": 0, "thread": thread,
    }
    _save_shares(data)
    base = PUBLIC_BASE_URL or request.host_url.rstrip("/")
    return jsonify({"ok": True, "token": token, "url": f"{base}/share/{token}"})


@app.get("/share/<token>")
def api_share_view(token: str):
    data  = _load_shares()
    share = (data.get("shares") or {}).get(token)
    if not isinstance(share, dict):
        return "<h1>Share not found</h1>", 404
    share["views"] = int(share.get("views") or 0) + 1
    data["shares"][token] = share
    _save_shares(data)
    return _render_thread_html(share.get("teammate", ""), share.get("thread", []), share.get("title", ""))


# ── OPERATOR DASHBOARD ────────────────────────────────────────────────────────

@app.get("/api/dashboard")
def api_dashboard():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    stats: Dict[str, Any] = {}

    entries       = read_task_log(limit=200)
    tm_counts: Dict[str, int] = {}
    for e in entries:
        tm = e.get("teammate") or "unknown"
        tm_counts[tm] = tm_counts.get(tm, 0) + 1
    stats["activity"] = {
        "total_actions":  len(entries),
        "error_count":    sum(1 for e in entries if e.get("status") == "error"),
        "top_teammates":  [{"name": t, "count": c}
                           for t, c in sorted(tm_counts.items(), key=lambda x: x[1], reverse=True)[:5]],
        "recent":         entries[-8:][::-1],
    }

    try:
        crm     = _crm_load(uname)
        clients = list((crm.get("clients") or {}).values())
        stages: Dict[str, int] = {}
        for c in clients:
            if isinstance(c, dict):
                s = (c.get("pipeline_stage") or "No stage").strip() or "No stage"
                stages[s] = stages.get(s, 0) + 1
        stats["crm"] = {"total_clients": len(clients), "stages": stages}
    except Exception:
        stats["crm"] = {"total_clients": 0, "stages": {}}

    try:
        runs_data = _load_runs(uname)
        all_runs  = list((runs_data.get("runs") or {}).values())
        by_status: Dict[str, int] = {}
        for r in all_runs:
            if isinstance(r, dict):
                s = r.get("status") or "unknown"
                by_status[s] = by_status.get(s, 0) + 1
        stats["runs"] = {"total": len(all_runs), "by_status": by_status}
    except Exception:
        stats["runs"] = {"total": 0, "by_status": {}}

    try:
        scheds = _load_schedules(uname)
        stats["schedules"] = {
            "total": len(scheds),
            "items": [{"teammate": s.get("teammate"), "stack": s.get("stack_name"),
                       "mode": s.get("mode"), "last_run": s.get("last_run")} for s in scheds[:10]],
        }
    except Exception:
        stats["schedules"] = {"total": 0, "items": []}

    try:
        rag_meta = _rag_load_meta(uname)
        docs     = list((rag_meta.get("docs") or {}).values())
        stats["rag"] = {"total_docs": len(docs),
                        "total_chunks": sum(int(d.get("chunks") or 0) for d in docs)}
    except Exception:
        stats["rag"] = {"total_docs": 0, "total_chunks": 0}

    try:
        smem = (_os_load(uname).get("shared_team_memory") or {})
        stats["shared_memory"] = {
            "facts": len(smem.get("facts") or []),
            "decisions": len(smem.get("decisions") or []),
            "open_loops": len(smem.get("open_loops") or []),
            "updated_at": smem.get("updated_at") or "",
        }
    except Exception:
        stats["shared_memory"] = {"facts": 0, "decisions": 0, "open_loops": 0, "updated_at": ""}

    try:
        wh_data = _load_webhooks()
        mine    = [wh for wh in (wh_data.get("webhooks") or {}).values()
                   if isinstance(wh, dict) and wh.get("owner") == uname]
        stats["webhooks"] = {"total": len(mine),
                             "total_triggers": sum(int(w.get("trigger_count") or 0) for w in mine)}
    except Exception:
        stats["webhooks"] = {"total": 0, "total_triggers": 0}

    return jsonify({"ok": True, "stats": stats, "generated_at": now_iso()})


# =============================================================================
# SESSION 2 UPGRADE — SHARED MEMORY · TOOL CALLING · WEBHOOKS
# =============================================================================

# ── SHARED TEAM MEMORY EXTRACTION ────────────────────────────────────────────

def _extract_shared_memory_async(username: str, prompt: str, outputs: Dict[str, str]) -> None:
    """Fire-and-forget background thread: extract facts from convene outputs."""
    def _worker():
        try:
            with app.app_context():
                _extract_shared_memory_sync(username, prompt, outputs)
        except Exception:
            pass
    threading.Thread(target=_worker, daemon=True).start()


def _extract_shared_memory_sync(username: str, prompt: str, outputs: Dict[str, str]) -> None:
    """LLM extraction of facts / decisions / open_loops from teammate outputs."""
    if not outputs:
        return
    combined = "\n\n".join(
        f"[{name}]: {text[:500]}" for name, text in list(outputs.items())[:6]
    )
    system = (
        "You extract structured memory from AI team discussions. "
        "Return ONLY valid JSON — no markdown, no code fences. "
        "Keys: facts (list), decisions (list), open_loops (list). "
        "facts: concrete facts stated. decisions: things decided or agreed on. "
        "open_loops: unresolved questions or pending actions. "
        "Max 6 items per list. Max 120 chars per item. Return {} if nothing noteworthy."
    )
    user_msg = f"Original prompt: {prompt[:300]}\n\nTeammate responses:\n{combined}"
    try:
        raw = call_llm(system, [{"role": "user", "content": user_msg}], temperature=0.1)
        raw = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        extracted = json.loads(raw)
        if not isinstance(extracted, dict):
            return
        facts      = [str(f)[:120] for f in (extracted.get("facts")      or []) if f][:6]
        decisions  = [str(d)[:120] for d in (extracted.get("decisions")   or []) if d][:6]
        open_loops = [str(o)[:120] for o in (extracted.get("open_loops")  or []) if o][:6]
        if not (facts or decisions or open_loops):
            return
        osd = _os_load(username)
        cur = osd.get("shared_team_memory") or {}
        if not isinstance(cur, dict):
            cur = {}
        cur["facts"]      = (list(cur.get("facts")      or []) + facts)[-12:]
        cur["decisions"]  = (list(cur.get("decisions")   or []) + decisions)[-12:]
        cur["open_loops"] = (list(cur.get("open_loops")  or []) + open_loops)[-12:]
        cur["updated_at"] = now_iso()
        osd["shared_team_memory"] = cur
        _os_save(username, osd)
    except Exception:
        pass


@app.get("/api/os/shared_memory")
def api_os_shared_memory_get():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    osd   = _os_load(uname)
    smem  = osd.get("shared_team_memory") or {}
    return jsonify({"ok": True, "shared_memory": smem})


@app.post("/api/os/shared_memory/clear")
def api_os_shared_memory_clear():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    osd   = _os_load(uname)
    osd["shared_team_memory"] = {"facts": [], "decisions": [], "open_loops": [], "updated_at": now_iso()}
    _os_save(uname, osd)
    return jsonify({"ok": True})


# ── TEAMMATE TOOL CALLING ─────────────────────────────────────────────────────

_TEAMMATE_TOOLS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "crm_lookup",
            "description": "Look up a CRM contact by name or email. Returns stage, notes, and contact info.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Name or email to search"}
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "calendar_check",
            "description": "List upcoming calendar events for the next N days (requires Google Calendar connected).",
            "parameters": {
                "type": "object",
                "properties": {
                    "days": {"type": "integer", "description": "Days ahead to look (1-14)", "default": 7}
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "remember_fact",
            "description": "Save an important fact or decision to shared team memory so every teammate knows it.",
            "parameters": {
                "type": "object",
                "properties": {
                    "fact": {"type": "string", "description": "The fact or decision to remember"}
                },
                "required": ["fact"],
            },
        },
    },
]


def _execute_teammate_tool(
    tool_name: str, tool_args: Dict[str, Any],
    username: str, u: Dict[str, Any]
) -> str:
    """Execute a teammate tool call and return a string result."""

    if tool_name == "crm_lookup":
        query = (tool_args.get("query") or "").strip().lower()
        if not query:
            return "No query provided."
        try:
            crm     = _crm_load(username)
            clients = crm.get("clients") or {}
            matches = []
            for _, c in list(clients.items())[:200]:
                if isinstance(c, dict):
                    if query in (c.get("name") or "").lower() or query in (c.get("email") or "").lower():
                        matches.append(c)
            if not matches:
                return f"No CRM contacts found matching '{query}'."
            lines = []
            for c in matches[:3]:
                lines.append(
                    f"Name: {c.get('name','')} | Email: {c.get('email','')} | "
                    f"Stage: {c.get('pipeline_stage','')} | Notes: {(c.get('notes','') or '')[:100]}"
                )
            return "CRM results:\n" + "\n".join(lines)
        except Exception as e:
            return f"CRM lookup error: {e}"

    elif tool_name == "calendar_check":
        days = max(1, min(14, int(tool_args.get("days") or 7)))
        try:
            cal_token, reason = _calendar_creds_for_user(u)
            if not cal_token:
                return f"Calendar not connected: {reason}"
            import requests as _req
            now_dt   = datetime.utcnow()
            time_min = now_dt.isoformat() + "Z"
            time_max = (now_dt + timedelta(days=days)).isoformat() + "Z"
            resp = _req.get(
                "https://www.googleapis.com/calendar/v3/calendars/primary/events",
                headers={"Authorization": f"Bearer {cal_token}"},
                params={"timeMin": time_min, "timeMax": time_max,
                        "singleEvents": "true", "orderBy": "startTime", "maxResults": "10"},
                timeout=15,
            )
            if resp.status_code != 200:
                return f"Calendar API error {resp.status_code}: {resp.text[:200]}"
            items = resp.json().get("items") or []
            if not items:
                return f"No events in the next {days} days."
            lines = []
            for ev in items[:8]:
                start = (ev.get("start") or {}).get("dateTime") or (ev.get("start") or {}).get("date") or ""
                lines.append(f"{start[:16].replace('T',' ')}: {ev.get('summary','(no title)')}")
            return "Upcoming events:\n" + "\n".join(lines)
        except Exception as e:
            return f"Calendar check failed: {e}"

    elif tool_name == "remember_fact":
        fact = (tool_args.get("fact") or "").strip()[:200]
        if not fact:
            return "No fact provided."
        try:
            osd  = _os_load(username)
            cur  = osd.get("shared_team_memory") or {}
            if not isinstance(cur, dict):
                cur = {}
            cur["facts"]      = (list(cur.get("facts") or []) + [fact])[-12:]
            cur["updated_at"] = now_iso()
            osd["shared_team_memory"] = cur
            _os_save(username, osd)
            return f"Remembered: '{fact}'"
        except Exception as e:
            return f"Could not save fact: {e}"

    return f"Unknown tool: {tool_name}"


def call_llm_with_tools(
    system: str,
    messages: List[Dict[str, Any]],
    temperature: float = 0.65,
    model: Optional[str] = None,
    username: str = "anon",
    u: Optional[Dict[str, Any]] = None,
) -> Tuple[str, List[Dict[str, Any]]]:
    """OpenAI call with tool support.  Returns (final_text, tool_log)."""
    use_model = (model or "").strip() or MODEL
    oai       = get_openai_client()
    timeout   = int(os.getenv("OPENAI_REQUEST_TIMEOUT_SECONDS", "45"))
    sys_msg   = [{"role": "system", "content": system}]
    msgs      = sys_msg + list(messages)
    tool_log: List[Dict[str, Any]] = []

    for _round in range(4):          # max 4 tool-use rounds
        resp   = oai.chat.completions.create(
            model=use_model, messages=msgs,
            temperature=temperature, timeout=timeout,
            tools=_TEAMMATE_TOOLS, tool_choice="auto",
        )
        choice = resp.choices[0]

        # No tool calls → return the text
        if choice.finish_reason == "stop" or not getattr(choice.message, "tool_calls", None):
            return (choice.message.content or "").strip(), tool_log

        # Build the assistant dict to append
        tc_dicts = []
        for tc in (choice.message.tool_calls or []):
            tc_dicts.append({
                "id": tc.id, "type": "function",
                "function": {"name": tc.function.name,
                             "arguments": tc.function.arguments or "{}"},
            })
        msgs.append({
            "role": "assistant",
            "content": choice.message.content or "",   # avoid None — some SDK versions reject null
            "tool_calls": tc_dicts,
        })

        # Execute each tool and append results
        for tc in (choice.message.tool_calls or []):
            fn_name = tc.function.name
            try:
                fn_args = json.loads(tc.function.arguments or "{}")
            except Exception:
                fn_args = {}
            result = _execute_teammate_tool(fn_name, fn_args, username, u or {})
            tool_log.append({"tool": fn_name, "args": fn_args, "result": result[:300]})
            msgs.append({
                "role": "tool", "tool_call_id": tc.id,
                "name": fn_name, "content": result,
            })

    # Safety: one final call after max rounds
    resp = oai.chat.completions.create(
        model=use_model, messages=msgs,
        temperature=temperature, timeout=timeout,
    )
    return (resp.choices[0].message.content or "").strip(), tool_log


# ── WEBHOOK SYSTEM ────────────────────────────────────────────────────────────

_WEBHOOKS_PATH = DATA / "webhooks.json"


def _load_webhooks() -> Dict[str, Any]:
    data = load_json(_WEBHOOKS_PATH, {"webhooks": {}, "updated_at": None})
    if not isinstance(data, dict):
        data = {"webhooks": {}, "updated_at": None}
    data.setdefault("webhooks", {})
    return data


def _save_webhooks(data: Dict[str, Any]) -> None:
    data["updated_at"] = now_iso()
    save_json(_WEBHOOKS_PATH, data)


@app.get("/api/webhooks")
def api_webhooks_list():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    data  = _load_webhooks()
    mine  = [wh for wh in (data.get("webhooks") or {}).values()
             if isinstance(wh, dict) and wh.get("owner") == uname]
    mine.sort(key=lambda x: str(x.get("created_at") or ""), reverse=True)
    return jsonify({"ok": True, "webhooks": mine})


@app.post("/api/webhooks")
def api_webhooks_create():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname   = (u.get("username") if isinstance(u, dict) else None) or "anon"
    payload = request.get_json(silent=True) or {}
    teammate   = (payload.get("teammate")   or "").strip()
    stack_name = (payload.get("stack_name") or "").strip()
    label      = (payload.get("label")      or "").strip()[:80]
    if not teammate or not stack_name:
        return jsonify({"ok": False, "error": "teammate and stack_name required"}), 400

    # Verify the stack exists
    stacks_data = _load_saved_stacks(uname, teammate)
    if stack_name not in (stacks_data.get("stacks") or {}):
        return jsonify({"ok": False, "error": "Stack not found"}), 404

    token = secrets.token_urlsafe(24)
    wh_id = uuid.uuid4().hex[:16]
    wh    = {
        "id":            wh_id,
        "token":         token,
        "teammate":      teammate,
        "stack_name":    stack_name,
        "label":         label or f"{teammate} / {stack_name}",
        "owner":         uname,
        "created_at":    now_iso(),
        "trigger_count": 0,
        "last_triggered": None,
    }
    data = _load_webhooks()
    data["webhooks"][token] = wh
    _save_webhooks(data)

    base = PUBLIC_BASE_URL or request.host_url.rstrip("/")
    url  = f"{base}/webhook/{token}"
    return jsonify({"ok": True, "webhook": wh, "url": url})


@app.post("/api/webhooks/<wh_id>/delete")
def api_webhooks_delete(wh_id: str):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = (u.get("username") if isinstance(u, dict) else None) or "anon"
    data  = _load_webhooks()
    # Find by id or token
    found_token = None
    for tok, wh in list((data.get("webhooks") or {}).items()):
        if isinstance(wh, dict) and (wh.get("id") == wh_id or tok == wh_id):
            if wh.get("owner") != uname:
                return jsonify({"ok": False, "error": "Not your webhook"}), 403
            found_token = tok
            break
    if not found_token:
        return jsonify({"ok": False, "error": "Webhook not found"}), 404
    del data["webhooks"][found_token]
    _save_webhooks(data)
    return jsonify({"ok": True})


@app.post("/webhook/<token>")
def api_webhook_receive(token: str):
    """Unauthenticated inbound webhook — triggers the mapped action stack."""
    data    = _load_webhooks()
    wh      = (data.get("webhooks") or {}).get(token)
    if not isinstance(wh, dict):
        return jsonify({"ok": False, "error": "Webhook not found"}), 404

    owner      = wh.get("owner") or "anon"
    teammate   = wh.get("teammate") or ""
    stack_name = wh.get("stack_name") or ""

    stacks_data = _load_saved_stacks(owner, teammate)
    stack       = (stacks_data.get("stacks") or {}).get(stack_name)
    if not stack:
        return jsonify({"ok": False, "error": "Stack not found"}), 404

    # Accept an optional input payload from the caller
    try:
        body = request.get_json(silent=True) or {}
        user_input = str(body.get("input") or body.get("message") or "")[:500]
    except Exception:
        user_input = ""

    steps  = _normalize_steps(stack.get("steps"))
    run    = _init_run(u=owner, teammate=teammate, stack_name=stack_name,
                       steps=steps, user_input=user_input)
    _persist_run(run)

    # Run in a background thread so the webhook caller gets an instant 200
    def _bg():
        try:
            with app.app_context():
                _run_action_stack_engine(run)
        except Exception:
            pass
    threading.Thread(target=_bg, daemon=True).start()

    # Update trigger count
    wh["trigger_count"] = int(wh.get("trigger_count") or 0) + 1
    wh["last_triggered"] = now_iso()
    data["webhooks"][token] = wh
    _save_webhooks(data)

    _os_log(owner, "webhook_trigger", {
        "token": token[:8] + "…", "teammate": teammate,
        "stack_name": stack_name, "run_id": run.get("id"),
    })

    return jsonify({"ok": True, "run_id": run.get("id"),
                    "teammate": teammate, "stack_name": stack_name})


# ── 1. SSE STREAMING FOLLOWUP ─────────────────────────────────────────────────
@app.post("/api/followup/stream")
def api_followup_stream():
    """SSE streaming followup — tokens arrive in real time instead of one big wait.
    Drops in alongside the existing /api/followup; same thread/logging semantics."""
    from flask import Response, stream_with_context

    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401

    try:
        data = request.get_json(force=True) or {}
    except Exception:
        data = {}

    name          = (data.get("name")    or "").strip()
    msg           = (data.get("message") or "").strip()
    file_ids      = data.get("file_ids") or []
    lighting_mode = bool(data.get("lighting_mode"))

    if not name or not msg:
        return jsonify({"ok": False, "error": "Missing name or message"}), 400

    reg       = load_registry()
    installed = reg.get("installed") or {}
    if name not in installed:
        return jsonify({"ok": False, "error": "Teammate not installed"}), 400

    defn = installed[name]
    msg2, attach_meta, vision_images = build_prompt_with_attachments(msg, file_ids)
    user_content = _build_user_content(msg2, vision_images)

    # Set image context for this teammate (mirrors non-streaming followup)
    bind_uploaded_images_to_teammate(name, file_ids)

    uname = _get_session_username()

    # RAG: retrieve relevant chunks from knowledge base
    rag_context = ""
    try:
        rag_context = _rag_retrieve(uname, msg, top_k=4)
    except Exception:
        rag_context = ""

    sys_prompt = teammate_system_prompt(defn, lighting_mode=lighting_mode, rag_context=rag_context)

    thread = load_thread(name)
    thread = thread[-14:] if len(thread) > 14 else thread

    preferred_model = (defn.get("preferred_model") or "").strip() or MODEL
    oai_client      = get_openai_client()

    # Snapshot thread before streaming so we save the right context
    pre_thread = list(thread)

    def generate():
        parts = []
        try:
            stream = oai_client.chat.completions.create(
                model=preferred_model,
                messages=[{"role": "system", "content": sys_prompt}]
                         + list(thread)
                         + [{"role": "user", "content": user_content}],
                temperature=0.65,
                stream=True,
                timeout=90,
            )
            for chunk in stream:
                if not chunk.choices:
                    continue
                token = getattr(chunk.choices[0].delta, "content", None) or ""
                if token:
                    parts.append(token)
                    yield "data: " + json.dumps({"token": token}) + "\n\n"

            complete_text = "".join(parts)

            # Persist thread
            new_thread = pre_thread + [
                {"role": "user",      "content": msg2},
                {"role": "assistant", "content": complete_text},
            ]
            save_thread(name, new_thread)

            draft = extract_email_draft(complete_text)

            try:
                append_task_log(
                    "teammate_followup_stream",
                    {"name": name, "message": msg,
                     "model": preferred_model,
                     "response_preview": complete_text[:400]},
                    teammate=name, status="success"
                )
                _mark_onboarding_step(uname, "first_prompt", True)
            except Exception:
                pass

            yield "data: " + json.dumps({
                "done":            True,
                "email_draft":     draft,
                "attachment_meta": attach_meta,
            }) + "\n\n"

        except Exception as exc:
            err_msg = str(exc) or "Stream error"
            try:
                _, err_msg = _classify_openai_error(exc)
            except Exception:
                pass
            yield "data: " + json.dumps({"error": err_msg}) + "\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":    "no-cache, no-store",
            "X-Accel-Buffering": "no",
            "Connection":       "keep-alive",
        },
    )


# ── 2. TEXT-TO-SPEECH ─────────────────────────────────────────────────────────
@app.post("/api/tts")
def api_tts():
    """Convert text to speech using OpenAI TTS-1.
    Returns raw MP3 bytes so the frontend can play them with an Audio element."""
    from flask import Response

    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401

    payload = request.get_json(force=True) or {}
    text    = (payload.get("text")  or "").strip()[:2000]   # cap at ~30 s
    voice   = (payload.get("voice") or "alloy").strip()
    if voice not in ("alloy", "echo", "fable", "onyx", "nova", "shimmer"):
        voice = "alloy"
    if not text:
        return jsonify({"ok": False, "error": "Missing text"}), 400

    try:
        oai  = get_openai_client()
        resp = oai.audio.speech.create(model="tts-1", voice=voice, input=text)
        return Response(
            resp.content,
            mimetype="audio/mpeg",
            headers={
                "Cache-Control":        "no-store",
                "Content-Disposition":  "inline; filename=speech.mp3",
            },
        )
    except Exception as exc:
        code, msg = _classify_openai_error(exc)
        return jsonify({"ok": False, "error": msg}), code


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False, threaded=True)
