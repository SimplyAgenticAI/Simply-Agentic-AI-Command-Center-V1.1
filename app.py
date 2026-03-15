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
import tempfile
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime, timedelta
from typing import Dict, Any, List, Tuple, Optional, Union

from flask import Flask, request, render_template_string, jsonify, session, redirect, url_for, make_response, g, send_from_directory, abort
from dotenv import load_dotenv
from openai import OpenAI
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

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

# Optional Claude / Anthropic support
try:
    import anthropic
except Exception:
    anthropic = None


load_dotenv()

APP_TITLE = os.getenv("APP_TITLE", " Simply Agentic AI Round Table V1.12")
MODEL = os.getenv("MODEL", "gpt-5.2")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
CLAUDE_API_KEY = os.getenv("CLAUDE_API_KEY")
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-3-5-sonnet-latest")
AI_PROVIDER = os.getenv("AI_PROVIDER", "openai")
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
    if request.path in ("/login", "/setup", "/reset", "/reset_password", "/static"):
        return None
    if request.path.startswith("/static/"):
        return None

    # allow setup if no users exist
    if request.path.startswith("/setup") and not has_any_user():
        return None

    if request.path.startswith("/api/") and request.path in ("/api/login", "/api/logout", "/api/reset_request", "/api/reset_password", "/api/me", "/api/user/settings", "/api/action_stack_schedules/tick"):
        return None

    if request.path.startswith("/api/") and not session.get("user"):
        # Local-first bootstrap: if the session is missing (common after redeploy/restart),
        # transparently restore a local owner user so the app remains usable without
        # breaking Settings, Core Framework, Image Library, teammate editing, onboarding, etc.
        try:
            session["user"] = ensure_local_owner_user()
        except Exception:
            return jsonify({"ok": False, "error": "Not authenticated"}), 401

    if request.path == "/" and not session.get("user"):
        # Local-first bootstrap on the main app page as well.
        try:
            session["user"] = ensure_local_owner_user()
        except Exception:
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
    {"key": "openai_key", "title": "Add OpenAI key"},
    {"key": "operator_profile", "title": "Fill out Operator Profile"},
    {"key": "full_team", "title": "Install full team"},
    {"key": "first_prompt", "title": "Send first prompt"},
    {"key": "gmail_connected", "title": "Connect Gmail"},
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

    # Step 1: OpenAI key
    try:
        key = (((u or {}).get("settings") or {}).get("openai_key") or "").strip()
        if key:
            _mark_onboarding_step(username, "openai_key", True)
    except Exception:
        pass

    # Step 2: Operator profile
    try:
        op = _load_operator_profile(username) or {}
        meaningful = ["business", "offers", "audience", "goals", "constraints", "tone_rules", "notes"]
        if any(((op.get(k) or "").strip() for k in meaningful)):
            _mark_onboarding_step(username, "operator_profile", True)
    except Exception:
        pass

    # Step 3: Full team installed
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

    # Step 5: Gmail connected
    try:
        if _user_gmail_oauth(u):
            _mark_onboarding_step(username, "gmail_connected", True)
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
    sys = teammate_system_prompt(defn, lighting_mode=lighting_mode)
    msg2, _, vision_images = build_prompt_with_attachments(prompt, file_ids)
    user_content = _build_user_content(msg2, vision_images)
    return call_llm(sys, [{"role": "user", "content": user_content}], temperature=0.65)

def _normalize_steps(steps: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if isinstance(steps, list):
        for s in steps:
            if not isinstance(s, dict):
                continue
            typ = (s.get("type") or "").strip().lower()
            if typ not in ("prompt", "ask_user", "wait", "save_memory", "route"):
                typ = "prompt"
            out.append({
                "type": typ,
                "label": (s.get("label") or "").strip()[:80],
                "prompt": (s.get("prompt") or ""),
                "seconds": int(s.get("seconds") or 0),
                "key": (s.get("key") or "").strip()[:80],
                "to_teammate": (s.get("to_teammate") or "").strip()[:64],
            })
    return out

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

def _run_action_stack_engine(run: Dict[str, Any]) -> Dict[str, Any]:
    """Run a stack until it completes or pauses.

    Pause states:
      - needs_input: stops on an ask_user step until resumed via API
      - waiting: stops on a wait step until wait_until (UTC) has passed
    """
    u = run.get("user") or "anon"
    steps = run.get("steps") or []
    outputs = run.get("outputs") or {}

    # If we were waiting, only resume when due
    try:
        if (run.get("status") == "waiting") and run.get("wait_until"):
            w = str(run.get("wait_until"))
            w_dt = None
            try:
                w_dt = datetime.fromisoformat(w.replace("Z", ""))
            except Exception:
                w_dt = None
            if w_dt and datetime.utcnow() < w_dt:
                # still waiting
                _persist_run(run)
                return run
            # due now, continue
            run["status"] = "running"
            run.pop("wait_until", None)
    except Exception:
        pass

    mem = (_load_action_memory(u).get("memory") or {})
    cursor = int(run.get("cursor") or 0)
    last_output = outputs.get(str(cursor - 1), "") if cursor > 0 else ""

    def _stack_task_log(step_num: int, stype: str, output: str, extra: Optional[Dict[str, Any]] = None, status: str = "success") -> None:
        # Logging must never break execution
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
        except Exception:
            pass

    while cursor < len(steps):
        step = steps[cursor]
        stype = step.get("type", "prompt")

        # Build a render context
        ctx: Dict[str, Any] = {"input": run.get("input", ""), "last": last_output, "teammate": run.get("teammate", "")}
        for i, out in outputs.items():
            try:
                idx = int(i)
                ctx[f"step{idx+1}.output"] = out
            except Exception:
                continue
        for k, v in (mem or {}).items():
            ctx[f"memory.{k}"] = v

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
                val_t = step.get("prompt") or "{{last}}"
                val = _safe_render(val_t, ctx)
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

            elif stype == "route":
                to_tm = (step.get("to_teammate") or "").strip()
                p = _safe_render(step.get("prompt") or "{{last}}", ctx)
                out = _call_teammate_prompt_for_user(u, to_tm, p)
                outputs[str(cursor)] = out
                last_output = out
                run["last_output"] = last_output
                _stack_task_log(cursor + 1, "route", out, {"to": to_tm})
                _append_run_log(run, "route", {"step": cursor + 1, "to": to_tm})

            else:  # "prompt" default
                p = _safe_render(step.get("prompt") or "", ctx)
                out = _call_teammate_prompt_for_user(u, run.get("teammate", ""), p)
                outputs[str(cursor)] = out
                last_output = out
                run["last_output"] = last_output
                _stack_task_log(cursor + 1, "prompt", out, {"label": step.get("label", "")})
                _append_run_log(run, "prompt", {"step": cursor + 1, "label": step.get("label", "")})

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
    except Exception:
        pass
    _append_run_log(run, "complete", {"steps": len(steps)})
    _persist_run(run)
    return run

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
    allowed_str_fields = ["job_title", "version", "mission", "thinking_style", "goal"]
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

def _calendar_create_event(access_token: str, title: str, start_iso: str, end_iso: str, timezone: str, attendees: Optional[List[str]] = None, description: str = "", location: str = "") -> Dict[str, Any]:
    import requests
    url = "https://www.googleapis.com/calendar/v3/calendars/primary/events"
    event: Dict[str, Any] = {
        "summary": title,
        "description": description or "",
        "location": location or "",
        "start": {"dateTime": start_iso, "timeZone": timezone},
        "end": {"dateTime": end_iso, "timeZone": timezone},
    }
    if attendees:
        clean = []
        for a in attendees:
            a = (a or "").strip()
            if not a:
                continue
            clean.append({"email": a})
        if clean:
            event["attendees"] = clean

    r = requests.post(url, headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}, json=event, timeout=20)
    data = r.json() if r.content else {}
    if r.status_code >= 400:
        raise Exception(f"Calendar API error: {data}")
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
        out.append({
            "id": it.get("id",""),
            "summary": it.get("summary",""),
            "start": start,
            "end": end,
            "htmlLink": it.get("htmlLink",""),
            "hangoutLink": it.get("hangoutLink",""),
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

def teammate_system_prompt(defn: Dict[str, Any], lighting_mode: bool = False) -> str:
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
        f"{email_rules}\n"
        f"{lighting_block}"
        f"CORE FRAMEWORK:\n{framework}\n"
        f"{operator_block}"
        f"{client_block}\n\n"
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

def call_llm(system: str, messages: List[Dict[str, Any]], temperature: float = 0.6) -> str:
    try:
        resp = get_openai_client().chat.completions.create(
            model=MODEL,
            messages=[{"role": "system", "content": system}] + messages,
            temperature=temperature,
                    timeout=60,
        )
        return (resp.choices[0].message.content or "").strip()
    except Exception as e:
        safe_msgs: List[Dict[str, Any]] = []
        for m in messages:
            c = m.get("content", "")
            if isinstance(c, list):
                texts = []
                for part in c:
                    if isinstance(part, dict) and part.get("type") == "text":
                        texts.append(part.get("text", ""))
                    elif isinstance(part, dict) and part.get("type") == "image_url":
                        texts.append("[Image attached but model did not accept image input]")
                c2 = "\n".join([t for t in texts if t]).strip()
                safe_msgs.append({"role": m.get("role", "user"), "content": c2})
            else:
                safe_msgs.append({"role": m.get("role", "user"), "content": c})
        try:
            resp2 = get_openai_client().chat.completions.create(
            model=MODEL,
            messages=[{"role": "system", "content": system}] + safe_msgs,
            temperature=temperature,
            timeout=60,
        )
        except Exception as e2:
            # bubble up for route handlers to return a clean JSON error
            raise e2
        out = (resp2.choices[0].message.content or "").strip()
        return out + f"\n\n[Note: image input fallback used due to error: {str(e)}]"


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
    if not u and not has_any_user():
        session["user"] = ensure_local_owner_user()
        u = current_user()
    return jsonify(_onboarding_status_payload(u))

@app.post("/api/onboarding/dismiss")
def api_onboarding_dismiss():
    u = current_user()
    if not u and not has_any_user():
        session["user"] = ensure_local_owner_user()
        u = current_user()
    username = (u.get("username") if isinstance(u, dict) else None) or _get_session_username()
    data = request.get_json(silent=True) or {}
    dismissed = bool(data.get("dismissed", True))
    _dismiss_onboarding(username, dismissed)
    return jsonify({"ok": True, "dismissed": dismissed})

@app.get("/api/user/settings")
def api_get_user_settings():
    u = current_user()
    # If session was lost (common after redeploy) we auto-bootstrap a local owner session
    # so Settings remains usable and the OpenAI key can always be saved.
    if not u:
        session['user'] = ensure_local_owner_user()
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
    # If session was lost (common after redeploy) we auto-bootstrap a local owner session
    # so Settings remains usable and the OpenAI key can always be saved.
    if not u:
        session['user'] = ensure_local_owner_user()
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
        try:
            session["user"] = ensure_local_owner_user()
            u = current_user()
        except Exception:
            u = None
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
    data = request.get_json(force=True)
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
    data = request.get_json(force=True)
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
    sys = teammate_system_prompt(defn, lighting_mode=lighting_mode)

    thread = load_thread(name)
    thread = thread[-14:] if len(thread) > 14 else thread

    latest_uploaded_image = bind_uploaded_images_to_teammate(name, file_ids)

    try:
        uname = _get_session_username()
    except Exception:
        uname = "anon"
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

    text = call_llm(sys, msgs, temperature=0.65)

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
        "email_draft": draft
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



    return jsonify({"ok": True, "name": name, "response": text, "email_draft": draft, "attachment_meta": attach_meta})


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

    if not start or not end:
        return jsonify({"ok": False, "error": "Missing start/end. Provide ISO datetime strings."}), 400
    try:
        created = _calendar_create_event(access_token, title=title, start_iso=start, end_iso=end, timezone=timezone, attendees=attendees, description=description, location=location)
        append_log("calendar_event_created", {"user": u.get("username", ""), "title": title, "start": start, "end": end, "at": now_iso()})
        return jsonify({"ok": True, "event": created})
    except Exception as e:
        append_log("calendar_event_error", {"user": u.get("username", ""), "error": str(e), "at": now_iso()})
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
      radial-gradient(900px 600px at 50% 40%, rgba(247,211,106,.12), transparent 58%),
      radial-gradient(900px 600px at 50% 52%, rgba(124,58,237,.22), transparent 55%),
      radial-gradient(800px 600px at 50% 45%, rgba(59,130,246,.15), transparent 55%),
      radial-gradient(1100px 800px at 50% 60%, rgba(10,14,30,.9), rgba(7,10,20,1) 65%);
    color:var(--text);
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    padding: 26px 14px;
  }
  .card{
    width: 520px;
    max-width: calc(100vw - 22px);
    background: rgba(14,22,48,.82);
    border:1px solid rgba(42,58,106,.9);
    border-radius: 18px;
    padding: 16px;
    box-shadow: 0 0 60px rgba(0,0,0,.45);
    backdrop-filter: blur(10px);
    position: relative;
    overflow: hidden;
  }
  .card::before{
    content:"";
    position:absolute;
    inset:0;
    padding:1px;
    border-radius:18px;
    background: linear-gradient(135deg, rgba(247,211,106,.70), rgba(124,58,237,.40), rgba(59,130,246,.35));
    -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
    -webkit-mask-composite: xor;
    mask-composite: exclude;
    pointer-events:none;
  }
  .brand{ display:flex; gap:10px; align-items:center; font-weight:800; letter-spacing:.2px; margin-bottom: 10px; }
  .dot{
    width:10px;height:10px;border-radius:999px;
    background: radial-gradient(circle at 30% 30%, #fff, #7c3aed);
    box-shadow: 0 0 14px rgba(124,58,237,.55);
  }
  .muted{ color: var(--muted); font-size: 12px; }
  label{ display:block; font-size: 11px; color: var(--muted); margin: 10px 0 6px 0; font-weight: 700; letter-spacing:.2px; }
  input{
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
  .row{ display:flex; gap:10px; align-items:center; justify-content:space-between; margin-top: 12px; flex-wrap:wrap; }
  .btn{
    border:1px solid rgba(42,58,106,.9);
    background: rgba(11,16,36,.9);
    color:var(--text);
    padding:10px 12px;
    border-radius:12px;
    cursor:pointer;
    font-size:13px;
  }
  .btn:hover{ background: rgba(20,28,60,.92); }
  .btnPrimary{
    border:1px solid rgba(247,211,106,.55);
    background: linear-gradient(180deg, rgba(124,58,237,.35), rgba(59,130,246,.12));
    box-shadow: 0 0 24px rgba(124,58,237,.18), 0 0 18px rgba(247,211,106,.12), inset 0 0 0 1px rgba(247,211,106,.18);
  }
  a{ color: #c7d2fe; text-decoration:none; }
  a:hover{ text-decoration: underline; }
  .err{ margin-top: 10px; color: #ffb4b4; font-size: 12px; white-space: pre-wrap; }
  .ok{ margin-top: 10px; color: #9effc2; font-size: 12px; white-space: pre-wrap; }

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
  body{ overflow-x:hidden; }
  .container{ padding: 12px; padding-bottom: 40px; }
  .row{ flex-wrap: wrap; gap: 10px; }
  .btn, .seatToolBtn{ padding: 10px 12px; border-radius: 12px; }
  .seatToolBtn{ font-size: 13px; }
  .actions{ flex-wrap: wrap; }
  .grid{ grid-template-columns: 1fr !important; gap: 10px; }
  #modalWin{ width: calc(100vw - 16px) !important; left: 8px !important; right: 8px !important; top: 8px !important; height: calc(100vh - 16px) !important; max-height: calc(100vh - 16px) !important; }
  #modalScroll{ max-height: calc(100vh - 120px) !important; }
  .seatTools{ flex-wrap: wrap; gap: 8px; }
  .seat{ min-width: 160px; }
  textarea, input, select{ font-size: 16px; } /* prevents iOS zoom */
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
</head><body>
  <div class="card">
    <div class="brand"><div class="dot"></div><div>{{app_title}}</div></div>
    <div class="muted">Login to access your command center.</div>

    <form method="post" action="/login">
      <label>Username</label>
      <input name="username" autocomplete="username" required/>
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
  </div>
</body></html>
"""


REGISTER_HTML = r"""
<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=5,user-scalable=yes"/>
<title>{{app_title}} | Create Account</title>
""" + AUTH_BASE_CSS + r"""
</head><body>
  <div class="card">
    <div class="brand"><div class="dot"></div><div>{{app_title}}</div></div>
    <div class="muted">Create a new account.</div>

    <form method="post" action="/register">
      <label>Username</label>
      <input name="username" autocomplete="username" required/>
      <label>Email (optional)</label>
      <input name="email" autocomplete="email"/>
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
    <div class="muted">Create the first account.</div>

    <form method="post" action="/setup">
      <label>Username</label>
      <input name="username" autocomplete="username" required/>
      <label>Email (optional)</label>
      <input name="email" autocomplete="email"/>
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
    return render_template_string(LOGIN_HTML, app_title=APP_TITLE, error=None, allow_setup=allow_setup, allow_signup=_signup_enabled())

@app.post("/login")
def login_post():
    username = _clean_username(request.form.get("username", ""))
    password = (request.form.get("password") or "").strip()
    remember = (request.form.get("remember") or "").strip()

    data = load_users()
    u = (data.get("users") or {}).get(username)
    if not u or not check_password_hash(u.get("password_hash",""), password):
        return render_template_string(LOGIN_HTML, app_title=APP_TITLE, error="Invalid username or password", allow_setup=(not has_any_user()), allow_signup=_signup_enabled())

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
    return render_template_string(REGISTER_HTML, app_title=APP_TITLE, error=None, ok="Account created. You can log in now.", require_code=_require_invite_code())
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
    :root{ --text:#e6edff; --muted:#b8c4ffcc; }
    *{box-sizing:border-box}
    html, body{ height:auto; min-height:100%; overflow-y:auto; }
    body{
      margin:0;
      font-family: Arial, sans-serif;
      background:
        radial-gradient(900px 600px at 50% 52%, rgba(124,58,237,.22), transparent 55%),
        radial-gradient(800px 600px at 50% 45%, rgba(59,130,246,.15), transparent 55%),
        radial-gradient(1100px 800px at 50% 60%, rgba(10,14,30,.9), rgba(7,10,20,1) 65%);
      color:var(--text);
    }

    .topbar{
      position: sticky; top: 0; z-index: 60;
      height:56px; display:flex; align-items:center; justify-content:space-between;
      padding:0 14px;
      background: linear-gradient(180deg, rgba(14,22,48,.92), rgba(14,22,48,.60));
      border-bottom:1px solid rgba(34,49,90,.8);
      backdrop-filter: blur(10px);
    }
    .brand{ display:flex; gap:10px; align-items:center; font-weight:700; letter-spacing:.2px; }
    .dot{
      width:10px;height:10px;border-radius:999px;
      background: radial-gradient(circle at 30% 30%, #fff, #7c3aed);
      box-shadow: 0 0 14px rgba(124,58,237,.55);
    }
    .rightmeta{ display:flex; gap:10px; align-items:center; font-size:12px; color:var(--muted); flex-wrap:wrap; justify-content:flex-end; }
    .btn{
      border:1px solid rgba(42,58,106,.9);
      background: rgba(11,16,36,.9);
      color:var(--text);
      padding:10px 12px;
      border-radius:12px;
      cursor:pointer;
      font-size:13px;
    }
    .btn:hover{ background: rgba(20,28,60,.92); }
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
      min-height: calc(100vh - 56px);
      display:grid;
      grid-template-columns: 1fr 420px;
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
        radial-gradient(circle at 50% 50%, rgba(124,58,237,.20), rgba(11,16,36,.86) 52%, rgba(7,10,20,.95) 76%),
        radial-gradient(circle at 50% 55%, rgba(59,130,246,.16), transparent 55%);
      border: 1px solid rgba(42,58,106,.85);
      box-shadow:
        0 0 0 1px rgba(17,24,39,.35) inset,
        0 0 70px rgba(124,58,237,.18),
        0 0 120px rgba(59,130,246,.10);
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
      border: 1px solid rgba(59,130,246,.15);
      box-shadow: 0 0 60px rgba(59,130,246,.10) inset;
    }

    .operator{
      position:absolute;
      left:50%; top:50%;
      transform: translate(-50%,-50%);
      width: 44%;
      min-width: 340px;
      max-width: 520px;
      background: rgba(14,22,48,.82);
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
    .seatRole{ font-size:11px; color:var(--muted); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
    .seatStatus{ font-size:11px; color:var(--muted); opacity:.95; }

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
      background: rgba(7,10,20,.65);
      color: var(--text);
      padding: 6px 8px;
      border-radius: 10px;
      font-size: 11px;
      cursor:pointer;
      pointer-events:auto;
    }
    .seatToolBtn:hover{
      background: rgba(14,22,48,.75);
      border-color: rgba(124,58,237,.55);
    }

    .side{
      position: sticky;
      top: 56px;
      align-self:start;
      height: calc(100vh - 56px);
      overflow:auto;
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
    }

    .sideHead{
      display:flex; align-items:center; justify-content:space-between; gap:10px;
      margin-bottom:10px;
    }
    .sideTitle{ display:flex; flex-direction:column; gap:2px; min-width:0; }
    .sideTitle .h1{ font-weight:800; }
    .sideTitle .h2{ font-size:12px; color:var(--muted); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }

    .thread{
      height: 40vh;
      overflow:auto;
      background: rgba(7,10,20,.65);
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
      background: rgba(7,10,20,.65);
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

    .tiny{ font-size: 11px; color:var(--muted); }

    .overlay{
      position:fixed; inset:0; display:none;
      align-items:flex-start; justify-content:center;
      padding-top: 68px;
      background: rgba(7,10,20,.65);
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
      resize: none;
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
      background: rgba(7,10,20,.45);
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
      background: rgba(7,10,20,.45);
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
      .topbarInner{ flex-wrap:wrap; height:auto; gap:10px; padding:10px 12px; }
      .rightmeta{ justify-content:flex-start; }
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

</style>
</head>
<body>
  <div class="topbar">
    <div class="brand">
      <div class="dot"></div>
      <div>{{app_title}}</div>
    </div>
    <div class="rightmeta">
      <div id="modelTag">Model: {{model}}</div>
      <button class="btn" id="assembleBtn">Assemble all</button>
      <button class="btn" id="frameworkBtn">Core framework</button>
      <button class="btn" id="manageTeamBtn">Add or dismiss teammates</button>
      <button class="btn" id="createTeamBtn">Create teammate</button>
      <button class="btn" id="installFullBtn">Install full team</button>
      <button class="btn" id="settingsBtn">Settings</button>
            <button class="btn" id="calendarBtn">Calendar</button>
<button class="btn" id="crmBtn">Client Center</button>
<button class="btn" id="imageLibBtn">Image Library</button>
      <button class="btn" id="onboardingBtn" title="Guided onboarding checklist">Next step</button>
            <button class="btn" id="openApiKeyHelpBtn" title="How to get and set your OpenAI API key">Get your OpenAI key</button>
      <a class="btn" href="/logout" style="text-decoration:none; display:inline-block;">Logout</a>
    </div>
  </div>

  <!-- ===== NEW: Mobile Vertical UI v2 (bottom bar + drawer) ===== -->
  <div class="mobileBar" id="mobileBar">
    <button class="btn" id="mobileMenuBtn">Menu</button>
    <button class="btn btnPrimary" id="mobileAssembleBtn">Assemble</button>
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
        <button class="btn" data-click="assembleBtn">Assemble all</button>
        <button class="btn" data-click="frameworkBtn">Core framework</button>
        <button class="btn" data-click="manageTeamBtn">Add or dismiss</button>
        <button class="btn" data-click="createTeamBtn">Create teammate</button>
        <button class="btn" data-click="installFullBtn">Install full team</button>
        <button class="btn" data-click="settingsBtn">Settings</button>
                <button class="btn" data-click="calendarBtn">Calendar</button>
<button class="btn" data-click="crmBtn">Client Center</button>
        <button class="btn" data-click="imageLibBtn">Image Library</button>
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


<div id="stackForm" class="modalForm" style="display:none;">
  <div class="tiny">Stack: queue multiple prompts for this teammate. Run now or schedule.</div>

  <div class="grid" style="margin-top:10px;">
    <div>
      <label>Stack name</label>
      <input id="stackName" placeholder="e.g. Welcome Sequence" />
    </div>
    <div>
      <label>Saved stacks</label>
      <select id="stackSelect"></select>
    </div>
  </div>

  <div style="margin-top:10px;">
    <label>Add Prompt step</label>
    <textarea id="stackPrompt" rows="3" placeholder="Example: Write the welcome email for {{input}}"></textarea>
    <div class="actions" style="justify-content:flex-start; gap:8px; margin-top:8px; flex-wrap:wrap;">
      <button class="btn" id="stackAddPromptBtn">Add step</button>
      <button class="btn" id="stackClearBtn">Clear</button>
      <button class="btn" id="stackSaveBtn">Save</button>
      <button class="btn btnPrimary" id="stackRunBtn">Run</button>
      <button class="btn" id="cancelStack">Close</button>
    </div>
  </div>

  <div id="stackSteps" style="margin-top:10px;"></div>
  <div id="stackStatus" class="tiny" style="margin-top:10px;"></div>

  <div class="tiny" style="margin:14px 0 6px;">Scheduling</div>
  <div class="grid">
    <div>
      <label>Run once at</label>
      <input id="stackRunAt" type="datetime-local" />
    </div>
    <div>
      <label>Run daily at</label>
      <input id="stackDailyAt" type="time" />
    </div>
  </div>
  <div class="actions" style="justify-content:flex-start; gap:8px; margin-top:8px; flex-wrap:wrap;">
    <button class="btn" id="stackScheduleOnceBtn">Schedule once</button>
    <button class="btn" id="stackScheduleDailyBtn">Schedule daily</button>
    <button class="btn" id="stackRefreshSchedulesBtn">Refresh</button>
  </div>
  <div id="stackSchedules" style="margin-top:8px;"></div>
</div>


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

                <div class="actions">
                  <button class="btn" id="cancelEdit">Cancel</button>
                  <button class="btn btnPrimary" id="saveEdit">Save changes</button>
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
                  <button class="btn btnPrimary" id="saveManage">Save</button>
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
                </div>
                <div class="tiny" id="settingsStatus" style="margin-top:10px;"></div>
              </div>

              

<div class="modalForm" id="crmForm" style="display:none;">
  <div class="tiny" style="margin-bottom:10px;">Client Command Center. Clients and broadcasts without leaving the Round Table.</div>

  <div class="pillRow" style="justify-content:flex-start; gap:8px; flex-wrap:wrap; margin-bottom:10px;">
    <button class="btn btnMini" id="crmTabClients">Clients</button>
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
    </div>

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
      </div>
      <div class="tiny" id="crmEditStatus" style="margin-top:8px;"></div>
    </div>
  </div>

  <!-- Pipeline -->
  <div id="crmViewPipeline" style="display:none;">
    <div class="tiny" style="margin-bottom:8px;">Edit your pipeline stages (one per line). This controls filtering, sequences, and followups.</div>
    <label>Stages</label>
    <textarea id="crmStagesText" style="height:180px" placeholder="Lead\nConversation\nInterested\nCall booked\nClient\nVIP\nPast client\nCold"></textarea>
    <div class="actions" style="justify-content:flex-end; margin-top:10px;">
      <button class="btn" id="crmReloadPipeline">Reload</button>
      <button class="btn btnPrimary" id="crmSavePipeline">Save</button>
    </div>
    <div class="tiny" id="crmPipelineStatus" style="margin-top:8px;"></div>
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
</div>

              <div class="modalForm" id="calendarForm" style="display:none;">
  <div class="tiny" style="margin-bottom:10px;">Click a date to add a task or schedule a call.</div>

  <div style="display:flex; gap:12px; flex-wrap:wrap;">
    <div style="flex: 1 1 360px; min-width: 280px;">
      <div class="pillRow" style="justify-content:space-between; align-items:center; margin-bottom:8px;">
        <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
          <button class="btn btnMini" id="calPrevBtn">Prev</button>
          <button class="btn btnMini" id="calTodayBtn">Today</button>
          <button class="btn btnMini" id="calNextBtn">Next</button>
        </div>
        <div class="pill" id="calMonthLabel">Month</div>
      </div>

      <div class="calWeekdays" id="calWeekdays"></div>
      <div class="calGrid" id="calGrid"></div>
      <div class="tiny" id="calLoadStatus" style="margin-top:8px; opacity:.85;"></div>
    </div>

    <div style="flex: 1 1 260px; min-width: 260px;">
      <div class="diagCard" style="padding:10px;">
        <div style="display:flex; justify-content:space-between; gap:8px; flex-wrap:wrap;">
          <div>
            <div style="font-weight:800;" id="calSelectedLabel">Select a date</div>
            <div class="tiny" style="opacity:.85;" id="calSelectedSub"> </div>
          </div>
        </div>

        <div style="height:10px"></div>

        <div style="border:1px solid rgba(255,255,255,.10); border-radius:14px; padding:10px; background: rgba(0,0,0,.18);">
          <div class="tiny" style="margin-bottom:8px;">Add task</div>
          <label>Title</label>
          <input id="calTaskTitle" placeholder="Follow up with..." />
          <div class="grid" style="margin-top:10px;">
            <div>
              <label>Time</label>
              <input id="calTaskTime" type="time" value="17:00" />
            </div>
            <div style="display:flex; align-items:flex-end; justify-content:flex-end;">
              <button class="btn btnPrimary" id="calAddTaskBtn">Add</button>
            </div>
          </div>
          <div class="tiny" id="calTaskStatus" style="margin-top:8px;"></div>
        </div>

        <div style="height:10px"></div>

        <div style="border:1px solid rgba(255,255,255,.10); border-radius:14px; padding:10px; background: rgba(0,0,0,.18);">
          <div class="tiny" style="margin-bottom:8px;">Schedule call</div>
          <label>Title</label>
          <input id="calCallTitle" placeholder="Strategy call" value="Strategy call" />
          <div class="grid" style="margin-top:10px;">
            <div>
              <label>Start</label>
              <input id="calCallTime" type="time" value="09:00" />
            </div>
            <div>
              <label>Duration</label>
              <select id="calCallDur">
                <option value="30">30 min</option>
                <option value="45">45 min</option>
                <option value="60">60 min</option>
              </select>
            </div>
          </div>
          <div class="actions" style="justify-content:flex-end; margin-top:10px;">
            <button class="btn btnPrimary" id="calCreateCallBtn">Create</button>
          </div>
          <div class="tiny" id="calCallStatus" style="margin-top:8px;"></div>
        </div>

        <div style="height:10px"></div>

        <div class="tiny" style="margin-bottom:6px;">Events</div>
        <div id="calDayEvents" class="tiny" style="opacity:.95;"></div>
      </div>
    </div>
  </div>
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

            <textarea class="opText" id="opPrompt" placeholder="Type a group prompt for the entire table. To assemble only, say: All teammates to the round table"></textarea>

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
      </div>
    </div>

    <div class="side">
      <div class="sideCard">
        <div class="sideHead">
          <div class="sideTitle">
            <div class="h1" id="seatTitle">Select a seat</div>
            <div class="h2" id="seatSub">Click any teammate around the table for individual chat.</div>
          </div>
          <button class="btn" id="refreshThread">Refresh</button>
        </div>

        <div class="passRow" id="seatPassRow" style="margin: 10px 0 0 0;">
          <button class="btn btnMini passBtn" id="passSeatRisk" title="Run Risk Assessment on the most recent assistant output in this seat">🔍 Risk</button>
          <button class="btn btnMini passBtn" id="passSeatScale" title="Run Scalability Ranking on the most recent assistant output in this seat">📈 Scale</button>
          <button class="btn btnMini passBtn" id="passSeatFail" title="Run Failure Simulator on the most recent assistant output in this seat">💥 Failure</button>          <button class="btn btnMini passBtn" id="passSeatConstr" title="Run Constraint Scan on the most recent assistant output in this seat">🧩 Constraints</button>
          <button class="btn btnMini passBtn" id="passSeatOpt" title="Run Optimization Pass on the most recent assistant output in this seat">⚡ Optimize</button>
          <div class="tiny" style="opacity:.9;">Runs on the latest assistant reply in this seat.</div>
        </div>

        <div class="thread" id="thread"></div>

        <div style="height:10px"></div>
        <textarea class="followBox" id="followMsg" placeholder="Send an individual message to the selected teammate..."></textarea>

        <div class="pillRow">
          <input type="file" id="dmFiles" multiple style="display:none" />
          <button class="btn btnMini" id="pickDmFiles">Upload files</button>
          <button class="btn btnMini" id="screenDmBtn">Share screen</button>
          <button class="btn btnMini" id="talkDmBtn">Talk</button>
          <!-- CHANGE: Always Listening toggle (DM) -->
          <button class="btn btnMini" id="alwaysListenDmBtn">Always listen</button>
          <button class="btn btnPrimary" id="sendFollow">Send to selected</button>
        </div>
        <div id="dmAttachList" class="pillRow"></div>

        <div class="tiny" style="margin-top:8px;">
          Tip: Share screen captures a screenshot and attaches it to your next message.
        </div>
        <div class="tiny" id="micStatusDm" style="margin-top:8px;">Mic: idle</div>
      </div>

      <div class="sideCard">
        <div class="sideHead">
          <div class="sideTitle">
            <div class="h1">Email Console</div>
            <div class="h2">When a teammate drafts an email, fields auto fill here. You approve before sending.</div>
          </div>
        </div>

        <div class="tiny" id="smtpStatus">SMTP: checking...</div>
        <div style="height:10px"></div>

        <div class="row2">
          <input class="field" id="emailFrom" placeholder="From" readonly/>
          <input class="field" id="emailTo" placeholder="To: name@email.com"/>
        </div>

        <div style="height:10px"></div>
        <input class="field" id="emailSubject" placeholder="Subject"/>

        <div style="height:10px"></div>
        <textarea class="field" id="emailBody" style="height:150px" placeholder="Email body"></textarea>

        <div style="display:flex; gap:10px; flex-wrap:wrap; margin-top:10px;">
          <button class="btn" id="draftWithSelected">Draft with selected</button>
          <button class="btn btnPrimary" id="sendEmailBtn">Approve and send</button>
        </div>

        <div class="tiny" style="margin-top:8px;">
          Sending is always manual. The teammate drafts. You approve.
        </div>
      </div>
    </div>
  </div>

  <!-- NEW: Diagnostics Panel v1 (additive) -->
  <div id="diagFab" title="Diagnostics">
    <button id="diagOpenBtn" type="button">Diag</button>
  </div>
  <div 
  <!-- NEW: Mobile table zoom controls (additive) -->
  <div id="tableZoomFab" aria-label="Table zoom controls" style="display:none">
    <button class="zbtn" id="zoomOutBtn" title="Zoom out">−</button>
    <button class="zbtn" id="zoomFitBtn" title="Fit to screen">Fit</button>
    <button class="zbtn" id="zoomCenterBtn" title="Center table">⦿</button>
    <button class="zbtn" id="tableLockBtn" title="Lock table so you can scroll">🔒</button>
    <button class="zbtn" id="zoomInBtn" title="Zoom in">+</button>
  </div>

id="diagOverlay"></div>
  <div id="diagPanel" role="dialog" aria-modal="true" aria-label="Diagnostics Panel">
    <div id="diagHeader">
      <div class="title">System Diagnostics</div>
      <div class="actions">
        <button class="diagBtn" id="diagRefreshBtn" type="button">Refresh</button>
        <button class="diagBtn" id="diagCopyBtn" type="button">Copy</button>
        <button class="diagBtn" id="diagCloseBtn" type="button">Close</button>
      </div>
    </div>
    <div id="diagBody">
      <div id="diagGrid">
        <div class="diagCard"><div class="diagLabel">Active teammates (detected)</div><div class="diagValue" id="diagActive">…</div></div>
        <div class="diagCard"><div class="diagLabel">Installed teammates</div><div class="diagValue" id="diagInstalled">…</div></div>
        <div class="diagCard"><div class="diagLabel">Email capability</div><div class="diagValue" id="diagEmail">…</div></div>
        <div class="diagCard"><div class="diagLabel">Calendar capability</div><div class="diagValue" id="diagCal">…</div></div>
      </div>
      <div class="diagLabel">Raw payload</div>
      <pre id="diagPre">Loading…</pre>
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
    let seatStatus = {};
    let lastGroupOutputs = {};
    let lastSeatAssistantText = "";
    let lastEmailDraftBy = "";
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
      try{ saveModalSize({width:w, height:h}); }catch(e){}
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
      if($("stackForm")) $("stackForm").style.display = "none";
      if($("apiKeyHelpForm")) $("apiKeyHelpForm").style.display = "none";
      if($("crmForm")) $("crmForm").style.display = "none";
      if($("calendarForm")) $("calendarForm").style.display = "none";
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

function showModal(title, body, imgUrl){
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

    (function initModalDrag(){
      const bar = $("modalBar");
      const win = $("modalWin");
      if(!bar || !win) return;

      let startX = 0, startY = 0;
      let startLeft = 0, startTop = 0;
      function clamp(v, min, max){ return Math.max(min, Math.min(max, v)); }

      bar.addEventListener("pointerdown", (e) => {
        const t = e.target;
        if(t && (t.id === "closeModal" || t.id === "minModal" || t.id === "restoreModal")) return;

        modalDragging = true;
        bar.setPointerCapture(e.pointerId);

        const r = win.getBoundingClientRect();
        startX = e.clientX;
        startY = e.clientY;
        startLeft = r.left;
        startTop = r.top;

        win.style.transform = "none";
        win.style.left = r.left + "px";
        win.style.top = r.top + "px";
      });

      bar.addEventListener("pointermove", (e) => {
        if(!modalDragging) return;

        const dx = e.clientX - startX;
        const dy = e.clientY - startY;

        const r = win.getBoundingClientRect();
        const nextLeft = startLeft + dx;
        const nextTop = startTop + dy;

        const maxLeft = window.innerWidth - r.width - 6;
        const maxTop = window.innerHeight - r.height - 6;

        win.style.left = clamp(nextLeft, 6, Math.max(6, maxLeft)) + "px";
        win.style.top = clamp(nextTop, 6, Math.max(6, maxTop)) + "px";
      });

      function endDrag(pointerId){
        if(!modalDragging) return;
        modalDragging = false;
        try{ bar.releasePointerCapture(pointerId); }catch(err){}
        const r = win.getBoundingClientRect();
        saveModalPos(r.left, r.top);
      }

      bar.addEventListener("pointerup", (e) => endDrag(e.pointerId));
      bar.addEventListener("pointercancel", (e) => endDrag(e.pointerId));
    })();

    (function initModalResizePersist(){
      const win = $("modalWin");
      if(!win) return;
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

      if(draft.to) $("emailTo").value = draft.to;
      if(draft.subject) $("emailSubject").value = draft.subject;
      if(draft.body) $("emailBody").value = draft.body;

      setEmailFrom(lastEmailDraftBy);

      showModal(
        "Email draft ready",
        "Fields were auto filled in the Email Console.\n\nReview them, then click Approve and send."
      );
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

    // -------- Action Stacks (Sequence Runner) --------
const ActionStack = { teammate: "", steps: [] };

function showStackTab(title){
  try{ document.body.style.overflow = "hidden"; }catch(_){}
  if($("modalTitle")) $("modalTitle").innerText = title || "Stack";
  if(typeof hideAllModalForms === "function") hideAllModalForms();
  if($("modalBody")) $("modalBody").style.display = "none";
  if($("stackForm")) $("stackForm").style.display = "block";
  if($("overlay")) $("overlay").classList.add("show");
  if(typeof applyModalPos === "function") applyModalPos();
  const sc = $("modalScroll");
  if(sc) sc.scrollTop = 0;  if($("clientsForm")) $("clientsForm").style.display = "none";
}



function renderRunOutputs(run){
  const box = $("stackStatus");
  if(!box || !run) return;
  const outputs = run.outputs || {};
  const keys = Object.keys(outputs).map(k => parseInt(k,10)).filter(n => !isNaN(n)).sort((a,b)=>a-b);
  if(keys.length === 0){
    box.innerHTML = `<div class="tiny">Run status: ${run.status}</div>`;
    return;
  }
  const lastKey = keys[keys.length-1];
  const last = outputs[String(lastKey)] || "";
  box.innerHTML = `<div class="tiny">Run status: ${run.status} • Last output shown below</div>`;
  if(run.status === "needs_input"){
    const wrap = document.createElement("div");
    wrap.className = "pillRow";
    wrap.style.marginTop = "10px";
    const inp = document.createElement("input");
    inp.id = "stackResumeInput";
    inp.className = "input";
    inp.placeholder = "Reply for Ask user step...";
    inp.style.flex = "1";
    const btn = document.createElement("button");
    btn.id = "stackResumeBtn";
    btn.className = "btn btnPrimary";
    btn.innerText = "Resume";
    btn.onclick = async()=>{
      try{
        const r = await fetch(`/api/action_stack_runs/${encodeURIComponent(run.id)}/resume`, {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({input: inp.value||""})});
        const d = await r.json();
        if(d.ok){ renderStackSteps(); renderRunOutputs(d.run); }
        else{ if($('stackStatus')) $('stackStatus').innerText = d.error || 'Resume failed.'; }
      }catch(e){ if($('stackStatus')) $('stackStatus').innerText = 'Resume failed.'; }
    };
    wrap.appendChild(inp);
    wrap.appendChild(btn);
    box.appendChild(wrap);
  }
  const stepsBox = $("stackSteps");
  // Remove previous output blocks if any
  try{ Array.from(document.querySelectorAll('.stackLastOutputBlock')).forEach(n=>n.remove()); }catch(_){ }
  if(stepsBox){
    const hr = document.createElement("div");
    hr.style.height="1px"; hr.style.background="rgba(42,58,106,.55)"; hr.style.margin="10px 0";
    const outTitle = document.createElement("div");
    outTitle.className="tiny";
    outTitle.className = (outTitle.className || "") + " stackLastOutputBlock";
    outTitle.innerText="Latest run outputs";
    const outPre = document.createElement("div");
    outPre.className="tiny";
    outPre.style.whiteSpace="pre-wrap";
    outPre.style.padding="10px";
    outPre.style.border="1px solid rgba(42,58,106,.65)";
    outPre.style.borderRadius="12px";
    outPre.style.background="rgba(7,10,20,.25)";
    outPre.className = (outPre.className || "") + " stackLastOutputBlock";
    outPre.innerText = String(last).slice(0,8000);
    hr.className = "stackLastOutputBlock";
    stepsBox.appendChild(hr);
    stepsBox.appendChild(outTitle);
    stepsBox.appendChild(outPre);
  }
}

function renderStackSteps(){
  const box = $("stackSteps");
  if(!box) return;
  box.innerHTML = "";
  if(ActionStack.steps.length === 0){
    const t = document.createElement("div");
    t.className = "tiny";
    t.innerText = "No steps yet. Add one or more prompt steps.";
    box.appendChild(t);
    return;
  }
  ActionStack.steps.forEach((s, idx) => {
    const row = document.createElement("div");
    row.className = "pillRow";
    row.style.marginTop = "6px";

    const pill = document.createElement("div");
    pill.className = "pill";
    pill.innerText = `Step ${idx+1}: Prompt`;
    row.appendChild(pill);

    const del = document.createElement("button");
    del.className = "btn";
    del.innerText = "Delete";
    del.onclick = () => { ActionStack.steps.splice(idx,1); renderStackSteps(); };
    row.appendChild(del);

    const up = document.createElement("button");
    up.className = "btn";
    up.innerText = "Up";
    up.onclick = () => {
      if(idx === 0) return;
      const tmp = ActionStack.steps[idx-1];
      ActionStack.steps[idx-1] = ActionStack.steps[idx];
      ActionStack.steps[idx] = tmp;
      renderStackSteps();
    };
    row.appendChild(up);

    const down = document.createElement("button");
    down.className = "btn";
    down.innerText = "Down";
    down.onclick = () => {
      if(idx >= ActionStack.steps.length-1) return;
      const tmp = ActionStack.steps[idx+1];
      ActionStack.steps[idx+1] = ActionStack.steps[idx];
      ActionStack.steps[idx] = tmp;
      renderStackSteps();
    };
    row.appendChild(down);

    box.appendChild(row);

    const pre = document.createElement("div");
    pre.className = "tiny";
    pre.style.whiteSpace = "pre-wrap";
    pre.style.marginTop = "4px";
    pre.innerText = (s.prompt || "").slice(0, 1200);
    box.appendChild(pre);
  });
}

async function loadStacksForTeammate(teammate){
  const sel = $("stackSelect");
  if(!sel) return;
  sel.innerHTML = "";
  const res = await fetch(`/api/teammates/${encodeURIComponent(teammate)}/stacks`);
  const data = await res.json();
  if(!data.ok) return;
  const opt0 = document.createElement("option");
  opt0.value = "";
  opt0.text = "(select)";
  sel.appendChild(opt0);
  (data.stacks || []).forEach((n) => {
    const opt = document.createElement("option");
    opt.value = n;
    opt.text = n;
    sel.appendChild(opt);
  });
}

async function loadStackDetail(teammate, name){
  if(!name) return;
  const res = await fetch(`/api/teammates/${encodeURIComponent(teammate)}/stacks/${encodeURIComponent(name)}`);
  const data = await res.json();
  if(!data.ok) return;
  const stack = data.stack || {};
  ActionStack.steps = (stack.steps || []).map(s => ({type:"prompt", prompt: s.prompt || ""}));
  if($("stackName")) $("stackName").value = stack.name || name;
  renderStackSteps();
}

async function loadSchedulesForTeammate(teammate){
  const box = $("stackSchedules");
  if(!box) return;
  box.innerHTML = "";
  const res = await fetch(`/api/teammates/${encodeURIComponent(teammate)}/stacks/schedules`);
  const data = await res.json();
  if(!data.ok) return;
  const items = data.schedules || [];
  if(items.length === 0){
    const t = document.createElement("div");
    t.className = "tiny";
    t.innerText = "No schedules yet.";
    box.appendChild(t);
    return;
  }
  items.forEach((s) => {
    const row = document.createElement("div");
    row.className = "pillRow";
    row.style.marginTop = "6px";
    const pill = document.createElement("div");
    pill.className = "pill";
    const mode = s.mode || "once";
    const when = mode === "daily" ? (`daily @ ${s.time || ""}`) : (s.run_at || "");
        const lr = s.last_run ? (` • last: ${s.last_run}`) : "";
        
    pill.innerText = `${s.stack_name || ""} • ${when}${lr}`;
    row.appendChild(pill);

    const del = document.createElement("button");
    del.className = "btn";
    del.innerText = "Delete";
    del.onclick = async () => {
      await fetch(`/api/teammates/${encodeURIComponent(teammate)}/stacks/schedule/delete`, {
        method:"POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({schedule_id: s.id})
      });
      loadSchedulesForTeammate(teammate);
    };
    row.appendChild(del);
    box.appendChild(row);
  });
}

async function saveCurrentStack(){
  const teammate = ActionStack.teammate;
  const name = (($("stackName") && $("stackName").value) || "").trim();
  if(!teammate){ if($("stackStatus")) $("stackStatus").innerText = "No teammate selected."; return; }
  if(!name){ if($("stackStatus")) $("stackStatus").innerText = "Enter a stack name."; return; }
  const res = await fetch(`/api/teammates/${encodeURIComponent(teammate)}/stacks/${encodeURIComponent(name)}`, {
    method:"POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({steps: ActionStack.steps})
  });
  const data = await res.json();
  if($("stackStatus")) $("stackStatus").innerText = data.ok ? "Saved." : (data.error || "Save failed.");
  loadStacksForTeammate(teammate);
}

async function runCurrentStack(){
  const teammate = ActionStack.teammate;
  const name = ((($("stackName") && $("stackName").value) || "").trim()) || ((($("stackSelect") && $("stackSelect").value) || "").trim());
  if(!teammate){ if($("stackStatus")) $("stackStatus").innerText = "No teammate selected."; return; }
  if(!name){ if($("stackStatus")) $("stackStatus").innerText = "Pick or type a stack name."; return; }
  const res = await fetch(`/api/teammates/${encodeURIComponent(teammate)}/stacks/${encodeURIComponent(name)}/run`, {
    method:"POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({input: (($("mainPrompt") && $("mainPrompt").value) || "").trim(), client_id: (window.ClientStore ? (ClientStore.active_id || "") : "")})
  });
  const data = await res.json();
  if(!data.ok){ if($("stackStatus")) $("stackStatus").innerText = data.error || "Run failed."; return; }
  renderStackSteps();
  renderRunOutputs(data.run);
}

async function scheduleOnce(){
  const teammate = ActionStack.teammate;
  const name = ((($("stackName") && $("stackName").value) || "").trim()) || ((($("stackSelect") && $("stackSelect").value) || "").trim());
  const runAt = ($("stackRunAt") && $("stackRunAt").value) || "";
  if(!teammate){ if($("stackStatus")) $("stackStatus").innerText = "No teammate selected."; return; }
  if(!name){ if($("stackStatus")) $("stackStatus").innerText = "Pick a stack name."; return; }
  if(!runAt){ if($("stackStatus")) $("stackStatus").innerText = "Pick a datetime."; return; }
  const res = await fetch(`/api/teammates/${encodeURIComponent(teammate)}/stacks/schedule`, {
    method:"POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({mode:"once", stack_name:name, run_at: runAt})
  });
  const data = await res.json();
  if($("stackStatus")) $("stackStatus").innerText = data.ok ? "Scheduled." : (data.error || "Schedule failed.");
  loadSchedulesForTeammate(teammate);
}

async function scheduleDaily(){
  const teammate = ActionStack.teammate;
  const name = ((($("stackName") && $("stackName").value) || "").trim()) || ((($("stackSelect") && $("stackSelect").value) || "").trim());
  const t = ($("stackDailyAt") && $("stackDailyAt").value) || "";
  if(!teammate){ if($("stackStatus")) $("stackStatus").innerText = "No teammate selected."; return; }
  if(!name){ if($("stackStatus")) $("stackStatus").innerText = "Pick a stack name."; return; }
  if(!t){ if($("stackStatus")) $("stackStatus").innerText = "Pick a daily time."; return; }
  const res = await fetch(`/api/teammates/${encodeURIComponent(teammate)}/stacks/schedule`, {
    method:"POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({mode:"daily", stack_name:name, time: t})
  });
  const data = await res.json();
  if($("stackStatus")) $("stackStatus").innerText = data.ok ? "Scheduled." : (data.error || "Schedule failed.");
  loadSchedulesForTeammate(teammate);
}

window.openStackForTeammate = function(name){
  ActionStack.teammate = name;
  ActionStack.steps = [];
  if($("stackName")) $("stackName").value = "";
  if($("stackPrompt")) $("stackPrompt").value = "";
  if($("stackStatus")) $("stackStatus").innerText = "";
  renderStackSteps();
  showStackTab(`Stack: ${name}`);
  loadStacksForTeammate(name);
  loadSchedulesForTeammate(name);
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

      const stackBtn = document.createElement("button");
      stackBtn.className = "seatToolBtn";
      stackBtn.innerText = "Stack";
      stackBtn.title = "Open Stack (queue multiple prompts and schedule)";
      stackBtn.addEventListener("pointerdown", (e) => { e.preventDefault(); e.stopPropagation(); });
      stackBtn.addEventListener("touchstart", (e) => { try{ if(window.openStackForTeammate) window.openStackForTeammate(defn.name); }catch(_){ } }, {passive:true});
      stackBtn.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        if(window.openStackForTeammate) window.openStackForTeammate(defn.name);
      });
      tools.appendChild(stackBtn);

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

        showModal("No active teammates", "Use Add or dismiss teammates in the top right to add seats back to the table.");
        setTablePulse(false);
        setTablePulseAll(false);
        $("seatTitle").innerText = "Select a seat";
        $("seatSub").innerText = "No active teammate selected.";
        if(selectedSeat !== "Operator") selectedSeat = "";
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
      profBtn.addEventListener("click", (e) => { e.preventDefault(); e.stopPropagation(); selectSeat("Operator"); });
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
      seat.addEventListener("click", (e) => { e.preventDefault(); selectSeat("Operator"); });
      seat.addEventListener("keydown", (e) => {
        if(e.key === "Enter" || e.key === " "){
          e.preventDefault(); selectSeat("Operator");
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
        <div class="who">Operator Profile</div>
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
      const rx = new RegExp("\\b" + nl.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\b", "i");
      return text.replace(rx, "").replace(/\s+/g, " ").trim();
    }

    function currentAlwaysTarget(){
      return (alwaysMode === "group") ? $("opPrompt") : $("followMsg");
    }
    function currentAlwaysStatusEl(){
      return (alwaysMode === "group") ? $("micStatusGroup") : $("micStatusDm");
    }

    function resetAlwaysBuffers(){
      alwaysInterimText = "";
      alwaysFinalText = "";
      alwaysFinalBaseline = "";
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
    function getCanonicalSpeech(event){
      let allFinal = "";
      let interim = "";

      for(let i = 0; i < event.results.length; i++){
        const txt = (event.results[i][0].transcript || "");
        if(event.results[i].isFinal){
          allFinal += txt + " ";
        }else{
          interim += txt;
        }
      }

      allFinal = allFinal.replace(/\s+/g, " ").trim();
      interim = interim.replace(/\s+/g, " ").trim();
      return { allFinal, interim };
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
        const canon = getCanonicalSpeech(event);
        const allFinalRaw = canon.allFinal;
        const interimRaw = canon.interim;

        const allFinal = subtractBaseline(allFinalRaw);
        const candidateText = (allFinal + " " + interimRaw).replace(/\s+/g, " ").trim();
        const hit = findFirstNameMention(candidateText);

        if(hit){
          const now = Date.now();
          if(now - lastNameSwitchAt > 650){
            lastNameSwitchAt = now;

            const cleanedFinal = removeNameOnce(allFinal, hit.name);
            const cleanedInterim = removeNameOnce(interimRaw, hit.name);

            const targetBefore = currentAlwaysTarget();
            if(targetBefore){
              targetBefore.value = (alwaysBaseText + " " + cleanedFinal + " " + cleanedInterim)
                .replace(/\s+/g, " ")
                .trim();
            }

            // Switch teammate and apply the same glow as clicking
            await selectSeat(hit.name);
            forceSeatSelectUI(hit.name);

            // Baseline the recognizer history so we do not replay old finals after switching
            alwaysFinalBaseline = allFinalRaw;

            // Start writing into the new target input from its existing content
            const t2 = currentAlwaysTarget();
            alwaysBaseText = (t2 && t2.value ? t2.value : "").trim();
            alwaysFinalText = "";
            alwaysInterimText = "";
            return;
          }
        }

        // UPDATE: no appending. AlwaysFinalText mirrors the canonical final transcript.
        alwaysFinalText = allFinal;
        alwaysInterimText = interimRaw;

        const target = currentAlwaysTarget();
        if(target){
          target.value = (alwaysBaseText + " " + alwaysFinalText + " " + alwaysInterimText)
            .replace(/\s+/g, " ")
            .trim();
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

    async function conveneAll(){
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
    $("assembleBtn").onclick = assembleAll;
    $("assembleBtn2").onclick = assembleAll;

    
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

async function sendFollow(){
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
      const res = await fetch("/api/install/full", {method:"POST"});
      const data = await res.json();
      if(!data.ok){
        showModal("Error", data.error || "Install failed");
        return;
      }
      await loadState();
      showModal("Installed", "Full team installed.");
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

    

    // =========================
    // CRM UI (Client Command Center)
    // =========================
    let crmCache = { clients: [], tasks: [], sequences: [], pipeline: [] };
    let crmEditingClientId = null;
    let crmEditingTaskId = null;

    function crmSetStatus(t){ const el=$("crmStatus"); if(el) el.innerText = t||""; }

    function crmHideViews(){
      const ids = ["crmViewClients","crmViewPipeline","crmViewBroadcast","crmViewBroadcastSMS","crmViewTasks","crmViewSequences","crmViewCalendar"]; 
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
          crmCache.pipeline = (data.pipeline_stages || []);
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
        showToast('Saved');
      }catch(e){
        if(st) st.innerText = 'Save failed';
      }
    }

    async function crmLoadPipelineIntoBox(){
      const st = $("crmPipelineStatus");
      if(st) st.innerText = 'Loading...';
      const data = await crmFetchState();
      const stages = (data && data.pipeline_stages) ? data.pipeline_stages : (crmCache.pipeline||[]);
      $("crmStagesText").value = (stages||[]).join('\n');
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

    function showCRMModal(){
      showModal();
      try{ ensureModalMinSize(900, 720); }catch(e){}
      if($("frameworkForm")) $("frameworkForm").style.display = "none";
      if($("modalForm")) $("modalForm").style.display = "none";
      if($("manageForm")) $("manageForm").style.display = "none";
      if($("createForm")) $("createForm").style.display = "none";
      if($("settingsForm")) $("settingsForm").style.display = "none";
      if($("stackForm")) $("stackForm").style.display = "none";
      if($("apiKeyHelpForm")) $("apiKeyHelpForm").style.display = "none";
      if($("calendarForm")) $("calendarForm").style.display = "none";
      if($("crmForm")) $("crmForm").style.display = "block";
      if($("modalBody")) $("modalBody").style.display = "none";
      if($("modalImg")) $("modalImg").style.display = "none";

      $("modalTitle").innerText = "Client Command Center";
      crmSetStatus('Loading...');

      // default view
      crmShowView('crmViewClients');

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

    // CRM tab binds (safe if missing)
    function bindCRM(){
      const b=(id,fn)=>{ const el=$(id); if(el) el.onclick=fn; };
      b('crmTabClients', async()=>{ crmShowView('crmViewClients'); try{ await crmFetchClients(); crmRenderClients(); }catch(e){} });
      b('crmTabPipeline', async()=>{ crmShowView('crmViewPipeline'); await crmLoadPipelineIntoBox(); });
      b('crmTabBroadcast', ()=>{ crmShowView('crmViewBroadcast'); $("crmBroadcastStatus").innerText=''; });
      b('crmTabBroadcastSMS', ()=>{ crmShowView('crmViewBroadcastSMS'); if($("crmSmsStatus")) $("crmSmsStatus").innerText=''; crmLoadSmsSettings(); });
      b('crmTabTasks', async()=>{ crmShowView('crmViewTasks'); try{ await crmFetchTasks(); crmRenderTasks(); }catch(e){} });
      b('crmTabSequences', async()=>{ crmShowView('crmViewSequences'); try{ await crmFetchSequences(); crmRenderSequences(); }catch(e){} });
      b('crmTabCalendar', ()=>{ crmShowView('crmViewCalendar'); });

      b('crmRefreshClients', async()=>{ crmSetStatus('Refreshing...'); await crmFetchClients(); crmRenderClients(); crmSetStatus('Ready'); });
      b('crmNewClientBtn', ()=> crmOpenClientEditor(null));
      b('crmCancelEdit', ()=>{ const ed=$("crmClientEditor"); if(ed) ed.style.display='none'; crmEditingClientId=null; });
      b('crmSaveClient', crmSaveClient);

      if($("crmSearch")) $("crmSearch").addEventListener('input', crmRenderClients);
      if($("crmFilter")) $("crmFilter").addEventListener('change', crmRenderClients);

      b('crmReloadPipeline', crmLoadPipelineIntoBox);
      b('crmSavePipeline', crmSavePipeline);

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

      b('crmRefreshSeq', async()=>{ try{ await crmFetchSequences(); crmRenderSequences(); }catch(e){} });
      b('crmNewSeqBtn', ()=>{ const ed=$("crmSeqEditor"); if(ed) ed.style.display='block'; if($("crmSeqStatus")) $("crmSeqStatus").innerText=''; });
      b('crmCancelSeq', ()=>{ const ed=$("crmSeqEditor"); if(ed) ed.style.display='none'; });
      b('crmSaveSeq', crmSaveSequence);
      b('crmEnrollBtn', crmEnroll);

      b('crmCreateEventBtn', crmCreateCalendarEvent);
    }

    // run once (safe)
    try{ bindCRM(); }catch(e){}

// =========================
// Calendar modal (month grid + date click actions)
// =========================
const cal = {
  y: (new Date()).getFullYear(),
  m: (new Date()).getMonth(), // 0-11
  selected: null, // 'YYYY-MM-DD'
  events: {}, // date -> [{summary, start, end, link}]
  tz: (Intl.DateTimeFormat().resolvedOptions().timeZone || "America/New_York")
};

function pad2(n){ return (n<10?('0'+n):(''+n)); }
function ymd(d){ return d.getFullYear()+'-'+pad2(d.getMonth()+1)+'-'+pad2(d.getDate()); }

function calSetStatus(t){ const el=$("calLoadStatus"); if(el) el.innerText = t||""; }

function calWeekdayHeader(){
  const box = $("calWeekdays");
  if(!box) return;
  const names = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
  box.innerHTML = names.map(n=>`<div class="calWd">${n}</div>`).join('');
}

async function calFetchEventsForVisibleRange(){
  const first = new Date(cal.y, cal.m, 1);
  const start = new Date(first);
  start.setDate(first.getDate() - first.getDay());

  const last = new Date(cal.y, cal.m + 1, 0);
  const end = new Date(last);
  end.setDate(last.getDate() + (6 - last.getDay()) + 1);

  const timeMin = start.toISOString();
  const timeMax = end.toISOString();

  calSetStatus('Loading events...');
  try{
    const res = await fetch(`/api/calendar/events?time_min=${encodeURIComponent(timeMin)}&time_max=${encodeURIComponent(timeMax)}&timezone=${encodeURIComponent(cal.tz)}`);
    const data = await res.json();
    if(!data.ok){
      cal.events = {};
      calSetStatus(data.error || 'Calendar not connected (connect in Settings)');
      return;
    }
    const events = data.events || [];
    const map = {};
    events.forEach(ev=>{
      const s = (ev.start || '').slice(0,10);
      if(!s) return;
      map[s] = map[s] || [];
      map[s].push(ev);
    });
    cal.events = map;
    calSetStatus('');
  }catch(e){
    cal.events = {};
    calSetStatus('Could not load events');
  }
}

function calRenderMonth(){
  const label = $("calMonthLabel");
  const grid = $("calGrid");
  if(!grid) return;

  const monthName = new Date(cal.y, cal.m, 1).toLocaleString(undefined, {month:'long', year:'numeric'});
  if(label) label.innerText = monthName;

  const first = new Date(cal.y, cal.m, 1);
  const start = new Date(first);
  start.setDate(first.getDate() - first.getDay());

  const cells = [];
  for(let i=0;i<42;i++){
    const d = new Date(start);
    d.setDate(start.getDate() + i);
    const inMonth = d.getMonth() === cal.m;
    const key = ymd(d);
    const evs = cal.events[key] || [];
    const dots = evs.slice(0,6).map(()=>'<span class="calDot"></span>').join('');
    const cls = ['calCell', inMonth ? '' : 'muted', (cal.selected===key ? 'selected':'')].filter(Boolean).join(' ');
    cells.push(`
      <div class="${cls}" data-cal-date="${key}">
        <div class="calNum">${d.getDate()}</div>
        <div class="calDots">${dots}</div>
      </div>
    `);
  }
  grid.innerHTML = cells.join('');

  grid.querySelectorAll('[data-cal-date]').forEach(el=>{
    el.addEventListener('click', ()=>{
      const dt = el.getAttribute('data-cal-date');
      calSelectDate(dt);
      calRenderMonth();
    });
  });
}

function calRenderDayPanel(){
  const lab = $("calSelectedLabel");
  const sub = $("calSelectedSub");
  const list = $("calDayEvents");
  const dt = cal.selected;

  if(!dt){
    if(lab) lab.innerText = 'Select a date';
    if(sub) sub.innerText = '';
    if(list) list.innerHTML = '<div style="opacity:.85;">No date selected.</div>';
    return;
  }

  const pretty = new Date(dt+'T00:00:00').toLocaleDateString(undefined, {weekday:'long', month:'short', day:'numeric', year:'numeric'});
  if(lab) lab.innerText = pretty;
  if(sub) sub.innerText = cal.tz;

  const evs = cal.events[dt] || [];
  if(!evs.length){
    if(list) list.innerHTML = '<div style="opacity:.85;">No events.</div>';
  }else{
    const rows = evs.slice(0,12).map(ev=>{
      const t = (ev.start || '').replace('T',' ').slice(0,16);
      const title = escapeHtml(ev.summary || 'Event');
      const join = ev.hangoutLink ? `<a href="${ev.hangoutLink}" target="_blank" rel="noopener">Join</a>` : (ev.htmlLink ? `<a href="${ev.htmlLink}" target="_blank" rel="noopener">Open</a>` : '');
      return `<div style="display:flex; justify-content:space-between; gap:8px; padding:6px 0; border-bottom:1px solid rgba(255,255,255,.08);">
        <div style="opacity:.95;">${title}<div style="opacity:.8; font-size:11px;">${escapeHtml(t)}</div></div>
        <div style="white-space:nowrap; opacity:.95;">${join}</div>
      </div>`;
    }).join('');
    if(list) list.innerHTML = `<div>${rows}</div>`;
  }
}

function calSelectDate(dt){
  cal.selected = dt;
  calRenderDayPanel();
  if($("calTaskStatus")) $("calTaskStatus").innerText = '';
  if($("calCallStatus")) $("calCallStatus").innerText = '';
}

async function calAddTask(){
  const st = $("calTaskStatus");
  if(st) st.innerText = 'Adding...';
  const dt = cal.selected;
  const title = ($("calTaskTitle").value||'').trim();
  const tm = ($("calTaskTime").value||'').trim();
  if(!dt){
    if(st) st.innerText = 'Pick a date first';
    return;
  }
  if(!title){
    if(st) st.innerText = 'Title required';
    return;
  }
  const due = tm ? `${dt}T${tm}` : dt;
  try{
    const res = await fetch('/api/crm/tasks', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({title, due})});
    const data = await res.json();
    if(!data.ok) throw new Error(data.error||'task failed');
    if(st) st.innerText = 'Added';
    $("calTaskTitle").value = '';
    showToast('Task added');
  }catch(e){
    if(st) st.innerText = 'Add failed';
  }
}

async function calCreateCall(){
  const st = $("calCallStatus");
  if(st) st.innerText = 'Creating...';
  const dt = cal.selected;
  if(!dt){
    if(st) st.innerText = 'Pick a date first';
    return;
  }
  const title = ($("calCallTitle").value||'Call').trim() || 'Call';
  const tm = ($("calCallTime").value||'09:00').trim();
  const dur = parseInt(($("calCallDur").value||'30').trim(),10) || 30;

  const startLocal = new Date(dt+'T'+tm+':00');
  const endLocal = new Date(startLocal.getTime() + dur*60000);

  try{
    const res = await fetch('/api/calendar/create_event', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        title,
        start: startLocal.toISOString(),
        end: endLocal.toISOString(),
        timezone: cal.tz
      })
    });
    const data = await res.json();
    if(!data.ok) throw new Error(data.error||'calendar failed');
    if(st) st.innerText = 'Created';
    showToast('Call scheduled');
    await calFetchEventsForVisibleRange();
    calRenderMonth();
    calRenderDayPanel();
  }catch(e){
    if(st) st.innerText = 'Create failed (connect Calendar in Settings)';
  }
}

function showCalendarModal(){
  showModal();
  if($("frameworkForm")) $("frameworkForm").style.display = "none";
  if($("modalForm")) $("modalForm").style.display = "none";
  if($("manageForm")) $("manageForm").style.display = "none";
  if($("createForm")) $("createForm").style.display = "none";
  if($("settingsForm")) $("settingsForm").style.display = "none";
  if($("stackForm")) $("stackForm").style.display = "none";
  if($("apiKeyHelpForm")) $("apiKeyHelpForm").style.display = "none";
  if($("crmForm")) $("crmForm").style.display = "none";
  if($("calendarForm")) $("calendarForm").style.display = "block";
  if($("modalBody")) $("modalBody").style.display = "none";
  if($("modalImg")) $("modalImg").style.display = "none";

  $("modalTitle").innerText = "Calendar";
  calWeekdayHeader();

  if(!cal.selected) cal.selected = ymd(new Date());
  calSelectDate(cal.selected);

  (async()=>{
    await calFetchEventsForVisibleRange();
    calRenderMonth();
    calRenderDayPanel();
  })();
}

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
  if($("calAddTaskBtn")) $("calAddTaskBtn").onclick = calAddTask;
  if($("calCreateCallBtn")) $("calCreateCallBtn").onclick = calCreateCall;
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
        // auto open settings, and show a coach bubble on the Settings button
        try{ showSettingsModal(true); }catch(e){}
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

// Stack UI bindings
if($("stackAddPromptBtn")) $("stackAddPromptBtn").onclick = () => {
  const p = ($("stackPrompt").value || "").trim();
  if(!p){ $("stackStatus").innerText = "Enter a prompt for the step."; return; }
  ActionStack.steps.push({type:"prompt", prompt: p});
  $("stackPrompt").value = "";
  $("stackStatus").innerText = "";
  renderStackSteps();
};
if($("stackClearBtn")) $("stackClearBtn").onclick = () => { ActionStack.steps = []; renderStackSteps(); $("stackStatus").innerText = "Cleared."; };
if($("stackSaveBtn")) $("stackSaveBtn").onclick = saveCurrentStack;
if($("stackRunBtn")) $("stackRunBtn").onclick = runCurrentStack;
if($("cancelStack")) $("cancelStack").onclick = () => hideModal();
if($("stackScheduleOnceBtn")) $("stackScheduleOnceBtn").onclick = scheduleOnce;
if($("stackScheduleDailyBtn")) $("stackScheduleDailyBtn").onclick = scheduleDaily;
if($("stackRefreshSchedulesBtn")) $("stackRefreshSchedulesBtn").onclick = () => loadSchedulesForTeammate(ActionStack.teammate);
if($("stackSelect")) $("stackSelect").onchange = () => loadStackDetail(ActionStack.teammate, $("stackSelect").value);

// Safe schedule runner tick (no background threads)
if(!window.__stackTickInterval){
  window.__stackTickInterval = setInterval(() => {
    fetch("/api/action_stack_schedules/tick", {method:"POST"}).catch(() => {});
  }, 20000);
}
// API key help button
if($("openApiKeyHelpBtn")) $("openApiKeyHelpBtn").onclick = () => openApiKeyHelp();
if($("closeApiKeyHelpBtn")) $("closeApiKeyHelpBtn").onclick = () => { try{ document.body.style.overflow = ""; }catch(_){ } hideModal(); };


// Client form bindings (safe)
if($("activeClientSelect")) $("activeClientSelect").onchange = () => setActiveClient($("activeClientSelect").value);
if($("clientSearch")) $("clientSearch").oninput = () => _renderClientSelect($("clientSearch").value);

// Stack UI bindings (safe)
if($("stackAddPromptBtn")) $("stackAddPromptBtn").onclick = () => {
  const p = ($("stackPrompt").value || "").trim();
  if(!p){ $("stackStatus").innerText = "Enter a prompt for the step."; return; }
  ActionStack.steps.push({type:"prompt", prompt: p});
  $("stackPrompt").value = "";
  $("stackStatus").innerText = "";
  renderStackSteps();
};
if($("stackClearBtn")) $("stackClearBtn").onclick = () => { ActionStack.steps = []; renderStackSteps(); $("stackStatus").innerText = "Cleared."; };
if($("stackSaveBtn")) $("stackSaveBtn").onclick = saveCurrentStack;
if($("stackRunBtn")) $("stackRunBtn").onclick = runCurrentStack;
if($("cancelStack")) $("cancelStack").onclick = () => { try{ document.body.style.overflow = ""; }catch(_){ } hideModal(); };
if($("stackScheduleOnceBtn")) $("stackScheduleOnceBtn").onclick = scheduleOnce;
if($("stackScheduleDailyBtn")) $("stackScheduleDailyBtn").onclick = scheduleDaily;
if($("stackRefreshSchedulesBtn")) $("stackRefreshSchedulesBtn").onclick = () => loadSchedulesForTeammate(ActionStack.teammate);
if($("stackSelect")) $("stackSelect").onchange = () => loadStackDetail(ActionStack.teammate, $("stackSelect").value);

// Safe schedule runner tick (no background threads)
if(!window.__stackTickInterval){
  window.__stackTickInterval = setInterval(() => {
    fetch("/api/action_stack_schedules/tick", {method:"POST"}).catch(() => {});
  }, 20000);
}
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


maybeAutoShowOnboarding();

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
<div id="onboardingPanel" style="position:fixed; right:16px; bottom:16px; z-index:9999; width:320px; max-width:calc(100vw - 32px); max-height:calc(100vh - 32px); min-width:260px; min-height:220px; resize:both; overflow:auto; display:none;">
  <div id="onbCard" style="background:rgba(20,24,34,0.96); border:1px solid rgba(255,255,255,0.10); border-radius:14px; box-shadow:0 12px 40px rgba(0,0,0,0.45); overflow:hidden;">
    <div id="onbHeader" style="padding:12px 12px 10px 12px; display:flex; align-items:center; justify-content:space-between; cursor:grab; user-select:none;">
      <div style="display:flex; gap:10px; align-items:center;">
        <div style="width:10px; height:10px; border-radius:999px; background:linear-gradient(135deg,#7c3aed,#22c55e); box-shadow:0 0 18px rgba(124,58,237,0.55);"></div>
        <div>
          <div style="font-weight:800; letter-spacing:0.2px; font-size:14px;">Get Started</div>
          <div id="onbSub" style="font-size:12px; opacity:0.8;">0 of 5 complete</div>
        </div>
      </div>
      <div style="display:flex; gap:8px; align-items:center;">
        <button id="onbExit" class="btn btnMini" style="padding:6px 10px;">Exit</button>
        <button id="onbHide" class="btn btnMini" style="padding:6px 10px;">Hide</button>
      </div>
    </div>
    <div id="onbList" style="padding:10px 12px 12px 12px; display:flex; flex-direction:column; gap:8px;"></div>
  </div>
</div>

<style>
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

  function onb$(id){ try{return document.getElementById(id);}catch(e){return null;} }

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
    try{
      // Undismiss (if previously hidden)
      await fetch("/api/onboarding/dismiss", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({dismissed:false})
      });
    }catch(e){}
    try{
      await fetchOnboarding();
      const panel = onb$("onboardingPanel");
      if(panel) panel.style.display = "block";
    }catch(e){}
  }

  function closeOnboarding(){
    const panel = onb$("onboardingPanel");
    if(panel) panel.style.display = "none";
    // Do not dismiss. User can reopen via "Next step" button.
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

    if(onbData.dismissed || onbData.all_done){
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
      if(key === "openai_key"){
        if(typeof showSettingsModal === "function"){ showSettingsModal(true); }
        setTimeout(()=>{ focusEl("openaiKey") || focusEl("apiKey"); }, 150);
        return;
      }

      if(key === "operator_profile"){
        if(typeof selectSeat === "function"){ await selectSeat("Operator"); }
        setTimeout(()=>{ focusEl("op_display_name"); }, 250);
        return;
      }

      if(key === "full_team"){
        try{
          const r = await fetch("/api/install/full", {method:"POST"});
          const d = await r.json();
          if(d && d.ok){ if(typeof showToast === "function") showToast("Installed full team"); }
          else{ if(typeof showToast === "function") showToast("Install failed"); }
        }catch(e){ if(typeof showToast === "function") showToast("Install failed"); }
        setTimeout(fetchOnboarding, 300);
        return;
      }

      if(key === "first_prompt"){
        focusEl("followMsg");
        try{ if(typeof showToast === "function") showToast("Type a first prompt and hit Send"); }catch(e){}
        return;
      }

      if(key === "gmail_connected"){
        if(typeof showSettingsModal === "function"){ showSettingsModal(true); }
        setTimeout(()=>{
          const btn = document.getElementById("gmailConnectBtn");
          if(btn){ btn.click(); }
          else{ window.location = "/gmail/connect"; }
        }, 200);
        return;
      }
    }finally{
      setTimeout(fetchOnboarding, 600);
    }
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
    });

    header.addEventListener("pointerup", (e)=>{
      drag.active = false;
      header.style.cursor = "grab";
      try{ header.releasePointerCapture(e.pointerId); }catch(err){}
    });
  }

  function wireHide(){
    const btn = onb$("onbHide");
    if(btn) btn.addEventListener("click", (e)=>{ try{ e.stopPropagation(); }catch(_){ } dismissOnboarding(); });
  }

  function wireExit(){
    const btn = onb$("onbExit");
    if(btn) btn.addEventListener("click", (e)=>{ try{ e.stopPropagation(); }catch(_){ } closeOnboarding(); });
  }

  try{
    try{ window.onboardingRefresh = fetchOnboarding; window.onboardingClose = closeOnboarding; window.onboardingOpen = openOnboarding; }catch(_){ }

    wireDrag();
    wireHide();
    wireExit();
    wireOnboardingButtons();
    setTimeout(fetchOnboarding, 450);
    setInterval(fetchOnboarding, 12000);
  }catch(e){}
})();
</script>


<style>
#opsDock{
  position: fixed;
  left: 14px;
  bottom: calc(14px + env(safe-area-inset-bottom));
  z-index: 285;
  display:flex;
  gap:8px;
  flex-wrap:wrap;
  max-width:min(92vw, 720px);
}
#opsDock .opsBtn{
  border:1px solid rgba(255,255,255,.14);
  background: linear-gradient(180deg, rgba(18,28,58,.94), rgba(9,14,28,.92));
  color: var(--text);
  padding:10px 12px;
  border-radius: 999px;
  cursor:pointer;
  font-weight:800;
  font-size:12px;
  letter-spacing:.2px;
  box-shadow: 0 10px 28px rgba(0,0,0,.28), 0 0 18px rgba(124,58,237,.12);
  backdrop-filter: blur(10px);
}
#opsDock .opsBtn:hover{ transform: translateY(-1px); }
#opsOverlay{
  display:none;
  position:fixed;
  inset:0;
  z-index: 286;
  background: rgba(2,6,16,.62);
}
#opsOverlay.show{ display:block; }
#opsPanel{
  display:none;
  position:fixed;
  z-index: 287;
  left: 50%;
  top: 72px;
  transform: translateX(-50%);
  width:min(1180px, calc(100% - 20px));
  max-width: calc(100% - 20px);
  min-height: min(560px, calc(100vh - 100px));
  max-height: calc(100vh - 92px);
  border:1px solid rgba(255,255,255,.12);
  border-radius: 18px;
  background: linear-gradient(180deg, rgba(9,14,28,.96), rgba(6,10,20,.94));
  box-shadow: 0 26px 80px rgba(0,0,0,.56), 0 0 60px rgba(59,130,246,.08);
  overflow:hidden;
  backdrop-filter: blur(12px);
  resize: both;
}
#opsPanel.show{ display:flex; flex-direction:column; }
#opsPanelHeader{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;
  padding:12px 14px;
  border-bottom:1px solid rgba(255,255,255,.10);
  background: linear-gradient(180deg, rgba(124,58,237,.14), rgba(59,130,246,.08));
  cursor: grab;
}
#opsPanelTitle{
  font-weight:900;
  letter-spacing:.2px;
  font-size:15px;
}
#opsPanelSub{ font-size:12px; color: var(--muted); }
#opsPanelBody{
  display:grid;
  grid-template-columns: 220px 1fr;
  min-height:0;
  flex:1;
}
#opsSide{
  border-right:1px solid rgba(255,255,255,.08);
  padding:12px;
  overflow:auto;
  background: rgba(255,255,255,.02);
}
#opsMain{
  padding:14px;
  overflow:auto;
}
.opsNavBtn{
  width:100%;
  text-align:left;
  margin-bottom:8px;
  border:1px solid rgba(255,255,255,.10);
  background: rgba(255,255,255,.04);
  color: var(--text);
  padding:10px 12px;
  border-radius: 12px;
  font-weight:700;
  cursor:pointer;
}
.opsNavBtn.active{
  background: linear-gradient(180deg, rgba(124,58,237,.22), rgba(59,130,246,.10));
  border-color: rgba(124,58,237,.45);
}
.opsGrid{
  display:grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap:12px;
}
.opsCard{
  border:1px solid rgba(255,255,255,.10);
  border-radius: 16px;
  background: rgba(255,255,255,.04);
  padding:12px;
}
.opsCard h4{
  margin:0 0 8px 0;
  font-size:13px;
  letter-spacing:.2px;
}
.opsTiny{ font-size:12px; color: var(--muted); }
.opsPill{
  display:inline-flex;
  align-items:center;
  gap:6px;
  border:1px solid rgba(255,255,255,.10);
  border-radius:999px;
  padding:6px 10px;
  font-size:11px;
  margin:0 6px 6px 0;
  background: rgba(255,255,255,.04);
}
.opsRow{ display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
.opsInput, .opsTextarea, .opsSelect{
  width:100%;
  border:1px solid rgba(255,255,255,.12);
  background: rgba(0,0,0,.22);
  color: var(--text);
  border-radius:12px;
  padding:10px 12px;
  font-size:13px;
}
.opsTextarea{ min-height: 120px; resize: vertical; }
.opsActions{ display:flex; gap:8px; flex-wrap:wrap; margin-top:10px; }
.opsActionBtn{
  border:1px solid rgba(255,255,255,.12);
  background: rgba(255,255,255,.06);
  color: var(--text);
  padding:9px 12px;
  border-radius: 12px;
  cursor:pointer;
  font-size:12px;
  font-weight:700;
}
.opsActionBtn.primary{
  background: linear-gradient(180deg, rgba(124,58,237,.26), rgba(59,130,246,.10));
  border-color: rgba(124,58,237,.48);
}
.opsList{
  display:flex;
  flex-direction:column;
  gap:10px;
}
.opsItem{
  border:1px solid rgba(255,255,255,.10);
  border-radius: 14px;
  padding:12px;
  background: rgba(255,255,255,.04);
}
.opsItemTitle{
  font-weight:800;
  font-size:13px;
  margin-bottom:6px;
}
.opsReason{
  font-size:12px;
  color: var(--muted);
  margin-top:6px;
}
.opsScore{
  font-weight:900;
  font-size:14px;
}
.opsBadge{
  display:inline-flex;
  align-items:center;
  padding:4px 8px;
  border-radius:999px;
  font-size:11px;
  margin-right:6px;
  border:1px solid rgba(255,255,255,.10);
  background: rgba(255,255,255,.05);
}
.opsPre{
  white-space: pre-wrap;
  font-size: 12px;
  line-height: 1.45;
  border:1px solid rgba(255,255,255,.10);
  border-radius:14px;
  padding:10px;
  background: rgba(0,0,0,.24);
}
@media (max-width: 900px){
  #opsDock{
    left: 10px;
    right: 10px;
    bottom: calc(86px + env(safe-area-inset-bottom));
    max-width:none;
  }
  #opsPanel{
    top: 10px;
    left: 10px;
    right: 10px;
    transform:none;
    width:auto;
    max-width:none;
    max-height: calc(100vh - 20px);
    min-height: calc(100vh - 20px);
    resize: none;
  }
  #opsPanelBody{
    grid-template-columns: 1fr;
  }
  #opsSide{
    border-right:none;
    border-bottom:1px solid rgba(255,255,255,.08);
  }
  .opsGrid{
    grid-template-columns: 1fr;
  }
}
</style>

<div id="opsDock">
  <button class="opsBtn" id="opsOpenBtn">Ops Center</button>
  <button class="opsBtn" id="opsQuickTaskBtn">Quick Task</button>
  <button class="opsBtn" id="opsQuickScanBtn">FB Scan</button>
</div>

<div id="opsOverlay"></div>

<div id="opsPanel" aria-hidden="true">
  <div id="opsPanelHeader">
    <div>
      <div id="opsPanelTitle">Ops Command Center</div>
      <div id="opsPanelSub">Tasks, diagnostics, teammate memory, and semi-auto Facebook review.</div>
    </div>
    <div class="opsRow">
      <button class="opsActionBtn" id="opsRefreshBtn">Refresh</button>
      <button class="opsActionBtn" id="opsSafeModeBtn">Safe Mode</button>
      <button class="opsActionBtn" id="opsCloseBtn">Close</button>
    </div>
  </div>
  <div id="opsPanelBody">
    <div id="opsSide">
      <button class="opsNavBtn active" data-ops-tab="dashboard">Dashboard</button>
      <button class="opsNavBtn" data-ops-tab="tasks">Tasks</button>
      <button class="opsNavBtn" data-ops-tab="memory">Memory</button>
      <button class="opsNavBtn" data-ops-tab="facebook">Facebook</button>
      <button class="opsNavBtn" data-ops-tab="insights">Post Insights</button>
      <div class="opsCard" style="margin-top:12px;">
        <h4>Quick status</h4>
        <div id="opsQuickStats" class="opsTiny">Loading…</div>
      </div>
    </div>
    <div id="opsMain">
      <div class="opsTab" id="opsTab-dashboard">
        <div class="opsGrid">
          <div class="opsCard">
            <h4>System readiness</h4>
            <div id="opsSystemChecks" class="opsList"></div>
          </div>
          <div class="opsCard">
            <h4>Startup snapshot</h4>
            <div id="opsStartupChecks" class="opsList"></div>
          </div>
        </div>
        <div class="opsCard" style="margin-top:12px;">
          <h4>Recent events</h4>
          <div id="opsEvents" class="opsList"></div>
        </div>
      </div>

      <div class="opsTab" id="opsTab-tasks" style="display:none;">
        <div class="opsGrid">
          <div class="opsCard">
            <h4>Create task</h4>
            <div class="opsTiny">Use this for structured, semi-auto work instead of discovering what to do next on the fly.</div>
            <div style="margin-top:10px;">
              <label class="opsTiny">Title</label>
              <input class="opsInput" id="opsTaskTitle" placeholder="Ex: Facebook cleanup pass" />
            </div>
            <div style="margin-top:10px;">
              <label class="opsTiny">Type</label>
              <select class="opsSelect" id="opsTaskType">
                <option value="general">General</option>
                <option value="facebook_cleanup">Facebook cleanup</option>
                <option value="content_batch">Content batch</option>
                <option value="lead_review">Lead review</option>
                <option value="research">Research</option>
              </select>
            </div>
            <div style="margin-top:10px;">
              <label class="opsTiny">Checklist</label>
              <textarea class="opsTextarea" id="opsTaskChecklist" placeholder="One step per line"></textarea>
            </div>
            <div style="margin-top:10px;">
              <label class="opsTiny">Notes</label>
              <textarea class="opsTextarea" id="opsTaskNotes" placeholder="Why this task matters, target URL, review notes, or safety reminders."></textarea>
            </div>
            <div class="opsActions">
              <button class="opsActionBtn primary" id="opsCreateTaskBtn">Create task</button>
            </div>
          </div>
          <div class="opsCard">
            <h4>Active task queue</h4>
            <div id="opsTasksList" class="opsList"></div>
          </div>
        </div>
      </div>

      <div class="opsTab" id="opsTab-memory" style="display:none;">
        <div class="opsGrid">
          <div class="opsCard">
            <h4>Save teammate memory</h4>
            <div style="margin-top:10px;">
              <label class="opsTiny">Teammate</label>
              <input class="opsInput" id="opsMemoryTeammate" placeholder="Alex, Willow, Sunshine, Operator…" />
            </div>
            <div style="margin-top:10px;">
              <label class="opsTiny">Source</label>
              <input class="opsInput" id="opsMemorySource" placeholder="manual, diagnostics, client call, content review" />
            </div>
            <div style="margin-top:10px;">
              <label class="opsTiny">Note</label>
              <textarea class="opsTextarea" id="opsMemoryNote" placeholder="Store something important so the teammate system keeps context."></textarea>
            </div>
            <div class="opsActions">
              <button class="opsActionBtn primary" id="opsSaveMemoryBtn">Save memory</button>
            </div>
          </div>
          <div class="opsCard">
            <h4>Recent memory notes</h4>
            <div id="opsMemoryList" class="opsList"></div>
          </div>
        </div>
      </div>

      <div class="opsTab" id="opsTab-facebook" style="display:none;">
        <div class="opsCard">
          <h4>Facebook inactive friend review</h4>
          <div class="opsTiny">Semi-auto only. Paste your Facebook friends-list link first. The app will save a guided review session, open the link in a new tab when you want, and then score any friend rows or profile notes you paste back in. Final keep or remove decisions still happen manually inside Facebook.</div>
          <div style="margin-top:10px;">
            <label class="opsTiny">Facebook friends-list or review URL</label>
            <input class="opsInput" id="opsFacebookUrl" placeholder="https://www.facebook.com/friends/list/..." />
          </div>
          <div class="opsActions">
            <button class="opsActionBtn primary" id="opsStartGuidedReviewBtn">Start guided review</button>
          </div>
          <div id="opsFacebookSession" class="opsList" style="margin-top:12px;"></div>
          <div style="margin-top:12px;">
            <label class="opsTiny">Paste copied friend rows or review notes</label>
            <textarea class="opsTextarea" id="opsFacebookRaw" placeholder="Paste copied friend rows, profile notes, or manual inactivity notes here. Separate people with blank lines for best results."></textarea>
          </div>
          <div class="opsActions">
            <button class="opsActionBtn primary" id="opsRunFriendScanBtn">Analyze inactive candidates</button>
          </div>
        </div>
        <div class="opsCard" style="margin-top:12px;">
          <h4>Candidate review</h4>
          <div id="opsFacebookCandidates" class="opsList"></div>
        </div>
      </div>

      <div class="opsTab" id="opsTab-insights" style="display:none;">
        <div class="opsCard">
          <h4>Facebook post insights</h4>
          <div class="opsTiny">Paste the post text and any metrics you have, like reach, comments, shares, saves, clicks, or reactions.</div>
          <div style="margin-top:10px;">
            <textarea class="opsTextarea" id="opsInsightsRaw" placeholder="Example:
Hook: Facebook reach is often misunderstood…
Reach: 2840
Comments: 31
Shares: 5
Reactions: 72"></textarea>
          </div>
          <div class="opsActions">
            <button class="opsActionBtn primary" id="opsAnalyzeInsightsBtn">Analyze post</button>
          </div>
        </div>
        <div class="opsCard" style="margin-top:12px;">
          <h4>Insight output</h4>
          <div id="opsInsightsOutput" class="opsList"></div>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
(function(){
  const OPS_STORE_KEY = "ops:center:v1";
  const state = {
    tab: "dashboard",
    safeMode: false,
    dashboard: null,
    tasks: [],
    notes: [],
    friendSession: null
  };

  function ops$(id){ return document.getElementById(id); }
  function opsQS(sel, root){ return (root||document).querySelector(sel); }
  function escapeHtml(str){
    return String(str == null ? "" : str)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  async function opsFetch(url, options){
    const res = await fetch(url, Object.assign({headers: {"Content-Type":"application/json"}}, options || {}));
    const rawText = await res.text();
    let data = null;
    try{
      data = rawText ? JSON.parse(rawText) : {};
    }catch(_){
      data = null;
    }
    if(!res.ok){
      const fallback = res.status === 401 ? "You need to log in again." : (rawText && rawText.trim() ? rawText.slice(0, 220) : ("Request failed: " + res.status));
      throw new Error((data && data.error) ? data.error : fallback);
    }
    if(!data || typeof data !== "object"){
      throw new Error("Invalid server response");
    }
    if(data.ok === false){
      throw new Error(data.error || "Request failed");
    }
    return data;
  }
  function saveOpsState(){
    try{
      localStorage.setItem(OPS_STORE_KEY, JSON.stringify({tab: state.tab, safeMode: !!state.safeMode}));
    }catch(_){}
  }
  function loadOpsState(){
    try{
      const raw = localStorage.getItem(OPS_STORE_KEY);
      if(!raw) return;
      const obj = JSON.parse(raw);
      if(obj && typeof obj === "object"){
        if(obj.tab) state.tab = obj.tab;
        state.safeMode = !!obj.safeMode;
      }
    }catch(_){}
  }
  function setSafeMode(on){
    state.safeMode = !!on;
    document.body.classList.toggle("opsSafeMode", !!on);
    if(on){
      try{
        if(window.showToast) window.showToast("Ops safe mode enabled");
      }catch(_){}
    }
    saveOpsState();
  }
  function levelBadge(ok){
    return ok ? '<span class="opsBadge">OK</span>' : '<span class="opsBadge">Needs attention</span>';
  }
  function renderChecks(containerId, checks){
    const el = ops$(containerId);
    if(!el) return;
    if(!checks || !checks.length){
      el.innerHTML = '<div class="opsTiny">No checks returned.</div>';
      return;
    }
    el.innerHTML = checks.map(item => `
      <div class="opsItem">
        <div class="opsItemTitle">${escapeHtml(item.name || "Check")} ${levelBadge(!!item.ok)}</div>
        <div class="opsReason">${escapeHtml(item.detail || "")}</div>
      </div>
    `).join("");
  }
  function renderEvents(events){
    const el = ops$("opsEvents");
    if(!el) return;
    if(!events || !events.length){
      el.innerHTML = '<div class="opsTiny">No recent events yet.</div>';
      return;
    }
    el.innerHTML = events.slice().reverse().map(item => `
      <div class="opsItem">
        <div class="opsItemTitle">${escapeHtml(item.message || item.kind || "Event")}</div>
        <div class="opsReason">${escapeHtml(item.ts || "")} • ${escapeHtml(item.level || "info")}</div>
        ${item.detail ? `<div class="opsPre" style="margin-top:8px;">${escapeHtml(typeof item.detail === "string" ? item.detail : JSON.stringify(item.detail, null, 2))}</div>` : ''}
      </div>
    `).join("");
  }
  function renderQuickStats(payload){
    const el = ops$("opsQuickStats");
    if(!el) return;
    const counts = (payload && payload.task_counts) || {};
    el.innerHTML = `
      <div class="opsPill">Queued: ${counts.queued || 0}</div>
      <div class="opsPill">Running: ${counts.running || 0}</div>
      <div class="opsPill">Needs review: ${counts.needs_review || 0}</div>
      <div class="opsPill">Done: ${counts.done || 0}</div>
      <div class="opsTiny" style="margin-top:8px;">Safe mode: ${state.safeMode ? "ON" : "OFF"}</div>
    `;
  }
  function taskButtons(task){
    const id = String(task.id || "");
    const launch = task && task.target_url ? `<a class="opsActionBtn primary" href="${escapeHtml(task.target_url)}" target="_blank" rel="noopener noreferrer">Open target</a>` : "";
    return `
      <div class="opsActions">
        ${launch}
        <button class="opsActionBtn" data-task-action="start" data-task-id="${escapeHtml(id)}">Run</button>
        <button class="opsActionBtn" data-task-action="review" data-task-id="${escapeHtml(id)}">Needs review</button>
        <button class="opsActionBtn" data-task-action="done" data-task-id="${escapeHtml(id)}">Done</button>
        <button class="opsActionBtn" data-task-action="reset" data-task-id="${escapeHtml(id)}">Reset</button>
      </div>
    `;
  }
  function renderTasks(tasks){
    const el = ops$("opsTasksList");
    if(!el) return;
    if(!tasks || !tasks.length){
      el.innerHTML = '<div class="opsTiny">No tasks yet. Create one on the left.</div>';
      return;
    }
    el.innerHTML = tasks.slice().reverse().map(task => {
      const steps = Array.isArray(task.checklist) ? task.checklist : [];
      return `
        <div class="opsItem">
          <div class="opsRow" style="justify-content:space-between;">
            <div class="opsItemTitle">${escapeHtml(task.title || "Task")}</div>
            <div class="opsScore">${escapeHtml(task.status || "queued")}</div>
          </div>
          <div class="opsReason">${escapeHtml(task.type || "general")} • ${escapeHtml(task.updated_at || task.created_at || "")}</div>
          ${task.target_url ? `<div class="opsPre" style="margin-top:8px;">${escapeHtml(task.target_url)}</div>` : ''}
          ${task.notes ? `<div class="opsPre" style="margin-top:8px;">${escapeHtml(task.notes)}</div>` : ''}
          ${steps.length ? `<div class="opsList" style="margin-top:8px;">${steps.map((step, idx)=>`
            <div class="opsItem" style="padding:8px 10px;">
              <label style="display:flex; gap:8px; align-items:flex-start; cursor:pointer;">
                <input type="checkbox" data-task-step="${idx}" data-task-id="${escapeHtml(task.id || "")}" ${step.done ? 'checked' : ''}/>
                <span>${escapeHtml(step.label || "")}</span>
              </label>
            </div>`).join("")}</div>` : ''}
          ${taskButtons(task)}
        </div>
      `;
    }).join("");
  }
  function renderMemory(notes){
    const el = ops$("opsMemoryList");
    if(!el) return;
    if(!notes || !notes.length){
      el.innerHTML = '<div class="opsTiny">No memory notes saved yet.</div>';
      return;
    }
    el.innerHTML = notes.slice().reverse().map(note => `
      <div class="opsItem">
        <div class="opsItemTitle">${escapeHtml(note.teammate || "operator")} <span class="opsBadge">${escapeHtml(note.source || "manual")}</span></div>
        <div class="opsReason">${escapeHtml(note.created_at || "")}</div>
        <div class="opsPre" style="margin-top:8px;">${escapeHtml(note.note || "")}</div>
      </div>
    `).join("");
  }

  function renderFriendSession(session){
    const el = ops$("opsFacebookSession");
    if(!el) return;
    if(!session){
      el.innerHTML = '<div class="opsTiny">No guided review session yet. Paste your Facebook link above and click Start guided review.</div>';
      return;
    }
    const instructions = Array.isArray(session.instructions) ? session.instructions : [];
    const launchUrl = escapeHtml(session.target_url || "");
    el.innerHTML = `
      <div class="opsItem">
        <div class="opsRow" style="justify-content:space-between;">
          <div class="opsItemTitle">Guided review ready</div>
          <div class="opsScore">${escapeHtml(session.status || "ready")}</div>
        </div>
        <div class="opsReason">${escapeHtml(session.created_at || "")}</div>
        <div class="opsPre" style="margin-top:8px;">${launchUrl}</div>
        ${launchUrl ? `<div class="opsActions"><a class="opsActionBtn primary" href="${launchUrl}" target="_blank" rel="noopener noreferrer">Open Facebook review tab</a></div>` : ""}
        ${instructions.length ? `<div class="opsList" style="margin-top:8px;">${instructions.map(x => `<div class="opsItem">${escapeHtml(x)}</div>`).join("")}</div>` : ""}
      </div>
    `;
  }

  function renderCandidates(items){
    const el = ops$("opsFacebookCandidates");
    if(!el) return;
    if(!items || !items.length){
      el.innerHTML = '<div class="opsTiny">No candidates yet. Run a scan above.</div>';
      return;
    }
    el.innerHTML = items.map(item => `
      <div class="opsItem">
        <div class="opsRow" style="justify-content:space-between;">
          <div class="opsItemTitle">${escapeHtml(item.name || "Unknown")}</div>
          <div class="opsScore">${escapeHtml(item.score || 0)}/100</div>
        </div>
        <div class="opsReason">Recommended action: ${escapeHtml(item.recommended_action || "review")}</div>
        <div class="opsReason">${(item.reasons || []).map(escapeHtml).join(" • ")}</div>
        <details style="margin-top:8px;">
          <summary class="opsTiny" style="cursor:pointer;">Show raw note</summary>
          <div class="opsPre" style="margin-top:8px;">${escapeHtml(item.raw || "")}</div>
        </details>
      </div>
    `).join("");
  }
  function renderInsights(analysis){
    const el = ops$("opsInsightsOutput");
    if(!el) return;
    if(!analysis){
      el.innerHTML = '<div class="opsTiny">Paste a post and run analysis.</div>';
      return;
    }
    const metrics = analysis.metrics || {};
    el.innerHTML = `
      <div class="opsItem">
        <div class="opsItemTitle">${escapeHtml(analysis.summary || "Analysis")}</div>
        <div class="opsRow" style="margin-top:8px;">
          <span class="opsPill">Reactions: ${metrics.reactions || 0}</span>
          <span class="opsPill">Comments: ${metrics.comments || 0}</span>
          <span class="opsPill">Shares: ${metrics.shares || 0}</span>
          <span class="opsPill">Clicks: ${metrics.clicks || 0}</span>
          <span class="opsPill">Saves: ${metrics.saves || 0}</span>
          <span class="opsPill">Reach: ${metrics.reach || 0}</span>
        </div>
      </div>
      <div class="opsGrid" style="margin-top:12px;">
        <div class="opsCard">
          <h4>Findings</h4>
          <div class="opsList">${(analysis.findings || []).map(x => `<div class="opsItem">${escapeHtml(x)}</div>`).join("")}</div>
        </div>
        <div class="opsCard">
          <h4>Next moves</h4>
          <div class="opsList">${(analysis.next_moves || []).map(x => `<div class="opsItem">${escapeHtml(x)}</div>`).join("")}</div>
        </div>
      </div>
    `;
  }
  function showTab(tab){
    state.tab = tab;
    saveOpsState();
    document.querySelectorAll(".opsNavBtn").forEach(btn => btn.classList.toggle("active", btn.getAttribute("data-ops-tab") === tab));
    document.querySelectorAll(".opsTab").forEach(el => el.style.display = "none");
    const active = ops$("opsTab-" + tab);
    if(active) active.style.display = "";
  }
  async function loadDashboard(){
    const payload = await opsFetch("/api/ops/dashboard");
    state.dashboard = payload;
    state.friendSession = payload.friend_session || null;
    renderChecks("opsSystemChecks", (payload.self_test && payload.self_test.checks) || []);
    renderChecks("opsStartupChecks", (payload.startup && payload.startup.checks) || []);
    renderEvents(payload.events || []);
    renderQuickStats(payload);
    renderFriendSession(state.friendSession);
  }
  async function loadTasks(){
    const payload = await opsFetch("/api/ops/tasks");
    state.tasks = payload.tasks || [];
    renderTasks(state.tasks);
    if(state.dashboard){
      state.dashboard.task_counts = payload.counts || {};
      renderQuickStats(state.dashboard);
    }
  }
  async function loadMemory(){
    const payload = await opsFetch("/api/ops/memory");
    state.notes = payload.notes || [];
    renderMemory(state.notes);
  }
  async function refreshAll(){
    try{
      await loadDashboard();
      await loadTasks();
      await loadMemory();
    }catch(err){
      console.error(err);
      try{ if(window.showToast) window.showToast(err.message || "Ops refresh failed"); }catch(_){}
    }
  }
  function openOpsPanel(tab){
    if(tab) showTab(tab);
    ops$("opsOverlay").classList.add("show");
    ops$("opsPanel").classList.add("show");
    ops$("opsPanel").setAttribute("aria-hidden", "false");
    refreshAll();
  }
  function closeOpsPanel(){
    ops$("opsOverlay").classList.remove("show");
    ops$("opsPanel").classList.remove("show");
    ops$("opsPanel").setAttribute("aria-hidden", "true");
  }
  async function createTaskFromForm(prefill){
    const titleEl = ops$("opsTaskTitle");
    const typeEl = ops$("opsTaskType");
    const checkEl = ops$("opsTaskChecklist");
    const notesEl = ops$("opsTaskNotes");
    if(prefill){
      if(titleEl && prefill.title) titleEl.value = prefill.title;
      if(typeEl && prefill.type) typeEl.value = prefill.type;
      if(checkEl && prefill.checklist) checkEl.value = prefill.checklist;
      if(notesEl && prefill.notes) notesEl.value = prefill.notes;
      openOpsPanel("tasks");
      return;
    }
    const payload = {
      title: titleEl ? titleEl.value : "",
      type: typeEl ? typeEl.value : "general",
      checklist: checkEl ? checkEl.value : "",
      notes: notesEl ? notesEl.value : "",
      semi_auto: true
    };
    const data = await opsFetch("/api/ops/tasks", {method:"POST", body: JSON.stringify(payload)});
    if(titleEl) titleEl.value = "";
    if(checkEl) checkEl.value = "";
    if(notesEl) notesEl.value = "";
    await loadTasks();
    await loadDashboard();
    try{ if(window.showToast) window.showToast("Task created"); }catch(_){}
    return data;
  }
  async function saveMemory(){
    const payload = {
      teammate: (ops$("opsMemoryTeammate")||{}).value || "operator",
      source: (ops$("opsMemorySource")||{}).value || "manual",
      note: (ops$("opsMemoryNote")||{}).value || ""
    };
    await opsFetch("/api/ops/memory", {method:"POST", body: JSON.stringify(payload)});
    if(ops$("opsMemoryNote")) ops$("opsMemoryNote").value = "";
    await loadMemory();
    await loadDashboard();
    try{ if(window.showToast) window.showToast("Memory saved"); }catch(_){}
  }
  async function startGuidedReview(){
    const targetUrl = ((ops$("opsFacebookUrl")||{}).value || "").trim();
    const payload = await opsFetch("/api/facebook/friend_review_session", {method:"POST", body: JSON.stringify({target_url: targetUrl})});
    state.friendSession = payload.session || null;
    renderFriendSession(state.friendSession);
    await loadTasks();
    await loadDashboard();
    showTab("facebook");
    try{ if(window.showToast) window.showToast("Guided review ready"); }catch(_){}
    return payload;
  }
  async function runFriendScan(){
    const raw = (ops$("opsFacebookRaw")||{}).value || "";
    const targetUrl = ((ops$("opsFacebookUrl")||{}).value || "").trim();
    const payload = await opsFetch("/api/facebook/friend_scan", {method:"POST", body: JSON.stringify({raw_text: raw, target_url: targetUrl})});
    renderCandidates(payload.candidates || []);
    if(payload.session){
      state.friendSession = payload.session;
      renderFriendSession(state.friendSession);
    }
    await loadTasks();
    await loadDashboard();
    showTab("facebook");
  }
  async function runPostInsights(){
    const raw = (ops$("opsInsightsRaw")||{}).value || "";
    const payload = await opsFetch("/api/facebook/post_insights", {method:"POST", body: JSON.stringify({raw_text: raw})});
    renderInsights(payload.analysis || null);
    await loadDashboard();
  }
  async function logUiEvent(kind, message, detail, level){
    try{
      await opsFetch("/api/ops/event", {method:"POST", body: JSON.stringify({kind, message, detail, level})});
    }catch(_){}
  }
  function wireTaskActions(){
    document.addEventListener("click", async (e)=>{
      const btn = e.target && e.target.closest ? e.target.closest("[data-task-action]") : null;
      if(!btn) return;
      const taskId = btn.getAttribute("data-task-id");
      const action = btn.getAttribute("data-task-action");
      if(!taskId || !action) return;
      try{
        await opsFetch(`/api/ops/tasks/${taskId}/action`, {method:"POST", body: JSON.stringify({action})});
        await loadTasks();
        await loadDashboard();
      }catch(err){
        try{ if(window.showToast) window.showToast(err.message || "Task update failed"); }catch(_){}
      }
    });
    document.addEventListener("change", async (e)=>{
      const cb = e.target;
      if(!cb || !cb.matches || !cb.matches("[data-task-step]")) return;
      const taskId = cb.getAttribute("data-task-id");
      const stepIndex = Number(cb.getAttribute("data-task-step") || 0);
      try{
        await opsFetch(`/api/ops/tasks/${taskId}/action`, {method:"POST", body: JSON.stringify({action:"toggle_step", step_index: stepIndex})});
        await loadTasks();
      }catch(err){
        try{ if(window.showToast) window.showToast(err.message || "Checklist update failed"); }catch(_){}
      }
    });
  }
  function wirePanel(){
    const panel = ops$("opsPanel");
    const overlay = ops$("opsOverlay");
    const openBtn = ops$("opsOpenBtn");
    const quickTaskBtn = ops$("opsQuickTaskBtn");
    const quickScanBtn = ops$("opsQuickScanBtn");
    const closeBtn = ops$("opsCloseBtn");
    const refreshBtn = ops$("opsRefreshBtn");
    const safeBtn = ops$("opsSafeModeBtn");

    if(openBtn) openBtn.addEventListener("click", ()=> openOpsPanel("dashboard"));
    if(closeBtn) closeBtn.addEventListener("click", closeOpsPanel);
    if(overlay) overlay.addEventListener("click", closeOpsPanel);
    if(refreshBtn) refreshBtn.addEventListener("click", refreshAll);
    if(safeBtn) safeBtn.addEventListener("click", ()=> setSafeMode(!state.safeMode));
    if(quickTaskBtn) quickTaskBtn.addEventListener("click", ()=> createTaskFromForm({
      title: "Semi-auto review pass",
      type: "general",
      checklist: "Review diagnostics\nReview current queue\nStart the highest-value task\nLeave a note before closing",
      notes: "Use this as a structured operator pass."
    }));
    if(quickScanBtn) quickScanBtn.addEventListener("click", ()=> openOpsPanel("facebook"));

    document.querySelectorAll(".opsNavBtn").forEach(btn=>{
      btn.addEventListener("click", ()=> showTab(btn.getAttribute("data-ops-tab") || "dashboard"));
    });
    const createBtn = ops$("opsCreateTaskBtn");
    if(createBtn) createBtn.addEventListener("click", ()=> createTaskFromForm());
    const memBtn = ops$("opsSaveMemoryBtn");
    if(memBtn) memBtn.addEventListener("click", saveMemory);
    const reviewBtn = ops$("opsStartGuidedReviewBtn");
    if(reviewBtn) reviewBtn.addEventListener("click", async ()=>{ try{ await startGuidedReview(); }catch(err){ try{ if(window.showToast) window.showToast(err.message || "Could not start guided review"); }catch(_){} } });
    const scanBtn = ops$("opsRunFriendScanBtn");
    if(scanBtn) scanBtn.addEventListener("click", async ()=>{ try{ await runFriendScan(); }catch(err){ try{ if(window.showToast) window.showToast(err.message || "Friend scan failed"); }catch(_){} } });
    const insightBtn = ops$("opsAnalyzeInsightsBtn");
    if(insightBtn) insightBtn.addEventListener("click", runPostInsights);

    try{
      if(window.enableFloatingWindow){
        window.enableFloatingWindow("opsPanel", "opsPanelHeader", "floating:ops");
      }
    }catch(_){}
  }

  loadOpsState();
  setSafeMode(state.safeMode);
  document.addEventListener("DOMContentLoaded", ()=>{
    showTab(state.tab || "dashboard");
    wirePanel();
    wireTaskActions();
    window.addEventListener("error", (e)=>{
      logUiEvent("ui_error", e && e.message ? e.message : "Unknown UI error", {source: e && e.filename, line: e && e.lineno}, "error");
    });
    window.addEventListener("unhandledrejection", (e)=>{
      const reason = e && e.reason && e.reason.message ? e.reason.message : String((e && e.reason) || "Promise rejection");
      logUiEvent("promise_rejection", reason, {}, "error");
    });
  });

  try{
    window.opsOpenPanel = openOpsPanel;
    window.opsRefreshAll = refreshAll;
  }catch(_){}
})();
</script>

</body>
</html>
"""


# =========================================================
# OPS COMMAND CENTER ADDITIVE PATCH
# =========================================================

OPS_DIR = DATA / "ops_center"
OPS_DIR.mkdir(exist_ok=True)

def _ops_user_dir(username: str) -> Path:
    p = OPS_DIR / _safe_name(username or "anon")
    p.mkdir(parents=True, exist_ok=True)
    return p

def _ops_user_json(username: str, name: str, default: Dict[str, Any]) -> Dict[str, Any]:
    path = _ops_user_dir(username) / f"{_safe_name(name)}.json"
    data = load_json(path, default)
    if not isinstance(data, dict):
        data = default
    return data

def _ops_save_user_json(username: str, name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    path = _ops_user_dir(username) / f"{_safe_name(name)}.json"
    save_json(path, payload)
    return payload

def _load_ops_tasks(username: str) -> Dict[str, Any]:
    data = _ops_user_json(username, "tasks", {"tasks": [], "updated_at": None})
    tasks = data.get("tasks")
    if not isinstance(tasks, list):
        tasks = []
    data["tasks"] = tasks
    return data

def _save_ops_tasks(username: str, data: Dict[str, Any]) -> Dict[str, Any]:
    data["updated_at"] = now_iso()
    return _ops_save_user_json(username, "tasks", data)

def _load_ops_memory(username: str) -> Dict[str, Any]:
    data = _ops_user_json(username, "memory", {"notes": [], "updated_at": None})
    notes = data.get("notes")
    if not isinstance(notes, list):
        notes = []
    data["notes"] = notes
    return data

def _save_ops_memory(username: str, data: Dict[str, Any]) -> Dict[str, Any]:
    data["updated_at"] = now_iso()
    return _ops_save_user_json(username, "memory", data)

def _load_ops_events(username: str) -> Dict[str, Any]:
    data = _ops_user_json(username, "events", {"events": [], "updated_at": None})
    events = data.get("events")
    if not isinstance(events, list):
        events = []
    data["events"] = events
    return data

def _save_ops_events(username: str, data: Dict[str, Any]) -> Dict[str, Any]:
    data["updated_at"] = now_iso()
    return _ops_save_user_json(username, "events", data)

def _append_ops_event(username: str, kind: str, message: str, detail: Any = None, level: str = "info") -> Dict[str, Any]:
    data = _load_ops_events(username)
    event = {
        "id": "evt_" + uuid.uuid4().hex[:10],
        "ts": now_iso(),
        "kind": (kind or "log").strip()[:64],
        "message": (message or "").strip()[:300],
        "detail": detail if isinstance(detail, (dict, list, str, int, float, bool)) or detail is None else str(detail),
        "level": (level or "info").strip()[:16],
    }
    data["events"] = (data.get("events") or [])[-199:] + [event]
    _save_ops_events(username, data)
    return event

def _ops_recent_events(username: str, limit: int = 50) -> List[Dict[str, Any]]:
    data = _load_ops_events(username)
    items = data.get("events") or []
    if not isinstance(items, list):
        return []
    return items[-max(1, min(limit, 200)):]


def _load_ops_friend_sessions(username: str) -> Dict[str, Any]:
    data = _ops_user_json(username, "friend_sessions", {"sessions": [], "updated_at": None})
    sessions = data.get("sessions")
    if not isinstance(sessions, list):
        sessions = []
    data["sessions"] = sessions
    return data

def _save_ops_friend_sessions(username: str, data: Dict[str, Any]) -> Dict[str, Any]:
    data["updated_at"] = now_iso()
    return _ops_save_user_json(username, "friend_sessions", data)

def _normalize_facebook_url(raw_url: str) -> str:
    raw_url = (raw_url or "").strip()
    if not raw_url:
        return ""
    try:
        parsed = urlparse(raw_url)
        if parsed.scheme not in ("http", "https"):
            return ""
        host = (parsed.netloc or "").lower().strip()
        if host.startswith("www."):
            host = host[4:]
        allowed = {
            "facebook.com",
            "m.facebook.com",
            "mbasic.facebook.com",
            "web.facebook.com",
            "fb.com",
        }
        if host not in allowed and not host.endswith(".facebook.com"):
            return ""
        return parsed.geturl()[:500]
    except Exception:
        return ""

def _latest_friend_session(username: str) -> Optional[Dict[str, Any]]:
    data = _load_ops_friend_sessions(username)
    sessions = [s for s in (data.get("sessions") or []) if isinstance(s, dict)]
    return sessions[-1] if sessions else None

def _new_friend_review_session(username: str, target_url: str) -> Dict[str, Any]:
    clean_url = _normalize_facebook_url(target_url)
    if not clean_url:
        raise ValueError("Paste a valid Facebook friends-list or profile-review URL")
    session_id = "fbscan_" + uuid.uuid4().hex[:10]
    session_obj = {
        "id": session_id,
        "target_url": clean_url,
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "status": "ready",
        "instructions": [
            "Open the Facebook link in a real browser tab while logged in.",
            "Scroll naturally and review one profile at a time.",
            "Copy visible friend rows, profile notes, or your own inactivity notes back into the analyzer box.",
            "Use the scored candidates as a review aid only, then remove manually inside Facebook if you choose.",
        ],
    }
    data = _load_ops_friend_sessions(username)
    data["sessions"] = (data.get("sessions") or [])[-49:] + [session_obj]
    _save_ops_friend_sessions(username, data)
    return session_obj

def _new_ops_task(username: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    now = now_iso()
    title = (payload.get("title") or "").strip()[:140]
    if not title:
        title = "Untitled task"
    task_type = (payload.get("type") or "general").strip()[:80]
    checklist = payload.get("checklist") or []
    if isinstance(checklist, str):
        checklist = [x.strip() for x in checklist.splitlines() if x.strip()]
    if not isinstance(checklist, list):
        checklist = []
    clean_steps = []
    for item in checklist[:30]:
        if isinstance(item, dict):
            label = (item.get("label") or "").strip()
        else:
            label = str(item).strip()
        if label:
            clean_steps.append({"label": label[:160], "done": False})
    task = {
        "id": "task_" + uuid.uuid4().hex[:10],
        "title": title,
        "type": task_type,
        "status": (payload.get("status") or "queued").strip()[:24],
        "priority": (payload.get("priority") or "normal").strip()[:24],
        "semi_auto": bool(payload.get("semi_auto", True)),
        "notes": (payload.get("notes") or "").strip()[:2000],
        "target_url": (payload.get("target_url") or "").strip()[:500],
        "source": (payload.get("source") or "manual").strip()[:80],
        "created_at": now,
        "updated_at": now,
        "completed_at": None,
        "teammate": (payload.get("teammate") or "").strip()[:64],
        "checklist": clean_steps,
        "result": payload.get("result") if isinstance(payload.get("result"), (dict, list, str, int, float, bool)) or payload.get("result") is None else str(payload.get("result")),
    }
    return task

def _find_ops_task(username: str, task_id: str) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any], int]:
    data = _load_ops_tasks(username)
    tasks = data.get("tasks") or []
    for idx, task in enumerate(tasks):
        if isinstance(task, dict) and task.get("id") == task_id:
            return task, data, idx
    return None, data, -1

def _task_counts(tasks: List[Dict[str, Any]]) -> Dict[str, int]:
    out = {"queued": 0, "running": 0, "needs_review": 0, "done": 0}
    for t in tasks:
        if not isinstance(t, dict):
            continue
        status = (t.get("status") or "queued").strip()
        if status not in out:
            out[status] = 0
        out[status] += 1
    return out

def _ops_startup_snapshot() -> Dict[str, Any]:
    items = []
    def add(name: str, ok: bool, detail: str):
        items.append({"name": name, "ok": bool(ok), "detail": detail})
    add("Data directory", DATA.exists(), f"{DATA}")
    add("Uploads directory", UPLOADS_DIR.exists(), f"{UPLOADS_DIR}")
    add("Threads directory", THREADS_DIR.exists(), f"{THREADS_DIR}")
    add("OpenAI import", True, "openai package imported")
    add("Anthropic import", anthropic is not None, "anthropic available" if anthropic is not None else "anthropic missing")
    add("OpenAI env", bool(OPENAI_API_KEY), "OPENAI_API_KEY available" if OPENAI_API_KEY else "OPENAI_API_KEY not set")
    add("Claude env", bool(CLAUDE_API_KEY), "CLAUDE_API_KEY available" if CLAUDE_API_KEY else "CLAUDE_API_KEY not set")
    return {"ok": all(i["ok"] for i in items if i["name"] not in ("Claude env", "Anthropic import")), "checks": items, "generated_at": now_iso()}

OPS_STARTUP_SNAPSHOT = _ops_startup_snapshot()

def _extract_years(raw: str) -> List[int]:
    years = []
    for y in re.findall(r"\b(20\d{2}|19\d{2})\b", raw or ""):
        try:
            years.append(int(y))
        except Exception:
            pass
    return years

def _facebook_activity_score(raw: str) -> Tuple[int, List[str], str]:
    txt = (raw or "").strip()
    low = txt.lower()
    reasons = []
    score = 50

    inactivity_signals = [
        ("no mutual friends", 14),
        ("no mutual groups", 16),
        ("no mutuals", 14),
        ("lives in", 2),
        ("joined facebook", 8),
        ("no recent posts", 18),
        ("inactive", 20),
        ("last active", 12),
        ("message unavailable", 5),
    ]
    strong_keep = [
        ("family", -28),
        ("client", -30),
        ("lead", -16),
        ("realtor", -10),
        ("investor", -10),
        ("recently posted", -18),
        ("commented", -18),
        ("reacted", -12),
        ("mutual friends", -8),
        ("mutual groups", -6),
    ]

    for phrase, delta in inactivity_signals:
        if phrase in low:
            score += delta
            reasons.append(f"Signal: {phrase}")
    for phrase, delta in strong_keep:
        if phrase in low:
            score += delta
            reasons.append(f"Counter-signal: {phrase}")

    yrs = _extract_years(txt)
    if yrs:
        latest = max(yrs)
        age = max(0, datetime.utcnow().year - latest)
        if age >= 4:
            score += min(30, age * 5)
            reasons.append(f"Latest visible year looks old: {latest}")
        elif age <= 1:
            score -= 18
            reasons.append(f"Recent year found: {latest}")

    if len(txt) < 40:
        score += 6
        reasons.append("Very little activity context provided")

    score = max(0, min(100, score))
    if score >= 70:
        action = "remove_candidate"
    elif score >= 45:
        action = "review"
    else:
        action = "keep"
    if not reasons:
        reasons.append("No strong inactivity signal found")
    return score, reasons[:6], action

def _parse_friend_scan_text(raw_text: str) -> List[Dict[str, Any]]:
    raw_text = (raw_text or "").strip()
    if not raw_text:
        return []
    chunks = [c.strip() for c in re.split(r"\n\s*\n+", raw_text) if c.strip()]
    if len(chunks) == 1:
        lines = [ln.strip() for ln in raw_text.splitlines() if ln.strip()]
        if len(lines) > 1 and len(lines) <= 80:
            chunks = lines
    out = []
    seen = set()
    for chunk in chunks[:150]:
        first_line = chunk.splitlines()[0].strip()
        name = re.sub(r"\s{2,}", " ", first_line)[:120]
        if not name:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        score, reasons, action = _facebook_activity_score(chunk)
        out.append({
            "id": "fb_" + uuid.uuid4().hex[:10],
            "name": name,
            "score": score,
            "recommended_action": action,
            "reasons": reasons,
            "raw": chunk[:3000],
        })
    out.sort(key=lambda x: (-int(x.get("score") or 0), (x.get("name") or "").lower()))
    return out

def _parse_metric_number(label: str, text_blob: str) -> Optional[int]:
    patterns = [
        rf"{label}\s*[:=]\s*([\d,]+)",
        rf"{label}\s+([\d,]+)",
    ]
    for pat in patterns:
        m = re.search(pat, text_blob, re.I)
        if m:
            try:
                return int(m.group(1).replace(",", ""))
            except Exception:
                return None
    return None

def _facebook_post_insights(raw_text: str) -> Dict[str, Any]:
    raw_text = (raw_text or "").strip()
    low = raw_text.lower()
    reactions = _parse_metric_number("reactions?", raw_text) or _parse_metric_number("likes?", raw_text) or 0
    comments = _parse_metric_number("comments?", raw_text) or 0
    shares = _parse_metric_number("shares?", raw_text) or 0
    clicks = _parse_metric_number("clicks?", raw_text) or 0
    reach = _parse_metric_number("reach", raw_text) or 0
    saves = _parse_metric_number("saves?", raw_text) or 0

    score = reactions + comments * 3 + shares * 5 + saves * 4 + clicks * 2
    findings = []
    next_moves = []

    if comments >= max(8, reactions * 0.15 if reactions else 8):
        findings.append("Comment rate looks strong. The post likely invited conversation instead of broadcasting.")
        next_moves.append("Write a pinned comment that asks a narrow follow-up question to extend the thread.")
    if shares >= 3:
        findings.append("Share activity is present, which usually means the idea feels identity-aligned or useful.")
        next_moves.append("Turn this topic into a sharper quote graphic or carousel while the signal is warm.")
    if reactions > 0 and comments == 0:
        findings.append("The post is getting passive approval more than conversation.")
        next_moves.append("Rewrite the closing line into a simpler, lower-friction question.")
    if reach and score:
        er = round((score / max(reach, 1)) * 100, 2)
        findings.append(f"Estimated weighted engagement score vs reach: {er}%")
    if "question" in low:
        findings.append("The copy appears to include a question, which usually helps comment depth.")
    if "story" in low or "experience" in low:
        findings.append("Story-style framing is present, which often improves read time and relatability.")
    if not findings:
        findings.append("Not enough structured metrics were found for a strong reading, but the paste is stored for review.")
        next_moves.append("Paste the post text plus reach, reactions, comments, and shares for a stronger diagnosis.")
    if not next_moves:
        next_moves.append("Test a shorter hook with a more specific audience angle.")
        next_moves.append("Reply to early comments quickly to increase conversation velocity.")
    return {
        "metrics": {
            "reactions": reactions,
            "comments": comments,
            "shares": shares,
            "clicks": clicks,
            "saves": saves,
            "reach": reach,
            "weighted_score": score,
        },
        "findings": findings[:6],
        "next_moves": next_moves[:6],
        "summary": "Conversation-led signal looks promising." if comments or shares else "This looks more passive than conversational so far.",
    }


def _ops_json_error(username: str, kind: str, exc: Exception, user_message: str, status: int = 500):
    try:
        _append_ops_event(username or "anon", kind, user_message, {"error": str(exc)}, "error")
    except Exception:
        pass
    return jsonify({"ok": False, "error": user_message, "detail": str(exc)}), status

def _ops_dashboard_payload(username: str, user_obj: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    user_obj = user_obj or {}
    self_test = _run_system_self_test_for_user(user_obj) if isinstance(user_obj, dict) else {"ok": False, "checks": []}
    tasks = _load_ops_tasks(username).get("tasks") or []
    notes = _load_ops_memory(username).get("notes") or []
    events = _ops_recent_events(username, 40)
    counts = _task_counts([t for t in tasks if isinstance(t, dict)])
    return {
        "ok": True,
        "startup": OPS_STARTUP_SNAPSHOT,
        "self_test": self_test,
        "task_counts": counts,
        "recent_tasks": [t for t in tasks[-12:] if isinstance(t, dict)],
        "recent_notes": [n for n in notes[-12:] if isinstance(n, dict)],
        "events": events,
        "feature_flags": {
            "ops_center": True,
            "semi_auto_facebook": True,
            "memory_notes": True,
            "task_engine": True,
            "post_insights": True,
        },
        "friend_session": _latest_friend_session(username),
    }

@app.get("/api/ops/dashboard")
def api_ops_dashboard():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    username = (u.get("username") or "").strip() or _get_session_username()
    return jsonify(_ops_dashboard_payload(username, u))

@app.get("/api/ops/tasks")
def api_ops_tasks_get():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    username = (u.get("username") or "").strip() or _get_session_username()
    data = _load_ops_tasks(username)
    tasks = [t for t in (data.get("tasks") or []) if isinstance(t, dict)]
    tasks.sort(key=lambda x: ((x.get("status") or "") == "done", x.get("updated_at") or ""), reverse=False)
    return jsonify({"ok": True, "tasks": tasks, "counts": _task_counts(tasks)})

@app.post("/api/ops/tasks")
def api_ops_tasks_post():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    username = (u.get("username") or "").strip() or _get_session_username()
    try:
        payload = request.get_json(silent=True) or {}
        task = _new_ops_task(username, payload)
        data = _load_ops_tasks(username)
        data["tasks"] = (data.get("tasks") or [])[-199:] + [task]
        _save_ops_tasks(username, data)
        _append_ops_event(username, "ops_task_created", f"Task created: {task.get('title')}", {"task_id": task.get("id"), "type": task.get("type")})
        append_task_log("ops_task_created", {"task": task}, teammate=task.get("teammate") or "", status="success")
        return jsonify({"ok": True, "task": task, "counts": _task_counts(data.get("tasks") or [])})
    except Exception as e:
        return _ops_json_error(username, "ops_task_create_error", e, "Task creation failed")


@app.post("/api/ops/tasks/<task_id>/action")
def api_ops_task_action(task_id: str):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    username = (u.get("username") or "").strip() or _get_session_username()
    try:
        payload = request.get_json(silent=True) or {}
        action = (payload.get("action") or "").strip().lower()
        task, data, idx = _find_ops_task(username, task_id)
        if not task:
            return jsonify({"ok": False, "error": "Task not found"}), 404
        if action == "start":
            task["status"] = "running"
        elif action == "review":
            task["status"] = "needs_review"
        elif action == "done":
            task["status"] = "done"
            task["completed_at"] = now_iso()
        elif action == "reset":
            task["status"] = "queued"
            task["completed_at"] = None
            for step in (task.get("checklist") or []):
                if isinstance(step, dict):
                    step["done"] = False
        elif action == "toggle_step":
            step_index = int(payload.get("step_index") or 0)
            steps = task.get("checklist") or []
            if 0 <= step_index < len(steps) and isinstance(steps[step_index], dict):
                steps[step_index]["done"] = not bool(steps[step_index].get("done"))
        elif action == "note":
            note = (payload.get("note") or "").strip()
            task["notes"] = (task.get("notes") or "")
            if note:
                task["notes"] = ((task.get("notes") or "").strip() + ("\n\n" if (task.get("notes") or "").strip() else "") + note)[:4000]
        else:
            return jsonify({"ok": False, "error": "Unsupported action"}), 400
        task["updated_at"] = now_iso()
        if not isinstance(data.get("tasks"), list):
            data["tasks"] = []
        if idx < 0 or idx >= len(data["tasks"]):
            return jsonify({"ok": False, "error": "Task storage is out of sync"}), 409
        data["tasks"][idx] = task
        _save_ops_tasks(username, data)
        _append_ops_event(username, "task_updated", f"{task.get('title')} → {task.get('status')}", {"task_id": task_id, "action": action})
        return jsonify({"ok": True, "task": task, "counts": _task_counts(data.get("tasks") or [])})
    except Exception as e:
        return _ops_json_error(username, "task_update_error", e, "Task action failed")



@app.get("/api/ops/memory")
def api_ops_memory_get():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    username = (u.get("username") or "").strip() or _get_session_username()
    data = _load_ops_memory(username)
    notes = [n for n in (data.get("notes") or []) if isinstance(n, dict)]
    teammate = (request.args.get("teammate") or "").strip().lower()
    if teammate:
        notes = [n for n in notes if (n.get("teammate") or "").strip().lower() == teammate]
    return jsonify({"ok": True, "notes": notes[-150:]})

@app.post("/api/ops/memory")
def api_ops_memory_post():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    username = (u.get("username") or "").strip() or _get_session_username()
    payload = request.get_json(silent=True) or {}
    note_text = (payload.get("note") or "").strip()
    if not note_text:
        return jsonify({"ok": False, "error": "Note is required"}), 400
    teammate = (payload.get("teammate") or "operator").strip()[:64]
    source = (payload.get("source") or "manual").strip()[:80]
    data = _load_ops_memory(username)
    note = {
        "id": "mem_" + uuid.uuid4().hex[:10],
        "teammate": teammate,
        "source": source,
        "note": note_text[:2500],
        "created_at": now_iso(),
    }
    data["notes"] = (data.get("notes") or [])[-299:] + [note]
    _save_ops_memory(username, data)
    _append_ops_event(username, "memory_saved", f"Memory note saved for {teammate}", {"note_id": note["id"]})
    return jsonify({"ok": True, "note": note, "count": len(data.get("notes") or [])})

@app.post("/api/ops/event")
def api_ops_event():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    username = (u.get("username") or "").strip() or _get_session_username()
    payload = request.get_json(silent=True) or {}
    evt = _append_ops_event(
        username,
        (payload.get("kind") or "ui").strip()[:64],
        (payload.get("message") or "UI event").strip()[:300],
        payload.get("detail"),
        (payload.get("level") or "info").strip()[:16],
    )
    return jsonify({"ok": True, "event": evt})

@app.post("/api/facebook/friend_review_session")
def api_facebook_friend_review_session():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    username = (u.get("username") or "").strip() or _get_session_username()
    try:
        payload = request.get_json(silent=True) or {}
        target_url = (payload.get("target_url") or "").strip()
        session_obj = _new_friend_review_session(username, target_url)
        task = _new_ops_task(username, {
            "title": "Facebook guided friend review",
            "type": "facebook_cleanup",
            "status": "running",
            "semi_auto": True,
            "source": "facebook_guided_review",
            "target_url": session_obj.get("target_url"),
            "notes": "Open the Facebook tab from this task, review people naturally, then paste copied friend rows or profile notes back into the analyzer for scoring. Final keep or remove decisions stay manual.",
            "checklist": session_obj.get("instructions") or [],
            "result": {"session_id": session_obj.get("id")},
        })
        data = _load_ops_tasks(username)
        data["tasks"] = (data.get("tasks") or [])[-199:] + [task]
        _save_ops_tasks(username, data)
        _append_ops_event(username, "facebook_guided_review", "Facebook guided review session created", {"task_id": task.get("id"), "session_id": session_obj.get("id")})
        return jsonify({"ok": True, "session": session_obj, "task": task})
    except Exception as e:
        return _ops_json_error(username, "facebook_guided_review_error", e, "Could not start the Facebook guided review")

@app.post("/api/facebook/friend_scan")
def api_facebook_friend_scan():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    username = (u.get("username") or "").strip() or _get_session_username()
    try:
        payload = request.get_json(silent=True) or {}
        raw_text = (payload.get("raw_text") or "").strip()
        target_url = (payload.get("target_url") or "").strip()
        session_obj = None
        if target_url:
            clean_url = _normalize_facebook_url(target_url)
            if not clean_url:
                return jsonify({"ok": False, "error": "Paste a valid Facebook URL before scanning"}), 400
            session_obj = _latest_friend_session(username)
            if not session_obj or session_obj.get("target_url") != clean_url:
                session_obj = _new_friend_review_session(username, clean_url)
        if not raw_text:
            return jsonify({"ok": False, "error": "Paste friend rows, profile notes, or review notes to scan"}), 400
        candidates = _parse_friend_scan_text(raw_text)
        if not candidates:
            return jsonify({"ok": False, "error": "No candidate lines were recognized"}), 400
        task = _new_ops_task(username, {
            "title": "Facebook inactive friend review",
            "type": "facebook_cleanup",
            "status": "needs_review",
            "semi_auto": True,
            "source": "facebook_scan",
            "target_url": session_obj.get("target_url") if session_obj else "",
            "notes": "Semi-auto safety flow only. Use the scored candidates as a review aid, then confirm manually inside Facebook before removing anyone.",
            "checklist": [
                "Open the Facebook review tab or your friends list in a real browser",
                "Review the highest-score candidates first",
                "Open each profile before any remove action",
                "Remove manually only after confirming inactivity",
                "Mark the task done after the review pass"
            ],
            "result": {"candidate_count": len(candidates), "top_candidates": candidates[:25], "session_id": session_obj.get("id") if session_obj else None},
        })
        data = _load_ops_tasks(username)
        data["tasks"] = (data.get("tasks") or [])[-199:] + [task]
        _save_ops_tasks(username, data)
        _append_ops_event(username, "facebook_scan", f"Facebook inactivity scan produced {len(candidates)} candidates", {"task_id": task.get("id")})
        return jsonify({"ok": True, "task": task, "session": session_obj, "candidates": candidates[:80]})
    except Exception as e:
        return _ops_json_error(username, "facebook_scan_error", e, "Friend scan failed")


@app.post("/api/facebook/post_insights")
def api_facebook_post_insights():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    username = (u.get("username") or "").strip() or _get_session_username()
    try:
        payload = request.get_json(silent=True) or {}
        raw_text = (payload.get("raw_text") or "").strip()
        if not raw_text:
            return jsonify({"ok": False, "error": "Paste the post text and any metrics you have"}), 400
        analysis = _facebook_post_insights(raw_text)
        _append_ops_event(username, "facebook_post_insights", "Facebook post insights generated", {"summary": analysis.get("summary")})
        return jsonify({"ok": True, "analysis": analysis})
    except Exception as e:
        return _ops_json_error(username, "facebook_post_insights_error", e, "Post insights failed")



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
    crm["clients"][cid] = client
    _crm_save(uname, crm)
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
        code, msg = _map_openai_error(e)
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)


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
