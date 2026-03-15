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

load_dotenv()

APP_TITLE = os.getenv("APP_TITLE", " Simply Agentic AI Round Table V1.12")
MODEL = os.getenv("MODEL", "gpt-5.2")
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


<!-- Mobile layout + onboarding hotfix -->
<style id="mobileRoundTableCenterAndOnboardingFix">
@media (max-width: 720px){
  #tableWrap{
    display:flex !important;
    flex-direction:column !important;
    align-items:center !important;
    justify-content:flex-start !important;
    gap:18px !important;
    width:100% !important;
    max-width:100% !important;
    overflow:visible !important;
    padding: 0 8px 8px 8px !important;
    margin: 0 auto !important;
  }
  #tableCore,
  #tableCore.table{
    order:1 !important;
    flex:0 0 auto !important;
    margin:0 auto !important;
  }
  #operator,
  #operator.operator{
    order:2 !important;
    position:relative !important;
    left:auto !important;
    top:auto !important;
    transform:none !important;
    width:min(100%, 560px) !important;
    max-width:min(100%, 560px) !important;
    min-width:0 !important;
    margin:0 auto 10px auto !important;
    z-index:25 !important;
  }
  #onboardingPanel{
    left:12px !important;
    right:12px !important;
    top:auto !important;
    bottom:calc(86px + env(safe-area-inset-bottom)) !important;
    width:auto !important;
    max-width:none !important;
    min-width:0 !important;
    max-height:min(72vh, 640px) !important;
    resize:none !important;
    z-index:9999 !important;
  }
  #onbHeader{ cursor:default !important; }
}
</style>

<script id="mobileRoundTableCenterAndOnboardingFixScript">
(function(){
  function isMobileFix(){
    try{ return window.matchMedia && window.matchMedia("(max-width: 720px)").matches; }catch(e){ return window.innerWidth <= 720; }
  }

  function applyRoundTableFix(){
    if(!isMobileFix()) return;
    try{
      var wrap = document.getElementById("tableWrap");
      var table = document.getElementById("tableCore");
      var op = document.getElementById("operator");
      if(!wrap || !table || !op) return;

      if(wrap.firstElementChild !== table){
        wrap.insertBefore(table, wrap.firstChild);
      }
      if(op.previousElementSibling !== table){
        wrap.insertBefore(table, op);
      }

      wrap.style.display = "flex";
      wrap.style.flexDirection = "column";
      wrap.style.alignItems = "center";
      wrap.style.justifyContent = "flex-start";
      wrap.style.gap = "18px";
      wrap.style.overflow = "visible";
      wrap.style.marginLeft = "auto";
      wrap.style.marginRight = "auto";

      table.style.order = "1";
      table.style.marginLeft = "auto";
      table.style.marginRight = "auto";

      op.style.order = "2";
      op.style.position = "relative";
      op.style.left = "auto";
      op.style.top = "auto";
      op.style.transform = "none";
      op.style.margin = "0 auto 10px auto";
      op.style.width = "min(100%, 560px)";
      op.style.maxWidth = "min(100%, 560px)";
      op.style.minWidth = "0";
    }catch(e){}
  }

  function applyOnboardingPanelFix(){
    if(!isMobileFix()) return;
    try{
      var panel = document.getElementById("onboardingPanel");
      if(!panel) return;
      panel.style.left = "12px";
      panel.style.right = "12px";
      panel.style.top = "auto";
      panel.style.bottom = "calc(86px + env(safe-area-inset-bottom))";
      panel.style.width = "auto";
      panel.style.maxWidth = "none";
      panel.style.minWidth = "0";
      panel.style.maxHeight = "min(72vh, 640px)";
      panel.style.resize = "none";
      panel.style.zIndex = "9999";
    }catch(e){}
  }

  function forceOpenOnboarding(){
    try{
      if(window.onboardingOpen){
        window.onboardingOpen();
      }
    }catch(e){}
    setTimeout(function(){
      try{
        applyOnboardingPanelFix();
        var panel = document.getElementById("onboardingPanel");
        if(panel){
          panel.style.display = "block";
          panel.scrollTop = 0;
        }
      }catch(e){}
    }, 80);
    setTimeout(function(){
      try{
        if(window.onboardingRefresh) window.onboardingRefresh();
      }catch(e){}
    }, 180);
  }

  function bindButtons(){
    ["onboardingBtn", "mobileOnboardingBtn"].forEach(function(id){
      var btn = document.getElementById(id);
      if(!btn || btn.dataset.mobileFixBound === "1") return;
      btn.dataset.mobileFixBound = "1";
      btn.addEventListener("click", function(){
        forceOpenOnboarding();
      }, true);
    });
  }

  function runFixes(){
    applyRoundTableFix();
    applyOnboardingPanelFix();
    bindButtons();
  }

  document.addEventListener("DOMContentLoaded", function(){
    runFixes();
    setTimeout(runFixes, 250);
    setTimeout(runFixes, 900);
  });

  window.addEventListener("resize", runFixes);
  window.addEventListener("orientationchange", function(){ setTimeout(runFixes, 120); });
})();
</script>


<style id="mobileDisplayCleanupV2">
@media (max-width: 720px){
  html, body{
    overflow-x: hidden !important;
  }

  /* Keep the mobile experience clean: hide only the decorative round table circle */
  #tableCore,
  #tableCore.table,
  #tableViewport,
  #rtStage,
  #tableZoomFab{
    display: none !important;
  }

  /* Return the cards/operator area to a clean vertical mobile layout */
  #tableWrap,
  .tableWrap{
    display: flex !important;
    flex-direction: column !important;
    align-items: stretch !important;
    justify-content: flex-start !important;
    width: 100% !important;
    max-width: 100% !important;
    min-height: 0 !important;
    height: auto !important;
    gap: 12px !important;
    padding: 0 12px 8px 12px !important;
    margin: 0 auto !important;
    overflow: visible !important;
    box-sizing: border-box !important;
  }

  #operator,
  #operator.operator{
    order: 1 !important;
    position: relative !important;
    left: auto !important;
    top: auto !important;
    transform: none !important;
    width: 100% !important;
    max-width: 100% !important;
    min-width: 0 !important;
    margin: 0 auto !important;
  }

  .seat{
    position: relative !important;
    left: auto !important;
    top: auto !important;
    transform: none !important;
    width: 100% !important;
    max-width: 100% !important;
    min-width: 0 !important;
    height: auto !important;
    min-height: 118px !important;
    cursor: default !important;
  }

  .seatTools{
    flex-wrap: wrap !important;
    gap: 8px !important;
  }

  .seatToolBtn{
    flex: 1 1 auto !important;
  }

  /* Make the Next step panel reliably visible on phones */
  #onboardingPanel{
    position: fixed !important;
    left: 12px !important;
    right: 12px !important;
    top: 12px !important;
    bottom: calc(86px + env(safe-area-inset-bottom)) !important;
    width: auto !important;
    max-width: none !important;
    min-width: 0 !important;
    max-height: none !important;
    height: auto !important;
    resize: none !important;
    overflow: auto !important;
    z-index: 99999 !important;
    box-sizing: border-box !important;
  }

  #onbCard{
    min-height: 0 !important;
  }

  #onbHeader{
    cursor: default !important;
  }
}
</style>

<script id="mobileDisplayCleanupV2Script">
(function(){
  function isMobile(){
    try{
      return window.matchMedia && window.matchMedia("(max-width: 720px)").matches;
    }catch(e){
      return window.innerWidth <= 720;
    }
  }

  function normalizeMobileLayout(){
    if(!isMobile()) return;
    try{
      var wrap = document.getElementById("tableWrap");
      var op = document.getElementById("operator");
      if(wrap && op && wrap.firstElementChild !== op){
        wrap.insertBefore(op, wrap.firstChild);
      }
    }catch(e){}

    try{
      document.querySelectorAll(".seat").forEach(function(el){
        el.style.left = "auto";
        el.style.top = "auto";
        el.style.transform = "none";
      });
    }catch(e){}
  }

  function forceOpenOnboardingMobile(){
    try{
      var overlay = document.getElementById("mobileDrawerOverlay");
      if(overlay) overlay.classList.remove("show");
      document.body.style.overflow = "";
    }catch(e){}

    try{
      if(typeof fetchOnboarding === "function"){
        fetchOnboarding();
      }
    }catch(e){}

    setTimeout(function(){
      try{
        var panel = document.getElementById("onboardingPanel");
        if(panel){
          panel.style.display = "block";
          panel.style.left = "12px";
          panel.style.right = "12px";
          panel.style.top = "12px";
          panel.style.bottom = "calc(86px + env(safe-area-inset-bottom))";
          panel.style.zIndex = "99999";
          panel.scrollTop = 0;
        }
      }catch(e){}
    }, 60);
  }

  function bindOnboardingButtons(){
    ["onboardingBtn", "mobileOnboardingBtn"].forEach(function(id){
      var btn = document.getElementById(id);
      if(!btn || btn.dataset.mobileDisplayCleanupBound === "1") return;
      btn.dataset.mobileDisplayCleanupBound = "1";
      btn.addEventListener("click", function(){
        if(isMobile()){
          forceOpenOnboardingMobile();
        }
      }, true);
    });
  }

  document.addEventListener("DOMContentLoaded", function(){
    normalizeMobileLayout();
    bindOnboardingButtons();
    setTimeout(normalizeMobileLayout, 150);
    setTimeout(bindOnboardingButtons, 250);
  });

  window.addEventListener("resize", function(){
    normalizeMobileLayout();
  });

  window.addEventListener("orientationchange", function(){
    setTimeout(normalizeMobileLayout, 120);
  });
})();
</script>

</body>
</html>

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
"""



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
"""




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
