import os
import json
import re
import smtplib
import uuid
import base64
import secrets
import hashlib
import hmac
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, List, Tuple, Optional, Union

from flask import Flask, request, render_template_string, jsonify, session, redirect, url_for, make_response, g
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

APP_TITLE = os.getenv("APP_TITLE", " Simply Agentic AI Round Table ")
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

client = OpenAI(api_key=OPENAI_API_KEY)
app = Flask(__name__)

# Quiet noisy request logs (especially the stack tick poll)
import logging
logging.getLogger("werkzeug").setLevel(logging.ERROR)

app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

BASE = Path(__file__).parent
DATA = BASE / "data"
REGISTRY_PATH = DATA / "teammates.json"
THREADS_DIR = DATA / "threads"
LOGS_DIR = DATA / "logs"
UPLOADS_DIR = DATA / "uploads"
UPLOAD_INDEX_PATH = UPLOADS_DIR / "_index.json"
FRAMEWORK_PATH = DATA / "core_framework.txt"

DATA.mkdir(exist_ok=True)
THREADS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)
UPLOADS_DIR.mkdir(exist_ok=True)

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
        # Local-first: if no users exist yet (fresh install), allow Settings so you can add your API key
        # without getting blocked by auth. We create a temporary local session user.
        if (not has_any_user()) and request.path in ("/api/user/settings", "/api/action_stack_schedules/tick"):
            session["user"] = ensure_local_owner_user()
        else:
            return jsonify({"ok": False, "error": "Not authenticated"}), 401

    if request.path == "/" and not session.get("user"):
        # if no users exist, send to setup
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
    return c or client

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
    sys = teammate_system_prompt(defn)
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

def teammate_system_prompt(defn: Dict[str, Any]) -> str:
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
        "If the user asks you to send an email, you must output a structured email draft so the UI can auto fill fields.\n"
        "You must use this exact format when an email draft is appropriate:\n"
        "```email\n"
        "To: recipient@email.com\n"
        "Subject: subject line\n"
        "Body: first line of body\n"
        "rest of body...\n"
        "```\n"
        "Do not claim the email was sent.\n"
        "No em dashes.\n"
            + operator_block
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
        f"Business: {_op.get('business','').strip()}\n"
        f"Offers: {_op.get('offers','').strip()}\n"
        f"Audience: {_op.get('audience','').strip()}\n"
        f"Goals: {_op.get('goals','').strip()}\n"
        f"Constraints: {_op.get('constraints','').strip()}\n"
        f"Tone rules: {_op.get('tone_rules','').strip()}\n"
        f"Notes: {_op.get('notes','').strip()}\n"
            + operator_block
    )

    framework = load_core_framework(        + operator_block
    )

    return (
        "You are a persistent, role locked Agentic AI Teammate.\n"
        "You are not a general assistant.\n"
        "Default mode is architect first, not task execution.\n\n"
        "You must obey the Core Framework below and the role block.\n"
        "If any request violates one or more pillars, pause, explain the conflict, and propose a compliant alternative.\n"
        "If a decision affects structure, memory, versioning, or long term behavior, ask one clarifying question and stop.\n"
        "No em dashes.\n\n"
        f"{email_rules}\n"
        f"CORE FRAMEWORK:\n{framework}\n\n"
        f"ROLE BLOCK (locked):\n{json.dumps(role_block, indent=2)}\n"
            + operator_block
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
        return 401, "Invalid OpenAI API key. Open Settings and paste a valid key that starts with sk-."
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
        _run_due_schedules_once()
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

    rec = {
        "id": file_id,
        "filename": filename,
        "relpath": str(Path(subdir) / f"{file_id}_{filename}"),
        "mimetype": mimetype,
        "size_bytes": size_bytes,
        "uploaded_at": now_iso(),
    }
    add_upload_record(file_id, rec)

    append_log("upload", rec)
    return jsonify({"ok": True, "file": rec})


@app.post("/api/convene")
def api_convene():
    data = request.get_json(force=True)
    prompt = (data.get("prompt") or "").strip()
    file_ids = data.get("file_ids") or []

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
    atlis_sys = teammate_system_prompt(atlis)
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

        sys = teammate_system_prompt(defn)

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

    if not name or not msg:
        return jsonify({"ok": False, "error": "Missing name or message"}), 400

    reg = load_registry()
    installed = reg["installed"]
    if name not in installed:
        return jsonify({"ok": False, "error": "Teammate not installed"}), 400

    msg2, attach_meta, vision_images = build_prompt_with_attachments(msg, file_ids)
    user_content = _build_user_content(msg2, vision_images)

    defn = installed[name]
    sys = teammate_system_prompt(defn)

    thread = load_thread(name)
    thread = thread[-14:] if len(thread) > 14 else thread

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

    return jsonify({"ok": True, "name": name, "response": text, "email_draft": draft, "attachment_meta": attach_meta})


@app.get("/api/thread/<name>")
def api_thread(name: str):
    reg = load_registry()
    installed = reg["installed"]
    if name not in installed:
        return jsonify({"ok": False, "error": "Teammate not installed"}), 400
    return jsonify({"ok": True, "thread": load_thread(name)})


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
            if not creds:
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
    session["gmail_oauth_state"] = state
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
    expected = session.get("gmail_oauth_state", "")
    if not state or not expected or state != expected:
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
    if not creds:
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
# =========================
# AUTH ROUTES
# =========================

AUTH_BASE_CSS = r"""
<style>
  :root{ --text:#e6edff; --muted:#b8c4ffcc; }
  *{box-sizing:border-box}
  body{
    margin:0;
    font-family: Arial, sans-serif;
    background:
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
    border:1px solid rgba(124,58,237,.75);
    background: linear-gradient(180deg, rgba(124,58,237,.35), rgba(59,130,246,.12));
    box-shadow: 0 0 24px rgba(124,58,237,.18);
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
</style>
"""

LOGIN_HTML = r"""
<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
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
      {% if allow_setup %}
        <div class="muted"><a href="/setup">First time setup</a></div>
      {% endif %}
    </div>

    {% if error %}<div class="err">{{error}}</div>{% endif %}
  </div>
</body></html>
"""

SETUP_HTML = r"""
<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
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
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
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
    return render_template_string(LOGIN_HTML, app_title=APP_TITLE, error=None, allow_setup=allow_setup)

@app.post("/login")
def login_post():
    username = _clean_username(request.form.get("username", ""))
    password = (request.form.get("password") or "").strip()
    remember = (request.form.get("remember") or "").strip()

    data = load_users()
    u = (data.get("users") or {}).get(username)
    if not u or not check_password_hash(u.get("password_hash",""), password):
        return render_template_string(LOGIN_HTML, app_title=APP_TITLE, error="Invalid username or password", allow_setup=(not has_any_user()))

    session["user"] = username
    session.permanent = bool(remember)
    # if remember is checked, keep for 30 days
    if remember:
        app.permanent_session_lifetime = timedelta(days=30)

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
    return jsonify({"ok": True, "profile": prof})



# =========================
# UI
# =========================

HTML = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
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
      top: 80px;
      transform: translateX(-50%);
      width: 680px;
      max-width: calc(100vw - 22px);
      height: 560px;
      max-height: calc(100vh - 100px);
      background: rgba(14,22,48,.92);
      border: 1px solid rgba(42,58,106,.9);
      border-radius: 18px;
      padding: 12px;
      box-shadow: 0 0 60px rgba(0,0,0,.45);
      display: flex;
      flex-direction: column;
      resize: both;
      overflow: hidden;
      min-width: 360px;
      min-height: 260px;
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
            <button class="btn" id="openApiKeyHelpBtn" title="How to get and set your OpenAI API key">Get your OpenAI key</button>
      <a class="btn" href="/logout" style="text-decoration:none; display:inline-block;">Logout</a>
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
                <input id="openaiKey" type="password" placeholder="sk-..." />

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

                <div class="actions">
                  <button class="btn" id="cancelSettings">Cancel</button>
                  <button class="btn btnPrimary" id="saveSettings">Save settings</button>
                </div>
                <div class="tiny" id="settingsStatus" style="margin-top:10px;"></div>
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
                <button class="btn btnMini" id="screenGroupBtn">Share screen</button>
                <button class="btn btnPrimary" id="conveneAll">Send to all</button>
              </div>
            </div>

            <textarea class="opText" id="opPrompt" placeholder="Type a group prompt for the entire table. To assemble only, say: All teammates to the round table"></textarea>

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

  <script>
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
    let lastEmailDraftBy = "";

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

    function applyModalPos(){
      const win = $("modalWin");
      if(!win) return;

      const saved = loadModalPos();
      const savedSize = loadModalSize();
      if(savedSize){
        win.style.width = Math.max(360, savedSize.width) + "px";
        win.style.height = Math.max(260, savedSize.height) + "px";
      }
      if(saved){
        win.style.transform = "none";
        win.style.left = saved.left + "px";
        win.style.top = saved.top + "px";
        return;
      }

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
      if($("modalImg")) $("modalImg").style.display = "none";
    }

    function showModal(title, body, imgUrl){
      $("modalTitle").innerText = title;
      $("modalBody").innerText = body || "";
      hideAllModalForms();
      $("modalBody").style.display = "block";

      $("editStatus").innerText = "";
      editingTeammate = "";

      const img = $("modalImg");
      if(imgUrl){
        img.src = imgUrl;
        img.style.display = "block";
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
        offsetX = e.clientX - r.left;
        offsetY = e.clientY - r.top;

        seat.classList.add("dragging");
        seat.setPointerCapture(e.pointerId);
      });

      seat.addEventListener("pointermove", (e) => {
        if(!dragging) return;

        const dx = Math.abs(e.clientX - startX);
        const dy = Math.abs(e.clientY - startY);
        if(dx > 6 || dy > 6) moved = true;

        const wrap = $("tableWrap");
        const wrapRect = wrap.getBoundingClientRect();

        let newLeft = (e.clientX - wrapRect.left) - offsetX;
        let newTop  = (e.clientY - wrapRect.top) - offsetY;

        const pad = 6;
        const maxLeft = wrapRect.width - seat.offsetWidth - pad;
        const maxTop  = wrapRect.height - seat.offsetHeight - pad;

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
        offsetX = e.clientX - r.left;
        offsetY = e.clientY - r.top;

        seat.classList.add("dragging");
        seat.setPointerCapture(e.pointerId);
      });

      seat.addEventListener("pointermove", (e) => {
        if(!dragging) return;
        const dx = e.clientX - startX;
        const dy = e.clientY - startY;
        if(Math.abs(dx) > 3 || Math.abs(dy) > 3) moved = true;

        const wrapRect = wrap.getBoundingClientRect();
        const left = e.clientX - wrapRect.left - offsetX;
        const top = e.clientY - wrapRect.top - offsetY;

        const maxLeft = wrapRect.width - 110;
        const maxTop = wrapRect.height - 110;

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

    function renderThread(msgs){
      const box = $("thread");
      box.innerHTML = "";
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
        content.innerText = m.content;
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
      renderThread(data.thread);
    }

    $("refreshThread").onclick = refreshThread;

    function renderGroupReplies(outputs, drafts){
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
        openBtn.onclick = () => showModal(name, outputs[name]);

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
        body.innerText = outputs[name];

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

    function speechSupported(){
      return !!(window.SpeechRecognition || window.webkitSpeechRecognition);
    }

    function startDictation(targetId, statusId){
      if(!speechSupported()){
        showModal("Mic not supported", "Speech to text is not supported here. Try Chrome on desktop or Android.");
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
      };

      try{
        rec.start();
      }catch(e){
        status.innerText = "Mic: error";
      }
    }

    $("talkGroupBtn").onclick = () => startDictation("opPrompt", "micStatusGroup");
    $("talkDmBtn").onclick = () => startDictation("followMsg", "micStatusDm");

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
    function startAlwaysListening(mode){
      if(!speechSupported()){
        showModal("Mic not supported", "Speech to text is not supported here. Try Chrome on desktop or Android.");
        return;
      }

      alwaysMode = mode || "dm";
      alwaysOn = true;
      updateAlwaysButtons();
      resetAlwaysBuffers();

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

      rec.onerror = () => {
        const s = currentAlwaysStatusEl();
        if(s) s.innerText = "Mic: error";
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
        showModal("Missing prompt", "Type a group prompt in the center card.");
        return;
      }

      const order = activeOrder();
      if(!order.length){
        showModal("No active teammates", "Use Add or dismiss teammates to add seats to the table.");
        return;
      }

      order.forEach(n => setSeatLive(n, "thinking"));
      setOpStatus("Sending to all");

      if(isAssemblyPhrase(prompt)){
        assemblyPulseActive = true;
        updateTablePulseFromStatuses();
      }else{
        assemblyPulseActive = false;
      }

      const res = await fetch("/api/convene", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({prompt, file_ids: groupFileIds})
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
        const lines = data.roll.map(r => `${r.name} | ${r.job_title} | ${r.version}`).join("\n");
        showModal("ROLL CALL (assembly only)", lines);
        return;
      }

      const outputs = data.outputs || {};
      const drafts = data.email_drafts || {};
      lastGroupOutputs = outputs;
      renderGroupReplies(outputs, drafts);

      Object.keys(outputs).forEach(n => setSeatLive(n, "done"));
      order.forEach(n => { if(!(n in outputs)) setSeatLive(n, "waiting"); });

      setOpStatus("Complete");

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
        body: JSON.stringify({name: selectedSeat, message: msg, file_ids: dmFileIds})
      });
      const data = await res.json();

      if(!data.ok){
        setSeatLive(selectedSeat, "waiting");
        setOpStatus("Error");
        showModal("Error", data.error || "Send failed");
        return;
      }

      setSeatLive(selectedSeat, "done");
      setOpStatus("Complete");
      $("followMsg").value = "";
      await refreshThread();

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
    };

    $("clearGroup").onclick = () => {
      lastGroupOutputs = {};
      renderGroupReplies({}, {});
    };

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
        showModal("Draft returned", data.response || "No content");
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

      const installedOrder = (state && state.installed_order) ? state.installed_order : [];
      const active = new Set((state && state.active_order) ? state.active_order : []);
      manageDraftActive = installedOrder.filter(n => active.has(n));

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
      const res = await fetch("/api/framework");
      const data = await res.json();
      if(!data.ok){
        $("frameworkStatus").innerText = data.error || "Load failed";
        return;
      }
      $("frameworkText").value = data.framework || "";
      $("frameworkStatus").innerText = "Ready";
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
      // ensure all other forms are hidden (avoid null errors that can break the Settings button)
      if($("frameworkForm")) $("frameworkForm").style.display = "none";
      if($("modalForm")) $("modalForm").style.display = "none";
      if($("manageForm")) $("manageForm").style.display = "none";
      if($("createForm")) $("createForm").style.display = "none";
      if($("settingsForm")) $("settingsForm").style.display = "block";
      if($("modalBody")) $("modalBody").style.display = "none";
      if($("modalImg")) $("modalImg").style.display = "none";
      loadSettings();
      if(auto){
        // slight UI nudge so first-time users know what to do
        $("modalTitle").innerText = "Settings: connect your key + email";
      }
    }

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


// ===== ONE BLOCK ENTER-TO-SEND + AUTO SEND AFTER VOICE =====

(function(){

  let lastSend = 0;
  function canSend(){
    const now = Date.now();
    if(now - lastSend < 900) return false;
    lastSend = now;
    return true;
  }

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

  function autoSend(mode){
    if(!canSend()) return;

    if(mode === "group"){
      const v = (document.getElementById("opPrompt").value || "").trim();
      if(v) conveneAll();
      return;
    }

    const v2 = (document.getElementById("followMsg").value || "").trim();
    if(v2) sendFollow();
  }

  if(typeof startDictation === "function"){
    const orig = startDictation;

    window.startDictation = function(targetId, statusId){
      const result = orig(targetId, statusId);

      setTimeout(() => {
        if(targetId === "opPrompt") autoSend("group");
        if(targetId === "followMsg") autoSend("dm");
      }, 400);

      return result;
    };
  }

  if(typeof startAlwaysListening === "function"){
    const origAlways = startAlwaysListening;

    window.startAlwaysListening = function(mode){
      const result = origAlways(mode);

      const target = mode === "group"
        ? document.getElementById("opPrompt")
        : document.getElementById("followMsg");

      if(!target) return result;

      let lastVal = target.value;

      const observer = new MutationObserver(() => {
        const current = target.value;

        if(current !== lastVal){
          lastVal = current;

          setTimeout(() => {
            autoSend(mode === "group" ? "group" : "dm");
          }, 600);
        }
      });

      observer.observe(target, { attributes: true, childList: true, subtree: true });

      return result;
    };
  }

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
    now = datetime.datetime.utcnow().isoformat() + "Z"
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
    c["updated_at"] = datetime.datetime.utcnow().isoformat() + "Z"
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
    now = datetime.datetime.utcnow().isoformat() + "Z"
    profile = dict(profile or {})
    profile["updated_at"] = now
    path = OPERATOR_PROFILE_DIR / f"{(username or 'anon')}.json"
    path.write_text(json.dumps(profile, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)
