"""
=============================================================================
TEAM INVITE SYSTEM — Simply Agentic AI
=============================================================================
HOW TO INTEGRATE:

1. Find the line near the top of app.py where you load your JSON data store
   (the function that reads/writes users.json or similar).  Make sure your
   user record already stores a "team_invites" list (added automatically below).

2. Paste the HELPER FUNCTIONS block right after your existing
   _add_team_member / _remove_team_member helpers.

3. Paste the ROUTES block right after your existing /api/team/remove route
   (around line 27741).

4. In your main HTML template, find the Settings panel and add the
   "My Team" tab by inserting the HTML/JS block at the bottom of this file.

5. Add these two env vars (Render → Environment):
      PUBLIC_BASE_URL   = https://your-app.onrender.com   ← already there
      (SMTP_* vars already exist — no new ones needed)

=============================================================================
"""

# =============================================================================
# ── SECTION 1: HELPER FUNCTIONS ──────────────────────────────────────────────
# Paste these right after your existing _remove_team_member() function.
# =============================================================================

INVITE_EXPIRY_HOURS = 48  # magic links expire after this many hours

def _invite_token_key(token: str) -> str:
    return f"invite:{token}"


def _create_team_invite(owner_username: str, invitee_email: str) -> tuple:
    """
    Create a pending invite record and return (token, error).
    Stores invite in the owner's user record under 'pending_invites'.
    """
    users = _load_users()          # your existing loader
    owner = users.get(owner_username)
    if not owner:
        return None, "Owner not found"

    plan        = _get_user_plan(owner_username)
    seat_limit  = _team_seat_limit(plan)
    members     = _get_team_members(owner_username)
    seats_used  = 1 + len(members)
    if seats_used >= seat_limit:
        plan_name = (PLANS.get(plan) or {}).get("name", plan)
        return None, f"You've used all {seat_limit} seat(s) on your {plan_name} plan."

    invitee_email = invitee_email.strip().lower()

    # Check if this email already has a pending invite
    pending = owner.get("pending_invites", [])
    for inv in pending:
        if inv.get("email") == invitee_email and inv.get("status") == "pending":
            # Re-use the existing token so we don't flood the inbox
            return inv["token"], None

    token   = secrets.token_urlsafe(32)
    expires = (datetime.utcnow() + timedelta(hours=INVITE_EXPIRY_HOURS)).isoformat()
    record  = {
        "token":   token,
        "email":   invitee_email,
        "owner":   owner_username,
        "status":  "pending",
        "created": datetime.utcnow().isoformat(),
        "expires": expires,
    }
    pending.append(record)
    owner["pending_invites"] = pending
    _save_users(users)             # your existing saver
    return token, None


def _accept_team_invite(token: str, accepting_username: str) -> tuple:
    """
    Called when an invitee clicks the magic link and is logged in.
    Returns (owner_username, error).
    """
    users = _load_users()
    now   = datetime.utcnow()

    # Scan all users for the invite token
    for uname, udata in users.items():
        for inv in udata.get("pending_invites", []):
            if inv.get("token") == token and inv.get("status") == "pending":
                # Check expiry
                try:
                    expires = datetime.fromisoformat(inv["expires"])
                except Exception:
                    expires = now  # treat malformed as expired

                if now > expires:
                    inv["status"] = "expired"
                    _save_users(users)
                    return None, "This invite link has expired. Ask the account owner to resend."

                # Check seat limit again (someone else may have filled it)
                plan       = _get_user_plan(uname)
                seat_limit = _team_seat_limit(plan)
                members    = _get_team_members(uname)
                if (1 + len(members)) >= seat_limit:
                    inv["status"] = "expired"
                    _save_users(users)
                    return None, "The team is now full. Ask the account owner to upgrade their plan."

                # All good — link the accounts
                ok, err = _add_team_member(uname, accepting_username)
                if not ok:
                    return None, err

                inv["status"]   = "accepted"
                inv["accepted_by"] = accepting_username
                inv["accepted_at"] = now.isoformat()

                # Re-load because _add_team_member may have saved
                users = _load_users()
                udata2 = users.get(uname, {})
                for i2 in udata2.get("pending_invites", []):
                    if i2.get("token") == token:
                        i2["status"]      = "accepted"
                        i2["accepted_by"] = accepting_username
                        i2["accepted_at"] = now.isoformat()
                _save_users(users)
                return uname, None

    return None, "Invite not found or already used."


def _cancel_team_invite(owner_username: str, token: str) -> tuple:
    """Owner cancels a pending invite."""
    users = _load_users()
    owner = users.get(owner_username)
    if not owner:
        return False, "Owner not found"
    pending = owner.get("pending_invites", [])
    for inv in pending:
        if inv.get("token") == token and inv.get("owner") == owner_username:
            inv["status"] = "cancelled"
            _save_users(users)
            return True, None
    return False, "Invite not found."


def _get_pending_invites(owner_username: str) -> list:
    """Return only 'pending' invites for this owner."""
    users   = _load_users()
    owner   = users.get(owner_username, {})
    pending = owner.get("pending_invites", [])
    now     = datetime.utcnow()
    result  = []
    for inv in pending:
        if inv.get("status") != "pending":
            continue
        # Auto-expire stale ones when fetching
        try:
            if now > datetime.fromisoformat(inv["expires"]):
                inv["status"] = "expired"
                continue
        except Exception:
            pass
        result.append({
            "token":   inv["token"],
            "email":   inv["email"],
            "created": inv["created"],
            "expires": inv["expires"],
        })
    # Persist any auto-expiries
    _save_users(users)
    return result


def _send_invite_email(owner_username: str, invitee_email: str, token: str) -> tuple:
    """Send the magic-link invite email. Returns (ok, error)."""
    base = PUBLIC_BASE_URL or "http://localhost:5000"
    link = f"{base}/team/accept?token={token}"

    subject = f"{owner_username} invited you to join their Simply Agentic AI team"
    html_body = f"""
<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:32px 24px;background:#0d0d0d;color:#e5e7eb;border-radius:12px;">
  <h2 style="color:#a78bfa;margin-top:0;">You're invited! 🎉</h2>
  <p><strong>{owner_username}</strong> has invited you to join their team on
     <strong>Simply Agentic AI</strong> — an AI-powered command center for
     sales, outreach, and operations.</p>
  <p style="margin:28px 0;">
    <a href="{link}"
       style="background:#7c3aed;color:#fff;padding:14px 28px;border-radius:8px;
              text-decoration:none;font-weight:600;display:inline-block;">
      Accept Invitation →
    </a>
  </p>
  <p style="font-size:13px;color:#9ca3af;">This link expires in {INVITE_EXPIRY_HOURS} hours.
     If you didn't expect this email you can safely ignore it.</p>
  <hr style="border:none;border-top:1px solid #374151;margin:24px 0;">
  <p style="font-size:12px;color:#6b7280;">
    Or paste this URL into your browser:<br>
    <span style="color:#a78bfa;">{link}</span>
  </p>
</div>
"""
    text_body = (
        f"{owner_username} invited you to Simply Agentic AI.\n\n"
        f"Accept here (expires in {INVITE_EXPIRY_HOURS} hours):\n{link}\n"
    )

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"{SMTP_FROM_NAME} <{SMTP_USER}>" if SMTP_USER else "noreply@simplyagentic.ai"
        msg["To"]      = invitee_email
        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            if SMTP_USER and SMTP_PASS:
                server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(msg["From"], [invitee_email], msg.as_string())
        return True, None
    except Exception as exc:
        return False, str(exc)


# =============================================================================
# ── SECTION 2: ROUTES ────────────────────────────────────────────────────────
# Paste these right after your existing /api/team/remove route (~line 27741).
# =============================================================================

@app.post("/api/team/invite")
def api_team_invite():
    """Owner sends a magic-link invite to an email address."""
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = u.get("username", "")
    if _get_team_owner(uname):
        return jsonify({"ok": False, "error": "Only the account owner can invite team members."}), 403

    payload = request.get_json(silent=True) or {}
    email   = (payload.get("email") or "").strip().lower()
    if not email or "@" not in email:
        return jsonify({"ok": False, "error": "A valid email address is required."}), 400

    token, err = _create_team_invite(uname, email)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    ok, send_err = _send_invite_email(uname, email, token)
    if not ok:
        # Still return the link so the owner can copy-paste manually
        base = PUBLIC_BASE_URL or request.host_url.rstrip("/")
        link = f"{base}/team/accept?token={token}"
        return jsonify({
            "ok":      True,
            "warning": f"Invite created but email failed to send ({send_err}). Share this link manually.",
            "link":    link,
        })

    return jsonify({"ok": True, "message": f"Invite sent to {email}. Link expires in {INVITE_EXPIRY_HOURS} hours."})


@app.get("/api/team/invites")
def api_team_invites():
    """Return pending invites for the current owner."""
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = u.get("username", "")
    if _get_team_owner(uname):
        return jsonify({"ok": False, "error": "Only account owners can view invites."}), 403
    return jsonify({"ok": True, "invites": _get_pending_invites(uname)})


@app.post("/api/team/invite/cancel")
def api_team_invite_cancel():
    """Owner cancels a pending invite by token."""
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    uname = u.get("username", "")
    if _get_team_owner(uname):
        return jsonify({"ok": False, "error": "Only account owners can cancel invites."}), 403
    payload = request.get_json(silent=True) or {}
    token   = (payload.get("token") or "").strip()
    if not token:
        return jsonify({"ok": False, "error": "Token required."}), 400
    ok, err = _cancel_team_invite(uname, token)
    if not ok:
        return jsonify({"ok": False, "error": err}), 400
    return jsonify({"ok": True, "message": "Invite cancelled."})


@app.get("/team/accept")
def team_accept_page():
    """
    Magic-link landing page.
    - If the user is already logged in → accept immediately and redirect to dashboard.
    - If not logged in → show a page that prompts login/register, storing the token in session.
    """
    token = request.args.get("token", "").strip()
    if not token:
        return redirect(url_for("index") + "?msg=invalid_invite")

    u = current_user()
    if u:
        # Already logged in — accept right now
        uname      = u.get("username", "")
        owner, err = _accept_team_invite(token, uname)
        if err:
            return redirect(url_for("index") + f"?msg=invite_error&detail={quote_plus(err)}")
        return redirect(url_for("index") + "?msg=invite_accepted")

    # Not logged in — store token in session and send to login
    session["pending_invite_token"] = token
    return redirect(url_for("index") + "?msg=login_to_accept_invite")


# Hook into your existing login / register success handler:
# After you call session["username"] = ..., add:
#
#   pending = session.pop("pending_invite_token", None)
#   if pending:
#       _accept_team_invite(pending, new_username)
#
# This auto-links the account immediately after the user logs in or registers.


# =============================================================================
# ── SECTION 3: HTML + JS — "My Team" Settings Tab ───────────────────────────
# Find where your Settings modal tabs are defined and add this tab.
# The tab button goes in the tab bar; the panel goes in the tab panels area.
# =============================================================================

MY_TEAM_TAB_HTML = """
<!-- ── Tab button (add to your settings tab bar) ───────────────────────── -->
<button class="settings-tab" data-tab="myteam" onclick="switchSettingsTab('myteam')">
  👥 My Team
</button>

<!-- ── Tab panel ────────────────────────────────────────────────────────── -->
<div id="settings-tab-myteam" class="settings-tab-panel" style="display:none;">
  <h3 style="color:#a78bfa;margin-top:0;">My Team</h3>

  <!-- Seat usage bar -->
  <div id="team-seat-bar" style="margin-bottom:20px;"></div>

  <!-- Invite form (owners only) -->
  <div id="team-invite-section">
    <label style="font-size:14px;color:#9ca3af;display:block;margin-bottom:6px;">
      Invite by email
    </label>
    <div style="display:flex;gap:8px;">
      <input id="team-invite-email" type="email" placeholder="colleague@example.com"
             style="flex:1;padding:10px 14px;background:#1a1a2e;border:1px solid #374151;
                    border-radius:8px;color:#e5e7eb;font-size:14px;">
      <button onclick="teamSendInvite()"
              style="padding:10px 20px;background:#7c3aed;color:#fff;border:none;
                     border-radius:8px;font-weight:600;cursor:pointer;">
        Send Invite
      </button>
    </div>
    <div id="team-invite-msg" style="margin-top:8px;font-size:13px;min-height:18px;"></div>
  </div>

  <!-- Current members -->
  <div style="margin-top:24px;">
    <h4 style="color:#e5e7eb;margin:0 0 12px;">Team Members</h4>
    <div id="team-members-list">
      <span style="color:#6b7280;font-size:13px;">Loading…</span>
    </div>
  </div>

  <!-- Pending invites -->
  <div id="team-pending-section" style="margin-top:24px;display:none;">
    <h4 style="color:#e5e7eb;margin:0 0 12px;">Pending Invites</h4>
    <div id="team-pending-list"></div>
  </div>
</div>
"""

MY_TEAM_JS = """
<script>
// ── Team Management ───────────────────────────────────────────────────────
async function loadTeamPanel() {
  try {
    const r  = await fetch('/api/team');
    const d  = await r.json();
    if (!d.ok) return;

    // Seat bar
    const pct  = Math.round((d.seats_used / d.seats_limit) * 100);
    const col   = pct >= 100 ? '#ef4444' : pct >= 80 ? '#f59e0b' : '#10b981';
    document.getElementById('team-seat-bar').innerHTML = `
      <div style="display:flex;justify-content:space-between;margin-bottom:6px;">
        <span style="font-size:13px;color:#9ca3af;">${d.plan_name} — ${d.seats_used} / ${d.seats_limit} seat(s) used</span>
        <span style="font-size:13px;color:${col};">${d.seats_left} left</span>
      </div>
      <div style="height:6px;background:#1f2937;border-radius:4px;overflow:hidden;">
        <div style="width:${pct}%;height:100%;background:${col};border-radius:4px;transition:width .4s;"></div>
      </div>`;

    // Members list
    const memberEl = document.getElementById('team-members-list');
    if (!d.members || d.members.length === 0) {
      memberEl.innerHTML = '<span style="color:#6b7280;font-size:13px;">No team members yet — send an invite below.</span>';
    } else {
      memberEl.innerHTML = d.members.map(m => `
        <div style="display:flex;align-items:center;justify-content:space-between;
                    padding:10px 14px;background:#1a1a2e;border-radius:8px;margin-bottom:8px;">
          <div>
            <span style="color:#e5e7eb;font-weight:500;">👤 ${m}</span>
            <span style="color:#6b7280;font-size:12px;margin-left:8px;">Team Member</span>
          </div>
          ${d.is_owner ? `<button onclick="teamRemoveMember('${m}')"
            style="padding:5px 12px;background:#7f1d1d;color:#fca5a5;border:1px solid #991b1b;
                   border-radius:6px;font-size:12px;cursor:pointer;">Remove</button>` : ''}
        </div>`).join('');
    }

    // Hide invite form for non-owners
    if (!d.is_owner) {
      document.getElementById('team-invite-section').style.display = 'none';
    }

    // Pending invites (owners only)
    if (d.is_owner) {
      const pr = await fetch('/api/team/invites');
      const pd = await pr.json();
      if (pd.ok && pd.invites && pd.invites.length > 0) {
        const sec = document.getElementById('team-pending-section');
        sec.style.display = 'block';
        document.getElementById('team-pending-list').innerHTML = pd.invites.map(inv => `
          <div style="display:flex;align-items:center;justify-content:space-between;
                      padding:10px 14px;background:#111827;border:1px solid #374151;
                      border-radius:8px;margin-bottom:8px;">
            <div>
              <span style="color:#d1d5db;font-size:13px;">✉️ ${inv.email}</span>
              <span style="color:#6b7280;font-size:11px;margin-left:8px;">
                Expires ${new Date(inv.expires + 'Z').toLocaleDateString()}
              </span>
            </div>
            <button onclick="teamCancelInvite('${inv.token}', this)"
              style="padding:4px 10px;background:#1f2937;color:#9ca3af;border:1px solid #374151;
                     border-radius:6px;font-size:12px;cursor:pointer;">Cancel</button>
          </div>`).join('');
      }
    }
  } catch(e) { console.error('loadTeamPanel', e); }
}

async function teamSendInvite() {
  const email = document.getElementById('team-invite-email').value.trim();
  const msg   = document.getElementById('team-invite-msg');
  if (!email) { msg.innerHTML = '<span style="color:#f87171;">Please enter an email address.</span>'; return; }
  msg.innerHTML = '<span style="color:#9ca3af;">Sending…</span>';
  try {
    const r = await fetch('/api/team/invite', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({email})
    });
    const d = await r.json();
    if (d.ok) {
      msg.innerHTML = `<span style="color:#34d399;">✓ ${d.message || 'Invite sent!'}</span>`;
      if (d.link) {
        msg.innerHTML += `<br><span style="color:#9ca3af;font-size:12px;">Manual link: <a href="${d.link}" style="color:#a78bfa;">${d.link}</a></span>`;
      }
      document.getElementById('team-invite-email').value = '';
      setTimeout(loadTeamPanel, 800);
    } else {
      msg.innerHTML = `<span style="color:#f87171;">✗ ${d.error}</span>`;
    }
  } catch(e) {
    msg.innerHTML = `<span style="color:#f87171;">Request failed. Check your connection.</span>`;
  }
}

async function teamRemoveMember(username) {
  if (!confirm(`Remove ${username} from your team?`)) return;
  const r = await fetch('/api/team/remove', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({username})
  });
  const d = await r.json();
  if (d.ok) loadTeamPanel();
  else alert(d.error);
}

async function teamCancelInvite(token, btn) {
  btn.textContent = '…';
  const r = await fetch('/api/team/invite/cancel', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({token})
  });
  const d = await r.json();
  if (d.ok) loadTeamPanel();
  else alert(d.error);
}

// Auto-load when the My Team tab is clicked
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-tab="myteam"]').forEach(btn => {
    btn.addEventListener('click', loadTeamPanel);
  });

  // Show a banner if the URL has ?msg=invite_accepted or similar
  const params = new URLSearchParams(window.location.search);
  const msg    = params.get('msg');
  if (msg === 'invite_accepted') {
    showToast('✅ You joined the team!', 'success');
  } else if (msg === 'login_to_accept_invite') {
    showToast('👥 Log in or register to accept your team invite.', 'info');
  } else if (msg === 'invite_error') {
    const detail = params.get('detail') || 'Unknown error';
    showToast('❌ Invite error: ' + detail, 'error');
  }
});
</script>
"""

# =============================================================================
# ── SECTION 4: LOGIN/REGISTER HOOK ───────────────────────────────────────────
# In your existing login and register success handlers, add the snippet below
# RIGHT AFTER you set session["username"] = username.
# =============================================================================

LOGIN_HOOK_SNIPPET = """
# ── Add this block after every successful login / register ──────────────────
pending_invite = session.pop("pending_invite_token", None)
if pending_invite:
    owner, inv_err = _accept_team_invite(pending_invite, username)
    if inv_err:
        # Non-fatal — user is still logged in, just show a message
        session["invite_error"] = inv_err
    else:
        session["invite_accepted"] = True
# ───────────────────────────────────────────────────────────────────────────
"""

if __name__ == "__main__":
    print("This is a patch file — integrate it into app.py following the comments above.")
    print()
    print("Sections:")
    print("  1. Helper functions  — paste after _remove_team_member()")
    print("  2. Routes            — paste after /api/team/remove route")
    print("  3. HTML + JS         — paste into your Settings modal")
    print("  4. Login hook        — paste after session['username'] = ... in login/register")
