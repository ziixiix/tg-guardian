"""
TG Guardian MTProto Monitor v0.5.27
Author: TG https://t.me/ziixiix
- Logs in as the user's own Telegram account(s) (Telethon / MTProto).
- MULTI-ACCOUNT: one process watches several Telegram accounts
  that all belong to the same owner. Each account has its own
  TelegramClient, its own session file (tg_guardian_<phone>.session;
  the original account keeps the legacy tg_guardian.session), its own
  baseline/pending state (devices.json keyed by phone), and its own
  per-account settings read from the Worker. All accounts share one
  API_ID / API_HASH (those identify the app, not the account).
- New accounts are added from the bot, no server change needed:
    /add_account <手机号> [名字] -> pick 短信登录 (login code) or 扫码登录 (QR)
    /code <验证码>               -> SMS login: the monitor finishes the login
    /2fa <二级密码>             -> only if the account has 2FA
  QR login needs two devices (one shows the QR, one scans); each QR is
  valid 30 s and auto-refreshes (max 10 refreshes).
  The monitor polls the Worker's /pending once every 2 minutes and gets ALL
  accounts' data (decisions, onboard requests, settings) in that one
  call, so 5 accounts still cost ~720 requests/day. The code / 2FA
  password arrive via /pending and are consumed on read by the Worker;
  the monitor keeps them in memory only, never logs them, and uses
  each exactly once.
- Polls each account's authorized sessions every 5 min.
- New device flow: report the new session to the Worker (/sync),
  the Worker alerts the owner with ✅ 是我本人 / ⛔ 踢掉 buttons.
  The monitor polls the Worker's /pending decisions every 120 s:
    - owner taps 是我本人 -> session is added to the trusted baseline
    - owner taps 踢掉      -> session is revoked immediately
    - no reply in 10 min  -> session is revoked automatically
  The monitor's own session is in the trusted baseline and is never revoked.
- Also listens for Telegram's own 777000 login-code messages in
  real time. A half-finished login (correct code, wrong 2FA password)
  never becomes an authorized session, so session polling cannot see it —
  but the code message arrives the moment the code is requested, so the
  monitor alerts immediately. The alert and the logs NEVER include the
  code digits themselves.
- Code alerts go through the Worker (/code-alert) with three buttons:
  ✅ 同意 / 🧊 拒绝·冻结验证码 / 🔒 拒绝·冻结二级密码.
  deny_code runs only the wrong-code freeze; deny_2fa runs only the
  Flood (2FA) protection; a legacy "deny" still runs both. No reply
  in 5 min auto-runs the Flood protection only. The /code-freeze
  report carries a mode field ("code" / "2fa" / "both") so the Worker
  can display which protection ran.
- Flood protection tries a no-code path first, using the monitor's own
  already-authorized session (no tdata needed, no fresh code requested):
  it calls account.GetPassword + auth.CheckPassword with a deliberately
  wrong 2FA password 5 times. If the no-code path does not return an
  explicit flood, the monitor falls back to the login-flow path (fresh
  code entered correctly, then wrong 2FA 5 times). The result alert
  says which path ran. Never upload a tdata bundle anywhere: it is a
  live login key, and the monitor already holds its own authorized
  session that can do everything an authorized session can do.
- Code freeze: a separate throwaway client requests ONE code and enters
  a deliberately wrong code 5 times against it, aiming to trigger
  Telegram's wrong-code limit (recovery time is recorded as an estimate).
  The freeze never touches the monitor's own session, and the throwaway
  session file is deleted after. While a freeze runs, code alerts are
  suppressed for 15 min because the freeze itself generates a code message.
- Auto times are read from the Worker's /pending response on every poll
  (auto_code_after / auto_revoke_after in seconds, alerts_enabled;
  settings live in Worker KV, changed with /set_guard and /set_revoke;
  env vars remain the fallback defaults).
- Hourly heartbeat: once an hour the monitor uploads a heartbeat and the
  current device snapshot to the Worker (/heartbeat), so /status shows
  the monitor is alive and /devices shows the snapshot. 2 KV writes per
  hour = 48/day, far under the free 1,000/day limit.
- KV writes happen only on new-device events (via the Worker), never on
  every poll, so the Cloudflare free KV write limit is not a problem.

Env vars (set in your server environment / Variables, never commit them):
  API_ID, API_HASH, BOT_TOKEN, OWNER_ID
  PHONE            main account's phone; also the seed account
  SESSION_STRING   optional, Telethon StringSession (avoids interactive login)
  CHECK_INTERVAL   seconds between session checks, default 300
  POLL_INTERVAL    seconds between decision polls, default 120
  AUTO_REVOKE_AFTER seconds of silence before auto-revoke, default 600
  AUTO_CODE_AFTER  seconds of silence before auto code protection, default 300
  STATE_FILE       snapshot file, default devices.json
"""
import asyncio
import hashlib
import io
import json
import logging
import os
import re
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone

import segno
from telethon import TelegramClient, events
from telethon import password as pwd_mod
from telethon.errors import (
    AuthKeyDuplicatedError,
    AuthTokenExpiredError,
    FloodWaitError,
    PasswordHashInvalidError,
    PhoneCodeExpiredError,
    PhoneCodeInvalidError,
    PhoneNumberFloodError,
    PhonePasswordFloodError,
    SessionPasswordNeededError,
)
from telethon.sessions import StringSession
from telethon.tl.functions.account import (
    GetAuthorizationsRequest,
    GetPasswordRequest,
    ResetAuthorizationRequest,
)
from telethon.tl.functions.auth import CheckPasswordRequest

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("tg-guardian-mtproto")

VERSION = "v0.5.27"

def norm_phone(p) -> str:
    """Digits-only phone. The Worker normalizes phones to digits-only,
    but the PHONE env var may carry a "+" — keys must match everywhere
    (ACCOUNTS, state file, Worker payloads) or one account looks like two."""
    return re.sub(r"\D", "", str(p or ""))


def display_phone(p) -> str:
    """Display only: every number the owner sees carries "+"."""
    d = norm_phone(p)
    return "+" + d if d else str(p or "")


API_ID = os.environ.get("API_ID", "").strip()
API_HASH = os.environ.get("API_HASH", "").strip()
BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
OWNER_ID = os.environ.get("OWNER_ID", "").strip()
PHONE = norm_phone(os.environ.get("PHONE", ""))
SESSION_STRING = os.environ.get("SESSION_STRING", "").strip()

def account_session(phone: str, session_name: str, kv_string: str = ""):
    """Return the session to log in with, in priority order: the
    StringSession stored in the Worker KV (written by the running monitor
    on every heartbeat, so a stateless container restart keeps its
    sessions), then SESSION_STRING_<phone> from the environment (seed /
    migration), else the file session name. The main account's env seed
    is the plain SESSION_STRING var (handled in main())."""
    if kv_string:
        return StringSession(kv_string)
    ss = os.environ.get(f"SESSION_STRING_{phone}", "").strip()
    if ss:
        return StringSession(ss)
    return session_name
CHECK_INTERVAL = int(os.environ.get("CHECK_INTERVAL", "300") or 300)
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "120") or 120)
# Watchdog (v0.5.20): if an account has no successful cycle for this long,
# exit so the hosting platform restarts the container with fresh clients.
DISCONNECT_EXIT_AFTER = int(os.environ.get("DISCONNECT_EXIT_AFTER", "1800") or 1800)
FAST_CHECK_INTERVAL = 3    # seconds between session checks while a code was just requested
FAST_CHECK_WINDOW = 300    # seconds of fast checking after a code alert
AUTO_REVOKE_AFTER = int(os.environ.get("AUTO_REVOKE_AFTER", "600") or 600)
AUTO_CODE_AFTER = int(os.environ.get("AUTO_CODE_AFTER", "300") or 300)
HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "3600") or 3600)
STATE_FILE = os.environ.get("STATE_FILE", "devices.json")
WORKER_URL = os.environ.get("WORKER_URL", "https://your-worker.your-subdomain.workers.dev").rstrip("/")  # 部署时改成你自己的 Worker 地址（或用环境变量 WORKER_URL 覆盖）
# Cloudflare's edge blocks Python's default "Python-urllib/..." User-Agent
# on workers.dev (HTTP 403) — that broke /pending and /sync. A plain
# custom User-Agent passes (verified: Mozilla UA -> 200, Python UA -> 403).
WORKER_HEADERS = {"User-Agent": "TG-Guardian-Monitor/0.5.8"}

WRONG_CODE = "00000"  # deliberately wrong code, only used to burn login attempts
FREEZE_MAX_ATTEMPTS = 5
FREEZE_SUPPRESS_SECONDS = 900  # 15 min

# 2FA protection (v0.4.6): a throwaway client requests ONE fresh code, the
# monitor captures that code from its own 777000 message (in memory only,
# never logged, never sent to the Worker or the bot), enters it correctly
# to reach the 2FA step, then enters a deliberately wrong 2FA password 5
# times. WRONG_2FA_PASSWORD must never be the user's real 2FA password.
WRONG_2FA_PASSWORD = "tg-guardian-wrong-2fa-00000"
TWOFA_MAX_ATTEMPTS = 5
TWOFA_CODE_WAIT_SECONDS = 90

_CODE_RE = re.compile(r"\d{5,6}")


def _looks_like_login_code(text: str) -> bool:
    """True if a 777000 message is a login-code delivery. The code digits
    are never logged or forwarded anywhere. The handler is already
    restricted to sender 777000 (Telegram's own login-code account), so a
    5-6 digit code is enough — requiring a Chinese/English keyword used
    to silently reject code messages in other languages (v0.5.4)."""
    if not text:
        return False
    return bool(_CODE_RE.search(text))


class Acct:
    """Per-account runtime state. One instance per monitored Telegram
    account; the main (seed) account keeps the legacy session file."""

    def __init__(self, phone: str, name: str = ""):
        self.phone = phone
        self.name = name or ""
        self.client = None  # TelegramClient once connected
        self.authorized = False
        self.session_name = "tg_guardian" if phone == PHONE else f"tg_guardian_{phone}"
        # Message ids of 777000 code messages already alerted on (dedupe).
        self.seen_code_messages = set()
        # Code alerts are ignored until this epoch time — set while a
        # freeze runs, because the freeze itself requests codes.
        self.suppress_until = 0.0
        # Code events already frozen in this process lifetime (in-memory
        # backstop: even if the state file is lost, a deny is never
        # frozen twice per run).
        self.freeze_done = set()
        # 2FA-protection code capture (in memory only, never logged).
        self.capture_active = False
        self.captured_code = None
        # Onboarding: phone_code_hash of the code the monitor requested
        # for /add_account, and the client being authorized.
        self.onboard_code_hash = None
        self.onboard_client = None
        # QR onboarding (v0.5.25): the background QR-login task, the
        # 2FA password handed over by process_onboard (memory only),
        # and which onboard record (created_at) the task was started
        # for, so a finished task is not restarted for the same record.
        self.qr_task = None
        self.qr_password = None
        self.qr_task_record = None
        self.qr_stopped_record = None  # record key a stop order killed (v0.5.27); never restarted
        self.last_check = 0.0
        self.last_heartbeat = 0.0
        self.last_ok = time.time()  # last successful cycle (disconnect watchdog)
        # Sustained Flood protection: the one-shot timer record from
        # GET /pending, and whether it already fired this round.
        self.sustain = None
        self.sustain_fired = False
        # The trigger_at last seen: a changed value means the Worker
        # rescheduled the timer (loop / count mode), so it may fire
        # again for the new round.
        self.sustain_trigger_at = None
        # Pause (v0.5.24): whether protection was paused on the last
        # poll, so a timed pause expiring can be announced once.
        self.was_paused = False

    @property
    def label(self) -> str:
        tail = self.phone[-4:] if self.phone else "????"
        return f"{self.name}（尾号 {tail}）" if self.name else f"尾号 {tail}"


ACCOUNTS: dict = {}  # phone -> Acct


def send_bot_alert(text: str, acct: Acct = None) -> None:
    """Send a message via the TG Guardian Bot (Bot API, no MTProto needed).
    With several accounts the alert names the account it belongs to."""
    if not BOT_TOKEN or not OWNER_ID:
        log.warning("BOT_TOKEN / OWNER_ID missing, alert not sent: %s", text[:120])
        return
    if acct is not None and len(ACCOUNTS) > 1:
        text = text.replace("TG Guardian", f"TG Guardian【{acct.label}】", 1)
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = json.dumps({"chat_id": OWNER_ID, "text": text}).encode()
    req = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            log.info("Bot alert sent, HTTP %s", resp.status)
    except Exception as exc:  # noqa: BLE001 - alerting must never kill the monitor
        log.warning("Failed to send bot alert: %s", exc)


def send_qr_photo(png: bytes, caption: str, phone: str) -> bool:
    """Send a QR-login photo to the owner via the Bot API (multipart
    sendPhoto), with a 停止扫码登录 button under it. The QR token is
    inside the image only; it is never logged."""
    if not BOT_TOKEN or not OWNER_ID:
        log.warning("BOT_TOKEN / OWNER_ID missing, QR photo not sent.")
        return False
    boundary = "----tgguardian" + hashlib.sha256(os.urandom(16)).hexdigest()[:24]
    keyboard = {"inline_keyboard": [[
        {"text": "🛑 停止扫码登录", "callback_data": f"onboard:qr_stop:{phone}"},
    ]]}
    parts = []

    def field(name: str, value: str) -> None:
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode()
        )

    field("chat_id", OWNER_ID)
    field("caption", caption)
    field("reply_markup", json.dumps(keyboard))
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="photo"; '
        f'filename="qr.png"\r\nContent-Type: image/png\r\n\r\n'.encode()
    )
    parts.append(png)
    parts.append(f"\r\n--{boundary}--\r\n".encode())
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{BOT_TOKEN}/sendPhoto",
        data=b"".join(parts),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            log.info("QR photo sent, HTTP %s", resp.status)
            return resp.status == 200
    except Exception as exc:  # noqa: BLE001 - a failed photo must not kill the QR task
        log.warning("Failed to send QR photo: %s", exc)
        return False


def post_worker(path: str, payload: dict):
    """POST a JSON body to the Worker. Returns the parsed JSON dict, or None."""
    if not BOT_TOKEN:
        return None
    body = dict(payload)
    body["token"] = BOT_TOKEN
    req = urllib.request.Request(
        f"{WORKER_URL}{path}",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", **WORKER_HEADERS},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read() or b"{}")
    except Exception as exc:  # noqa: BLE001
        log.warning("Worker %s failed: %s", path, exc)
        return None


def fetch_pending() -> dict:
    """Poll the Worker once per cycle for ALL accounts: owner decisions,
    onboard requests, per-account settings, removed accounts."""
    if not BOT_TOKEN:
        return {}
    url = f"{WORKER_URL}/pending?token={BOT_TOKEN}"
    req = urllib.request.Request(url, headers=WORKER_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read() or b"{}")
            return data if data.get("ok") else {}
    except Exception as exc:  # noqa: BLE001
        log.warning("Worker /pending fetch failed: %s", exc)
        return {}


def per_account(data: dict, phone: str) -> dict:
    """Per-account slice of a /pending response, with a legacy fallback
    for an older Worker that returns top-level pending/code_events/
    settings for the single account."""
    per = data.get("per_account") or {}
    if isinstance(per, dict) and phone in per:
        return per[phone]
    return {
        "pending": data.get("pending", []),
        "code_events": data.get("code_events", []),
        "settings": data.get("settings", {}),
    }


def register_account(phone: str, name: str = "") -> bool:
    """Tell the Worker this phone is a monitored account (also migrates
    the original single account's legacy KV keys on first use)."""
    data = post_worker("/register-account", {"phone": phone, "name": name})
    ok = bool(data and data.get("ok"))
    log.info("Worker /register-account %s: %s", phone, "ok" if ok else data)
    return ok


def report_onboard(phone: str, state: str, detail: str = "") -> None:
    """Report add-account progress; the Worker messages the owner."""
    post_worker("/onboard-status", {"phone": phone, "state": state, "detail": detail})

def report_code_alert(acct: Acct, event_id: int) -> bool:
    """Report a login-code request to the Worker; the Worker sends the owner
    an alert with ✅ 同意 / 🧊 拒绝·冻结验证码 / 🔒 拒绝·冻结二级密码
    buttons. Returns True if accepted."""
    data = post_worker("/code-alert", {
        "account": acct.phone,
        "event_id": str(event_id),
        "detected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })
    ok = bool(data and data.get("ok"))
    log.info("Worker /code-alert %s for %s: %s", "accepted" if ok else "failed", acct.phone, data)
    return ok


# Fast session check after a login-code request (v0.5.10): a code alert
# means a new session may appear within minutes, so check every 3 s for
# 5 min instead of waiting for the next 5-min cycle, then revert.
FAST_CHECK_UNTIL = 0.0


def fast_check_active() -> bool:
    return time.time() < FAST_CHECK_UNTIL


def alert_code_request(acct: Acct, event_id: int) -> None:
    """Shared alert path for a detected login-code request (used by the
    real-time handler and by the poll_777000 backup): Worker button alert
    first, plain direct alert as fallback."""
    global FAST_CHECK_UNTIL
    # A code was just requested: a new session may appear within minutes.
    FAST_CHECK_UNTIL = time.time() + FAST_CHECK_WINDOW
    log.warning("Login code requested for %s (code not logged). Alerting owner.", acct.phone)
    log.info("Fast session check for the next %d s (code requested).", FAST_CHECK_WINDOW)
    if report_code_alert(acct, event_id):
        return  # Worker sent the button alert; nothing more to do here
    send_bot_alert(
        "⚠️ TG Guardian：有人正在请求登录验证码！\n\n"
        "不是你本人就不要把验证码告诉任何人，也不要输入它。",
        acct,
    )


WAKEUP = asyncio.Event()
WAKEUP_MARKER = "⚡ TG Guardian：正在唤醒监控端"
# Direct decisions (v0.5.9): the Worker may carry the owner's decision in
# the wake-up message itself — second line "kind:phone:id:ts" — so the
# monitor acts in seconds instead of waiting up to ~120 s for the KV write
# to propagate to the /pending read. The handler only enqueues; the main
# loop executes, so a direct decision can never race the poll path.
# The KV record is still the source of truth and the /pending poll is the
# backstop; the shared apply_* helpers dedupe, so a decision is never
# executed twice.
DIRECT_QUEUE: list = []
# Serializes process_onboard (v0.5.26): the main loop runs it every
# poll, and the wake-up handler also runs it immediately on fresh
# data, so a tapped stop/cancel halts the QR task within seconds
# even while the main loop is mid-cycle.
_ONBOARD_LOCK = asyncio.Lock()
# Onboard orders (v0.5.27) ride the same wake-up: "onboard_qr"
# starts the QR task, "onboard_qr_stop" cancels it - no /pending wait.
DIRECT_KINDS = {
    "allow": "device",
    "revoke": "device",
    "code_allow": "code",
    "code_deny_code": "code",
    "code_deny_2fa": "code",
    "code_deny": "code",
    "onboard_qr": "onboard",
    "onboard_qr_stop": "onboard",
}
DIRECT_MAX_AGE = 120  # seconds: ignore a directive older than this (stale delivery)


def parse_directive(text: str):
    """Parse a wake-up message carrying a decision: the second line is
    "kind:phone:id:ts". Returns (kind, phone, id) or None when the message
    carries no (valid, fresh) directive — the plain wake-up then just
    triggers the normal /pending poll."""
    lines = (text or "").split("\n")
    if len(lines) < 2:
        return None
    parts = lines[1].strip().split(":")
    if len(parts) != 4:
        return None
    kind, phone, ident, ts = parts
    if kind not in DIRECT_KINDS or not phone.isdigit() or not ident:
        return None
    try:
        age = time.time() - int(ts)
    except ValueError:
        return None
    if age < 0 or age > DIRECT_MAX_AGE:
        return None
    return (kind, phone, ident)


async def execute_directive(kind: str, phone: str, ident: str, data: dict | None = None) -> bool:
    """Run one decision straight from the wake-up message, without
    waiting for it to show up in /pending. The KV record is still the
    source of truth: when the same decision arrives via /pending later,
    the shared apply_* helpers find the item already handled and do
    nothing. Returns True if the directive was applied (or was already
    applied); False leaves it to the /pending poll."""
    if kind == "onboard_qr":
        # QR start order carried by the wake-up (v0.5.27): start the
        # QR task now instead of waiting for the KV write to reach
        # /pending. ident is the record's created_at digits - the
        # same key _ensure_qr_task derives from the /pending item -
        # so the poll path will not start it twice.
        acct = ACCOUNTS.get(phone)
        if acct is None:
            acct = Acct(phone, "")
            ACCOUNTS[phone] = acct
        _ensure_qr_task(acct, {"created_at": ident})
        log.info("[%s] QR onboarding started from the wake-up message.", phone)
        return True
    if kind == "onboard_qr_stop":
        # Stop order (v0.5.27): cancel the QR task at once and mark
        # its record stopped, so a stale /pending read that still
        # shows the record cannot restart it.
        acct = ACCOUNTS.get(phone)
        if acct is not None:
            if acct.qr_task_record:
                acct.qr_stopped_record = acct.qr_task_record
            task = getattr(acct, "qr_task", None)
            if task is not None and not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                log.info("[%s] QR onboarding stopped from the wake-up message.", phone)
        return True
    acct = ACCOUNTS.get(phone)
    if acct is None or not acct.authorized or acct.client is None:
        log.warning("[%s] Direct %s %s: account not ready, leaving it to the /pending poll.", phone, kind, ident)
        return False
    try:
        if kind in ("allow", "revoke"):
            done = await apply_device_decision(acct, ident, kind)
        elif kind == "code_allow":
            done = mark_code_allowed(acct, ident)
        else:
            # Code protections only run for an event the Worker still
            # lists for this account; a tap on an expired alert is
            # ignored here (the Worker already told the owner).
            per = per_account(data or {}, phone)
            known_ids = {str(ev.get("id", "")) for ev in per.get("code_events", [])}
            if data and ident not in known_ids and ident not in acct.freeze_done:
                log.warning("[%s] Direct %s %s: unknown code event, skipping.", phone, kind, ident)
                return True
            mode = {"code_deny_code": "code", "code_deny_2fa": "2fa", "code_deny": "both"}[kind]
            done = await apply_code_decision(acct, ident, mode)
    except Exception as exc:  # noqa: BLE001 - a failed direct run must not kill the loop; the poll retries it
        log.warning("[%s] Direct %s %s failed, leaving it to the /pending poll: %s", phone, kind, ident, exc)
        return False
    if done:
        log.info("[%s] Direct %s %s applied from the wake-up message.", phone, kind, ident)
    else:
        log.info("[%s] Direct %s %s already handled, nothing to do.", phone, kind, ident)
    return True


# An ended session is dropped from the baseline only after it is missing
# from this many consecutive checks: a single missing cycle could be a
# transient list glitch, and dropping it at once would make it look like
# a brand-new device (and alert) if it came back. Two in a row is a real
# end. Without this, an ended session was logged "ended/removed" on
# every cycle forever, because it was never removed from `known`.
GONE_GRACE_CYCLES = 2
_GONE_COUNT: dict[str, dict[str, int]] = {}


def fetch_bot_id() -> int | None:
    """One-off Bot API getMe call so the monitor knows which Telegram
    user id is our own bot (only its messages may wake the poll loop)."""
    if not BOT_TOKEN:
        return None
    try:
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{BOT_TOKEN}/getMe",
            headers=WORKER_HEADERS,
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read() or b"{}")
        result = data.get("result") or {}
        bot_id = result.get("id")
        return int(bot_id) if bot_id else None
    except Exception as exc:  # noqa: BLE001 - wake-up is best-effort
        log.warning("Bot getMe failed, wake-up disabled: %s", exc)
        return None


def make_wakeup_handler(bot_id: int):
    """Watch for the Worker's wake-up message: after the owner taps a
    decision button, the Worker sends the owner a short message from the
    bot; this handler fires immediately and ends the poll sleep early,
    so the decision is processed within seconds instead of at the next
    120 s poll. Only messages FROM the bot with the marker count — the
    bot's other messages (alerts, results) never wake the loop. Since
    v0.5.9 the wake-up may also carry the decision itself (second line
    "kind:phone:id:ts"); the handler only enqueues it — the main loop
    executes it, so it can never race the poll path. Since v0.5.26 the
    handler also schedules an immediate onboard check (process_onboard
    on fresh data, serialized by _ONBOARD_LOCK) so a tapped stop/cancel
    halts the QR task within seconds.
    """
    async def on_wakeup(event) -> None:
        text = event.raw_text or ""
        if event.sender_id == bot_id and text.startswith(WAKEUP_MARKER):
            directive = parse_directive(text)
            if directive is not None:
                DIRECT_QUEUE.append(directive)
                log.info("Wake-up with direct decision received: %s %s %s.", *directive)
            WAKEUP.set()
            asyncio.create_task(_run_onboard_check())
            log.info("Wake-up received, polling /pending now.")
    return on_wakeup


def make_code_handler(acct: Acct):
    """Real-time handler for Telegram's own login-code messages (777000),
    bound to one account's client.

    Fires the moment a code is requested, long before a session exists —
    this is what catches half-finished logins (correct code, wrong 2FA
    password) that session polling can never see.
    """

    async def on_code_message(event) -> None:
        try:
            text = (event.raw_text or "") if hasattr(event, "raw_text") else ""
            # Capture for the 2FA protection FIRST, before the suppress check:
            # the protection's own fresh code arrives as a 777000 message while
            # alerts are suppressed. The digits live in memory only, are never
            # logged, and are cleared after one use.
            if acct.capture_active and _looks_like_login_code(text):
                m = _CODE_RE.search(text)
                if m:
                    acct.captured_code = m.group(0)
                # Mark it seen: the backup poll must never re-alert on a
                # code the monitor requested itself (2FA flow / flood probe).
                msg_id = getattr(event, "id", None)
                if msg_id is not None:
                    acct.seen_code_messages.add(msg_id)
                return
            if time.time() < acct.suppress_until:
                return  # code messages generated by our own freeze, ignore them
            msg_id = getattr(event, "id", None)
            if msg_id is not None:
                if msg_id in acct.seen_code_messages:
                    return
                acct.seen_code_messages.add(msg_id)
                if len(acct.seen_code_messages) > 50:
                    acct.seen_code_messages.clear()
            if not _looks_like_login_code(text):
                # A 777000 message with no code digits: log only its id,
                # never its text, so a missed code leaves a trace.
                log.info("[%s] 777000 message without a code (id=%s), ignored.", acct.phone, msg_id)
                return
            alert_code_request(acct, msg_id if msg_id is not None else int(time.time()))
        except Exception as exc:  # noqa: BLE001 - handler must never kill the monitor
            log.warning("Code-message handler failed for %s: %s", acct.phone, exc)

    return on_code_message


def describe(auth) -> str:
    parts = [
        f"hash={auth.hash}",
        f"device={auth.device_model or '?'}",
        f"platform={auth.platform or '?'}",
        f"system={auth.system_version or '?'}",
        f"app={auth.app_name or '?'} {auth.app_version or ''}".strip(),
        f"ip={auth.ip or '?'}",
        f"country={auth.country or '?'}",
        f"region={auth.region or '?'}",
        f"current={auth.current}",
        f"created={auth.date_created}",
        f"active={auth.date_active}",
    ]
    return " | ".join(parts)


def tidy_session(info: dict) -> str:
    """One session in the same tidy form as the Worker's new-device
    alert: device · app / place / IP / 创建 MM-DD HH:MM (SGT). Falls
    back to the stored raw desc for pending items created by an older
    version that did not store the structured fields."""
    if not info.get("device") and not info.get("app") and not info.get("country"):
        return info.get("desc") or "?"
    device = info.get("device") or "?"
    app = info.get("app") or "?"
    place = " ".join(x for x in (info.get("country"), info.get("region")) if x and x != "?")
    lines = [f"{device} · {app}"]
    if place:
        lines.append(place)
    ip = info.get("ip")
    if ip and ip != "?":
        lines.append(f"IP {ip}")
    created = _sgt_short(info.get("created") or "")
    if created:
        lines.append(f"创建 {created}")
    return "\n".join(lines)


def fingerprint(auths) -> str:
    blob = "\n".join(sorted(describe(a) for a in auths))
    return hashlib.sha256(blob.encode()).hexdigest()


def load_state() -> dict:
    """Whole state file. Format: {"accounts": {phone: {"sessions": {},
    "pending": {}, "code_processed": []}}}. A flat pre-v0.5 file
    ({"sessions": ...}) is migrated under PHONE on first save."""
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    if isinstance(data.get("accounts"), dict):
        data["accounts"] = {norm_phone(k): v for k, v in data["accounts"].items()}
    if "accounts" not in data and ("sessions" in data or "pending" in data):
        data = {"accounts": {PHONE: {
            "sessions": data.get("sessions", {}),
            "pending": data.get("pending", {}),
            "code_processed": data.get("code_processed", []),
        }}}
    return data


def load_account_state(phone: str) -> dict:
    return load_state().get("accounts", {}).get(phone, {})


def save_account_state(phone: str, partial: dict) -> None:
    # Merge with the existing file instead of replacing it: the session
    # check (check_once) and the decision poll (process_pending) save
    # {"sessions", "pending"} only — a plain overwrite here used to wipe
    # "code_processed", so a denied code event was frozen again every poll.
    data = load_state()
    accounts = data.get("accounts", {})
    if not isinstance(accounts, dict):
        accounts = {}
    cur = accounts.get(phone, {})
    if not isinstance(cur, dict):
        cur = {}
    cur.update(partial)
    accounts[phone] = cur
    data["accounts"] = accounts
    with open(STATE_FILE, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)


def sync_new_device(acct: Acct, auth) -> bool:
    """Report a new session to the Worker; the Worker alerts the owner with
    allow/revoke buttons. Returns True if the Worker accepted the report."""
    if not BOT_TOKEN:
        return False
    data = post_worker("/sync", {
        "account": acct.phone,
        "hash": str(auth.hash),
        "device": auth.device_model or "?",
        "platform": auth.platform or "?",
        "app": f"{auth.app_name or '?'} {auth.app_version or ''}".strip(),
        "ip": auth.ip or "?",
        "country": auth.country or "?",
        "region": auth.region or "",
        "created": str(auth.date_created),
        "detected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })
    ok = bool(data and data.get("ok"))
    log.info("Worker /sync %s for %s: %s", "accepted" if ok else "failed", acct.phone, data)
    return ok


async def revoke_session(client: TelegramClient, hash_int: int) -> bool:
    try:
        await client(ResetAuthorizationRequest(hash_int))
        log.warning("Revoked session hash=%s", hash_int)
        return True
    except Exception as exc:  # noqa: BLE001
        log.warning("Failed to revoke session hash=%s: %s", hash_int, exc)
        return False


async def check_once(acct: Acct) -> None:
    client = acct.client
    result = await client(GetAuthorizationsRequest())
    auths = list(result.authorizations)
    current = {str(a.hash): describe(a) for a in auths}
    by_hash = {str(a.hash): a for a in auths}
    state = load_account_state(acct.phone)
    known = state.get("sessions", {})
    pending = state.get("pending", {})

    if not known and not pending:
        save_account_state(acct.phone, {"sessions": current, "fingerprint": fingerprint(auths), "pending": {}})
        log.info("[%s] Baseline saved: %d authorized session(s).", acct.phone, len(current))
        for text in current.values():
            log.info("  %s", text)
        return

    # Never treat the monitor's own session as new.
    new_hashes = sorted(
        h for h in set(current) - set(known) - set(pending)
        if not by_hash[h].current
    )
    gone_hashes = sorted(set(known) - set(current))

    if new_hashes:
        for h in new_hashes:
            auth = by_hash[h]
            pending[h] = {
                "desc": current[h],
                "detected_at": time.time(),
                "device": auth.device_model or "?",
                "app": f"{auth.app_name or '?'} {auth.app_version or ''}".strip(),
                "ip": auth.ip or "?",
                "country": auth.country or "?",
                "region": auth.region or "",
                "created": str(auth.date_created),
            }
            if sync_new_device(acct, auth):
                log.warning("[%s] New session reported to Worker for owner decision: %s", acct.phone, current[h])
            else:
                msg = (
                    "🚨 TG Guardian：新设备登录\n\n"
                    f"{tidy_session(pending[h])}\n\n"
                    "没回复会自动注销；不是你本人请在设置 → 设备里注销它。"
                )
                log.warning("[%s] New session detected (direct alert): %s", acct.phone, current[h])
                send_bot_alert(msg, acct)
    if gone_hashes:
        gone_map = _GONE_COUNT.setdefault(acct.phone, {})
        for h in gone_hashes:
            n = gone_map.get(h, 0) + 1
            gone_map[h] = n
            if n == 1:
                log.info("[%s] Session ended/removed: %s", acct.phone, known[h])
                pending.pop(h, None)
            elif n >= GONE_GRACE_CYCLES:
                desc = known[h]
                known.pop(h, None)
                gone_map.pop(h, None)
                log.info("[%s] Session removed from baseline: %s", acct.phone, desc)
    for h in list(_GONE_COUNT.get(acct.phone, {})):
        if h in current:
            _GONE_COUNT[acct.phone].pop(h, None)

    # Pending sessions that disappeared on their own are no longer pending.
    for h in list(pending):
        if h not in current:
            pending.pop(h, None)

    save_account_state(acct.phone, {"sessions": known, "fingerprint": fingerprint(auths), "pending": pending})
    if new_hashes or gone_hashes:
        log.info("[%s] Snapshot updated: %d trusted session(s), %d pending.", acct.phone, len(known), len(pending))
    else:
        log.info("[%s] No change: %d authorized session(s), %d pending.", acct.phone, len(current), len(pending))
    await poll_777000(acct)


async def poll_777000(acct: Acct) -> None:
    """Backup for the real-time 777000 handler: on every session check,
    read the latest messages in the 777000 dialog and alert on any recent
    login code the event stream missed (e.g. a restored client that
    stopped receiving updates). Only messages from the last 10 minutes
    count, so a restart never re-alerts on an old code; dedupe is by
    message id, same as the handler. Suppressed while a freeze runs."""
    if acct.client is None or time.time() < acct.suppress_until:
        return
    try:
        msgs = await acct.client.get_messages(777000, limit=5)
    except Exception as exc:  # noqa: BLE001
        log.warning("[%s] 777000 poll failed: %s", acct.phone, exc)
        return
    if msgs is None:
        return
    if not isinstance(msgs, list):
        msgs = [msgs]
    now = time.time()
    for m in msgs:
        if m is None:
            continue
        msg_id = getattr(m, "id", None)
        if msg_id is None or msg_id in acct.seen_code_messages:
            continue
        acct.seen_code_messages.add(msg_id)
        date = getattr(m, "date", None)
        if date is None or now - date.timestamp() > 600:
            continue  # stale code from before this check cycle
        text = getattr(m, "raw_text", None) or getattr(m, "text", None) or ""
        if not _looks_like_login_code(text):
            continue
        log.warning("[%s] 777000 poll caught a code the handler missed (id=%s).", acct.phone, msg_id)
        alert_code_request(acct, msg_id)

async def run_freeze(acct: Acct, event_id: str) -> dict:
    """Owner tapped 拒绝 on a code alert: try to freeze code delivery.

    A separate throwaway Telethon client (never the monitor's own session)
    starts fresh logins with the account's phone number and enters a
    deliberately wrong code up to 5 times, aiming to trigger Telegram's
    wrong-code limit. Returns a result dict; the recovery time is an
    estimate (Telegram does not publish the exact lockout length).
    """
    acct.suppress_until = time.time() + FREEZE_SUPPRESS_SECONDS  # 15 min: freeze codes must not re-alert
    frozen_at = datetime.now(timezone.utc)
    expected_recovery = frozen_at + timedelta(hours=1)
    result = {
        "event_id": str(event_id),
        "frozen_at": frozen_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        # Set only when the limit actually triggered; a freeze that never
        # started must not carry a recovery time (v0.5.3).
        "expected_recovery_at": "",
        "attempts": 0,
        "outcome": "未执行",
        "triggered": False,
    }
    phone = acct.phone
    freeze_client = None
    try:
        freeze_client = TelegramClient(f"tg_guardian_freeze_{phone}", int(API_ID), API_HASH)
        await freeze_client.connect()
        outcome = "已触发"
        # One code request only: the same code is then entered wrong 5 times
        # against its phone_code_hash. No need to request 5 separate codes.
        try:
            sent = await freeze_client.send_code_request(phone)
            code_hash = sent.phone_code_hash
        except FloodWaitError as exc:
            result["outcome"] = f"限流 {exc.seconds} 秒，未开始"
            log.warning("[%s] Freeze: flood wait %s s on code request.", phone, exc.seconds)
            return result
        except PhonePasswordFloodError:
            # The password flood is already active, so code delivery is
            # already blocked; the code freeze itself did not run.
            result["outcome"] = "账号已处二级密码洪水中，无需冻结验证码"
            log.warning("[%s] Freeze: password flood already active on code request.", phone)
            return result
        except PhoneNumberFloodError:
            result["outcome"] = "验证码请求受限，未开始"
            log.warning("[%s] Freeze: code-request flood on code request.", phone)
            return result
        for attempt in range(1, FREEZE_MAX_ATTEMPTS + 1):
            try:
                try:
                    await freeze_client.sign_in(phone, WRONG_CODE, phone_code_hash=code_hash)
                except PhoneCodeInvalidError:
                    result["attempts"] += 1
                    log.warning("[%s] Freeze attempt %d/%d: wrong code rejected as expected.",
                                phone, attempt, FREEZE_MAX_ATTEMPTS)
                    await asyncio.sleep(1)
                    continue
                except SessionPasswordNeededError:
                    # The wrong code was somehow accepted: log this client out
                    # at once and stop — it must never stay authorized.
                    await freeze_client.log_out()
                    outcome = "冻结用的登录竟被接受，已退出该会话"
                    log.error("[%s] Freeze: unexpected sign-in success, logged out.", phone)
                    break
                # sign_in returned without error (should not happen with a
                # wrong code): treat as a failed freeze attempt and stop.
                outcome = "输错的验证码未被拒绝，已停止"
                log.error("[%s] Freeze: wrong code was not rejected.", phone)
                break
            except PhoneCodeExpiredError:
                outcome = "验证码已过期"
                log.warning("[%s] Freeze: code expired during freeze.", phone)
                break
            except FloodWaitError as exc:
                outcome = f"限流 {exc.seconds} 秒，已停止"
                result["triggered"] = True
                result["expected_recovery_at"] = expected_recovery.strftime("%Y-%m-%dT%H:%M:%SZ")
                log.warning("[%s] Freeze: flood wait %s s.", phone, exc.seconds)
                break
            except Exception as exc:  # noqa: BLE001
                outcome = f"中断：{exc}"
                log.warning("[%s] Freeze interrupted: %s", phone, exc)
                break
        else:
            # All 5 wrong entries were rejected without an explicit lockout
            # error; Telegram's exact behaviour is not published, so the
            # recovery time stays an estimate.
            result["triggered"] = True
            result["expected_recovery_at"] = expected_recovery.strftime("%Y-%m-%dT%H:%M:%SZ")
        result["outcome"] = outcome
    except Exception as exc:  # noqa: BLE001
        result["outcome"] = f"失败：{exc}"
        log.warning("[%s] Freeze failed: %s", phone, exc)
    finally:
        if freeze_client is not None:
            try:
                await freeze_client.disconnect()
            except Exception:  # noqa: BLE001
                pass
        try:
            session_file = f"tg_guardian_freeze_{phone}.session"
            if os.path.exists(session_file):
                os.remove(session_file)
        except OSError:
            pass
    return result


async def run_2fa_flood_nocode(acct: Acct) -> dict:
    """No-code 2FA attempt: use the monitor's own already-authorized
    session (NOT a tdata import — the monitor already holds an authorized
    session, which is all this needs) to check a deliberately wrong 2FA
    password 5 times via account.GetPassword + auth.CheckPassword.

    Whether Telegram counts these attempts toward the login flood
    (PHONE_PASSWORD_FLOOD) is NOT verified — the only verified trigger
    is the login flow — so this returns flooded=True only on an explicit
    FloodWaitError. Anything else means "try the login-flow path".
    Never logs out the main client; a CheckPassword call cannot change
    the monitor's own session.
    """
    client = acct.client
    phone = acct.phone
    frozen_at = datetime.now(timezone.utc)
    expected_recovery = frozen_at + timedelta(hours=1)
    result = {
        "twofa_attempts": 0,
        "twofa_outcome": "未执行",
        "expected_recovery_at": "",
        "flooded": False,
        "triggered": False,
        "method": "nocode",
    }
    # The SRP id from GetPassword is single-use: re-fetching it before
    # every attempt (v0.5.11) fixes "Invalid SRP ID provided" aborts.
    for attempt in range(1, TWOFA_MAX_ATTEMPTS + 1):
        try:
            pwd = await client(GetPasswordRequest())
        except (FloodWaitError, PhonePasswordFloodError) as exc:
            # The flood is already active (most likely armed by this run's
            # earlier wrong passwords): report it as triggered instead of
            # falling through to the login flow, whose code request would
            # fail with the same flood.
            result["flooded"] = True
            result["triggered"] = True
            result["expected_recovery_at"] = expected_recovery.strftime("%Y-%m-%dT%H:%M:%SZ")
            result["twofa_outcome"] = "已触发"
            log.warning("[%s] 2FA nocode: flood on GetPassword after %d wrong passwords.",
                        phone, result["twofa_attempts"])
            return result
        except Exception as exc:  # noqa: BLE001
            if attempt == 1:
                result["twofa_outcome"] = "免验证码路径不可用，改走登录流程"
            else:
                result["twofa_outcome"] = f"免验证码路径中断：{exc}"
            log.warning("[%s] 2FA nocode: GetPassword failed: %s", phone, exc)
            return result
        try:
            check = pwd_mod.compute_check(pwd, WRONG_2FA_PASSWORD)
            await client(CheckPasswordRequest(check))
            # A wrong password was somehow accepted: stop this path at
            # once. Do NOT log out the main client — that would kill the
            # monitor. The login-flow fallback has its own guards.
            result["twofa_outcome"] = "异常：错误的二级密码竟被接受"
            log.error("[%s] 2FA nocode: unexpected check success, stopping nocode path.", phone)
            return result
        except PasswordHashInvalidError:
            result["twofa_attempts"] += 1
            log.warning("[%s] 2FA nocode attempt %d/%d: wrong 2FA password rejected as expected.",
                        phone, attempt, TWOFA_MAX_ATTEMPTS)
            await asyncio.sleep(1)
            continue
        except FloodWaitError as exc:
            result["twofa_attempts"] += 1
            result["flooded"] = True
            result["triggered"] = True
            result["expected_recovery_at"] = expected_recovery.strftime("%Y-%m-%dT%H:%M:%SZ")
            if result["twofa_attempts"] <= 1:
                result["twofa_outcome"] = "已触发"
            else:
                result["twofa_outcome"] = "已触发"
            log.warning("[%s] 2FA nocode: flood wait %s s after %d wrong passwords.",
                        phone, exc.seconds, result["twofa_attempts"])
            return result
        except Exception as exc:  # noqa: BLE001
            result["twofa_outcome"] = f"免验证码路径中断：{exc}"
            log.warning("[%s] 2FA nocode interrupted: %s", phone, exc)
            return result
    # All 5 wrong entries were rejected without an explicit flood error.
    # Telegram may still count them, but there is no proof — fall back.
    result["twofa_outcome"] = "免验证码路径未触发限制，改走登录流程"
    log.warning("[%s] 2FA nocode: 5 wrong passwords rejected, no explicit flood; falling back.", phone)
    return result

async def run_2fa_flood(acct: Acct, event_id: str) -> dict:
    """2FA protection: trigger Telegram's wrong-2FA limit (PHONE_PASSWORD_FLOOD).

    Tries the no-code path FIRST (run_2fa_flood_nocode: the monitor's own
    authorized session checks a wrong 2FA password 5 times — no fresh
    code, no tdata). If that does not return an explicit flood, falls
    back to the login-flow path: a separate throwaway client (never the
    monitor's own session) requests ONE fresh code, the monitor captures
    that code from its own 777000 message (in memory only, never logged,
    never sent anywhere), enters it correctly to reach the 2FA step, then
    enters a deliberately wrong 2FA password 5 times. Returns
    {"twofa_attempts", "twofa_outcome", "expected_recovery_at", "method"};
    the recovery time is estimated by trigger count in 24h (1st-3rd 1h, 4th 6h, 5th+ 24h); the Worker computes it and returns it with /code-freeze, and the local 1h value is only a fallback.
    """
    # No-code path first: no fresh code is requested, so the user gets no
    # extra code message if it works.
    nocode = await run_2fa_flood_nocode(acct)
    if nocode.get("flooded"):
        return {
            "twofa_attempts": nocode.get("twofa_attempts", 0),
            "twofa_outcome": nocode.get("twofa_outcome", ""),
            "expected_recovery_at": nocode.get("expected_recovery_at", ""),
            "triggered": bool(nocode.get("triggered")),
            "method": "nocode",
        }
    log.warning("[%s] 2FA nocode path did not flood (%s); falling back to login flow.",
                acct.phone, nocode.get("twofa_outcome"))
    acct.suppress_until = time.time() + FREEZE_SUPPRESS_SECONDS  # 15 min: own codes must not re-alert
    phone = acct.phone
    frozen_at = datetime.now(timezone.utc)
    expected_recovery = frozen_at + timedelta(hours=1)
    result = {
        "twofa_attempts": 0,
        "twofa_outcome": "未执行",
        # Set only when the limit actually triggered (v0.5.3): every early
        # return below (no 2FA on the account, no code, invalid code, ...)
        # must leave this empty, or /status claims a protection that never ran.
        "expected_recovery_at": "",
        "triggered": False,
        "method": "login-flow",
    }
    client2 = None
    throwaway_authorized = False
    try:
        client2 = TelegramClient(f"tg_guardian_2fa_{phone}", int(API_ID), API_HASH)
        await client2.connect()
        # Clear any stale capture, then request ONE fresh code.
        acct.captured_code = None
        acct.capture_active = True
        try:
            sent = await client2.send_code_request(phone)
            code_hash = sent.phone_code_hash
        except FloodWaitError as exc:
            result["twofa_outcome"] = f"限流 {exc.seconds} 秒，未开始"
            log.warning("[%s] 2FA flood: flood wait %s s on code request.", phone, exc.seconds)
            return result
        except PhonePasswordFloodError:
            # The password flood is already active (most likely armed by
            # the no-code path's wrong passwords just now): the account
            # is locked, so the protection DID trigger — report it as
            # such instead of a generic failure.
            result["twofa_attempts"] = nocode.get("twofa_attempts", 0)
            result["twofa_outcome"] = "已触发"
            result["triggered"] = True
            result["expected_recovery_at"] = expected_recovery.strftime("%Y-%m-%dT%H:%M:%SZ")
            log.warning("[%s] 2FA flood: password flood already active on code request; treating as triggered.", phone)
            return result
        except PhoneNumberFloodError:
            # Only code requests are limited; the password flood did NOT
            # trigger. Report it plainly instead of a generic failure.
            result["twofa_outcome"] = "验证码请求受限，未开始"
            log.warning("[%s] 2FA flood: code-request flood on code request.", phone)
            return result
        # Wait for the 777000 message carrying this fresh code to reach the
        # monitor client. The code digits are never logged.
        code = None
        deadline = time.time() + TWOFA_CODE_WAIT_SECONDS
        while time.time() < deadline:
            if acct.captured_code:
                code = acct.captured_code
                acct.captured_code = None
                break
            await asyncio.sleep(1)
        acct.capture_active = False
        if not code:
            result["twofa_outcome"] = "未收到验证码，未执行"
            log.warning("[%s] 2FA flood: no code captured within %s s.", phone, TWOFA_CODE_WAIT_SECONDS)
            return result
        # Enter the code correctly to reach the 2FA step.
        try:
            await client2.sign_in(phone, code, phone_code_hash=code_hash)
            # No 2FA was required: log this client out at once and stop —
            # it must never stay authorized.
            await client2.log_out()
            result["twofa_outcome"] = "账号未设二级密码，已退出该会话"
            log.error("[%s] 2FA flood: unexpected sign-in success without 2FA, logged out.", phone)
            return result
        except SessionPasswordNeededError:
            # Expected: the account has 2FA. The code was accepted, so the
            # throwaway client is now an authorized session.
            throwaway_authorized = True
        except PhoneCodeInvalidError:
            result["twofa_outcome"] = "验证码无效，未执行"
            log.warning("[%s] 2FA flood: code invalid.", phone)
            return result
        except PhoneCodeExpiredError:
            result["twofa_outcome"] = "验证码已过期，未执行"
            log.warning("[%s] 2FA flood: code expired.", phone)
            return result
        except FloodWaitError as exc:
            result["twofa_outcome"] = f"限流 {exc.seconds} 秒，未开始"
            log.warning("[%s] 2FA flood: flood wait %s s on sign-in.", phone, exc.seconds)
            return result
        # Wrong 2FA password 5 times.
        for attempt in range(1, TWOFA_MAX_ATTEMPTS + 1):
            try:
                await client2.sign_in(password=WRONG_2FA_PASSWORD)
                # A wrong password was somehow accepted: log out at once.
                await client2.log_out()
                result["twofa_outcome"] = "错误的二级密码竟被接受，已退出该会话"
                log.error("[%s] 2FA flood: unexpected sign-in success with wrong password, logged out.", phone)
                return result
            except PasswordHashInvalidError:
                result["twofa_attempts"] += 1
                log.warning("[%s] 2FA flood attempt %d/%d: wrong 2FA password rejected as expected.",
                            phone, attempt, TWOFA_MAX_ATTEMPTS)
                await asyncio.sleep(1)
                continue
            except FloodWaitError as exc:
                result["twofa_attempts"] += 1
                result["twofa_outcome"] = "已触发"
                result["triggered"] = True
                result["expected_recovery_at"] = expected_recovery.strftime("%Y-%m-%dT%H:%M:%SZ")
                log.warning("[%s] 2FA flood: flood wait %s s after %d wrong passwords.",
                            phone, exc.seconds, result["twofa_attempts"])
                break
            except Exception as exc:  # noqa: BLE001
                result["twofa_outcome"] = f"中断：{exc}"
                log.warning("[%s] 2FA flood interrupted: %s", phone, exc)
                break
        else:
            # All 5 wrong entries were rejected without an explicit flood
            # error; Telegram's exact behaviour is not published, so the
            # recovery time stays an estimate.
            result["twofa_outcome"] = "已触发"
            result["triggered"] = True
            result["expected_recovery_at"] = expected_recovery.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception as exc:  # noqa: BLE001
        result["twofa_outcome"] = f"失败：{exc}"
        log.warning("[%s] 2FA flood failed: %s", phone, exc)
    finally:
        acct.capture_active = False
        acct.captured_code = None
        if client2 is not None:
            if throwaway_authorized:
                # Log the throwaway session out (v0.5.11): otherwise it
                # lingers as an authorized session, pops up as a "new
                # device" alert, and its /sync report clears the
                # just-stored flood record. Best effort only — a flood
                # may block the call itself.
                try:
                    await client2.log_out()
                    log.info("[%s] 2FA flood: throwaway session logged out.", phone)
                except Exception as exc:  # noqa: BLE001
                    log.warning("[%s] 2FA flood: throwaway log-out failed: %s", phone, exc)
            try:
                await client2.disconnect()
            except Exception:  # noqa: BLE001
                pass
        try:
            session_file = f"tg_guardian_2fa_{phone}.session"
            if os.path.exists(session_file):
                os.remove(session_file)
        except OSError:
            pass
    return result


async def run_combined_protection(acct: Acct, event_id: str) -> dict:
    """Run both code protections for one denied / unanswered code event.

    Order matters: the 2FA protection runs FIRST because its block lasts
    until next day (the stronger, longer layer). The wrong-code freeze
    runs after it; if the account is already flooded by the 2FA step, the
    freeze's code request may be refused with FloodWait — that is reported
    honestly in its outcome, not treated as a failure of the protection,
    because the account is already locked.
    Returns the combined result dict for POST /code-freeze.
    """
    twofa = await run_2fa_flood(acct, event_id)
    freeze = await run_freeze(acct, event_id)
    combined = dict(freeze)
    combined["twofa_attempts"] = twofa.get("twofa_attempts", 0)
    combined["twofa_outcome"] = twofa.get("twofa_outcome", "")
    combined["twofa_triggered"] = bool(twofa.get("triggered"))
    # Recovery time comes only from a layer that actually triggered; if
    # neither did, there is nothing to recover from.
    if not combined.get("triggered") and twofa.get("triggered"):
        combined["expected_recovery_at"] = twofa.get("expected_recovery_at", "")
    return combined


async def run_protection(acct: Acct, event_id: str, mode: str) -> dict:
    """Run one code protection for a decided code event and return the
    /code-freeze payload. mode is "code" (wrong-code freeze only),
    "2fa" (2FA protection only) or "both" (2FA first, then code freeze)."""
    if mode == "code":
        result = await run_freeze(acct, event_id)
        result["mode"] = "code"
        return result
    if mode == "2fa":
        twofa = await run_2fa_flood(acct, event_id)
        now = datetime.now(timezone.utc)
        return {
            "event_id": str(event_id),
            "frozen_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expected_recovery_at": twofa.get("expected_recovery_at", ""),
            "mode": "2fa",
            "attempts": 0,
            "outcome": "",
            "twofa_attempts": twofa.get("twofa_attempts", 0),
            "twofa_outcome": twofa.get("twofa_outcome", ""),
            "twofa_triggered": bool(twofa.get("triggered")),
        }
    result = await run_combined_protection(acct, event_id)
    result["mode"] = "both"
    return result

def settings_from(per: dict) -> dict:
    """Worker settings for one account, with env defaults.

    The Worker stores auto times (seconds), the alerts switch and the
    pause deadline in KV;
    the monitor picks them up on every /pending poll (<= 120 s), so a
    /set_guard or /set_revoke command takes effect within two minutes.
    A missing or invalid value falls back to the env default.
    """
    raw = per.get("settings", {}) or {}
    if not isinstance(raw, dict):
        raw = {}

    def _seconds(key, fallback):
        try:
            v = int(raw.get(key, fallback))
        except (TypeError, ValueError):
            return fallback
        return v if 60 <= v <= 3600 else fallback

    def _pause_until():
        try:
            v = int(raw.get("pause_until", 0))
        except (TypeError, ValueError):
            return 0
        return v if v == -1 or v >= 0 else 0

    return {
        "auto_code_after": _seconds("auto_code_after", AUTO_CODE_AFTER),
        "auto_revoke_after": _seconds("auto_revoke_after", AUTO_REVOKE_AFTER),
        "alerts_enabled": raw.get("alerts_enabled", True) is not False,
        "pause_until": _pause_until(),
    }


def _is_paused(settings: dict) -> bool:
    """pause_until: -1 = paused until manually resumed; a ms-epoch
    timestamp = paused until then; 0/absent = not paused."""
    pu = settings.get("pause_until", 0)
    return pu == -1 or (isinstance(pu, int) and pu > int(time.time() * 1000))


def _sgt_short(iso: str) -> str:
    """ISO UTC timestamp -> "MM-DD HH:MM" Singapore time ("" when empty)."""
    if not iso:
        return ""
    try:
        dt = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        return dt.astimezone(timezone(timedelta(hours=8))).strftime("%m-%d %H:%M")
    except ValueError:
        return str(iso)


def mark_code_allowed(acct: Acct, event_id: str) -> bool:
    """Record a code event as owner-allowed (nothing to freeze)."""
    state = load_account_state(acct.phone)
    processed = set(state.get("code_processed", [])) | acct.freeze_done
    if event_id in processed:
        return False
    processed.add(event_id)
    acct.freeze_done.add(event_id)
    save_account_state(acct.phone, {"code_processed": sorted(processed)})
    log.info("[%s] Owner allowed the login-code request %s; nothing to do.", acct.phone, event_id)
    return True


async def apply_code_decision(acct: Acct, event_id: str, mode: str, auto: bool = False, auto_code_after: int = AUTO_CODE_AFTER) -> bool:
    """Run one code protection (freeze / 2FA / both) for a decided event.

    Shared by the /pending poll path (process_code_events) and the direct
    wake-up path (execute_directive). Marks the event processed (local
    state + in-memory set) so a later /pending delivery of the same
    decision is a no-op. Returns True if the protection ran.
    """
    state = load_account_state(acct.phone)
    processed = set(state.get("code_processed", [])) | acct.freeze_done
    if event_id in processed:
        return False
    mode_name = {"code": "冻结验证码功能", "2fa": "冻结二级密码", "both": "冻结验证码功能并触发Flood保护"}[mode]
    auto_minutes = auto_code_after // 60
    log.warning("[%s] Owner decision on code request %s: %s.", acct.phone, event_id, mode_name)
    if mode == "2fa":
        doing = "🧊 TG Guardian：正在处理，过程中如果再收到验证码消息，忽略即可。"
    else:
        doing = f"🧊 TG Guardian：正在{mode_name}，过程中会再收到验证码消息，忽略即可。"
    send_bot_alert(
        doing
        + (f"\n\n（{auto_minutes} 分钟无回复，自动冻结。）" if auto else ""),
        acct,
    )
    try:
        result = await run_protection(acct, event_id, mode)
    except Exception as exc:  # noqa: BLE001 - a failed protection must still be recorded, never retried silently
        result = {
            "event_id": str(event_id),
            "frozen_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expected_recovery_at": (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "mode": mode,
            "attempts": 0,
            "outcome": f"失败：{exc}",
            "twofa_attempts": 0,
            "twofa_outcome": f"失败：{exc}",
        }
        log.warning("[%s] Protection raised unexpectedly: %s", acct.phone, exc)
    # The Worker owns the recovery estimate (trigger count in 24h)
    # and returns it; use it for the alert, fall back to the local
    # 1h value when the Worker is older or the POST failed.
    _resp = post_worker("/code-freeze", {"account": acct.phone, **result})
    if isinstance(_resp, dict) and _resp.get("expected_recovery_at"):
        result["expected_recovery_at"] = _resp["expected_recovery_at"]
        result["estimate_hours"] = _resp.get("estimate_hours") or 1
        result["flood_count"] = _resp.get("flood_count")
    processed.add(event_id)
    acct.freeze_done.add(event_id)
    save_account_state(acct.phone, {"code_processed": sorted(processed)})
    recovery = _sgt_short(result["expected_recovery_at"])
    title = {"code": "🧊 TG Guardian：验证码冻结结果",
             "2fa": "🔒 TG Guardian：Flood保护结果",
             "both": "🧊 TG Guardian：验证码冻结 + Flood保护结果"}[mode]
    lines = [title, ""]
    if auto:
        lines.append(f"（{auto_code_after // 60} 分钟无回复，自动冻结二级密码。）")
    if mode in ("code", "both"):
        lines.append(f"验证码冻结：{result['outcome']}")
        lines.append(f"验证码输错次数：{result['attempts']} 次")
    if mode in ("2fa", "both"):
        lines.append(f"Flood保护：{result.get('twofa_outcome', '')}")
    lines.append(f"预计恢复时间：{recovery}")
    lines.append("")
    if result.get("flood_count"):
        lines.append(f"触发次数（24 小时内）：第 {result['flood_count']} 次")
    lines.append(f"恢复时间按 {result.get('estimate_hours') or 1} 小时估算。")
    send_bot_alert("\n".join(lines), acct)
    return True


async def process_code_events(acct: Acct, data: dict) -> None:
    """Apply owner decisions on login-code alerts from the Worker."""
    per = per_account(data, acct.phone)
    code_events = per.get("code_events", [])
    if not code_events:
        return
    settings = settings_from(per)
    auto_code_after = settings["auto_code_after"]
    paused = _is_paused(settings)
    state = load_account_state(acct.phone)
    processed = set(state.get("code_processed", [])) | acct.freeze_done
    now = time.time()
    for ev in code_events:
        event_id = str(ev.get("id", ""))
        status = ev.get("status")
        if not event_id or event_id in processed:
            continue
        auto = False
        mode = None  # "code" | "2fa" | "both"
        if status == "pending":
            # No owner reply within the configured time -> auto-run the
            # 2FA protection ONLY (default 5 min; /set_guard changes it).
            try:
                detected = datetime.fromisoformat(
                    str(ev.get("detected_at", "")).replace("Z", "+00:00")
                )
                elapsed = now - detected.timestamp()
            except ValueError:
                elapsed = 0
            if not paused and elapsed >= auto_code_after:
                mode = "2fa"
                auto = True
                log.warning("[%s] Code request %s unanswered for %d s; auto-freezing 2FA.",
                            acct.phone, event_id, auto_code_after)
        elif status == "allow":
            mark_code_allowed(acct, event_id)
            processed.add(event_id)
        elif status == "deny_code":
            mode = "code"
        elif status == "deny_2fa":
            mode = "2fa"
        elif status == "deny":
            # Legacy Worker (<= 1.3.7) with a single 拒绝 button: run both.
            mode = "both"
        if mode:
            if await apply_code_decision(acct, event_id, mode, auto, auto_code_after):
                processed.add(event_id)


async def probe_flood(acct: Acct) -> dict:
    """Manual flood check (/check_flood): ask Telegram for a login code
    on a throwaway client and see whether it is refused. A successful
    code request proves the flood has lifted (auth.sendCode itself
    returns the flood error while one is active); a flood error
    (FloodWait / PHONE_PASSWORD_FLOOD / PHONE_NUMBER_FLOOD) proves it
    has not. The result also says whether the flood is definitely active
    (flood_active) and the real wait in seconds when Telegram gives one. Never enters any password, so a probe can never
    trigger a flood — it only spends one code request. The probe's own
    code message is swallowed by the capture flag (digits discarded,
    message marked seen) so it never alerts the owner."""
    phone = acct.phone
    result = {"lifted": False, "detail": "", "flood_active": False, "wait_seconds": None}
    client2 = None
    try:
        client2 = TelegramClient(f"tg_guardian_probe_{phone}", int(API_ID), API_HASH)
        await client2.connect()
        acct.captured_code = None
        acct.capture_active = True
        try:
            await client2.send_code_request(phone)
            result["lifted"] = True
            result["detail"] = "\u9a8c\u8bc1\u7801\u5df2\u9001\u8fbe"
        except FloodWaitError as exc:
            result["flood_active"] = True
            result["wait_seconds"] = int(exc.seconds) if exc.seconds else None
            result["detail"] = f"限流 {exc.seconds} 秒"
        except PhonePasswordFloodError:
            result["flood_active"] = True
            result["detail"] = "密码洪水限制中"
        except PhoneNumberFloodError:
            result["flood_active"] = True
            result["detail"] = "验证码请求受限"
        # Give the probe's own code message a few seconds to arrive so
        # the handler swallows it instead of alerting on it.
        for _ in range(8):
            if acct.captured_code:
                break
            await asyncio.sleep(1)
    except Exception as exc:  # noqa: BLE001
        result["detail"] = f"\u68c0\u67e5\u5931\u8d25\uff1a{exc}"
        log.warning("[%s] Flood probe failed: %s", phone, exc)
    finally:
        acct.capture_active = False
        acct.captured_code = None
        if client2 is not None:
            try:
                await client2.disconnect()
            except Exception:  # noqa: BLE001
                pass
        try:
            session_file = f"tg_guardian_probe_{phone}.session"
            if os.path.exists(session_file):
                os.remove(session_file)
        except OSError:
            pass
    return result


async def run_scheduled_flood(acct: Acct) -> None:
    """Fire a one-shot sustained Flood protection: the owner timer
    elapsed, so trigger the 2FA flood once and report it. Mirrors the
    deny_2fa result path (apply_code_decision) but with a sustain event
    id, so the Worker clears the timer and counts the trigger toward
    the 24h history. The account may already be flooded (e.g. the owner
    triggered one by hand) — run_2fa_flood reports that as triggered."""
    event_id = f"sustain:{acct.phone}:{int(time.time())}"
    log.warning("[%s] Sustained Flood protection due; triggering once.", acct.phone)
    send_bot_alert("⏰ TG Guardian：持续Flood保护到时间了，正在触发 Flood 保护…", acct)
    try:
        result = await run_2fa_flood(acct, event_id)
    except Exception as exc:  # noqa: BLE001
        result = {
            "event_id": event_id,
            "frozen_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expected_recovery_at": (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "mode": "2fa",
            "attempts": 0,
            "outcome": f"失败：{exc}",
            "twofa_attempts": 0,
            "twofa_outcome": f"失败：{exc}",
            "triggered": False,
        }
        log.warning("[%s] Scheduled flood raised unexpectedly: %s", acct.phone, exc)
    # The Worker owns the recovery estimate (trigger count in 24h)
    # and returns it; use it for the alert, fall back to the local
    # 1h value when the Worker is older or the POST failed.
    result["event_id"] = event_id
    _resp = post_worker("/code-freeze", {"account": acct.phone, **result})
    sustain_out = None
    if isinstance(_resp, dict) and _resp.get("expected_recovery_at"):
        result["expected_recovery_at"] = _resp["expected_recovery_at"]
        result["estimate_hours"] = _resp.get("estimate_hours") or 1
        result["flood_count"] = _resp.get("flood_count")
        sustain_out = _resp.get("sustain")
    recovery = _sgt_short(result["expected_recovery_at"])
    triggered = bool(result.get("triggered"))
    title = "⏰ TG Guardian：持续Flood保护已触发" if triggered else "⏰ TG Guardian：持续Flood保护失败"
    is_loop = bool(sustain_out and sustain_out.get("mode") == "loop")
    lines = [title, "", f"Flood保护：{result.get('twofa_outcome', '')}"]
    if not is_loop:
        lines.append(f"预计恢复时间：{recovery}")
    lines.append("")
    if result.get("flood_count"):
        lines.append(f"触发次数（24 小时内）：第 {result['flood_count']} 次")
    if not is_loop:
        lines.append(f"恢复时间按 {result.get('estimate_hours') or 1} 小时估算。")
    if sustain_out:
        if sustain_out.get("next_trigger_at"):
            nxt = _sgt_short(sustain_out["next_trigger_at"])
            if sustain_out.get("mode") == "loop":
                lines.append(f"下次触发：{nxt}（循环中）。")
            else:
                lines.append(f"下次触发：{nxt}（还剩 {sustain_out.get('remaining')} 次，共 {sustain_out.get('total')} 次）。")
        else:
            lines.append("定时器已关闭。")
    send_bot_alert("\n".join(lines), acct)


async def process_sustain(acct: Acct, data: dict) -> None:
    """Fire a one-shot sustained Flood protection when its timer elapses.
    The timer record comes from GET /pending (per-account 'sustain').
    Fires at most once per record (sustain_fired); the Worker clears the
    record when the trigger reports via /code-freeze, which resets the
    flag on the next poll. Fires on the next poll after the time elapses
    (up to 120 s late at the 120 s poll cadence)."""
    per = per_account(data, acct.phone)
    sustain = per.get("sustain")
    if not sustain:
        acct.sustain = None
        acct.sustain_fired = False
        acct.sustain_trigger_at = None
        return
    acct.sustain = sustain
    trigger_at_raw = str(sustain.get("trigger_at", ""))
    if acct.sustain_trigger_at != trigger_at_raw:
        # A new round (the timer was set or rescheduled): allow firing.
        acct.sustain_trigger_at = trigger_at_raw
        acct.sustain_fired = False
    if acct.sustain_fired:
        return
    try:
        trigger_at = datetime.fromisoformat(trigger_at_raw.replace("Z", "+00:00"))
    except ValueError:
        log.warning("[%s] Sustained Flood record has a bad trigger_at: %s", acct.phone, sustain)
        return
    if _is_paused(settings_from(per)):
        return
    if datetime.now(timezone.utc) >= trigger_at:
        acct.sustain_fired = True
        await run_scheduled_flood(acct)


async def check_pause_expiry(acct: Acct, data: dict) -> None:
    """Announce once when a timed pause expires (v0.5.24).

    pause_until is a ms-epoch timestamp for a timed pause, -1 for an
    indefinite one and 0 after a manual /resume_guard. Only the timed
    case needs an announcement here - a manual resume is already
    confirmed by the Worker reply, and an indefinite pause never
    expires on its own."""
    per = per_account(data, acct.phone)
    settings = settings_from(per)
    pu = settings.get("pause_until", 0)
    paused_now = _is_paused(settings)
    if acct.was_paused and not paused_now and isinstance(pu, int) and pu > 0:
        send_bot_alert("▶️ TG Guardian：暂停时间到，保护已恢复。", acct)
    acct.was_paused = paused_now


async def process_flood_probe(acct: Acct, data: dict) -> None:
    """Run a manual flood check requested with /check_flood."""
    per = per_account(data, acct.phone)
    probe = per.get("flood_probe")
    if not probe:
        return
    log.warning("[%s] Manual flood check requested; probing.", acct.phone)
    result = await probe_flood(acct)
    post_worker("/flood-probe", {
        "account": acct.phone,
        "lifted": result["lifted"],
        "detail": result["detail"],
        "flood_active": result.get("flood_active", False),
        "wait_seconds": result.get("wait_seconds"),
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    })
    log.warning("[%s] Flood probe result: lifted=%s (%s).", acct.phone, result["lifted"], result["detail"])


def format_session(auth) -> dict:
    """Structured device info for the Worker to render readably."""
    return {
        "device": auth.device_model or "?",
        "platform": auth.platform or "?",
        "app": f"{auth.app_name or '?'} {auth.app_version or ''}".strip(),
        "ip": auth.ip or "?",
        "country": auth.country or "?",
        "region": auth.region or "",
        "created": str(auth.date_created),
        "active": str(auth.date_active),
        "current": bool(auth.current),
    }


async def upload_heartbeat(acct: Acct) -> None:
    """Upload a heartbeat + current device snapshot to the Worker (hourly).

    Lets /status show the monitor is alive and /devices show the snapshot.
    2 KV writes per call; failures are logged, never fatal.
    """
    try:
        result = await acct.client(GetAuthorizationsRequest())
        auths = list(result.authorizations)
        payload = {
            "account": acct.phone,
            "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "version": VERSION,
            "count": len(auths),
            "sessions": [format_session(a) for a in auths],
        }
        # Keep the Worker KV copy of this account's StringSession fresh so
        # a stateless container restart can restore the session (v0.5.22).
        # Sent with every heartbeat (not deduped) so the copy lands even
        # if the Worker was upgraded after this monitor started.
        try:
            ss = StringSession.save(acct.client.session)
        except Exception:  # noqa: BLE001
            ss = ""
        if ss:
            payload["session_string"] = ss
        data = post_worker("/heartbeat", payload)
        if data and data.get("ok"):
            log.info("[%s] Heartbeat uploaded: %d session(s).", acct.phone, len(auths))
        else:
            log.warning("[%s] Heartbeat upload not accepted (Worker may be an older version).", acct.phone)
    except Exception as exc:  # noqa: BLE001
        log.warning("[%s] Heartbeat upload failed: %s", acct.phone, exc)


async def apply_device_decision(acct: Acct, hash_str: str, kind: str, auto: bool = False, auto_revoke_after: int = AUTO_REVOKE_AFTER) -> bool:
    """Apply one device decision (allow / revoke) to the local baseline.

    Shared by the /pending poll path (process_pending) and the direct
    wake-up path (execute_directive): the same code runs either way, so a
    decision carried in the wake-up message and the same decision arriving
    later via /pending can never both act — the first one removes the
    item from local pending, the second finds nothing to do.
    Returns True if the item was present and handled.
    """
    state = load_account_state(acct.phone)
    known = state.get("sessions", {})
    pending = state.get("pending", {})
    info = pending.get(hash_str)
    if info is None:
        return False
    revoke_minutes = auto_revoke_after // 60
    if kind == "allow":
        known[hash_str] = info["desc"]
        pending.pop(hash_str, None)
        log.info("[%s] Owner allowed new session, added to baseline: %s", acct.phone, info["desc"])
    elif kind == "revoke":
        try:
            hash_int = int(hash_str)
        except ValueError:
            pending.pop(hash_str, None)
            save_account_state(acct.phone, {"sessions": known, "pending": pending})
            return True
        ok = await revoke_session(acct.client, hash_int)
        pending.pop(hash_str, None)
        known.pop(hash_str, None)
        if ok:
            send_bot_alert(
                (f"⏱️ TG Guardian：新设备 {revoke_minutes} 分钟无回复，已自动注销。\n\n" if auto
                 else "⛔ TG Guardian：已按你的决定注销该设备。\n\n")
                + tidy_session(info),
                acct,
            )
        else:
            send_bot_alert(
                "⚠️ TG Guardian：尝试注销新设备失败，请在 Telegram 设置 → 设备里手动注销。\n\n"
                + tidy_session(info),
                acct,
            )
    else:
        return False
    save_account_state(acct.phone, {"sessions": known, "pending": pending})
    # A decision just changed the baseline (allow / revoke / auto-revoke):
    # push the fresh snapshot to the Worker now instead of waiting for
    # the next hourly heartbeat, so /devices shows it immediately.
    await upload_heartbeat(acct)
    return True


async def process_pending(acct: Acct, data: dict) -> None:
    """Apply owner decisions from the Worker, or auto-revoke after silence.

    The silence window comes from the Worker settings (default 10 min;
    /set_guard, /set_revoke changes it), picked up on every /pending poll.
    Each item is applied by apply_device_decision, the same helper the
    direct wake-up path uses.
    """
    state = load_account_state(acct.phone)
    pending = state.get("pending", {})
    if not pending:
        return
    per = per_account(data, acct.phone)
    decisions = {str(p.get("hash")): p.get("status") for p in per.get("pending", [])}
    settings = settings_from(per)
    auto_revoke_after = settings["auto_revoke_after"]
    paused = _is_paused(settings)
    now = time.time()
    for h in list(pending):
        status = decisions.get(h, "pending")
        elapsed = now - float(pending[h].get("detected_at", now))
        if status == "allow":
            await apply_device_decision(acct, h, "allow", False, auto_revoke_after)
        elif status == "revoke" or (status == "pending" and not paused and elapsed >= auto_revoke_after):
            await apply_device_decision(acct, h, "revoke", status == "pending", auto_revoke_after)


# QR onboarding (v0.5.25): each QR token lives ~30 s; the monitor
# regenerates and re-sends the photo up to QR_MAX_REFRESH times after
# the first one (~5.5 min total), then gives up. The 2FA password is
# awaited for up to QR_2FA_TIMEOUT seconds after a successful scan.
QR_MAX_REFRESH = 10
QR_WAIT_TIMEOUT = 30
QR_2FA_TIMEOUT = 300


def _qr_png(url: str) -> bytes:
    """Render the tg://login URL as PNG bytes (segno)."""
    buf = io.BytesIO()
    segno.make(url).save(buf, kind="png", scale=8, border=2)
    return buf.getvalue()


async def _qr_2fa(acct: Acct, client) -> bool:
    """QR scan succeeded but the account has 2FA: ask the owner for
    the password via the Worker (awaiting_2fa -> /2fa ->
    password_received, stashed on the Acct by process_onboard) and
    sign in. Returns True once authorized."""
    phone = acct.phone
    while True:
        report_onboard(phone, "awaiting_2fa")
        deadline = time.time() + QR_2FA_TIMEOUT
        while not acct.qr_password:
            if time.time() > deadline:
                report_onboard(phone, "failed", "等二级密码超时")
                await _drop_onboard_client(acct)
                return False
            await asyncio.sleep(1)
        password = acct.qr_password
        acct.qr_password = None
        try:
            await client.sign_in(password=password)
            return True
        except PasswordHashInvalidError:
            report_onboard(phone, "password_invalid")
            continue
        except FloodWaitError as exc:
            report_onboard(phone, "flood", f"Telegram 限流 {exc.seconds} 秒")
            await _drop_onboard_client(acct)
            return False
        except Exception as exc:  # noqa: BLE001
            log.warning("[%s] QR 2FA sign-in failed: %s", phone, exc)
            report_onboard(phone, "failed", str(exc))
            await _drop_onboard_client(acct)
            return False


def _qr_still_active(phone: str) -> bool:
    """Fresh /pending check for the QR loop (v0.5.26): the onboard
    record must still exist in QR mode before another photo is sent.
    The stop button deletes the record in the Worker, but the KV
    delete can take a while to show up in /pending reads, so the
    loop re-checks before every photo instead of trusting the data
    it started with. A failed fetch returns True (unknown - the
    process_onboard cancel paths remain the backstop)."""
    data = fetch_pending()
    if not data:
        return True
    for item in data.get("onboard", []) or []:
        if norm_phone(item.get("phone", "")) == norm_phone(phone):
            return str(item.get("mode", "") or "") == "qr" and item.get("state") != "cancelled"
    return False


async def _run_onboard_check() -> None:
    """Run process_onboard once on fresh /pending data (v0.5.26).
    The wake-up handler schedules this so a tapped stop/cancel halts
    the QR task within seconds, even while the main loop is busy
    with a check cycle. Serialized with the main loop's own
    process_onboard call via _ONBOARD_LOCK."""
    async with _ONBOARD_LOCK:
        data = fetch_pending()
        await process_onboard(data)


async def run_qr_onboard(acct: Acct) -> None:
    """QR-login onboarding as a background task: send QR photos to
    the owner until one is scanned (30 s each, up to QR_MAX_REFRESH
    regenerations), handle 2FA, verify the scanned account's phone,
    then hand over to _finish_onboard. Runs as an asyncio task so
    the main loop (session checks, code alerts, polls) never blocks;
    process_onboard cancels it when the onboard record disappears
    (停止扫码登录 button) or is cancelled (/cancel_add)."""
    phone = acct.phone
    try:
        await _ensure_onboard_client(acct)
        client = acct.client
        if client is None:
            report_onboard(phone, "failed", "监控端没能创建登录会话")
            return
        if await client.is_user_authorized():
            # Session already authorized (e.g. restored): still verify
            # it belongs to this phone before adopting it.
            me = await client.get_me()
            if norm_phone(getattr(me, "phone", "")) != phone:
                log.warning("[%s] QR onboarding found a different account authorized; logging out.", phone)
                try:
                    await client.log_out()
                except Exception:  # noqa: BLE001
                    pass
                report_onboard(phone, "failed", "扫码登录的是另一个账号，已自动退出")
                await _drop_onboard_client(acct)
                return
            await _finish_onboard(acct)
            return
        refreshes = 0
        photos_sent = 0
        while True:
            # v0.5.26: before each refresh, confirm the onboard record
            # still exists - the stop button deletes it, and a KV-stale
            # /pending at wake-up time must not keep the photos coming.
            # The first photo skips the check: process_onboard just
            # validated the record, and a lagging read must not kill a
            # fresh flow (the task is not restarted for the same record).
            if photos_sent >= 1 and not _qr_still_active(phone):
                log.info("[%s] QR onboarding stopped (record gone).", phone)
                await _drop_onboard_client(acct)
                return
            qr = await client.qr_login()
            caption = (
                f"📷 账号【{acct.label}】扫码登录（第 {refreshes + 1} 张）\n"
                f"30 秒内扫码，过期自动刷新（最多刷新 {QR_MAX_REFRESH} 次）。\n"
                "用这个账号的 Telegram：设置 → 设备 → 链接桌面设备。"
            )
            send_qr_photo(_qr_png(qr.url), caption, phone)
            photos_sent += 1
            try:
                await qr.wait(timeout=QR_WAIT_TIMEOUT)
                break
            except SessionPasswordNeededError:
                if not await _qr_2fa(acct, client):
                    return
                break
            except (asyncio.TimeoutError, AuthTokenExpiredError):
                refreshes += 1
                if refreshes > QR_MAX_REFRESH:
                    log.warning("[%s] QR onboarding gave up after %d refreshes.", phone, QR_MAX_REFRESH)
                    report_onboard(phone, "failed", f"二维码刷新 {QR_MAX_REFRESH} 次都过期了还没扫上")
                    await _drop_onboard_client(acct)
                    return
                continue
        me = await client.get_me()
        if norm_phone(getattr(me, "phone", "")) != phone:
            log.warning("[%s] QR login authorized a different account; logging out.", phone)
            try:
                await client.log_out()
            except Exception:  # noqa: BLE001
                pass
            report_onboard(phone, "failed", "扫码登录的是另一个账号，已自动退出")
            await _drop_onboard_client(acct)
            return
        await _finish_onboard(acct)
    except asyncio.CancelledError:
        log.info("[%s] QR onboarding stopped.", phone)
        await _drop_onboard_client(acct)
        raise
    except FloodWaitError as exc:
        report_onboard(phone, "flood", f"Telegram 限流 {exc.seconds} 秒")
        await _drop_onboard_client(acct)
    except Exception as exc:  # noqa: BLE001 - a QR failure must not kill the monitor
        log.warning("[%s] QR onboarding failed: %s", phone, exc)
        report_onboard(phone, "failed", str(exc))
        await _drop_onboard_client(acct)
    finally:
        if acct.qr_task is asyncio.current_task():
            acct.qr_task = None


def _ensure_qr_task(acct: Acct, item: dict) -> None:
    """Start the QR onboarding task for this record if it is not
    already running. A task that already ran for this exact record
    (same created_at) is not restarted, so a persistent failure
    cannot loop QR photos forever; re-running /add_account creates a
    fresh record and starts again."""
    task = getattr(acct, "qr_task", None)
    if task is not None and not task.done():
        return
    created = "".join(ch for ch in str(item.get("created_at", "") or "") if ch.isdigit())
    if created and created == getattr(acct, "qr_stopped_record", None):
        return
    if acct.qr_task_record is not None and acct.qr_task_record == created:
        return
    acct.qr_task_record = created
    acct.qr_task = asyncio.create_task(run_qr_onboard(acct))


async def _finish_onboard(acct: Acct) -> None:
    """The onboard client is now authorized: it becomes the account's
    monitoring client."""
    acct.authorized = True
    acct.onboard_client = None
    acct.onboard_code_hash = None
    log.info("[%s] Onboarding complete, account is now monitored.", acct.phone)
    report_onboard(acct.phone, "done")
    # Upload the fresh session string to the Worker KV right away so a
    # container restart before the next hourly heartbeat keeps it.
    await upload_heartbeat(acct)
    acct.last_heartbeat = time.time()


async def _drop_onboard_client(acct: Acct) -> None:
    """Disconnect and delete the onboarding client's session file."""
    client = acct.onboard_client or acct.client
    acct.onboard_client = None
    acct.onboard_code_hash = None
    if client is not None:
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001
            pass
    if acct.client is client:
        acct.client = None
    try:
        session_file = acct.session_name + ".session"
        if os.path.exists(session_file):
            os.remove(session_file)
    except OSError:
        pass


async def _ensure_onboard_client(acct: Acct) -> None:
    """Make sure the account has a live client for onboarding.

    A restored session (env / KV / file) that is not authorized may be
    dead for good (e.g. its auth key was used from two IPs at once);
    onboarding needs a brand-new session, so drop such a client (and
    its session file) and create a fresh one. A client already in the
    middle of onboarding is kept as is."""
    if acct.client is not None and not acct.authorized and acct.onboard_client is None:
        await _drop_onboard_client(acct)
    if acct.client is None:
        client = TelegramClient(acct.session_name, int(API_ID), API_HASH)
        client.add_event_handler(make_code_handler(acct), events.NewMessage(from_users=777000))
        await client.connect()
        acct.client = client
        acct.onboard_client = client


async def process_onboard(data: dict) -> None:
    """Drive /add_account onboarding: send the code, sign in with the
    code the owner sends via /code, then with the 2FA password via /2fa.
    The code / password arrive in this /pending payload and are consumed
    on read by the Worker, so each is used at most once here; they are
    kept in memory only and never logged. Records in the
    choose_method state wait for the owner's 短信/扫码 tap; QR records
    (mode="qr") run as background tasks (run_qr_onboard)."""
    items = data.get("onboard", []) or []
    # QR tasks whose record disappeared (the 停止扫码登录 button
    # deletes it in the Worker) must stop and clean up their client.
    onboard_phones = {norm_phone(o.get("phone", "")) for o in items}
    for phone, acct in list(ACCOUNTS.items()):
        task = getattr(acct, "qr_task", None)
        if task is not None and not task.done() and norm_phone(phone) not in onboard_phones:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            # The record may just not have propagated to this read
            # yet (v0.5.27): forget the started-record key so the
            # task can start again when the record shows up. A real
            # stop also sends onboard_qr_stop, whose qr_stopped_record
            # still blocks a restart.
            acct.qr_task_record = None
    for item in items:
        phone = str(item.get("phone", "")).strip()
        if not phone:
            continue
        state = item.get("state", "")
        acct = ACCOUNTS.get(phone)
        if state == "cancelled":
            if acct is not None:
                task = getattr(acct, "qr_task", None)
                if task is not None and not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                await _drop_onboard_client(acct)
                if not acct.authorized:
                    ACCOUNTS.pop(phone, None)
                log.info("[%s] Onboarding cancelled, cleaned up.", phone)
            report_onboard(phone, "cancelled_done")
            continue
        if acct is None:
            acct = Acct(phone, str(item.get("name", "") or ""))
            ACCOUNTS[phone] = acct
        mode = str(item.get("mode", "") or "")
        if state == "choose_method":
            continue  # owner has not picked 短信/扫码 yet
        if mode == "qr":
            if state == "password_received":
                pw = str(item.get("password", "") or "")
                if pw:
                    acct.qr_password = pw
            _ensure_qr_task(acct, item)
            continue
        try:
            if state == "pending_send":
                await _ensure_onboard_client(acct)
                if await acct.client.is_user_authorized():
                    await _finish_onboard(acct)
                    continue
                try:
                    sent = await acct.client.send_code_request(phone)
                    acct.onboard_code_hash = sent.phone_code_hash
                except FloodWaitError as exc:
                    log.warning("[%s] Onboard: flood wait %s s on code request.", phone, exc.seconds)
                    report_onboard(phone, "flood", f"Telegram 限流 {exc.seconds} 秒")
                    continue
                except Exception as exc:  # noqa: BLE001
                    log.warning("[%s] Onboard: code request failed: %s", phone, exc)
                    report_onboard(phone, "send_failed", str(exc))
                    continue
                report_onboard(phone, "code_sent")
            elif state == "code_received":
                code = str(item.get("code", "") or "").strip()
                if not code:
                    continue  # secret already consumed by an earlier poll; wait for a re-send
                if acct.client is None or not acct.onboard_code_hash:
                    # The code hash was lost (e.g. monitor restarted after
                    # the code was requested): request a fresh code and ask
                    # the owner to send the new one.
                    try:
                        await _ensure_onboard_client(acct)
                        sent = await acct.client.send_code_request(phone)
                        acct.onboard_code_hash = sent.phone_code_hash
                    except FloodWaitError as exc:
                        report_onboard(phone, "flood", f"Telegram 限流 {exc.seconds} 秒")
                        continue
                    except Exception as exc:  # noqa: BLE001
                        report_onboard(phone, "send_failed", str(exc))
                        continue
                    report_onboard(phone, "code_sent", "已重新发送验证码")
                    continue
                try:
                    await acct.client.sign_in(phone, code, phone_code_hash=acct.onboard_code_hash)
                except SessionPasswordNeededError:
                    report_onboard(phone, "awaiting_2fa")
                    continue
                except PhoneCodeInvalidError:
                    report_onboard(phone, "code_invalid")
                    continue
                except PhoneCodeExpiredError:
                    try:
                        sent = await acct.client.send_code_request(phone)
                        acct.onboard_code_hash = sent.phone_code_hash
                    except FloodWaitError as exc:
                        report_onboard(phone, "flood", f"Telegram 限流 {exc.seconds} 秒")
                        continue
                    except Exception as exc:  # noqa: BLE001
                        report_onboard(phone, "send_failed", str(exc))
                        continue
                    report_onboard(phone, "code_sent", "验证码已过期，已重新发送")
                    continue
                except FloodWaitError as exc:
                    report_onboard(phone, "flood", f"Telegram 限流 {exc.seconds} 秒")
                    continue
                except Exception as exc:  # noqa: BLE001
                    log.warning("[%s] Onboard: sign-in failed: %s", phone, exc)
                    report_onboard(phone, "failed", str(exc))
                    continue
                await _finish_onboard(acct)
            elif state == "password_received":
                password = str(item.get("password", "") or "")
                if not password or acct.client is None:
                    continue  # secret already consumed; wait for a re-send
                try:
                    await acct.client.sign_in(password=password)
                except PasswordHashInvalidError:
                    report_onboard(phone, "password_invalid")
                    continue
                except FloodWaitError as exc:
                    report_onboard(phone, "flood", f"Telegram 限流 {exc.seconds} 秒")
                    continue
                except Exception as exc:  # noqa: BLE001
                    log.warning("[%s] Onboard: 2FA sign-in failed: %s", phone, exc)
                    report_onboard(phone, "failed", str(exc))
                    continue
                await _finish_onboard(acct)
        except Exception as exc:  # noqa: BLE001 - one account's onboarding must not stop the others
            log.warning("[%s] Onboard processing failed: %s", phone, exc)


async def sync_main_phone(data: dict) -> None:
    """Adopt a new phone number for the main (seed) account after the
    owner changed it in Telegram and ran /change_phone (so the Worker's
    account list now carries the new number). The session file is the
    fixed "tg_guardian" one and stays valid (same account); only TG
    Guardian's phone label moves, so no PHONE env-var change and no
    manual restart are needed. Ground truth is get_me().phone, and we
    only re-key when the new number is already in the Worker's list
    (i.e. /change_phone has run); otherwise the stale label keeps
    working and the owner can migrate later. Also moves the persisted
    per-account state (session baseline, code_processed)."""
    global PHONE
    phones = {norm_phone(e.get("phone", "")) for e in data.get("accounts", []) or []}
    phones.discard("")
    if not phones or PHONE in phones:
        return
    acct = ACCOUNTS.get(PHONE)
    if not acct or not acct.authorized or acct.client is None:
        return
    try:
        me = await acct.client.get_me()
    except Exception:  # noqa: BLE001
        return
    actual = norm_phone(getattr(me, "phone", "") or "")
    if not actual or actual == PHONE or actual not in phones:
        return
    old = PHONE
    try:
        state = load_state()
        accounts_state = state.get("accounts", {})
        if isinstance(accounts_state, dict) and old in accounts_state:
            accounts_state[actual] = accounts_state.pop(old)
            state["accounts"] = accounts_state
            with open(STATE_FILE, "w", encoding="utf-8") as fh:
                json.dump(state, fh, ensure_ascii=False, indent=2)
    except Exception as exc:  # noqa: BLE001
        log.warning("Phone-change state migration failed: %s", exc)
    acct.phone = actual
    ACCOUNTS.pop(old, None)
    ACCOUNTS[actual] = acct
    PHONE = actual
    log.info("[%s] Main account phone changed %s -> %s; re-keyed, session unchanged.", actual, old, actual)


async def ensure_clients(data: dict) -> None:
    """Create clients for Worker-listed accounts we do not have yet
    (e.g. after a monitor restart, from their saved session files).
    Onboarding accounts are handled by process_onboard instead."""
    onboard_phones = {str(o.get("phone", "")) for o in data.get("onboard", []) or []}
    warned = getattr(ensure_clients, "_warned", set())
    for entry in data.get("accounts", []) or []:
        phone = norm_phone(entry.get("phone", ""))
        if not phone:
            continue
        # A rename in the Worker (via /rename_account) reaches the
        # monitor through the accounts list; sync the display name so
        # alerts use the new name without a restart.
        if phone in ACCOUNTS:
            new_name = str(entry.get("name", "") or "")
            if ACCOUNTS[phone].name != new_name:
                ACCOUNTS[phone].name = new_name
        if phone in ACCOUNTS or phone in onboard_phones:
            continue
        acct = Acct(phone, str(entry.get("name", "") or ""))
        ACCOUNTS[phone] = acct
        try:
            kv_string = str(((data.get("per_account") or {}).get(phone) or {}).get("session_string") or "")
            client = TelegramClient(account_session(phone, acct.session_name, kv_string), int(API_ID), API_HASH)
            client.add_event_handler(make_code_handler(acct), events.NewMessage(from_users=777000))
            await client.connect()
            acct.client = client
            if await client.is_user_authorized():
                acct.authorized = True
                me = await client.get_me()
                log.info("[%s] Monitoring client restored as %s.", phone, me.username or me.first_name)
            else:
                log.warning("[%s] Restored session is not authorized; re-add with /add_account.", phone)
                if phone not in warned:
                    warned.add(phone)
                    send_bot_alert(f"⚠️ 账号【{acct.label}】会话失效：先 /remove_account {display_phone(phone)}，再 /add_account {display_phone(phone)}。")
        except Exception as exc:  # noqa: BLE001
            log.warning("[%s] Failed to start monitoring client: %s", phone, exc)
            if isinstance(exc, AuthKeyDuplicatedError) and phone not in warned:
                warned.add(phone)
                send_bot_alert(f"⚠️ 账号【{acct.label}】会话失效：先 /remove_account {display_phone(phone)}，再 /add_account {display_phone(phone)}。")
            ACCOUNTS.pop(phone, None)
    ensure_clients._warned = warned


async def cleanup_accounts(data: dict) -> None:
    """Drop clients for accounts the owner removed, and clean up orphaned
    onboarding clients (their onboard record is gone without a done)."""
    removed = {norm_phone(r) for r in (data.get("removed", []) or [])}
    onboard_phones = {norm_phone(o.get("phone", "")) for o in data.get("onboard", []) or []}
    listed = {norm_phone(a.get("phone", "")) for a in data.get("accounts", []) or []}
    for phone in list(ACCOUNTS):
        acct = ACCOUNTS[phone]
        if getattr(acct, "qr_task", None) is not None and not acct.qr_task.done():
            continue  # QR task owns this client; process_onboard stops it
        if phone in removed and len(ACCOUNTS) > 1:
            log.info("[%s] Account removed by owner, dropping client and session file.", phone)
            await _drop_onboard_client(acct)
            ACCOUNTS.pop(phone, None)
            continue
        if not acct.authorized and phone not in listed and phone not in onboard_phones:
            log.info("[%s] Orphaned onboarding client, cleaning up.", phone)
            await _drop_onboard_client(acct)
            ACCOUNTS.pop(phone, None)


async def main() -> None:
    if not API_ID or not API_HASH:
        log.error("API_ID / API_HASH are not set. Set them in Enzonic Variables and restart.")
        sys.exit(2)

    # Bootstrap the main (seed) account: the original single account.
    # Session priority (v0.5.22): the StringSession stored in the Worker
    # KV (kept fresh by heartbeats), then the SESSION_STRING env seed,
    # then the legacy session file.
    kv_string = ""
    try:
        boot_data = fetch_pending()
        kv_string = str(((boot_data.get("per_account") or {}).get(PHONE) or {}).get("session_string") or "")
    except Exception:  # noqa: BLE001 - fall back to env/file below
        kv_string = ""
    if kv_string:
        session = StringSession(kv_string)
    elif SESSION_STRING:
        session = StringSession(SESSION_STRING)
    else:
        session = "tg_guardian"

    main_acct = Acct(PHONE, "主账号")
    ACCOUNTS[PHONE] = main_acct
    client = TelegramClient(session, int(API_ID), API_HASH)
    # Real-time login-code alerts (v0.3): Telegram delivers the code as a
    # 777000 message to this already-logged-in account.
    client.add_event_handler(make_code_handler(main_acct), events.NewMessage(from_users=777000))
    main_acct.client = client
    main_authorized = False
    try:
        await client.connect()
        main_authorized = await client.is_user_authorized()
    except Exception as exc:  # noqa: BLE001 - a dead session must not crash-loop the monitor
        log.warning("Main account session unusable (%s); staying up for re-login via /remove_account + /add_account.", exc)
    if not main_authorized and (kv_string or SESSION_STRING):
        # Stateless hosting: never block on an interactive login; the
        # owner re-logins through the bot (/remove_account + /add_account).
        send_bot_alert(f"⚠️ 账号【{main_acct.label}】会话失效：先 /remove_account {display_phone(PHONE)}，再 /add_account {display_phone(PHONE)}。")
        log.warning("Main account not authorized; monitor stays up for re-login via the bot.")
    elif not main_authorized:
        if not PHONE:
            log.error(
                "Not authorized yet. Set SESSION_STRING, or set PHONE and run once "
                "interactively (Telegram login code + 2FA password) to create the session."
            )
            sys.exit(3)
        log.info("First login: sending code to %s ...", PHONE)
        await client.send_code_request(PHONE)
        code = input("Telegram login code: ").strip()
        try:
            await client.sign_in(PHONE, code)
        except Exception:
            password = input("2FA password: ").strip()
            await client.sign_in(password=password)
        main_authorized = True
        if SESSION_STRING == "":
            log.info("Authorized. Session saved to tg_guardian.session - keep this file safe, never upload it to GitHub.")

    main_acct.authorized = main_authorized
    if main_authorized:
        me = await client.get_me()
        log.info("TG Guardian MTProto monitor %s started as %s (id=%s).", VERSION, me.username or me.first_name, me.id)
    else:
        log.info("TG Guardian MTProto monitor %s started (main account awaiting re-login).", VERSION)
    # Adopt a changed main-account number (after /change_phone) before
    # registering, so a stale PHONE env var doesn't re-add the old number.
    try:
        await sync_main_phone(fetch_pending())
    except Exception:  # noqa: BLE001
        pass
    register_account(PHONE, "主账号")
    bot_id = fetch_bot_id()
    if bot_id:
        client.add_event_handler(make_wakeup_handler(bot_id), events.NewMessage(from_users=bot_id))
        log.info("Decision wake-up attached (bot id=%s).", bot_id)
    else:
        log.warning("Could not fetch bot id; decision wake-up disabled (poll backstop still works).")
    send_bot_alert(
        f"✅ TG Guardian 监控 {VERSION} 已启动：新设备先告警，超时自动注销；验证码告警三个按钮，超时自动冻结二级密码"
        "（时间用 /set_guard、/set_revoke 改）；每小时上报心跳和设备快照。"
    )

    last_register = time.time()
    while True:
        try:
            data = fetch_pending()
            # Direct decisions carried in wake-up messages (v0.5.9):
            # run them before the poll path sees them, so the poll path
            # finds them already handled.
            while DIRECT_QUEUE:
                kind, phone, ident = DIRECT_QUEUE.pop(0)
                await execute_directive(kind, phone, ident, data)
            await sync_main_phone(data)
            await ensure_clients(data)
            async with _ONBOARD_LOCK:
                await process_onboard(data)
            await cleanup_accounts(data)
            # Re-register the main account if the Worker has no accounts
            # yet (e.g. KV was wiped), at most once an hour.
            if not data.get("accounts") and time.time() - last_register >= 3600:
                register_account(PHONE, "主账号")
                last_register = time.time()
            now = time.time()
            # Fast check window (v0.5.10): a code was requested recently,
            # so a new session may appear any second — check every 3 s.
            check_interval = FAST_CHECK_INTERVAL if fast_check_active() else CHECK_INTERVAL
            for phone in list(ACCOUNTS):
                acct = ACCOUNTS[phone]
                if not acct.authorized or acct.client is None:
                    continue
                try:
                    if not acct.client.is_connected():
                        log.warning("[%s] Client disconnected, reconnecting.", phone)
                        await acct.client.connect()
                    if now - acct.last_check >= check_interval:
                        await check_once(acct)
                        acct.last_check = time.time()
                    if now - acct.last_heartbeat >= HEARTBEAT_INTERVAL:
                        await upload_heartbeat(acct)
                        acct.last_heartbeat = time.time()
                    await process_pending(acct, data)
                    await process_code_events(acct, data)
                    await process_flood_probe(acct, data)
                    await process_sustain(acct, data)
                    await check_pause_expiry(acct, data)
                    acct.last_ok = time.time()
                except Exception as exc:  # noqa: BLE001 - one account's failure must not stop the others
                    log.warning("[%s] Monitor cycle failed, will retry: %s", phone, exc)
                    if isinstance(exc, AuthKeyDuplicatedError):
                        # Session permanently dead: stop cycling this account
                        # and wait for the owner to re-login via the bot.
                        acct.authorized = False
                        if not getattr(acct, "_dead_alerted", False):
                            acct._dead_alerted = True
                            send_bot_alert(f"⚠️ 账号【{acct.label}】会话失效：先 /remove_account {display_phone(phone)}，再 /add_account {display_phone(phone)}。")
                    elif time.time() - acct.last_ok > DISCONNECT_EXIT_AFTER:
                        log.error("[%s] No successful cycle for %d s, exiting so the platform restarts the monitor.", phone, DISCONNECT_EXIT_AFTER)
                        os._exit(1)
        except Exception as exc:  # noqa: BLE001 - keep polling through transient errors
            log.warning("Monitor cycle failed, will retry: %s", exc)
        # Sleep 3 s while the fast-check window is open (so the next
        # check runs on time), otherwise the usual 120 s poll cadence.
        sleep_s = FAST_CHECK_INTERVAL if fast_check_active() else POLL_INTERVAL
        try:
            await asyncio.wait_for(WAKEUP.wait(), timeout=sleep_s)
        except asyncio.TimeoutError:
            pass
        WAKEUP.clear()


if __name__ == "__main__":
    asyncio.run(main())
