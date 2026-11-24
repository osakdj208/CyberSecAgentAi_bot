#!/usr/bin/env python3
"""
CYBER SECURITY AI AGENT - Telegram Bot
======================================
Telegram front-end for the existing Next.js + FastAPI engine project.

Design (mirrors the web app's safety model in docs/ADMIN-APPROVAL.md):
- Anyone who can open the bot may *submit* a scan request (public IPv4 only).
- Nothing is scanned on submission. Every request stays `pending`.
- Only the admin (ADMIN_TELEGRAM_ID) can approve/reject, via inline buttons.
- On approval the bot mints a short-lived, IP-bound HMAC permit in exactly
  the format the engine verifies (engine/main.py: valid_dynamic_permit),
  then calls the engine's /scans/intel endpoint with the bearer token.
- The engine remains the final guard: AUTHORIZED_CIDRS allowlist, global-IP
  check, bounded Nmap profile (top 10-100 TCP ports, no NSE/exploits).

Stdlib only: no pip installs needed. Config comes from environment variables
(see .env.example). Secrets are never hard-coded and never logged.
"""
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

# ---------------------------------------------------------------- config
TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
ADMIN_ID = int(os.environ.get("ADMIN_TELEGRAM_ID", "0") or 0)
ENGINE_URL = os.environ.get("ENGINE_URL", "").rstrip("/")
ENGINE_TOKEN = os.environ.get("ENGINE_API_TOKEN", "")
PERMIT_SECRET = os.environ.get("SCAN_APPROVAL_SECRET", "")
DB_PATH = os.environ.get("BOT_DB_PATH", os.path.join(os.path.dirname(__file__), "bot.db"))
APPROVAL_TTL_HOURS = 24          # same as the web workflow
PERMIT_TTL_MS = 5 * 60 * 1000    # permit is minted at scan time, short-lived

CATALOG_NOTE = (
    "الكتالوج في المشروع يضم عشرات الأدوات (ZAP, Nuclei, Trivy, YARA وغيرها) "
    "لكن حالتها كلها «مخطط لها». الموصّل الوحيد الجاهز فعلياً هو Nmap + "
    "استخبارات IP السلبية، وهذا البوت يعرض ذلك بصدق ولا يدّعي تشغيل البقية."
)

# ---------------------------------------------------------------- storage
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """CREATE TABLE IF NOT EXISTS scan_requests(
               id TEXT PRIMARY KEY, user_id INTEGER, username TEXT,
               ip TEXT, auth_ref TEXT, top_ports INTEGER,
               status TEXT, created_at REAL, expires_at REAL,
               result TEXT, error TEXT,
               proof_file_id TEXT, proof_text TEXT)"""
    )
    return conn


def save_request(req):
    with db() as c:
        c.execute(
            "INSERT INTO scan_requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (req["id"], req["user_id"], req["username"], req["ip"],
             req["auth_ref"], req["top_ports"], req["status"],
             req["created_at"], req["expires_at"], None, None,
             req.get("proof_file_id"), req.get("proof_text")),
        )


def get_request(rid):
    with db() as c:
        row = c.execute("SELECT * FROM scan_requests WHERE id=?", (rid,)).fetchone()
    return dict(row) if row else None


def list_requests(user_id, limit=10):
    with db() as c:
        rows = c.execute(
            "SELECT * FROM scan_requests WHERE user_id=? ORDER BY created_at DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def transition(rid, from_status, to_status, result=None, error=None):
    """Atomically move a request between states (mirrors transitionPendingRequest)."""
    with db() as c:
        cur = c.execute(
            "UPDATE scan_requests SET status=?, result=COALESCE(?,result), error=COALESCE(?,error)"
            " WHERE id=? AND status=?",
            (to_status, result, error, rid, from_status),
        )
        return cur.rowcount == 1


# ---------------------------------------------------------------- security helpers
def validate_target(value: str) -> str:
    """Same rules as the web validator + engine: literal, globally routable IPv4/IPv6."""
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        raise ValueError("الهدف يجب أن يكون عنوان IP حرفياً (لا تُقبل أسماء النطاقات).")
    if not address.is_global:
        raise ValueError("تُقبل فقط عناوين IP العامة القابلة للتوجيه عالمياً.")
    return str(address)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def create_scan_permit(ip: str, request_id: str, expires_ms: int) -> str:
    """Byte-compatible with app/lib/approval-store.ts createScanPermit()."""
    if not PERMIT_SECRET:
        raise RuntimeError("SCAN_APPROVAL_SECRET is not configured")
    payload = _b64url(json.dumps(
        {"ip": ip, "id": request_id, "exp": expires_ms},
        separators=(",", ":")).encode())
    signature = _b64url(hmac.new(
        PERMIT_SECRET.encode(), payload.encode(), hashlib.sha256).digest())
    return payload + "." + signature


# ---------------------------------------------------------------- engine client
def engine_call(method, path, body=None, permit=None):
    if not ENGINE_URL or not ENGINE_TOKEN:
        raise RuntimeError("المحرك غير مربوط بعد: ENGINE_URL / ENGINE_API_TOKEN غير مضبوطة.")
    headers = {"Authorization": f"Bearer {ENGINE_TOKEN}", "Content-Type": "application/json"}
    if permit:
        headers["X-Scan-Approval"] = permit
    req = urllib.request.Request(
        ENGINE_URL + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise RuntimeError(f"المحرك رفض الطلب ({exc.code}): {detail}") from exc


def run_approved_scan(req):
    permit = create_scan_permit(req["ip"], req["id"], int(time.time() * 1000) + PERMIT_TTL_MS)
    return engine_call("POST", "/scans/intel", body={
        "target_ip": req["ip"],
        "authorization_reference": req["auth_ref"],
        "confirm_authorized": True,
        "top_ports": req["top_ports"],
    }, permit=permit)


def format_report(req, result) -> str:
    lines = [f"✅ اكتمل الفحص للهدف {result.get('target', req['ip'])}",
             f"المرجع: {req['auth_ref']}  |  الملف: {result.get('profile','')}"]
    summary = result.get("summary") or {}
    if summary:
        lines.append(f"المنافذ المرصودة: {summary.get('ports_observed','?')} "
                     f"| المفتوحة: {summary.get('open_ports','?')}")
    ports = [p for p in (result.get("ports") or []) if p.get("state") == "open"]
    if ports:
        lines.append("\nالمنافذ المفتوحة:")
        for p in ports[:50]:
            svc = " ".join(x for x in [p.get("service"), p.get("product"), p.get("version")] if x)
            lines.append(f"• {p.get('port')}/{p.get('protocol')} — {svc}")
    passive = result.get("passive") or {}
    geo = passive.get("geo") or {}
    if geo:
        lines.append("\nمعلومات عامة: " + "، ".join(f"{k}: {v}" for k, v in geo.items()))
    rdns = (passive.get("reverse_dns") or {}).get("hostname")
    if rdns:
        lines.append(f"DNS العكسي: {rdns}")
    for warning in (passive.get("warnings") or [])[:5]:
        lines.append(f"⚠️ {warning}")
    lines.append("\nالحدود: فحص محدود بأشهر 100 منفذ TCP، بلا استغلال ولا سكربتات اقتحامية.")
    return "\n".join(lines)


# ---------------------------------------------------------------- telegram api
# Two modes:
# - Direct: TELEGRAM_BOT_TOKEN in env (normal VPS deployment).
# - Connector: TELEGRAM_API_HELPER points to the custom.telegram-bot helper;
#   the token lives in the Secure Vault and is swapped in on egress, so this
#   process never sees the real token.
HELPER = os.environ.get("TELEGRAM_API_HELPER", "")


def tg(method, **params):
    http_timeout = params.pop("_http_timeout", 130)
    if HELPER:
        out = subprocess.run(
            [sys.executable, HELPER, method, json.dumps(params)],
            capture_output=True, text=True, timeout=140)
        if out.returncode != 0:
            raise RuntimeError(f"telegram helper failed: {out.stderr.strip()[:300]}")
        return json.loads(out.stdout)
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{TOKEN}/{method}",
        data=json.dumps(params).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=http_timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(f"telegram HTTP {exc.code}: {body}") from exc


def send(chat_id, text, reply_markup=None):
    payload = {"chat_id": chat_id, "text": text[:4000]}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    return tg("sendMessage", **payload)


def kb(rows):
    return {"inline_keyboard": [[{"text": t, "callback_data": d} for t, d in row] for row in rows]}


MAIN_KB = kb([
    [("🔎 طلب فحص جديد", "new_scan")],
    [("📋 طلباتي", "my_requests"), ("🩺 حالة المحرك", "health")],
    [("🧰 كتالوج الأدوات", "catalog")],
])

# per-user conversation state (in-memory; durable data lives in SQLite)
STATE = {}


def handle_message(msg):
    chat_id = msg["chat"]["id"]
    user = msg.get("from", {})
    text = (msg.get("text") or "").strip()
    state = STATE.get(chat_id)

    if text.startswith("/start"):
        STATE.pop(chat_id, None)
        send(chat_id,
             "مرحباً بك في بوت CYBER SECURITY AI AGENT 🛡️\n"
             "منصة دفاعية: فحص Nmap محدود + استخبارات IP، ولا يُنفَّذ أي فحص "
             "إلا بعد موافقة الأدمن على الهدف المحدد.\n\nاختر من القائمة:",
             MAIN_KB)
        return
    if text.startswith("/health"):
        return show_health(chat_id)
    if text.startswith("/myrequests"):
        return show_my_requests(chat_id, user.get("id"))
    if text.startswith("/catalog"):
        send(chat_id, "🧰 " + CATALOG_NOTE +
             "\n\nالموصّل الجاهز: Nmap TCP/service discovery (أشهر 10–100 منفذ) "
             "+ RDAP + RIPEstat + DNS عكسي + جغرافيا IP + سمعة AbuseIPDB (اختياري).",
             MAIN_KB)
        return

    if state and state["step"] == "await_ip":
        try:
            ip = validate_target(text)
        except ValueError as exc:
            send(chat_id, f"❌ {exc}\nأرسل عنوان IP عاماً صحيحاً، أو /start للإلغاء.")
            return
        state.update(step="await_ref", ip=ip)
        send(chat_id, f"الهدف: {ip}\nالآن أرسل مرجع التصريح (مثال: رقم التذكرة أو lab-2026-001) "
                      "— إثبات أنك تملك هذا العنوان أو لديك تصريح مكتوب لفحصه.")
        return
    if state and state["step"] == "await_ref":
        if not (4 <= len(text) <= 120):
            send(chat_id, "❌ مرجع التصريح يجب أن يكون بين 4 و120 حرفاً. أعد الإرسال.")
            return
        state.update(step="await_proof", auth_ref=text)
        send(chat_id, "الآن أرسل إثبات التصريح ليتحقق منه الأدمن قبل القرار: "
                      "مستند أو صورة (فاتورة الخادم، لوحة المزوّد، تصريح مكتوب)، "
                      "أو اكتب تفاصيل الإثبات نصاً. إن لم يوجد إثبات جاهز أرسل «تخطي» "
                      "— وسيبقى القرار النهائي للأدمن.")
        return
    if state and state["step"] == "await_proof":
        proof_file_id = None
        proof_text = None
        if msg.get("document"):
            proof_file_id = msg["document"]["file_id"]
            proof_text = msg.get("caption") or "مستند إثبات مرفق"
        elif msg.get("photo"):
            proof_file_id = msg["photo"][-1]["file_id"]
            proof_text = msg.get("caption") or "صورة إثبات مرفقة"
        elif text and text not in ("تخطي", "skip"):
            proof_text = text[:1000]
        state.update(step="await_ports", proof_file_id=proof_file_id,
                     proof_text=proof_text)
        send(chat_id, "اختر حجم الفحص:", kb([
            [("10 منافذ", "ports:10"), ("50 منفذاً", "ports:50"), ("100 منفذ", "ports:100")]]))
        return
    send(chat_id, "اختر من القائمة، أو أرسل /start للبدء.", MAIN_KB)


def show_health(chat_id):
    try:
        health = engine_call("GET", "/health")
        tools = engine_call("GET", "/tools")
        ready = health.get("execution_enabled")
        tool_lines = "\n".join(
            f"• {t['name']}: {t['state']}" for t in tools.get("available", []))
        send(chat_id, f"🩺 حالة المحرك: {'جاهز ✅' if ready else 'متدهور ⚠️'}\n{tool_lines}", MAIN_KB)
    except Exception as exc:  # engine not deployed/configured yet
        send(chat_id, f"🩺 المحرك غير متاح حالياً.\n{exc}", MAIN_KB)


def show_my_requests(chat_id, user_id):
    rows = list_requests(user_id)
    if not rows:
        send(chat_id, "لا توجد طلبات بعد.", MAIN_KB)
        return
    icons = {"pending": "⏳", "approved": "✅", "rejected": "🚫",
             "scanning": "🔄", "completed": "✔️", "failed": "❌"}
    lines = [f"{icons.get(r['status'],'•')} {r['ip']} — {r['status']} — {r['id'][:8]}"
             for r in rows]
    send(chat_id, "📋 آخر طلباتك:\n" + "\n".join(lines), MAIN_KB)


def notify_admin(req):
    if not ADMIN_ID:
        return
    send(ADMIN_ID,
         "🔔 طلب فحص جديد بانتظار قرارك\n"
         f"الهدف: {req['ip']}\nمن: {req['username']} (ID {req['user_id']})\n"
         f"مرجع التصريح: {req['auth_ref']}\nالمنافذ: {req['top_ports']}\n"
         f"إثبات التصريح: {req.get('proof_text') or 'غير مرفق — تحقق بنفسك قبل الاعتماد'}\n"
         f"رقم الطلب: {req['id'][:8]}",
         kb([[("✅ اعتماد وتنفيذ", f"approve:{req['id']}"),
              ("🚫 رفض", f"reject:{req['id']}")]]))
    if req.get("proof_file_id"):
        try:
            tg("sendDocument", chat_id=ADMIN_ID, document=req["proof_file_id"],
               caption=f"إثبات تصريح الطلب {req['id'][:8]} للهدف {req['ip']}")
        except Exception:
            try:
                tg("sendPhoto", chat_id=ADMIN_ID, photo=req["proof_file_id"],
                   caption=f"إثبات تصريح الطلب {req['id'][:8]} للهدف {req['ip']}")
            except Exception as exc:
                print("proof forward error:", exc)


def handle_callback(cb):
    data = cb.get("data", "")
    msg = cb.get("message", {})
    chat_id = msg.get("chat", {}).get("id")
    user = cb.get("from", {})
    tg("answerCallbackQuery", callback_query_id=cb["id"])

    if data == "new_scan":
        STATE[chat_id] = {"step": "await_ip"}
        send(chat_id, "أرسل عنوان IP العام المراد فحصه (مثال: 203.0.113.10).\n"
                      "تنبيه: لا ترسل إلا عنواناً تملكه أو لديك تصريح مكتوب لفحصه.")
    elif data == "health":
        show_health(chat_id)
    elif data == "my_requests":
        show_my_requests(chat_id, user.get("id"))
    elif data == "catalog":
        send(chat_id, "🧰 " + CATALOG_NOTE, MAIN_KB)
    elif data.startswith("ports:"):
        state = STATE.get(chat_id)
        if not state or state.get("step") != "await_ports":
            send(chat_id, "انتهت الجلسة، ابدأ من جديد بـ /start")
            return
        top_ports = int(data.split(":")[1])
        req = {
            "id": uuid.uuid4().hex, "user_id": user.get("id"),
            "username": user.get("username") or user.get("first_name", "?"),
            "ip": state["ip"], "auth_ref": state["auth_ref"],
            "proof_file_id": state.get("proof_file_id"),
            "proof_text": state.get("proof_text"),
            "top_ports": top_ports, "status": "pending",
            "created_at": time.time(),
            "expires_at": time.time() + APPROVAL_TTL_HOURS * 3600,
        }
        save_request(req)
        STATE.pop(chat_id, None)
        send(chat_id, f"⏳ تم إنشاء الطلب {req['id'][:8]} للهدف {req['ip']}.\n"
                      "لن يبدأ أي فحص قبل موافقة الأدمن. ستصلك النتيجة هنا.")
        notify_admin(req)
    elif data.startswith(("approve:", "reject:")):
        if user.get("id") != ADMIN_ID:
            send(chat_id, "🚫 هذا القرار للأدمن فقط.")
            return
        action, rid = data.split(":", 1)
        req = get_request(rid)
        if not req or req["status"] != "pending":
            send(chat_id, "هذا الطلب لم يعد معلّقاً.")
            return
        if req["expires_at"] < time.time():
            transition(rid, "pending", "failed", error="approval expired")
            send(chat_id, "انتهت صلاحية هذا الطلب (24 ساعة).")
            return
        if action == "reject":
            transition(rid, "pending", "rejected")
            send(chat_id, f"🚫 رفضت طلب {rid[:8]}.")
            send(req["user_id"], f"🚫 تم رفض طلب فحص {req['ip']} من الأدمن.")
            return
        # approve -> scan (the engine re-validates allowlist + permit anyway)
        if not transition(rid, "pending", "scanning"):
            send(chat_id, "هذا الطلب قيد المعالجة أصلاً.")
            return
        send(chat_id, f"✅ اعتمدت {rid[:8]}، جارٍ الفحص…")
        send(req["user_id"], f"🔄 بدأ فحص {req['ip']}، قد يستغرق حتى دقيقتين…")
        try:
            result = run_approved_scan(req)
            transition(rid, "scanning", "completed", result=json.dumps(result))
            report = format_report(req, result)
            send(req["user_id"], report, MAIN_KB)
            if req["user_id"] != ADMIN_ID:
                send(ADMIN_ID, f"✔️ اكتمل فحص {req['ip']} وأُرسل التقرير للمستخدم.")
        except Exception as exc:
            transition(rid, "scanning", "failed", error=str(exc)[:400])
            send(req["user_id"], f"❌ فشل فحص {req['ip']}: {exc}")
            send(ADMIN_ID, f"❌ فشل فحص {req['ip']} ({rid[:8]}): {exc}")


def main():
    if not TOKEN and not HELPER:
        raise SystemExit("Set TELEGRAM_BOT_TOKEN or TELEGRAM_API_HELPER (see .env.example)")
    if not ADMIN_ID:
        print("WARNING: ADMIN_TELEGRAM_ID is not set - nobody can approve scans.")
    try:
        me = tg("getMe")
        print("Bot identity:", (me.get("result") or {}).get("username"))
    except Exception as exc:
        print("getMe failed:", exc)
    try:
        tg("deleteWebhook", drop_pending_updates=False)
    except Exception as exc:
        print("deleteWebhook failed:", exc)
    offset = 0
    backoff = 5
    print("Bot is running (long polling)…")
    while True:
        try:
            resp = tg("getUpdates", offset=offset, timeout=50,
                      allowed_updates=["message", "callback_query"],
                      _http_timeout=70)
        except Exception as exc:
            wait = backoff
            text = str(exc)
            match = re.search(r'"retry_after":\s*(\d+)', text)
            if match:
                wait = max(wait, int(match.group(1)) + 2)
            if "409" in text:
                wait = max(wait, 30)
                try:
                    tg("deleteWebhook", drop_pending_updates=False)
                except Exception:
                    pass
            print(f"poll error: {exc} (retry in {wait}s)")
            time.sleep(wait)
            backoff = min(backoff * 2, 60)
            continue
        backoff = 5
        for update in resp.get("result", []):
            offset = update["update_id"] + 1
            try:
                if "message" in update:
                    handle_message(update["message"])
                elif "callback_query" in update:
                    handle_callback(update["callback_query"])
            except Exception as exc:  # keep polling on per-update errors
                print("update error:", exc)


if __name__ == "__main__":
    main()
