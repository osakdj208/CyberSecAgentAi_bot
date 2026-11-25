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
import html
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import sys
import threading
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
BOT_MODE = os.environ.get("BOT_MODE", "poll").strip().lower()
WEBHOOK_BASE = os.environ.get("WEBHOOK_BASE", "").rstrip("/")

CATALOG_NOTE = (
    "الموصّلات الجاهزة فعلياً: (1) فحص IP: Nmap محدود + استخبارات IP سلبية. "
    "(2) فحص موقع شامل: كشف ثغرات Nuclei بقوالب مقيدة + فحص TLS عميق + "
    "ترويسات أمان HTTP + سجلات DNS. "
    "(3) فحص موقع عميق: قوالب CVE الكاملة على دفعات + زحف Katana لاكتشاف "
    "الصفحات والروابط + بحث ساكن عن أصل الخادم خلف Cloudflare + فحص اختياري "
    "بجلسة حساب اختبار. "
    "(4) فحص خادم الأصل مباشرة بهوية الموقع + بصمة مرور متفق عليها لعبور "
    "جدران الحماية بتصريح المالك. "
    "(5) بطاقة حساب تيليجرام: بطاقة معلومات عامة لأي حساب أو قناة أو مجموعة "
    "عامة (الاسم والنوع وعدد الأعضاء والوصف العام + تقدير تقريبي لتاريخ "
    "الإنشاء من نطاق المعرف الرقمي) — بيانات منشورة علناً فقط. ومع تفعيل "
    "البحث العميق (حساب تيليجرام مخصص): الرقم الرقمي لأي معرف عام + علامات "
    "تيليجرام الرسمية (موثّق/احتيالي/مزيّف) + عدد صور الملف ومجموعة النقاش "
    "المرتبطة بالقناة. "
    "(6) بطاقة رقم هاتف: بيانات الترقيم العالمية لأي رقم بالصيغة الدولية "
    "(الدولة والمشغّل المسجل لنطاق الرقم ونوع الخط والصلاحية) + الحسابات "
    "العامة المرتبطة بالرقم: تيليجرام عبر اكتشافه الرسمي (يظهر فقط من سمح "
    "بالعثور عليه برقمه في إعداداته)؛ واتساب وسيغنال لا يوفران تحققاً "
    "عاماً موثوقاً من الأرقام فلا تُعرض لهما نتائج مختلقة. "
    "(7) تقييم شامل لمنظومة (EASM): من نطاق واحد — اكتشاف ساكن للنطاقات "
    "الفرعية، فحص منافذ لأهم الخوادم، تقييم ويب (Nuclei + TLS + ترويسات) "
    "لأهم المواقع الحية، بصمات تقنية، تدقيق أمان بريد (SPF/DKIM/DMARC)، "
    "ودرجة أمان موحدة 0-100 بخصومات معلنة الأسباب وأولويات إصلاح. "
    "بقية أدوات الكتالوج في المشروع الأصلي "
    "(ZAP الكامل، Trivy، YARA وغيرها) ما زالت «مخططاً لها» ولم تُبنَ بعد — "
    "هذا البوت يعرض الجاهز فقط بصدق."
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
    try:
        conn.execute("ALTER TABLE scan_requests ADD COLUMN kind TEXT DEFAULT 'ip'")
    except sqlite3.OperationalError:
        pass  # column already exists (v2 databases)
    try:
        conn.execute("ALTER TABLE scan_requests ADD COLUMN deep INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # column already exists (v3 databases)
    try:
        conn.execute("ALTER TABLE scan_requests ADD COLUMN origin_ip TEXT")
    except sqlite3.OperationalError:
        pass  # column already exists (v4 databases)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS tg_updates(
               update_id INTEGER PRIMARY KEY, payload TEXT,
               processed INTEGER DEFAULT 0, received_at REAL)"""
    )
    return conn


def enqueue_update(update):
    """Store a Telegram update delivered by the engine's webhook endpoint."""
    with db() as c:
        c.execute(
            "INSERT OR IGNORE INTO tg_updates VALUES (?,?,0,?)",
            (update["update_id"], json.dumps(update), time.time()),
        )


def fetch_unprocessed(limit=20):
    with db() as c:
        rows = c.execute(
            "SELECT update_id, payload FROM tg_updates WHERE processed=0"
            " ORDER BY update_id ASC LIMIT ?",
            (limit,),
        ).fetchall()
    return [(r["update_id"], r["payload"]) for r in rows]


def mark_processed(update_id):
    with db() as c:
        c.execute("UPDATE tg_updates SET processed=1 WHERE update_id=?", (update_id,))


def webhook_secret() -> str:
    """Shared with the engine (main.py derives it identically). Derived from
    SCAN_APPROVAL_SECRET so no extra env var is needed; never logged."""
    if not PERMIT_SECRET:
        raise RuntimeError("SCAN_APPROVAL_SECRET is not configured")
    return hmac.new(PERMIT_SECRET.encode(), b"telegram-webhook-v1",
                    hashlib.sha256).hexdigest()


def save_request(req):
    with db() as c:
        c.execute(
            "INSERT INTO scan_requests (id, user_id, username, ip, auth_ref,"
            " top_ports, status, created_at, expires_at, result, error,"
            " proof_file_id, proof_text, kind, deep, origin_ip)"
            " VALUES (?,?,?,?,?,?,?,?,?,NULL,NULL,?,?,?,?,?)",
            (req["id"], req["user_id"], req["username"], req["ip"],
             req["auth_ref"], req["top_ports"], req["status"],
             req["created_at"], req["expires_at"],
             req.get("proof_file_id"), req.get("proof_text"),
             req.get("kind", "ip"), req.get("deep", 0),
             req.get("origin_ip")),
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


HOST_RE = re.compile(r"^(?=.{4,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")


def validate_host(value: str) -> str:
    """Domain target for the web-assessment flow: a real domain name, never
    an IP literal (those use the IP flow) and never a URL with a path."""
    host = (value or "").strip().lower()
    for prefix in ("https://", "http://"):
        if host.startswith(prefix):
            host = host[len(prefix):]
    host = host.split("/")[0].split(":")[0].rstrip(".")
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass
    if is_ip:
        raise ValueError("هذا عنوان IP — استخدم «طلب فحص جديد» لفحص العناوين.")
    if not HOST_RE.match(host):
        raise ValueError("أرسل اسم نطاق صحيحاً (مثال: example.com).")
    return host


def resolve_host_ips(host: str):
    """Resolve at approval time; the web permit binds this exact address set,
    and the engine re-resolves and requires its set to be a subset of it."""
    import socket
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except Exception:
        raise ValueError("النطاق لا يُحلّ إلى أي عنوان (فشل DNS).")
    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise ValueError("النطاق لا يُحلّ إلى أي عنوان (فشل DNS).")
    for ip in ips:
        if not ipaddress.ip_address(ip).is_global:
            raise ValueError("النطاق يشير إلى عنوان غير عام — مرفوض حمايةً للشبكات الداخلية.")
    return ips


def create_web_permit(host: str, ips, request_id: str, expires_ms: int) -> str:
    """Host + resolved-address-set bound permit; verified by the engine's
    valid_web_permit(). Same HMAC scheme as create_scan_permit()."""
    if not PERMIT_SECRET:
        raise RuntimeError("SCAN_APPROVAL_SECRET is not configured")
    payload = _b64url(json.dumps(
        {"host": host, "ips": list(ips), "kind": "web",
         "id": request_id, "exp": expires_ms},
        separators=(",", ":")).encode())
    signature = _b64url(hmac.new(
        PERMIT_SECRET.encode(), payload.encode(), hashlib.sha256).digest())
    return payload + "." + signature


# ---------------------------------------------------------------- engine client
def engine_call(method, path, body=None, permit=None, timeout=120):
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
        with urllib.request.urlopen(req, timeout=timeout) as resp:
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


def create_origin_permit(host: str, ip: str, request_id: str, expires_ms: int) -> str:
    """Host + origin-IP bound permit; verified by the engine's
    check_origin_target(). Same HMAC scheme as create_web_permit()."""
    if not PERMIT_SECRET:
        raise RuntimeError("SCAN_APPROVAL_SECRET is not configured")
    payload = _b64url(json.dumps(
        {"host": host, "ip": ip, "kind": "origin",
         "id": request_id, "exp": expires_ms},
        separators=(",", ":")).encode())
    signature = _b64url(hmac.new(
        PERMIT_SECRET.encode(), payload.encode(), hashlib.sha256).digest())
    return payload + "." + signature


def run_approved_origin_scan(req):
    permit = create_origin_permit(req["ip"], req["origin_ip"], req["id"],
                                  int(time.time() * 1000) + PERMIT_TTL_MS)
    deep = bool(req.get("deep"))
    cookie = AUTH_SECRETS.pop(req["id"], None)  # one-shot: dropped at use
    pass_pair = PASS_SECRETS.pop(req["id"], None)
    return engine_call("POST", "/scans/origin", body={
        "target_host": req["ip"],
        "origin_ip": req["origin_ip"],
        "authorization_reference": req["auth_ref"],
        "confirm_authorized": True,
        "deep": deep,
        "auth_cookie": cookie,
        "pass_header_name": pass_pair[0] if pass_pair else None,
        "pass_header_value": pass_pair[1] if pass_pair else None,
    }, permit=permit, timeout=1500 if deep else 900)


def run_approved_web_scan(req):
    ips = resolve_host_ips(req["ip"])
    permit = create_web_permit(req["ip"], ips, req["id"],
                               int(time.time() * 1000) + PERMIT_TTL_MS)
    deep = bool(req.get("deep"))
    cookie = AUTH_SECRETS.pop(req["id"], None)  # one-shot: dropped at use
    pass_pair = PASS_SECRETS.pop(req["id"], None)
    return engine_call("POST", "/scans/web", body={
        "target_host": req["ip"],
        "authorization_reference": req["auth_ref"],
        "confirm_authorized": True,
        "deep": deep,
        "auth_cookie": cookie,
        "pass_header_name": pass_pair[0] if pass_pair else None,
        "pass_header_value": pass_pair[1] if pass_pair else None,
    }, permit=permit, timeout=1500 if deep else 900)


def create_full_permit(host: str, ips, request_id: str, expires_ms: int) -> str:
    """Domain + resolved-address-set bound permit for the full
    attack-surface assessment; verified by the engine's
    valid_full_permit(). Same HMAC scheme as create_web_permit()."""
    if not PERMIT_SECRET:
        raise RuntimeError("SCAN_APPROVAL_SECRET is not configured")
    payload = _b64url(json.dumps(
        {"host": host, "ips": list(ips), "kind": "full",
         "id": request_id, "exp": expires_ms},
        separators=(",", ":")).encode())
    signature = _b64url(hmac.new(
        PERMIT_SECRET.encode(), payload.encode(), hashlib.sha256).digest())
    return payload + "." + signature


def run_approved_full_scan(req):
    ips = resolve_host_ips(req["ip"])
    permit = create_full_permit(req["ip"], ips, req["id"],
                                int(time.time() * 1000) + PERMIT_TTL_MS)
    return engine_call("POST", "/scans/full", body={
        "target_host": req["ip"],
        "authorization_reference": req["auth_ref"],
        "confirm_authorized": True,
    }, permit=permit, timeout=1800)


SEV_AR = {"critical": "حرجة", "high": "عالية", "medium": "متوسطة",
          "low": "منخفضة", "info": "معلومة", "unknown": "غير مصنفة"}


def format_web_report(req, result, origin_ip=None) -> str:
    host = result.get("target", req["ip"])
    title = (f"🎯 اكتمل فحص خادم الأصل {origin_ip} للموقع {host}" if origin_ip
             else f"✅ اكتمل فحص الموقع {host}")
    lines = [f"{title} ({'🔬 عميق' if result.get('deep') else '⚡ سريع'})",
             f"المرجع: {req['auth_ref']}  |  الملف: {result.get('profile','')}"]
    ips = result.get("resolved_ips") or []
    if ips:
        lines.append("العناوين: " + "، ".join(ips))
    dnsr = result.get("dns") or {}
    records = dnsr.get("records") or {}
    if dnsr.get("status") == "ready":
        lines.append("\n🌐 سجلات DNS:")
        for rtype in ("A", "AAAA", "MX", "NS"):
            vals = records.get(rtype) or []
            if vals:
                lines.append(f"• {rtype}: " + "، ".join(vals[:4]))
    elif dnsr:
        lines.append("\n🌐 سجلات DNS: غير متاحة في هذه النسخة من المحرك.")
    http = result.get("http") or {}
    if http.get("status") == "ready":
        lines.append(f"\n🔗 HTTP: الحالة {http.get('http_status')} عبر {http.get('scheme')} — {http.get('final_url')}")
        if http.get("server"):
            lines.append(f"الخادم: {http['server']}")
        lines.append(f"ترويسات الأمان ({http.get('score','?')}):")
        for h in http.get("present") or []:
            lines.append(f"  ✅ {h}")
        for h in http.get("missing") or []:
            lines.append(f"  ❌ {h}")
        for c in (http.get("cookies") or [])[:5]:
            flags = c.get("flags") or {}
            bad = [k for k, v in flags.items() if not v]
            if bad:
                lines.append(f"  ⚠️ كوكيز {c.get('name')}: ينقصه {'، '.join(bad)}")
    tls = result.get("tls") or {}
    if tls.get("status") == "ready":
        issuer = (tls.get("issuer") or {}).get("organizationName") \
            or (tls.get("issuer") or {}).get("commonName") or "?"
        lines.append(f"\n🔐 TLS: {tls.get('tls_version')} | الشهادة من {issuer} | "
                     f"تنتهي {tls.get('not_after')} (بعد {tls.get('days_left')} يوم)")
        legacy = [k for k, v in (tls.get("legacy_protocols") or {}).items() if v]
        if legacy:
            lines.append("  ⚠️ بروتوكولات قديمة مدعومة: " + "، ".join(legacy))
        else:
            lines.append("  ✅ لا بروتوكولات TLS قديمة (1.0/1.1)")
    nuc = result.get("nuclei") or {}
    lines.append("\n🛡️ فحص الثغرات (Nuclei):")
    if nuc.get("status") == "ready":
        counts = nuc.get("counts") or {}
        if counts:
            lines.append("النتائج: " + "، ".join(
                f"{SEV_AR.get(k, k)}: {v}" for k, v in counts.items()))
        else:
            lines.append("لا نتائج ضمن القوالب المحدودة — لم يُرصد شيء.")
        for f in (nuc.get("findings") or [])[:25]:
            lines.append(f"• [{SEV_AR.get(f.get('severity'), f.get('severity'))}] "
                         f"{f.get('name')} — {f.get('matched_at')}")
    else:
        lines.append(f"الحالة: {nuc.get('status')} — {nuc.get('note','')}")
    batches = nuc.get("batches") or []
    if len(batches) > 1:
        lines.append("دفعات الفحص: " + "، ".join(
            f"{b.get('label')}: {b.get('total')}" for b in batches
            if b.get("status") == "ready"))
    crawl = result.get("crawl") or {}
    if crawl.get("status") == "ready":
        lines.append(f"\n🕷️ الزحف العميق: اكتُشفت {crawl.get('total')} صفحة/رابط")
        for u in (crawl.get("notable") or [])[:8]:
            lines.append(f"  • {u}")
    origin = result.get("origin") or {}
    if origin.get("status") == "ready":
        lines.append(f"\n🎯 أصل الخادم (بحث ساكن عبر {origin.get('subdomains_checked')} نطاقاً فرعياً):")
        cands = origin.get("candidates") or []
        if cands:
            for c in cands:
                mark = "يخدم الموقع فعلياً ✅" if c.get("serves_site") else "مرشح غير مؤكد"
                lines.append(f"  • {c.get('ip')} (عبر {'، '.join(c.get('via_subdomains') or [])}) — {mark}")
        else:
            lines.append("  لا مرشحين — الأصل مخفي جيداً خلف الواجهة.")
    if result.get("authenticated"):
        lines.append("\n🔑 أُجري الفحص بجلسة حساب اختبار زوّدها المالك لهذا الفحص (لم تُحفظ).")
    if result.get("pass_used"):
        lines.append("🚪 مرّ الفاحص ببصمة مرور متفق عليها مع المالك (قاعدة سماح في جدار الحماية).")
    if origin_ip:
        lines.append("ملاحظة: طبقات الويب أعلاه كما يخدمها الخادم الأصلي مباشرة؛ "
                     "ولفحص منافذ وخدمات نفس الخادم استخدم «طلب فحص جديد» على عنوان الأصل.")
    lines.append("\nالحدود: كشف فقط بقوالب مقيدة (بلا استغلال ولا وسوم اقتحامية)، "
                 "ونتائج الماسح تقارير أولية يراجعها الأدمن قبل أي إجراء.")
    return "\n".join(lines)


def format_full_report(req, result) -> str:
    base = result.get("base_domain", req["ip"])
    score = result.get("score") or {}
    lines = [f"🏢 اكتمل التقييم الشامل للمنظومة {base}",
             f"المرجع: {req['auth_ref']}  |  الملف: {result.get('profile','')}"]
    if result.get("elapsed_seconds") is not None:
        lines.append(f"مدة التقييم: {result['elapsed_seconds']} ثانية")
    lines.append(f"\n🏆 درجة الأمان الإجمالية: {score.get('score', '?')}/100 "
                 f"({score.get('grade', '')})")
    deductions = score.get("deductions") or []
    if deductions:
        lines.append("أسباب الخصم:")
        for d in deductions[:8]:
            lines.append(f"  −{d.get('points')}: {d.get('label')}")
    priorities = result.get("priorities") or []
    if priorities:
        lines.append("\n🚨 أولويات الإصلاح:")
        for i, p in enumerate(priorities[:8], 1):
            lines.append(f"{i}. {p}")
    discovery = result.get("discovery") or {}
    subs = discovery.get("subdomains_found") or []
    lines.append(f"\n🔭 الاكتشاف: {len(subs)} نطاقاً فرعياً مكتشفاً ساكناً، "
                 f"و{len(discovery.get('hosts_assessed') or [])} مضيفاً قُيّم فعلياً")
    for s in subs[:15]:
        lines.append(f"  • {s}")
    if len(subs) > 15:
        lines.append(f"  … و{len(subs) - 15} أخرى")
    email = result.get("email") or {}
    if email.get("status") == "ready":
        lines.append("\n📧 أمان البريد:")
        if not email.get("has_mx"):
            lines.append("  لا سجلات MX — النطاق لا يستقبل بريداً (بنود "
                         "SPF/DMARC لا تنطبق عملياً)")
        spf = email.get("spf") or {}
        if spf.get("present"):
            strength = {"strict": "صارم (-all)", "softfail": "لين (~all)",
                        "weak": "ضعيف الإنهاء"}.get(spf.get("strength"),
                                                    spf.get("strength"))
            lines.append(f"  SPF: موجود — {strength}")
        elif email.get("has_mx"):
            lines.append("  SPF: ❌ غائب — أي شخص يستطيع إرسال بريد منتحلاً نطاقك")
        dmarc = email.get("dmarc") or {}
        if dmarc.get("present"):
            lines.append(f"  DMARC: موجود — السياسة p={dmarc.get('policy')}")
        elif email.get("has_mx"):
            lines.append("  DMARC: ❌ غائب — لا حماية من انتحال النطاق")
        dkim = email.get("dkim") or {}
        if dkim.get("found"):
            lines.append(f"  DKIM: مفاتيح معلنة للمحددات: {', '.join(dkim['found'])}")
        elif email.get("has_mx"):
            lines.append(f"  DKIM: لم يُعثر على مفاتيح بين {dkim.get('selectors_checked')} "
                         "محدداً شائعاً فُحص")
    hosts = result.get("hosts") or []
    if hosts:
        lines.append("\n🖥️ المضيفون المقيّمون:")
    for h in hosts:
        http = h.get("http") or {}
        head = f"\n▸ {h.get('host')} ({'، '.join(h.get('ips') or [])})"
        lines.append(head)
        if http.get("status") == "ready":
            lines.append(f"  HTTP {http.get('http_status')} عبر {http.get('scheme')} "
                         f"| ترويسات الأمان: {http.get('score', '?')}")
        else:
            lines.append("  HTTP: لا خدمة ويب مستجيبة")
        tech = (h.get("tech") or {}).get("hints") or []
        for hint in tech[:3]:
            lines.append(f"  🔧 {hint}")
        tls = h.get("tls") or {}
        if tls.get("status") == "ready":
            legacy = [k for k, v in (tls.get("legacy_protocols") or {}).items() if v]
            lines.append(f"  TLS: {tls.get('tls_version')} | تنتهي الشهادة بعد "
                         f"{tls.get('days_left')} يوم"
                         + (f" | ⚠️ قديمة: {', '.join(legacy)}" if legacy else ""))
        nuc = h.get("nuclei") or {}
        if nuc.get("status") == "ready":
            counts = nuc.get("counts") or {}
            if counts:
                lines.append("  نتائج Nuclei: " + "، ".join(
                    f"{SEV_AR.get(k, k)}: {v}" for k, v in counts.items()))
                for f in (nuc.get("findings") or [])[:5]:
                    lines.append(f"    • [{SEV_AR.get(f.get('severity'), f.get('severity'))}] "
                                 f"{f.get('name')} — {f.get('matched_at')}")
            else:
                lines.append("  نتائج Nuclei: لا شيء ضمن القوالب المحدودة")
        elif nuc.get("status") == "skipped_budget":
            lines.append("  نتائج Nuclei: تخطّت ميزانية الوقت (مُعلن، غير مُسقط بصمت)")
        elif nuc.get("status") not in ("skipped", None):
            lines.append(f"  نتائج Nuclei: {nuc.get('status')}")
    ports_by_ip = result.get("ports_by_ip") or []
    if ports_by_ip:
        lines.append("\n🔌 المنافذ (أشهر 100 لكل خادم):")
    for entry in ports_by_ip:
        open_ports = [p for p in (entry.get("ports") or [])
                      if p.get("state") == "open"]
        if entry.get("error"):
            lines.append(f"  {entry['ip']}: تعذّر فحص المنافذ ({entry['error']})")
        elif open_ports:
            lines.append(f"  {entry['ip']}:")
            for p in open_ports[:12]:
                svc = " ".join(x for x in [p.get("service"), p.get("product"),
                                           p.get("version")] if x)
                lines.append(f"    • {p.get('port')}/{p.get('protocol')} — {svc}")
        else:
            lines.append(f"  {entry['ip']}: لا منافذ مفتوحة ضمن المفحوص")
    lines.append("\nالحدود: اكتشاف ساكن (شهادات + كلمات شائعة محلولة فعلياً)، "
                 "حدود معلنة: حتى 10 مضيفين تُقاس طبقاتهم، 3 منهم بفحص Nuclei "
                 "كامل، و4 عناوين بفحص منافذ — والمتجاوز يُعلن متخطّى لا يُحذف "
                 "بصمت. الدرجة هيورستيك شفاف: كل خصم مسبّب في التقرير.")
    return "\n".join(lines)


def send_long(chat_id, text, reply_markup=None):
    """Send a long report as consecutive messages (Telegram caps ~4096)."""
    chunks, current = [], ""
    for line in text.split("\n"):
        if len(current) + len(line) + 1 > 3800:
            chunks.append(current)
            current = line
        else:
            current = current + "\n" + line if current else line
    if current:
        chunks.append(current)
    for i, chunk in enumerate(chunks):
        send(chat_id, chunk, reply_markup if i == len(chunks) - 1 else None)


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
    [("🌐 فحص موقع شامل", "web_scan")],
    [("🎯 فحص خادم الأصل", "origin_scan")],
    [("🏢 تقييم شامل لمنظومة", "full_scan")],
    [("🪪 بطاقة حساب تيليجرام", "tg_card")],
    [("📱 بطاقة رقم هاتف", "phone_card")],
    [("📋 طلباتي", "my_requests"), ("🩺 حالة المحرك", "health")],
    [("🧰 كتالوج الأدوات", "catalog")],
])

# per-user conversation state (in-memory; durable data lives in SQLite)
STATE = {}

# One-shot test-account session cookies for deep web scans, keyed by
# request id. MEMORY ONLY: never written to the DB, disk, or logs, and
# dropped the moment the approved scan runs (or the request dies).
AUTH_SECRETS = {}

# One-shot CDN pass fingerprints (owner-agreed WAF allowlist header),
# keyed by request id: (header_name, header_value). Same memory-only
# lifecycle as AUTH_SECRETS: never persisted, dropped at use or rejection.
PASS_SECRETS = {}


# ---------------------------------------------------------------- tg card
# Public Telegram account card (catalogue item W8): public data only — the
# public t.me preview page plus Bot API getChat for public chats. Telegram
# does not publish real creation dates, so the creation period is an
# approximate range inferred from the numeric ID and always labelled as
# an estimate.

TG_ID_DATE_RANGES = [
    (10_000_000, "2013 – 2014"),
    (50_000_000, "2014 – 2015"),
    (100_000_000, "2015 – 2016"),
    (200_000_000, "2016 – 2017"),
    (400_000_000, "2017 – 2019"),
    (700_000_000, "2019 – 2020"),
    (1_100_000_000, "2020 – 2021"),
    (1_700_000_000, "2021 – 2022"),
    (2_600_000_000, "2022 – 2023"),
    (4_000_000_000, "2023 – 2024"),
]

TG_KIND_LABELS = {"channel": "قناة", "supergroup": "مجموعة خارقة",
                  "group": "مجموعة", "private": "مستخدم", "bot": "بوت"}


def estimate_creation_period(user_id):
    """Approximate account-creation period from the numeric ID range."""
    if not isinstance(user_id, int) or isinstance(user_id, bool) or user_id <= 0:
        return None
    for upper, label in TG_ID_DATE_RANGES:
        if user_id < upper:
            return label
    return "2024 – 2026"


def parse_tg_query(text):
    """Parse a card query: @username / t.me link / bare username / numeric ID.

    Returns ("username", name) or ("id", int) or None."""
    value = (text or "").strip()
    m = re.search(r"(?:https?://)?t\.me/([A-Za-z0-9_]{5,32})", value)
    if m:
        return ("username", m.group(1))
    value = value.lstrip("@").strip()
    if re.fullmatch(r"-?\d{5,20}", value):
        return ("id", int(value))
    if re.fullmatch(r"[A-Za-z0-9_]{5,32}", value):
        return ("username", value)
    return None


def _meta_content(page, prop):
    m = re.search(r'<meta[^>]+property="%s"[^>]+content="([^"]*)"' % prop, page)
    if not m:
        m = re.search(r'<meta[^>]+content="([^"]*)"[^>]+property="%s"' % prop, page)
    return html.unescape(m.group(1)).strip() if m else ""


def parse_tme_page(page):
    """Extract public fields from a t.me/<username> preview page."""
    if not page:
        return {}
    info = {}
    title = _meta_content(page, "og:title")
    if title and title != "Telegram":
        info["name"] = title
    desc = _meta_content(page, "og:description")
    if desc:
        info["description"] = desc
    m = re.search(r'<div class="tgme_page_extra">(.+?)</div>', page, re.S)
    if m:
        extra = re.sub(r"<[^>]+>", " ", m.group(1))
        info["extra"] = re.sub(r"\s+", " ", html.unescape(extra)).strip()
    if "subscribers" in info.get("extra", ""):
        info["kind_hint"] = "channel"
    elif "members" in info.get("extra", ""):
        info["kind_hint"] = "group"
    if "What can this bot do?" in page:
        info["kind_hint"] = "bot"
        m = re.search(r'<div class="tgme_page_description">(.+?)</div>',
                      page, re.S)
        if m:
            about = re.sub(r"<[^>]+>", " ", m.group(1))
            about = re.sub(r"\s+", " ", html.unescape(about)).strip()
            if about:
                info["description"] = about
    return info


def fetch_tme_page(username):
    req = urllib.request.Request(
        f"https://t.me/{username}",
        headers={"User-Agent": "Mozilla/5.0 (compatible; CyberSecAgentBot/1.0)"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.read().decode("utf-8", "replace")
    except Exception:
        return ""


def tg_card_lookup(query, is_admin=False):
    """Build the public Telegram card text for a parsed query."""
    kind, value = query
    username = value if kind == "username" else None
    numeric_id = value if kind == "id" else None
    chat = None
    page_info = {}
    chat_ref = f"@{username}" if username else numeric_id
    try:
        res = tg("getChat", chat_id=chat_ref, _http_timeout=30)
        if res.get("ok"):
            chat = res["result"]
    except Exception:
        chat = None
    if username:
        page_info = parse_tme_page(fetch_tme_page(username))
    if chat:
        numeric_id = chat.get("id", numeric_id)
        username = chat.get("username") or username

    # Deep tier (MTProto, dedicated account): resolves what the Bot API
    # cannot — numeric ID for users, official flags, photo count, linked
    # discussion group. Dormant until TG_API_ID/TG_API_HASH/TG_SESSION
    # are configured; any failure degrades to the public card.
    deep = None
    deep_state = "off"
    try:
        import tgdeep
        if tgdeep.configured():
            deep_state = "on"
            deep = tgdeep.deep_lookup(query)
    except Exception:
        deep = None
    deep_ok = bool(deep) and not deep.get("error")
    if deep_ok:
        numeric_id = deep.get("marked_id") or deep.get("id") or numeric_id
        username = deep.get("username") or username

    name = None
    if chat:
        name = chat.get("title") or " ".join(
            x for x in [chat.get("first_name"), chat.get("last_name")]
            if x) or None
    if not name:
        name = page_info.get("name")
    if deep_ok and deep.get("name"):
        name = deep["name"]

    kind_label = None
    if chat and chat.get("type") in TG_KIND_LABELS:
        kind_label = TG_KIND_LABELS[chat["type"]]
    if page_info.get("kind_hint") == "bot" or (
            username and username.lower().endswith("bot")):
        kind_label = "بوت"
    elif page_info.get("kind_hint") in ("channel", "group"):
        kind_label = TG_KIND_LABELS[page_info["kind_hint"]]
    if not kind_label and username:
        kind_label = "مستخدم"
    if not kind_label and numeric_id is not None and numeric_id < 0:
        kind_label = "قناة/مجموعة (من صيغة المعرف)"
    if deep_ok and deep.get("kind") in (
            "user", "bot", "channel", "supergroup", "group"):
        kind_label = TG_KIND_LABELS[
            {"user": "private"}.get(deep["kind"], deep["kind"])]

    members = None
    if chat and chat.get("type") in ("channel", "supergroup", "group"):
        try:
            res = tg("getChatMemberCount", chat_id=chat["id"],
                     _http_timeout=30)
            if res.get("ok"):
                members = res["result"]
        except Exception:
            members = None

    if deep_ok and deep.get("participants") is not None:
        members = deep["participants"]

    description = None
    if chat and chat.get("description"):
        description = chat["description"]
    elif page_info.get("description"):
        description = page_info["description"]
    if deep_ok and deep.get("about"):
        description = deep["about"]

    deep_lines = []
    if deep_ok:
        if deep.get("verified"):
            deep_lines.append("✔️ موثّق رسمياً من تيليجرام")
        if deep.get("scam"):
            deep_lines.append("⚠️ موسوم «احتيالي» رسمياً من تيليجرام")
        if deep.get("fake"):
            deep_lines.append("⚠️ موسوم «مزيّف» رسمياً من تيليجرام")
        if deep.get("photos") is not None and deep.get("kind") in (
                "user", "bot"):
            deep_lines.append(f"صور الملف الشخصي العامة: {deep['photos']}")
        if deep.get("linked_username"):
            deep_lines.append(
                f"مجموعة النقاش المرتبطة: @{deep['linked_username']}")
        elif deep.get("linked_title"):
            deep_lines.append(
                f"مجموعة النقاش المرتبطة: {deep['linked_title']}")

    state_note = None
    if not deep_lines:
        if deep_state == "on" and deep and deep.get("error") == "flood":
            state_note = ("🔬 البحث العميق مقيّد مؤقتاً من تيليجرام — "
                          "أعد المحاولة بعد دقائق.")
        elif deep_state == "on" and is_admin and deep and deep.get(
                "error") == "session_not_authorized":
            state_note = "🔬 جلسة البحث العميق غير صالحة — تحتاج إعادة تفعيل."
        elif deep_state == "off" and is_admin:
            state_note = "🔬 البحث العميق غير مفعّل بعد (بانتظار خطوة التفعيل)."

    if not name and not chat and not page_info and numeric_id is None:
        msg = ("🪪 لم أجد بيانات عامة لهذا المعرف — قد يكون غير موجود "
               "أو غير عام. البيانات الخاصة لا تُجمع ولا تُعرض أبداً.")
        return msg + ("\n" + state_note if state_note else "")

    lines = ["🪪 بطاقة حساب تيليجرام (بيانات عامة)"]
    if name:
        lines.append(f"الاسم: {name}")
    if username:
        lines.append(f"المعرف: @{username}")
    if numeric_id is not None:
        lines.append(f"المعرف الرقمي: {numeric_id}")
    if kind_label:
        lines.append(f"النوع: {kind_label}")
    if members is not None:
        lines.append(f"الأعضاء/المشتركون: {members:,}")
    elif page_info.get("extra") and any(
            w in page_info["extra"] for w in ("subscribers", "members")):
        lines.append(f"إحصائية عامة: {page_info['extra']}")
    if deep_lines:
        lines.append("🔬 من البحث العميق:")
        lines.extend(deep_lines)
    elif state_note:
        lines.append(state_note)
    if numeric_id is not None and numeric_id > 0:
        period = estimate_creation_period(numeric_id)
        if period:
            lines.append(
                f"تاريخ الإنشاء التقديري: حوالي {period} "
                "(تقدير تقريبي من نطاق المعرف الرقمي — تيليجرام لا ينشر "
                "التاريخ الحقيقي)")
    if description:
        lines.append(f"الوصف العام: {description[:400]}")
    lines.append("المصدر: الصفحة العامة t.me وواجهة تيليجرام الرسمية.")
    return "\n".join(lines)


# ------------------------------------------------- phone card (R1 + R3)
def _phone_type_labels():
    import phonenumbers
    pt = phonenumbers.PhoneNumberType
    return {
        pt.MOBILE: "جوال",
        pt.FIXED_LINE: "ثابت",
        pt.FIXED_LINE_OR_MOBILE: "ثابت أو جوال",
        pt.VOIP: "صوت عبر الإنترنت (VoIP)",
        pt.TOLL_FREE: "رقم مجاني",
        pt.PREMIUM_RATE: "رقم مميز التكلفة",
        pt.SHARED_COST: "رقم مشترك التكلفة",
        pt.PAGER: "بيجر",
        pt.PERSONAL_NUMBER: "رقم شخصي",
        pt.UAN: "رقم خدمة موحد",
        pt.VOICEMAIL: "بريد صوتي",
        pt.UNKNOWN: "غير محدد",
    }


def parse_phone_number(text):
    """Parse a phone number in international format against the global
    numbering plan (libphonenumber data). Pure numbering data — no
    personal information is looked up here. Returns None when the
    number cannot be parsed at all, {"valid": False} when it parses
    but is not a real allocated number."""
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder
    except Exception:
        return None
    raw = re.sub(r"[\s\-()]+", "", (text or "").strip())
    if raw.startswith("00"):
        raw = "+" + raw[2:]
    if not raw.startswith("+"):
        return None
    try:
        num = phonenumbers.parse(raw, None)
    except Exception:
        return None
    if not phonenumbers.is_valid_number(num):
        return {"valid": False}
    e164 = phonenumbers.format_number(
        num, phonenumbers.PhoneNumberFormat.E164)
    country = (geocoder.description_for_number(num, "ar")
               or geocoder.description_for_number(num, "en") or "")
    oper = (carrier.name_for_number(num, "ar")
            or carrier.name_for_number(num, "en") or "")
    return {"valid": True, "e164": e164, "country": country,
            "carrier": oper,
            "type": _phone_type_labels().get(
                phonenumbers.number_type(num), "غير محدد")}


def phone_card_lookup(text, is_admin=False):
    """Build the phone card: R1 numbering data + R3 public accounts
    discoverable by this number (Telegram's own discovery — only users
    who allow being found by number; WhatsApp and Signal offer no
    reliable public number check, and the card says so honestly)."""
    info = parse_phone_number(text)
    if info is None:
        return ("❌ تعذّرت قراءة الرقم — أرسله بالصيغة الدولية الكاملة "
                "(مثال: +967700000000).")
    if not info.get("valid"):
        return ("❌ الرقم غير صالح وفق خطة الترقيم العالمية — تأكد من "
                "رمز الدولة والرقم ثم أعد المحاولة.")
    lines = ["📱 بطاقة رقم هاتف (بيانات ترقيم عامة)"]
    lines.append(f"الرقم بالصيغة الدولية: {info['e164']}")
    if info.get("country"):
        lines.append(f"الدولة: {info['country']}")
    if info.get("carrier"):
        lines.append(f"المشغّل المسجل لنطاق الرقم: {info['carrier']} "
                     "(قد يختلف إن نُقل الرقم إلى مشغّل آخر)")
    lines.append(f"نوع الخط: {info['type']}")
    lines.append("الحالة: صالح وفق خطة الترقيم العالمية")
    lines.append("🔗 الحسابات العامة المرتبطة بالرقم:")
    tg_res = None
    tg_state = "off"
    try:
        import tgdeep
        if tgdeep.configured():
            tg_state = "on"
            tg_res = tgdeep.phone_lookup(info["e164"])
    except Exception:
        tg_res = None
    if tg_res and tg_res.get("found"):
        who = (f"@{tg_res['username']}" if tg_res.get("username")
               else (tg_res.get("name") or "حساب"))
        extra = (f" — المعرف الرقمي: {tg_res['id']}"
                 if tg_res.get("id") else "")
        lines.append(f"تيليجرام: يوجد حساب عام — {who}{extra}")
        if tg_res.get("verified"):
            lines.append("   ✔️ موثّق رسمياً من تيليجرام")
        if tg_res.get("scam"):
            lines.append("   ⚠️ موسوم «احتيالي» رسمياً من تيليجرام")
        if tg_res.get("fake"):
            lines.append("   ⚠️ موسوم «مزيّف» رسمياً من تيليجرام")
    elif tg_res and tg_res.get("error") == "flood":
        lines.append("تيليجرام: التحقق مقيّد مؤقتاً من تيليجرام — "
                     "أعد المحاولة بعد دقائق.")
    elif (tg_state == "on" and tg_res
          and tg_res.get("error") == "session_not_authorized" and is_admin):
        lines.append("تيليجرام: جلسة البحث غير صالحة — تحتاج إعادة تفعيل.")
    elif tg_state == "on":
        lines.append("تيليجرام: لا حساب قابل للاكتشاف بهذا الرقم — إما "
                     "غير مسجل، أو صاحبه أغلق «العثور عليّ برقمي» في "
                     "إعدادات خصوصيته.")
    elif is_admin:
        lines.append("تيليجرام: يتطلب البحث العميق المفعّل.")
    else:
        lines.append("تيليجرام: التحقق غير متاح حالياً.")
    lines.append("واتساب: لا يوفر تحققاً عاماً موثوقاً من الأرقام — "
                 "صفحته العامة متطابقة للأرقام المسجلة وغير المسجلة "
                 "(تحققنا من ذلك فعلياً)، فلا نتيجة صادقة ممكنة.")
    lines.append("سيغنال: لا يوفر أي تحقق عام من الأرقام — غير متاح "
                 "بأي طريقة رسمية.")
    lines.append("ملاحظة: ظهور أي حساب يقرره صاحبه في إعدادات اكتشافه — "
                 "ما أخفاه صاحبه لا يظهر هنا أبداً.")
    return "\n".join(lines)


def handle_message(msg):
    chat_id = msg["chat"]["id"]
    user = msg.get("from", {})
    text = (msg.get("text") or "").strip()
    state = STATE.get(chat_id)

    if text.startswith("/start"):
        STATE.pop(chat_id, None)
        send(chat_id,
             "مرحباً بك في بوت CYBER SECURITY AI AGENT 🛡️\n"
             "منصة دفاعية: فحص خوادم ومواقع (سريع، عميق، وعلى الأصل مباشرة)، "
             "ولا يُنفَّذ أي فحص إلا بعد موافقة الأدمن على الهدف المحدد.\n\nاختر من القائمة:",
             MAIN_KB)
        return
    if text.startswith("/health"):
        return show_health(chat_id)
    if text.startswith("/myrequests"):
        return show_my_requests(chat_id, user.get("id"))
    if text.startswith("/catalog"):
        send(chat_id, "🧰 " + CATALOG_NOTE, MAIN_KB)
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
    if state and state["step"] == "o_await_host":
        try:
            host = validate_host(text)
        except Exception as exc:
            send(chat_id, f"❌ {exc}\nأرسل اسم نطاق صحيحاً، أو /start للإلغاء.")
            return
        state.update(step="o_await_ip", ip=host)
        send(chat_id, f"الموقع: {host}\nأرسل الآن عنوان IP الخادم الأصلي الذي "
                      "يخدم هذا الموقع فعلياً (العنوان الحقيقي خلف Cloudflare "
                      "إن وُجد) — يزوّده مالك الموقع عادة من لوحة استضافته:")
        return
    if state and state["step"] == "o_await_ip":
        candidate = (text or "").strip()
        try:
            ip_obj = ipaddress.ip_address(candidate)
        except ValueError:
            ip_obj = None
        if ip_obj is None or not ip_obj.is_global:
            send(chat_id, "❌ أرسل عنوان IP عاماً صالحاً للخادم الأصلي (مثال: 203.0.113.10):")
            return
        state.update(step="o_await_ref", origin_ip=str(ip_obj))
        send(chat_id, "الآن أرسل مرجع التصريح — إثبات أن مالك الموقع صرّح بفحص "
                      "خادمه الأصلي (4 أحرف على الأقل):")
        return
    if state and state["step"] == "o_await_ref":
        if not (4 <= len(text) <= 120):
            send(chat_id, "❌ مرجع التصريح يجب أن يكون بين 4 و120 حرفاً. أعد الإرسال.")
            return
        state.update(step="o_await_proof", auth_ref=text)
        send(chat_id, "الآن أرسل إثبات التصريح ليتحقق منه الأدمن قبل القرار: "
                      "مستند أو صورة (لوحة الاستضافة، فاتورة النطاق، تصريح مكتوب)، "
                      "أو اكتب تفاصيل الإثبات نصاً. إن لم يوجد إثبات جاهز أرسل «تخطي» "
                      "— وسيبقى القرار النهائي للأدمن.")
        return
    if state and state["step"] == "o_await_proof":
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
        state.update(step="o_await_depth", proof_file_id=proof_file_id,
                     proof_text=proof_text)
        send(chat_id, "اختر عمق فحص الأصل:", kb([
            [("⚡ سريع — طبقات الويب على الأصل", "odepth:quick")],
            [("🔬 عميق — + قوالب CVE الكاملة", "odepth:deep")]]))
        return
    if state and state["step"] == "o_await_cookie":
        if text and text not in ("تخطي", "skip"):
            state["cookie"] = text[:2048]
        state.update(step="o_await_pass")
        send(chat_id, PASS_PROMPT)
        return
    if state and state["step"] == "o_await_pass":
        create_origin_request(chat_id, user, state, deep=True,
                              cookie=state.get("cookie"),
                              pass_pair=parse_pass_pair(text))
        return
    if state and state["step"] == "w_await_host":
        try:
            host = validate_host(text)
        except ValueError as exc:
            send(chat_id, f"❌ {exc}\nأرسل اسم نطاق صحيحاً، أو /start للإلغاء.")
            return
        state.update(step="w_await_ref", ip=host)
        send(chat_id, f"الموقع: {host}\nالآن أرسل مرجع التصريح — إثبات أنك تملك "
                      "هذا الموقع أو لديك تصريح مكتوب لفحصه.")
        return
    if state and state["step"] == "w_await_ref":
        if not (4 <= len(text) <= 120):
            send(chat_id, "❌ مرجع التصريح يجب أن يكون بين 4 و120 حرفاً. أعد الإرسال.")
            return
        state.update(step="w_await_proof", auth_ref=text)
        send(chat_id, "الآن أرسل إثبات التصريح ليتحقق منه الأدمن قبل القرار: "
                      "مستند أو صورة (لوحة الاستضافة، فاتورة النطاق، تصريح مكتوب)، "
                      "أو اكتب تفاصيل الإثبات نصاً. إن لم يوجد إثبات جاهز أرسل «تخطي» "
                      "— وسيبقى القرار النهائي للأدمن.")
        return
    if state and state["step"] == "w_await_proof":
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
        state.update(step="w_await_depth", proof_file_id=proof_file_id,
                     proof_text=proof_text)
        send(chat_id, "اختر عمق الفحص:", kb([
            [("⚡ سريع — أساسيات + ثغرات شائعة", "wdepth:quick")],
            [("🔬 عميق — CVE كاملة + زحف + أصل الخادم", "wdepth:deep")]]))
        return
    if state and state["step"] == "w_await_cookie":
        if text and text not in ("تخطي", "skip"):
            state["cookie"] = text[:2048]
        state.update(step="w_await_pass")
        send(chat_id, PASS_PROMPT)
        return
    if state and state["step"] == "w_await_pass":
        create_web_request(chat_id, user, state, deep=True,
                           cookie=state.get("cookie"),
                           pass_pair=parse_pass_pair(text))
        return
    if state and state["step"] == "f_await_host":
        try:
            host = validate_host(text)
        except ValueError as exc:
            send(chat_id, f"❌ {exc}\nأرسل اسم نطاق صحيحاً، أو /start للإلغاء.")
            return
        state.update(step="f_await_ref", ip=host)
        send(chat_id, f"المنظومة: {host}\nالآن أرسل مرجع التصريح — إثبات أنك "
                      "تملك هذا النطاق أو لديك تصريح مكتوب لتقييم منظومته.")
        return
    if state and state["step"] == "f_await_ref":
        if not (4 <= len(text) <= 120):
            send(chat_id, "❌ مرجع التصريح يجب أن يكون بين 4 و120 حرفاً. أعد الإرسال.")
            return
        state.update(step="f_await_proof", auth_ref=text)
        send(chat_id, "الآن أرسل إثبات التصريح ليتحقق منه الأدمن قبل القرار: "
                      "مستند أو صورة (لوحة النطاق/الاستضافة، تصريح مكتوب)، "
                      "أو اكتب تفاصيل الإثبات نصاً. إن لم يوجد إثبات جاهز أرسل "
                      "«تخطي» — وسيبقى القرار النهائي للأدمن.")
        return
    if state and state["step"] == "f_await_proof":
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
        state.update(proof_file_id=proof_file_id, proof_text=proof_text)
        create_full_request(chat_id, user, state)
        return
    if state and state["step"] == "tg_await_query":
        query = parse_tg_query(text)
        if not query:
            send(chat_id, "❌ أرسل معرفاً صحيحاً: @username أو رابط t.me "
                          "أو معرفاً رقمياً، أو /start للإلغاء.")
            return
        STATE.pop(chat_id, None)
        send(chat_id, "🔎 جارٍ جلب البيانات العامة…")
        try:
            card = tg_card_lookup(query, is_admin=(user.get("id") == ADMIN_ID))
        except Exception as exc:
            card = f"❌ تعذّر إكمال البحث: {exc}"
        send(chat_id, card, MAIN_KB)
        return
    if state and state["step"] == "phone_await_number":
        STATE.pop(chat_id, None)
        send(chat_id, "🔎 جارٍ التحقق من الرقم…")
        try:
            card = phone_card_lookup(
                text, is_admin=(user.get("id") == ADMIN_ID))
        except Exception as exc:
            card = f"❌ تعذّر إكمال التحقق: {exc}"
        send(chat_id, card, MAIN_KB)
        return
    send(chat_id, "اختر من القائمة، أو أرسل /start للبدء.", MAIN_KB)


def create_web_request(chat_id, user, state, deep, cookie=None, pass_pair=None):
    req = {
        "id": uuid.uuid4().hex, "user_id": user.get("id"),
        "username": user.get("username") or user.get("first_name", "?"),
        "ip": state["ip"], "auth_ref": state["auth_ref"],
        "proof_file_id": state.get("proof_file_id"),
        "proof_text": state.get("proof_text"),
        "top_ports": 0, "status": "pending", "kind": "web",
        "deep": 1 if deep else 0,
        "created_at": time.time(),
        "expires_at": time.time() + APPROVAL_TTL_HOURS * 3600,
    }
    save_request(req)
    if cookie:
        AUTH_SECRETS[req["id"]] = cookie
    if pass_pair:
        PASS_SECRETS[req["id"]] = pass_pair
    STATE.pop(chat_id, None)
    send(chat_id, f"⏳ تم إنشاء طلب فحص الموقع {req['id'][:8]} للهدف {req['ip']} "
                  f"({'🔬 عميق' if deep else '⚡ سريع'}).\n"
                  "لن يبدأ أي فحص قبل موافقة الأدمن. ستصلك النتيجة هنا.")
    notify_admin(req)


PASS_PROMPT = ("🚪 خطوة اختيارية أخيرة: بصمة المرور. إن اتفقت مع مالك الموقع "
               "على ترويسة مرور في جدار حمايته (قاعدة سماح في Cloudflare مثلاً)، "
               "أرسلها بالشكل: الاسم: القيمة — مثال: X-Scanner-Pass: سر-متفق-عليه. "
               "تُستخدم مرة واحدة في الذاكرة فقط ولا تُحفظ في أي قاعدة أو سجل. "
               "أو أرسل «تخطي».")

COOKIE_PROMPT = ("🔬 فحص عميق. خطوة اختيارية: إن أردت فحص ما بعد تسجيل "
                 "الدخول، أرسل كوكيز جلسة حساب اختبار أنشأه مالك الموقع لهذا "
                 "الغرض. تُستخدم مرة واحدة في الذاكرة فقط ولا تُحفظ في أي "
                 "قاعدة أو سجل — لكنها ستظهر في محادثة تيليجرام هذه، لذا "
                 "حساب اختبار فقط. أو أرسل «تخطي».")


def parse_pass_pair(text):
    """Parse an owner-agreed pass header given as 'Name: value'."""
    if not text or text in ("تخطي", "skip") or ":" not in text:
        return None
    name, _, value = text.partition(":")
    name, value = name.strip(), value.strip()
    if not re.fullmatch(r"[A-Za-z0-9-]{1,60}", name) or not value or len(value) > 256:
        return None
    return (name, value)


def create_origin_request(chat_id, user, state, deep, cookie=None, pass_pair=None):
    req = {
        "id": uuid.uuid4().hex, "user_id": user.get("id"),
        "username": user.get("username") or user.get("first_name", "?"),
        "ip": state["ip"], "auth_ref": state["auth_ref"],
        "proof_file_id": state.get("proof_file_id"),
        "proof_text": state.get("proof_text"),
        "top_ports": 0, "status": "pending", "kind": "origin",
        "origin_ip": state.get("origin_ip"), "deep": 1 if deep else 0,
        "created_at": time.time(),
        "expires_at": time.time() + APPROVAL_TTL_HOURS * 3600,
    }
    save_request(req)
    if cookie:
        AUTH_SECRETS[req["id"]] = cookie
    if pass_pair:
        PASS_SECRETS[req["id"]] = pass_pair
    STATE.pop(chat_id, None)
    send(chat_id, f"⏳ تم إنشاء طلب فحص الأصل {req['id'][:8]}: الموقع {req['ip']} "
                  f"على الخادم {req['origin_ip']} "
                  f"({'🔬 عميق' if deep else '⚡ سريع'}).\n"
                  "لن يبدأ أي فحص قبل موافقة الأدمن. ستصلك النتيجة هنا.")
    notify_admin(req)


def create_full_request(chat_id, user, state):
    req = {
        "id": uuid.uuid4().hex, "user_id": user.get("id"),
        "username": user.get("username") or user.get("first_name", "?"),
        "ip": state["ip"], "auth_ref": state["auth_ref"],
        "proof_file_id": state.get("proof_file_id"),
        "proof_text": state.get("proof_text"),
        "top_ports": 0, "status": "pending", "kind": "full",
        "deep": 1,
        "created_at": time.time(),
        "expires_at": time.time() + APPROVAL_TTL_HOURS * 3600,
    }
    save_request(req)
    STATE.pop(chat_id, None)
    send(chat_id, f"⏳ تم إنشاء طلب التقييم الشامل {req['id'][:8]} للمنظومة {req['ip']}.\n"
                  "يشمل: اكتشاف النطاقات الفرعية + منافذ الخوادم + تقييم ويب "
                  "للمواقع الحية + أمان البريد + درجة أمان موحدة.\n"
                  "لن يبدأ أي فحص قبل موافقة الأدمن، وقد يستغرق بعد الاعتماد "
                  "حتى ٣٠ دقيقة. ستصلك النتيجة هنا.")
    notify_admin(req)


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
    kind = req.get("kind", "ip")
    is_web = kind in ("web", "origin")
    extras = (" + جلسة حساب اختبار" if AUTH_SECRETS.get(req["id"]) else "") + \
             (" + بصمة مرور" if PASS_SECRETS.get(req["id"]) else "")
    if kind == "full":
        title = "🔔 طلب تقييم شامل لمنظومة بانتظار قرارك\n"
        scope_line = ("النوع: تقييم شامل 🏢 (اكتشاف نطاقات فرعية + منافذ + "
                      "ويب لكل مضيف حي + بريد + درجة أمان)")
        target_line = f"النطاق: {req['ip']}"
    elif kind == "origin":
        title = "🔔 طلب فحص خادم أصل بانتظار قرارك\n"
        scope_line = ("النوع: فحص أصل عميق 🔬 (CVE كاملة + ويب على الأصل مباشرة)"
                      if req.get("deep") else
                      "النوع: فحص أصل 🎯 (ويب مباشرة على الخادم)") + extras
        target_line = f"الموقع: {req['ip']}  |  الخادم الأصلي: {req.get('origin_ip')}"
    elif is_web and req.get("deep"):
        title = "🔔 طلب فحص موقع شامل بانتظار قرارك\n"
        scope_line = "النوع: فحص عميق 🔬 (CVE كاملة + زحف + أصل الخادم)" + extras
        target_line = f"الهدف: {req['ip']}"
    elif is_web:
        title = "🔔 طلب فحص موقع شامل بانتظار قرارك\n"
        scope_line = "النوع: ثغرات (Nuclei) + TLS + ترويسات أمان + DNS"
        target_line = f"الهدف: {req['ip']}"
    else:
        title = "🔔 طلب فحص جديد بانتظار قرارك\n"
        scope_line = f"المنافذ: {req['top_ports']}"
        target_line = f"الهدف: {req['ip']}"
    send(ADMIN_ID,
         title
         + f"{target_line}\nمن: {req['username']} (ID {req['user_id']})\n"
         f"مرجع التصريح: {req['auth_ref']}\n"
         + scope_line + "\n"
         + f"إثبات التصريح: {req.get('proof_text') or 'غير مرفق — تحقق بنفسك قبل الاعتماد'}\n"
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
    elif data == "web_scan":
        STATE[chat_id] = {"step": "w_await_host"}
        send(chat_id, "أرسل اسم نطاق الموقع المراد فحصه فحصاً شاملاً (مثال: example.com).\n"
                      "يشمل: كشف ثغرات Nuclei + شهادة TLS + ترويسات الأمان + سجلات DNS.\n"
                      "تنبيه: لا ترسل إلا موقعاً تملكه أو لديك تصريح مكتوب لفحصه.")
    elif data == "origin_scan":
        STATE[chat_id] = {"step": "o_await_host"}
        send(chat_id, "🎯 فحص خادم الأصل: فحص ويب كامل يُنفَّذ على الخادم الحقيقي "
                      "مباشرة بهوية الموقع — يقيس الموقع من مصدره لا من واجهة "
                      "Cloudflare.\nأرسل اسم نطاق الموقع (مثال: example.com).\n"
                      "تنبيه: لا ترسل إلا موقعاً تملكه أو لديك تصريح مكتوب لفحصه، "
                      "وعنوان أصله يزوّده مالكه.")
    elif data == "full_scan":
        STATE[chat_id] = {"step": "f_await_host"}
        send(chat_id, "🏢 تقييم شامل لمنظومة كاملة من نطاق واحد: اكتشاف "
                      "النطاقات الفرعية + فحص منافذ الخوادم + تقييم ويب "
                      "للمواقع الحية (ثغرات + TLS + ترويسات) + تدقيق أمان "
                      "البريد (SPF/DKIM/DMARC) + درجة أمان موحدة وأولويات "
                      "إصلاح.\nأرسل النطاق الرئيسي (مثال: example.com).\n"
                      "تنبيه: لا ترسل إلا نطاقاً تملكه أو لديك تصريح مكتوب "
                      "لتقييمه، والتقييم قد يستغرق حتى ٣٠ دقيقة بعد اعتماد الأدمن.")
    elif data == "tg_card":
        STATE[chat_id] = {"step": "tg_await_query"}
        send(chat_id, "🪪 بطاقة حساب تيليجرام: أرسل المعرف (@username) أو "
                      "رابط t.me أو المعرف الرقمي لحساب أو قناة أو مجموعة "
                      "عامة.\nأعرض البيانات العامة فقط: الاسم والنوع وعدد "
                      "الأعضاء والوصف العام وتقديراً تقريبياً لتاريخ الإنشاء.")
    elif data == "phone_card":
        STATE[chat_id] = {"step": "phone_await_number"}
        send(chat_id, "📱 بطاقة رقم هاتف: أرسل الرقم بالصيغة الدولية "
                      "الكاملة (مثال: +967700000000).\nأعرض: الدولة "
                      "والمشغّل ونوع الخط من بيانات الترقيم العالمية، "
                      "والحساب العام المرتبط بالرقم في تيليجرام إن سمح "
                      "صاحبه بالعثور عليه برقمه.")
    elif data == "health":
        show_health(chat_id)
    elif data == "my_requests":
        show_my_requests(chat_id, user.get("id"))
    elif data == "catalog":
        send(chat_id, "🧰 " + CATALOG_NOTE, MAIN_KB)
    elif data.startswith("wdepth:"):
        state = STATE.get(chat_id)
        if not state or state.get("step") != "w_await_depth":
            send(chat_id, "انتهت الجلسة، ابدأ من جديد بـ /start")
            return
        if data == "wdepth:quick":
            create_web_request(chat_id, user, state, deep=False)
        else:
            state.update(step="w_await_cookie")
            send(chat_id, "🔬 فحص عميق. خطوة اختيارية أخيرة: إن أردت فحص ما بعد "
                          "تسجيل الدخول، أرسل كوكيز جلسة حساب اختبار أنشأه مالك "
                          "الموقع لهذا الغرض. تُستخدم مرة واحدة في الذاكرة فقط "
                          "ولا تُحفظ في أي قاعدة أو سجل — لكنها ستظهر في محادثة "
                          "تيليجرام هذه، لذا حساب اختبار فقط. أو أرسل «تخطي».")
    elif data.startswith("odepth:"):
        state = STATE.get(chat_id)
        if not state or state.get("step") != "o_await_depth":
            send(chat_id, "انتهت الجلسة، ابدأ من جديد بـ /start")
            return
        if data == "odepth:quick":
            create_origin_request(chat_id, user, state, deep=False)
        else:
            state.update(step="o_await_cookie")
            send(chat_id, COOKIE_PROMPT)
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
            AUTH_SECRETS.pop(rid, None)
            PASS_SECRETS.pop(rid, None)
            send(chat_id, f"🚫 رفضت طلب {rid[:8]}.")
            send(req["user_id"], f"🚫 تم رفض طلب فحص {req['ip']} من الأدمن.")
            return
        # approve -> scan (the engine re-validates allowlist + permit anyway)
        if not transition(rid, "pending", "scanning"):
            send(chat_id, "هذا الطلب قيد المعالجة أصلاً.")
            return
        kind = req.get("kind", "ip")
        is_web = kind in ("web", "origin")
        send(chat_id, f"✅ اعتمدت {rid[:8]}، جارٍ الفحص…")
        send(req["user_id"], f"🔄 بدأ فحص {req['ip']}، "
             + ("التقييم الشامل قد يستغرق حتى ٣٠ دقيقة…" if kind == "full"
                else "العميق قد يستغرق حتى ٢٥ دقيقة…" if is_web and req.get("deep")
                else "قد يستغرق حتى عشر دقائق…" if is_web
                else "قد يستغرق حتى دقيقتين…"))
        try:
            if kind == "full":
                result = run_approved_full_scan(req)
                transition(rid, "scanning", "completed", result=json.dumps(result))
                send_long(req["user_id"], format_full_report(req, result), MAIN_KB)
            elif kind == "origin":
                result = run_approved_origin_scan(req)
                transition(rid, "scanning", "completed", result=json.dumps(result))
                send_long(req["user_id"], format_web_report(
                    req, result, origin_ip=req.get("origin_ip")), MAIN_KB)
            elif is_web:
                result = run_approved_web_scan(req)
                transition(rid, "scanning", "completed", result=json.dumps(result))
                send_long(req["user_id"], format_web_report(req, result), MAIN_KB)
            else:
                result = run_approved_scan(req)
                transition(rid, "scanning", "completed", result=json.dumps(result))
                send(req["user_id"], format_report(req, result), MAIN_KB)
            if req["user_id"] != ADMIN_ID:
                send(ADMIN_ID, f"✔️ اكتمل فحص {req['ip']} وأُرسل التقرير للمستخدم.")
        except Exception as exc:
            transition(rid, "scanning", "failed", error=str(exc)[:400])
            send(req["user_id"], f"❌ فشل فحص {req['ip']}: {exc}")
            send(ADMIN_ID, f"❌ فشل فحص {req['ip']} ({rid[:8]}): {exc}")


def process_update(update):
    if "message" in update:
        handle_message(update["message"])
    elif "callback_query" in update:
        handle_callback(update["callback_query"])


def register_webhook_loop():
    """Register the webhook with Telegram, retrying patiently (respecting
    retry_after) until it lands. Runs in a background thread so queued
    updates are consumed even while registration is still pending."""
    secret = webhook_secret()
    url = f"{WEBHOOK_BASE}/telegram/hook/{secret}"
    wait = 30
    while True:
        try:
            res = tg("setWebhook", url=url, secret_token=secret,
                     allowed_updates=["message", "callback_query"],
                     drop_pending_updates=False, max_connections=10,
                     _http_timeout=30)
            if res.get("ok"):
                print("Webhook registered OK")
                break
            print("setWebhook not ok:", str(res)[:200])
        except Exception as exc:
            match = re.search(r'"retry_after":\s*(\d+)', str(exc))
            if match:
                wait = max(wait, int(match.group(1)) + 5)
            print(f"setWebhook failed: {exc} (retry in {wait}s)")
        time.sleep(wait)
        wait = min(wait * 2, 600)
    # Watchdog: if the webhook is ever removed or replaced, restore it.
    while True:
        time.sleep(300)
        try:
            info = tg("getWebhookInfo", _http_timeout=30)
            current = (info.get("result") or {}).get("url", "")
            if current != url:
                print("Webhook missing/changed - re-registering")
                tg("setWebhook", url=url, secret_token=secret,
                   allowed_updates=["message", "callback_query"],
                   drop_pending_updates=False, max_connections=10,
                   _http_timeout=30)
                print("Webhook re-registered OK")
        except Exception as exc:
            print("webhook watchdog error:", exc)


def run_webhook_consumer():
    print("Bot is running (webhook queue consumer)…")
    while True:
        try:
            rows = fetch_unprocessed(20)
            if not rows:
                time.sleep(1)
                continue
            for update_id, payload in rows:
                try:
                    process_update(json.loads(payload))
                except Exception as exc:  # one bad update must not stall the queue
                    print("update error:", exc)
                mark_processed(update_id)
        except Exception as exc:
            print("queue error:", exc)
            time.sleep(3)


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
    if BOT_MODE == "webhook" and WEBHOOK_BASE and not HELPER:
        threading.Thread(target=register_webhook_loop, daemon=True).start()
        run_webhook_consumer()
        return
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
                process_update(update)
            except Exception as exc:  # keep polling on per-update errors
                print("update error:", exc)


if __name__ == "__main__":
    main()
