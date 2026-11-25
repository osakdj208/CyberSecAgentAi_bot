import base64, hashlib, hmac, ipaddress, json, os, secrets, shutil, socket, sqlite3, subprocess, time, urllib.request, urllib.error, xml.etree.ElementTree as ET
from typing import Optional
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

app = FastAPI(title="Cyber Security AI Agent Engine", version="0.8.0")
NMAP_PATH = shutil.which("nmap")
TOKEN = os.environ.get("ENGINE_API_TOKEN", "")
PERMIT_SECRET = os.environ.get("SCAN_APPROVAL_SECRET", "")
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
NETWORKS = []
for item in os.environ.get("AUTHORIZED_CIDRS", "").split(","):
    item = item.strip()
    if item:
        NETWORKS.append(ipaddress.ip_network(item, strict=False))

class ScanRequest(BaseModel):
    target_ip: str
    authorization_reference: str = Field(min_length=4, max_length=120)
    confirm_authorized: bool
    top_ports: int = Field(default=100, ge=10, le=100)

def require_auth(value: Optional[str]):
    if not TOKEN or not value or not secrets.compare_digest(value, f"Bearer {TOKEN}"):
        raise HTTPException(status_code=401, detail="Valid engine bearer token required")

def valid_dynamic_permit(value: Optional[str], target: str) -> bool:
    if not value or not PERMIT_SECRET: return False
    try:
        payload, signature = value.split(".", 1)
        expected = hmac.new(PERMIT_SECRET.encode(), payload.encode(), hashlib.sha256).digest()
        supplied = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        if not hmac.compare_digest(expected, supplied): return False
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return data.get("ip") == target and bool(data.get("id")) and isinstance(data.get("exp"), (int, float)) and data["exp"] > time.time() * 1000
    except Exception: return False

def check_target(value: str, permit: Optional[str] = None):
    try: address = ipaddress.ip_address(value)
    except ValueError: raise HTTPException(status_code=400, detail="Target must be a literal IP address.")
    if not address.is_global: raise HTTPException(status_code=400, detail="Only globally routable public IP addresses are eligible.")
    # Authorization gate (owner decision, 2026-11-24): a short-lived, IP-bound
    # HMAC permit issued after the admin personally verifies the requester's
    # authorization proof in the Telegram bot. The permit alone authorizes any
    # globally routable target; there is no single-server restriction.
    if not valid_dynamic_permit(permit, str(address)):
        raise HTTPException(status_code=403, detail="Target requires an active admin approval bound to this exact IP.")
    # AUTHORIZED_CIDRS is now an OPTIONAL extra narrowing restriction: when the
    # operator configures it, targets must also fall inside it. Empty = permit gate only.
    if NETWORKS and not any(address.version == net.version and address in net for net in NETWORKS):
        raise HTTPException(status_code=403, detail="Target is outside the engine's authorized CIDR restrictions.")
    return str(address)

def fetch_json(url, headers=None, timeout=8):
    req = urllib.request.Request(url, headers=headers or {"User-Agent":"CyberSecurityAI-Agent/0.3"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read(1_000_000).decode("utf-8", "replace"))

def passive_intel(target):
    report = {"rdap":None,"routing":None,"reverse_dns":None,"reputation":None,"geo":None,"sources":[],"warnings":[]}
    try:
        report["rdap"] = fetch_json(f"https://rdap.org/ip/{target}")
        report["sources"].append({"name":"RDAP","url":f"https://rdap.org/ip/{target}"})
    except Exception as exc: report["warnings"].append("RDAP lookup unavailable: " + type(exc).__name__)
    try:
        report["routing"] = fetch_json(f"https://stat.ripe.net/data/network-info/data.json?resource={target}")
        report["sources"].append({"name":"RIPEstat Network Info","url":"https://stat.ripe.net/"})
    except Exception as exc: report["warnings"].append("Routing/ASN lookup unavailable: " + type(exc).__name__)
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(target)
        report["reverse_dns"] = {"hostname":hostname,"aliases":aliases,"addresses":addresses}
    except Exception: report["reverse_dns"] = {"hostname":None,"note":"No PTR record returned."}
    try:
        geo = fetch_json(f"https://ipapi.co/{target}/json/")
        report["geo"] = {k:geo.get(k) for k in ("country_name","region","city","org","asn","timezone") if geo.get(k)}
        report["sources"].append({"name":"ipapi.co","url":f"https://ipapi.co/{target}/"})
    except Exception as exc: report["warnings"].append("Geolocation lookup unavailable: " + type(exc).__name__)
    if ABUSEIPDB_KEY:
        try:
            report["reputation"] = fetch_json(f"https://api.abuseipdb.com/api/v2/check?ipAddress={target}&maxAgeInDays=90", {"Key":ABUSEIPDB_KEY,"Accept":"application/json"})
            report["sources"].append({"name":"AbuseIPDB","url":"https://www.abuseipdb.com/"})
        except Exception as exc: report["warnings"].append("AbuseIPDB lookup unavailable: " + type(exc).__name__)
    else:
        report["reputation"] = {"status":"not_configured","note":"Set ABUSEIPDB_API_KEY to enable reputation checks; no reputation verdict was inferred."}
    report["collected_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return report

def nmap_data(target, top_ports):
    if not NMAP_PATH: raise HTTPException(status_code=503, detail="Nmap binary is not installed in this engine image.")
    # Keep untrusted target data out of process arguments entirely. Nmap reads
    # the already-validated literal IP from stdin via its documented -iL - mode.
    # The request schema bounds this profile to 10–100 common TCP ports.
    port_limit = max(10, min(100, int(top_ports)))
    command=[NMAP_PATH,"-n","-sT","-sV","-T2","--max-retries","2","--host-timeout","85s","--top-ports",str(port_limit),"-oX","-","-iL","-"]
    try: result=subprocess.run(command,input=target+"\n",capture_output=True,text=True,timeout=90,check=False,shell=False)
    except subprocess.TimeoutExpired: raise HTTPException(status_code=408,detail="Scan timed out after 90 seconds.")
    if result.returncode not in (0,1): raise HTTPException(status_code=502,detail="Nmap execution failed; consult engine logs.")
    try:
        root=ET.fromstring(result.stdout); host=root.find("host"); ports=[]
        if host is not None:
            for port in host.findall("./ports/port"):
                state=port.find("state"); service=port.find("service")
                ports.append({"port":port.get("portid"),"protocol":port.get("protocol"),"state":state.get("state") if state is not None else "unknown","service":service.get("name") if service is not None else "unknown","product":service.get("product") if service is not None else None,"version":service.get("version") if service is not None else None})
        return {"ports":ports,"summary":{"ports_observed":len(ports),"open_ports":sum(1 for p in ports if p["state"]=="open")}}
    except ET.ParseError: raise HTTPException(status_code=502,detail="Could not parse scanner output.")

@app.get("/health")
def health(authorization: Optional[str] = Header(default=None)):
    require_auth(authorization)
    ready=bool(TOKEN and NMAP_PATH and PERMIT_SECRET)
    return {"status":"ok" if ready else "degraded","engine":"nmap-plus-ip-intelligence","authorization_gate":"admin_approval_permit","allowlist_configured":bool(NETWORKS),"dynamic_approval_configured":bool(PERMIT_SECRET),"nmap_available":bool(NMAP_PATH),"nuclei_available":bool(NUCLEI_PATH),"execution_enabled":ready}

@app.get("/tools")
def tools(authorization: Optional[str] = Header(default=None)):
    require_auth(authorization)
    return {"available":[{"name":"Nmap TCP/service discovery","state":"ready" if NMAP_PATH else "unavailable","profile":"top 100 ports, conservative timing, no exploit scripts"},{"name":"RDAP allocation lookup","state":"ready"},{"name":"RIPEstat ASN/routing lookup","state":"ready"},{"name":"Reverse DNS","state":"ready"},{"name":"IP geolocation","state":"ready"},{"name":"AbuseIPDB reputation","state":"ready" if ABUSEIPDB_KEY else "optional_api_key_required"},{"name":"Nuclei vulnerability detection (curated, no intrusive tags)","state":"ready" if NUCLEI_PATH else "unavailable"},{"name":"TLS deep probe (certificate, protocols, legacy)","state":"ready"},{"name":"HTTP security headers & cookies analysis","state":"ready"},{"name":"DNS records inventory","state":"ready" if dns else "unavailable"},{"name":"Katana deep crawl (deep mode)","state":"ready" if KATANA_PATH else "unavailable"},{"name":"Nuclei CVE tree, per-year batches (deep mode)","state":"ready" if NUCLEI_PATH else "unavailable"},{"name":"Origin discovery behind CDNs (deep mode)","state":"ready"},{"name":"Origin-direct web assessment","state":"ready"},{"name":"Owner-agreed CDN pass fingerprint","state":"ready"},{"name":"Full attack-surface assessment (subdomains, per-host web, ports, score)","state":"ready"},{"name":"Email security audit (SPF / DMARC / DKIM selectors)","state":"ready" if dns else "unavailable"}]}

@app.post("/scans/intel")
def intel_scan(request: ScanRequest, authorization: Optional[str] = Header(default=None), x_scan_approval: Optional[str] = Header(default=None)):
    require_auth(authorization)
    if not request.confirm_authorized: raise HTTPException(status_code=400,detail="Explicit authorization confirmation is required.")
    target=check_target(request.target_ip,x_scan_approval)
    passive=passive_intel(target)
    active=nmap_data(target,request.top_ports)
    return {"status":"completed","target":target,"authorization_reference":request.authorization_reference,"profile":"approved-public-ip-intelligence","passive":passive,"ports":active["ports"],"summary":active["summary"],"limitations":["Only the 100 most common TCP ports are checked by default.","No exploit attempts, credential attacks, vulnerability exploitation, or intrusive NSE scripts are run.","Reputation data requires an optional AbuseIPDB API key."]}


# ------------------------------------------------------------ telegram webhook
# Telegram pushes updates to this endpoint; they are queued in the bot's
# SQLite DB (same file the bot process uses) and consumed by bot.py.
# The path secret is derived from SCAN_APPROVAL_SECRET exactly as bot.py
# derives it (webhook_secret), so no extra env var is needed.
BOT_DB_PATH = os.environ.get("BOT_DB_PATH", "/tmp/bot.db")

def _webhook_secret() -> str:
    return hmac.new(PERMIT_SECRET.encode(), b"telegram-webhook-v1", hashlib.sha256).hexdigest()

@app.post("/telegram/hook/{secret}")
async def telegram_hook(secret: str, request: Request):
    if not PERMIT_SECRET or not hmac.compare_digest(secret, _webhook_secret()):
        raise HTTPException(status_code=404, detail="not found")
    header_secret = request.headers.get("x-telegram-bot-api-secret-token")
    if header_secret is not None and not hmac.compare_digest(header_secret, _webhook_secret()):
        raise HTTPException(status_code=403, detail="bad secret token")
    try:
        update = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="bad json")
    update_id = update.get("update_id") if isinstance(update, dict) else None
    if not isinstance(update_id, int):
        raise HTTPException(status_code=400, detail="missing update_id")
    conn = sqlite3.connect(BOT_DB_PATH, timeout=10)
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS tg_updates(update_id INTEGER PRIMARY KEY, payload TEXT, processed INTEGER DEFAULT 0, received_at REAL)")
        conn.execute("INSERT OR IGNORE INTO tg_updates VALUES (?,?,0,?)", (update_id, json.dumps(update), time.time()))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


# Backward-compatible guarded endpoint retained for existing engine clients/tests.
@app.post("/scans/nmap")
def nmap_scan(request: ScanRequest, authorization: Optional[str] = Header(default=None), x_scan_approval: Optional[str] = Header(default=None)):
    require_auth(authorization)
    if not request.confirm_authorized:
        raise HTTPException(status_code=400, detail="Explicit authorization confirmation is required.")
    target = check_target(request.target_ip, x_scan_approval)
    data = nmap_data(target, request.top_ports)
    return {"status":"completed","target":target,"authorization_reference":request.authorization_reference,"profile":"nmap-safe-profile","ports":data["ports"],"summary":data["summary"]}


# ------------------------------------------------------------ web scan (v0.5.0)
# Phase 1 (developed separately in dev-v2; production untouched):
# comprehensive *detection-only* website assessment for a domain the
# requester proved authorization for, gated by the same admin-approval model.
# The bot mints a short-lived HMAC permit bound to the host AND the exact
# resolved IP set it saw at approval time; the engine re-resolves and
# requires its own resolved set to be a subset of the permitted set
# (anti DNS-rebinding), and every resolved address must be globally routable.
import re, ssl, urllib.parse
try:
    import dns.resolver
except Exception:  # dnspython optional: DNS section degrades honestly
    dns = None

NUCLEI_PATH = shutil.which("nuclei")
NUCLEI_TEMPLATES = os.environ.get("NUCLEI_TEMPLATES_DIR", "/opt/nuclei-templates")
HOST_RE = re.compile(r"^(?=.{4,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
SECURITY_HEADERS = ["strict-transport-security", "content-security-policy",
                    "x-frame-options", "x-content-type-options",
                    "referrer-policy", "permissions-policy"]

class WebScanRequest(BaseModel):
    target_host: str
    authorization_reference: str = Field(min_length=4, max_length=120)
    confirm_authorized: bool
    deep: bool = False
    # Optional session cookie of a dedicated TEST account supplied by the
    # site owner for authenticated detection. Used in-memory for this scan
    # only: never stored, never logged, never echoed in the response.
    auth_cookie: Optional[str] = Field(default=None, max_length=2048)
    # Optional owner-agreed CDN pass fingerprint: a header the owner
    # allowlisted in their WAF (e.g. a Cloudflare skip rule). In-memory
    # only for this scan; never stored, logged, or echoed.
    pass_header_name: Optional[str] = Field(default=None, max_length=60)
    pass_header_value: Optional[str] = Field(default=None, max_length=256)

def normalize_host(value: str) -> str:
    host = (value or "").strip().lower()
    for prefix in ("https://", "http://"):
        if host.startswith(prefix):
            host = host[len(prefix):]
    host = host.split("/")[0].split(":")[0].rstrip(".")
    try:
        ipaddress.ip_address(host)
        raise HTTPException(status_code=400, detail="Target is an IP address; use the IP scan flow.")
    except ValueError:
        pass
    if not HOST_RE.match(host):
        raise HTTPException(status_code=400, detail="Target must be a valid domain name.")
    return host

def resolve_host_ips(host: str):
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except Exception:
        raise HTTPException(status_code=400, detail="Domain does not resolve.")
    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise HTTPException(status_code=400, detail="Domain does not resolve.")
    for ip in ips:
        if not ipaddress.ip_address(ip).is_global:
            raise HTTPException(status_code=403, detail="Domain resolves to a non-public address; refused.")
    return ips

def valid_web_permit(value: Optional[str], host: str, ips) -> bool:
    if not value or not PERMIT_SECRET: return False
    try:
        payload, signature = value.split(".", 1)
        expected = hmac.new(PERMIT_SECRET.encode(), payload.encode(), hashlib.sha256).digest()
        supplied = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        if not hmac.compare_digest(expected, supplied): return False
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return (data.get("kind") == "web" and data.get("host") == host
                and bool(data.get("id")) and isinstance(data.get("exp"), (int, float))
                and data["exp"] > time.time() * 1000
                and set(data.get("ips") or []) >= set(ips))
    except Exception: return False

def check_web_target(value: str, permit: Optional[str] = None):
    host = normalize_host(value)
    ips = resolve_host_ips(host)
    if not valid_web_permit(permit, host, ips):
        raise HTTPException(status_code=403, detail="Target requires an active admin approval bound to this host and its resolved addresses.")
    if NETWORKS:
        for ip in ips:
            address = ipaddress.ip_address(ip)
            if not any(address.version == net.version and address in net for net in NETWORKS):
                raise HTTPException(status_code=403, detail="Target is outside the engine's authorized CIDR restrictions.")
    return host, ips

def dns_records(host: str):
    if dns is None:
        return {"status": "unavailable", "note": "dnspython not installed in this engine image."}
    out = {"status": "ready", "records": {}}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 4
    resolver.lifetime = 6
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CAA"):
        try:
            answers = resolver.resolve(host, rtype)
            out["records"][rtype] = sorted(str(r) for r in answers)[:10]
        except Exception:
            out["records"][rtype] = []
    return out

def _analyze_headers(headers: dict, set_cookies):
    lower = {str(k).lower(): str(v) for k, v in headers.items()}
    present = [h for h in SECURITY_HEADERS if h in lower]
    missing = [h for h in SECURITY_HEADERS if h not in lower]
    cookie_findings = []
    for cookie in set_cookies or []:
        flags = {"secure": "secure" in cookie.lower(),
                 "httponly": "httponly" in cookie.lower(),
                 "samesite": "samesite" in cookie.lower()}
        cookie_findings.append({"name": cookie.split("=")[0].strip()[:60], "flags": flags})
    return {"present": present, "missing": missing,
            "score": f"{len(present)}/{len(SECURITY_HEADERS)}",
            "server": lower.get("server"), "powered_by": lower.get("x-powered-by"),
            "cookies": cookie_findings}

class _RedirectRecorder(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        self.chain = []
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append({"status": code, "to": newurl})
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def http_probe(host: str, extra_headers: dict = None):
    result = {"status": "unavailable"}
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        recorder = _RedirectRecorder()
        opener = urllib.request.build_opener(recorder)
        req = urllib.request.Request(url, headers={"User-Agent": "CyberSecurityAI-Agent/0.5", **(extra_headers or {})})
        try:
            with opener.open(req, timeout=10) as resp:
                resp.read(65536)
                headers = dict(resp.headers.items())
                cookies = resp.headers.get_all("Set-Cookie") if hasattr(resp.headers, "get_all") else []
                result = {"status": "ready", "scheme": scheme, "final_url": resp.geturl(),
                          "http_status": resp.status, "redirects": recorder.chain[:5]}
                result.update(_analyze_headers(headers, cookies))
                return result
        except urllib.error.HTTPError as exc:
            headers = dict(exc.headers.items()) if exc.headers else {}
            cookies = exc.headers.get_all("Set-Cookie") if exc.headers and hasattr(exc.headers, "get_all") else []
            result = {"status": "ready", "scheme": scheme, "final_url": url,
                      "http_status": exc.code, "redirects": recorder.chain[:5]}
            result.update(_analyze_headers(headers, cookies))
            return result
        except Exception as exc:
            result = {"status": "unavailable", "error": f"{scheme}: {type(exc).__name__}"}
    return result

def _cert_days_left(not_after: str):
    try:
        return int((ssl.cert_time_to_seconds(not_after) - time.time()) // 86400)
    except Exception:
        return None

def tls_probe(host: str, connect_to: str = None):
    out = {"status": "unavailable"}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((connect_to or host, 443), timeout=8) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                out = {"status": "ready", "tls_version": tls.version(),
                       "cipher": (tls.cipher() or [None])[0],
                       "subject": dict(x[0] for x in cert.get("subject", ())),
                       "issuer": dict(x[0] for x in cert.get("issuer", ())),
                       "not_after": cert.get("notAfter"),
                       "days_left": _cert_days_left(cert.get("notAfter", "")),
                       "sans": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:20]}
    except Exception as exc:
        return {"status": "unavailable", "error": type(exc).__name__}
    legacy = {}
    for name, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            c2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c2.minimum_version = ver
            c2.maximum_version = ver
            c2.check_hostname = False
            c2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((connect_to or host, 443), timeout=6) as raw:
                with c2.wrap_socket(raw, server_hostname=host):
                    legacy[name] = True
        except Exception:
            legacy[name] = False
    out["legacy_protocols"] = legacy
    return out

def parse_nuclei_jsonl(text: str):
    findings, counts = [], {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue
        info = item.get("info") or {}
        severity = (info.get("severity") or "unknown").lower()
        counts[severity] = counts.get(severity, 0) + 1
        findings.append({"template": item.get("template-id"), "name": info.get("name"),
                         "severity": severity, "matched_at": item.get("matched-at"),
                         "type": item.get("type"),
                         "description": (info.get("description") or "")[:300],
                         "reference": (info.get("reference") or [])[:3]})
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    findings.sort(key=lambda f: order.get(f["severity"], 5))
    return findings[:100], counts

def _nuclei_base_args(cookie=None, headers=None):
    args = ["-jsonl", "-silent", "-nc", "-ni", "-duc",
            "-severity", "low,medium,high,critical",
            "-etags", "dos,intrusive,fuzz,brute-force",
            "-rl", "25", "-c", "5", "-timeout", "6", "-retries", "1",
            "-max-host-error", "3"]
    for h in (headers or []):
        args += ["-H", h]
    if cookie:
        args += ["-H", "Cookie: " + cookie]
    return args

def _run_nuclei(targets, template_dirs, cookie, cap, headers=None):
    if not NUCLEI_PATH:
        return None
    command = [NUCLEI_PATH]
    for t in targets:
        command += ["-u", t]
    command += _nuclei_base_args(cookie, headers)
    for d in template_dirs:
        command += ["-t", d]
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=cap, check=False, shell=False)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "findings": [], "counts": {}, "total": 0}
    findings, counts = parse_nuclei_jsonl(result.stdout)
    return {"status": "ready", "findings": findings, "counts": counts,
            "total": sum(counts.values())}

CURATED_DIRS = ("http/exposures", "http/misconfiguration",
                "http/vulnerabilities", "http/takeovers",
                "http/miscellaneous", "ssl", "dns", "network")

def _template_dirs(relative):
    return [os.path.join(NUCLEI_TEMPLATES, r) for r in relative
            if os.path.isdir(os.path.join(NUCLEI_TEMPLATES, r))]

def nuclei_scan(host: str, deep: bool = False, cookie: str = None,
                extra_targets=None, headers=None, targets_override=None):
    """Curated detection scan; in deep mode the full CVE tree also runs,
    one year per bounded batch, so peak memory stays free-tier safe."""
    if not NUCLEI_PATH:
        return {"status": "unavailable",
                "note": "Nuclei binary is not installed in this engine image."}
    base_targets = targets_override or [f"https://{host}", f"http://{host}"]
    targets = base_targets + [t for t in (extra_targets or [])
                              if t not in base_targets][:30]
    curated = _template_dirs(CURATED_DIRS)
    merged = _run_nuclei(targets, curated or [NUCLEI_TEMPLATES], cookie, 480, headers=headers)
    if merged is None:
        return {"status": "unavailable",
                "note": "Nuclei binary is not installed in this engine image."}
    batches = [{"label": "curated", "status": merged["status"],
                "total": merged["total"]}]
    all_findings = list(merged["findings"])
    counts = dict(merged["counts"])
    if deep:
        cve_root = os.path.join(NUCLEI_TEMPLATES, "http", "cves")
        years = []
        if os.path.isdir(cve_root):
            years = sorted((d for d in os.listdir(cve_root) if d.isdigit()),
                           reverse=True)
        spent = 0
        for year in years:
            if spent > 900:
                batches.append({"label": f"cve-{year}",
                                "status": "skipped_budget", "total": 0})
                continue
            t0 = time.time()
            part = _run_nuclei(base_targets,
                               [os.path.join(cve_root, year)], cookie, 200,
                               headers=headers)
            spent += int(time.time() - t0)
            if part is None:
                continue
            batches.append({"label": f"cve-{year}", "status": part["status"],
                            "total": part["total"]})
            all_findings += part["findings"]
            for k, v in part["counts"].items():
                counts[k] = counts.get(k, 0) + v
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3,
             "info": 4, "unknown": 5}
    seen, unique = set(), []
    for f in sorted(all_findings, key=lambda x: order.get(x["severity"], 5)):
        key = (f.get("template"), f.get("matched_at"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    # Counts describe the deduplicated findings the report actually lists,
    # so the summary and the list can never disagree.
    counts = {}
    for f in unique:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {"status": "ready", "findings": unique[:100], "counts": counts,
            "total": sum(counts.values()), "batches": batches,
            "deep": bool(deep)}

# ------------------------------------------------------------ katana crawl
KATANA_PATH = shutil.which("katana")
NOTABLE_WORDS = ("login", "admin", "api", "swagger", "graphql", "upload",
                 "panel", "dashboard", ".git", "backup", "config",
                 "phpmyadmin", "wp-admin", "console", "actuator")

def katana_crawl(host: str, cookie: str = None, headers=None):
    """Bounded same-host crawl (depth 2) that discovers the pages and
    endpoints the vulnerability scan should also cover."""
    if not KATANA_PATH:
        return {"status": "unavailable",
                "note": "Katana crawler is not installed in this engine image."}
    command = [KATANA_PATH, "-u", f"https://{host}", "-silent", "-nc",
               "-d", "2", "-c", "10", "-rl", "30", "-timeout", "8",
               "-retries", "1", "-jc", "-kf", "all"]
    if cookie:
        command += ["-H", "Cookie: " + cookie]
    for h in (headers or []):
        command += ["-H", h]
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=150, check=False, shell=False)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "urls": [], "total": 0, "notable": []}
    urls = []
    for line in (result.stdout or "").splitlines():
        u = line.strip()
        if not u.startswith("http"):
            continue
        try:
            parsed = urllib.parse.urlparse(u)
        except Exception:
            continue
        if (parsed.hostname or "").lower() != host.lower():
            continue
        if u not in urls:
            urls.append(u)
        if len(urls) >= 300:
            break
    notable = [u for u in urls
               if any(w in u.lower() for w in NOTABLE_WORDS)][:30]
    return {"status": "ready", "total": len(urls), "urls": urls,
            "notable": notable}

# ------------------------------------------------------------ origin discovery
# Cloudflare edge ranges (public, stable): addresses inside them are the
# CDN edge, never the origin we are looking for.
CF_V4 = ["173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
         "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
         "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
         "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
         "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"]
CF_NETS = [ipaddress.ip_network(c) for c in CF_V4]
SUBDOMAIN_WORDS = ["mail", "direct", "origin", "server", "ftp", "cpanel",
                   "webmail", "www2", "backend", "host", "portal", "mx"]

def _is_cloudflare(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in CF_NETS)

def _crtsh_subdomains(base: str):
    try:
        data = fetch_json(f"https://crt.sh/?q=%25.{base}&output=json",
                          timeout=15)
    except Exception:
        return []
    names = set()
    if isinstance(data, list):
        for row in data:
            for name in str(row.get("name_value", "")).split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name.endswith(base) and "@" not in name:
                    names.add(name)
    return sorted(names)[:60]

def _verify_origin(ip: str, host: str) -> bool:
    """Ask the candidate address directly, with the site's Host/SNI: if it
    answers like the site, it very likely IS the origin server."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, 443), timeout=6) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                tls.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                            "Connection: close\r\n\r\n".encode())
                data = tls.recv(1024).decode("utf-8", "replace")
                return data.startswith("HTTP/")
    except Exception:
        return False

def origin_discovery(host: str):
    """Passive origin hunt: certificate-transparency subdomains plus the
    usual direct/mail subdomains, filtered to non-Cloudflare addresses."""
    base = host[4:] if host.startswith("www.") else host
    subs = set(_crtsh_subdomains(base))
    subs |= {f"{w}.{base}" for w in SUBDOMAIN_WORDS}
    found = {}
    for sub in sorted(subs):
        try:
            infos = socket.getaddrinfo(sub, None, proto=socket.IPPROTO_TCP)
        except Exception:
            continue
        for info in infos:
            ip = info[4][0]
            try:
                if not ipaddress.ip_address(ip).is_global:
                    continue
            except ValueError:
                continue
            if not _is_cloudflare(ip):
                found.setdefault(ip, []).append(sub)
    candidates = []
    for ip, names in list(found.items())[:5]:
        candidates.append({"ip": ip, "via_subdomains": names[:4],
                           "serves_site": _verify_origin(ip, host)})
    return {"status": "ready", "base_domain": base,
            "subdomains_checked": len(subs), "candidates": candidates,
            "note": "Candidates are non-Cloudflare addresses of related "
                    "subdomains; serves_site means the address answered "
                    "for this site when asked directly."}


def _pass_headers(request):
    """The owner-agreed CDN pass fingerprint for this scan, if supplied."""
    name = getattr(request, "pass_header_name", None)
    value = getattr(request, "pass_header_value", None)
    if not name or not value:
        return {}
    if not re.fullmatch(r"[A-Za-z0-9-]{1,60}", name):
        raise HTTPException(status_code=400, detail="Invalid pass header name.")
    return {name: value}

@app.post("/scans/web")
def web_scan(request: WebScanRequest, authorization: Optional[str] = Header(default=None), x_scan_approval: Optional[str] = Header(default=None)):
    require_auth(authorization)
    if not request.confirm_authorized: raise HTTPException(status_code=400, detail="Explicit authorization confirmation is required.")
    host, ips = check_web_target(request.target_host, x_scan_approval)
    pass_headers = _pass_headers(request)
    probe_headers = dict(pass_headers)
    if request.auth_cookie:
        probe_headers["Cookie"] = request.auth_cookie
    pass_list = [f"{k}: {v}" for k, v in pass_headers.items()]
    crawl = katana_crawl(host, request.auth_cookie, headers=pass_list) if request.deep else {"status": "skipped"}
    extra = crawl.get("urls") if crawl.get("status") == "ready" else None
    origin = origin_discovery(host) if request.deep else {"status": "skipped"}
    return {"status": "completed", "target": host, "resolved_ips": ips,
            "authorization_reference": request.authorization_reference,
            "profile": "approved-web-assessment-v2" if request.deep else "approved-web-assessment-v1",
            "deep": bool(request.deep), "authenticated": bool(request.auth_cookie),
            "pass_used": bool(pass_headers),
            "dns": dns_records(host), "http": http_probe(host, extra_headers=probe_headers),
            "tls": tls_probe(host),
            "nuclei": nuclei_scan(host, deep=request.deep,
                                  cookie=request.auth_cookie,
                                  extra_targets=extra,
                                  headers=pass_list),
            "crawl": {k: crawl.get(k) for k in ("status", "total", "notable", "note")},
            "origin": origin,
            "limitations": ["Detection only: curated Nuclei templates with dos/intrusive/fuzz/brute-force tags excluded; no exploitation is attempted.",
                            "Deep mode adds the full CVE template tree in per-year batches and a depth-2 crawl; findings remain scanner reports for the admin to review.",
                            "Origin candidates are passive discoveries (certificate transparency + related subdomains), verified by a direct request; a well-hidden origin may not appear.",
                            "An authenticated scan uses only the test-account session the owner supplied for this scan; it is never stored."]}

# ------------------------------------------------- origin-direct assessment
class OriginScanRequest(BaseModel):
    target_host: str
    origin_ip: str
    authorization_reference: str = Field(min_length=4, max_length=120)
    confirm_authorized: bool
    deep: bool = False
    auth_cookie: Optional[str] = Field(default=None, max_length=2048)
    pass_header_name: Optional[str] = Field(default=None, max_length=60)
    pass_header_value: Optional[str] = Field(default=None, max_length=256)

def valid_origin_permit(value: Optional[str], host: str, ip: str) -> bool:
    if not value or not PERMIT_SECRET:
        return False
    try:
        payload, signature = value.split(".", 1)
        expected = hmac.new(PERMIT_SECRET.encode(), payload.encode(),
                            hashlib.sha256).digest()
        supplied = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        if not hmac.compare_digest(expected, supplied):
            return False
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return (data.get("kind") == "origin" and data.get("host") == host
                and data.get("ip") == ip
                and bool(data.get("id"))
                and isinstance(data.get("exp"), (int, float))
                and data["exp"] > time.time() * 1000)
    except Exception:
        return False

def check_origin_target(host_value, ip_value, permit):
    """Origin scans require a permit minted for exactly this host+IP pair."""
    host = normalize_host(host_value)
    try:
        ip = ipaddress.ip_address((ip_value or "").strip())
    except ValueError:
        raise HTTPException(status_code=422,
                            detail="origin_ip must be a literal IP address.")
    if not ip.is_global:
        raise HTTPException(status_code=403,
                            detail="Origin address must be globally routable.")
    if not valid_origin_permit(permit, host, str(ip)):
        raise HTTPException(status_code=403,
                            detail="Target requires an active admin approval "
                                   "bound to this host and origin address.")
    return host, str(ip)

def _raw_http_get(ip, port, host, use_tls, hdrs):
    sock = socket.create_connection((ip, port), timeout=8)
    if use_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    lines = ["GET / HTTP/1.1", f"Host: {host}",
             "User-Agent: Mozilla/5.0 (compatible; authorized-assessment/1.0)",
             "Accept: */*", "Connection: close"]
    for k, v in (hdrs or {}).items():
        lines.append(f"{k}: {v}")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    data = b""
    while len(data) < 65536:
        chunk = sock.recv(8192)
        if not chunk:
            break
        data += chunk
    sock.close()
    head = data.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", "replace")
    head_lines = head.split("\r\n")
    parts = head_lines[0].split()
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
    headers, cookies = {}, []
    for line in head_lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            k, v = k.strip().lower(), v.strip()
            if k == "set-cookie":
                cookies.append(v)
            else:
                headers[k] = v
    return status, headers, cookies

def http_probe_at(ip: str, host: str, hdrs: dict = None):
    """Single-hop probe of the site AS SERVED BY THE ORIGIN ITSELF: the
    request goes to the origin address with the site's Host/SNI identity,
    and redirects are recorded, not followed (following would leave the
    origin and measure the CDN again)."""
    last = None
    for scheme, port, use_tls in (("https", 443, True), ("http", 80, False)):
        try:
            status, headers, cookies = _raw_http_get(ip, port, host, use_tls, hdrs)
        except Exception as exc:
            last = {"status": "unavailable",
                    "note": f"{type(exc).__name__}: origin did not answer on {scheme}."}
            continue
        result = {"status": "ready", "scheme": scheme,
                  "final_url": f"{scheme}://{host}/ (directly from origin {ip})",
                  "http_status": status,
                  "redirects": ([{"status": status, "to": headers["location"]}]
                                if headers.get("location") else [])}
        result.update(_analyze_headers(headers, cookies))
        return result
    return last

@app.post("/scans/origin")
def origin_scan(request: OriginScanRequest, authorization: Optional[str] = Header(default=None), x_scan_approval: Optional[str] = Header(default=None)):
    require_auth(authorization)
    if not request.confirm_authorized: raise HTTPException(status_code=400, detail="Explicit authorization confirmation is required.")
    host, ip = check_origin_target(request.target_host, request.origin_ip, x_scan_approval)
    pass_headers = _pass_headers(request)
    probe_headers = dict(pass_headers)
    if request.auth_cookie:
        probe_headers["Cookie"] = request.auth_cookie
    pass_list = [f"{k}: {v}" for k, v in pass_headers.items()]
    nuclei = nuclei_scan(host, deep=request.deep, cookie=request.auth_cookie,
                         headers=pass_list + [f"Host: {host}"],
                         targets_override=[f"https://{ip}", f"http://{ip}"])
    return {"status": "completed", "target": host, "origin_ip": ip,
            "authorization_reference": request.authorization_reference,
            "profile": "approved-origin-assessment-v2" if request.deep else "approved-origin-assessment-v1",
            "deep": bool(request.deep), "authenticated": bool(request.auth_cookie),
            "pass_used": bool(pass_headers),
            "dns": dns_records(host),
            "http": http_probe_at(ip, host, probe_headers),
            "tls": tls_probe(host, connect_to=ip),
            "nuclei": nuclei,
            "crawl": {"status": "skipped",
                      "note": "Crawl is not run in origin mode; the origin server itself is the target."},
            "limitations": ["The web assessment is served by the origin address directly (Host/SNI identity of the site); public DNS data is shown for reference only.",
                            "Detection only, identical guardrails to the standard web assessment; no exploitation is attempted.",
                            "For ports and services on the same server, run the standard IP scan on the origin address."]}

# ------------------------------------------------- full attack-surface assessment
class FullScanRequest(BaseModel):
    target_host: str
    authorization_reference: str = Field(min_length=4, max_length=120)
    confirm_authorized: bool

def valid_full_permit(value: Optional[str], host: str, ips) -> bool:
    if not value or not PERMIT_SECRET: return False
    try:
        payload, signature = value.split(".", 1)
        expected = hmac.new(PERMIT_SECRET.encode(), payload.encode(), hashlib.sha256).digest()
        supplied = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        if not hmac.compare_digest(expected, supplied): return False
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return (data.get("kind") == "full" and data.get("host") == host
                and bool(data.get("id")) and isinstance(data.get("exp"), (int, float))
                and data["exp"] > time.time() * 1000
                and set(data.get("ips") or []) >= set(ips))
    except Exception: return False

def check_full_target(value: str, permit: Optional[str] = None):
    host = normalize_host(value)
    ips = resolve_host_ips(host)
    if not valid_full_permit(permit, host, ips):
        raise HTTPException(status_code=403, detail="Target requires an active admin approval bound to this host and its resolved addresses.")
    if NETWORKS:
        for ip in ips:
            address = ipaddress.ip_address(ip)
            if not any(address.version == net.version and address in net for net in NETWORKS):
                raise HTTPException(status_code=403, detail="Target is outside the engine's authorized CIDR restrictions.")
    return host, ips

DISCOVERY_WORDS = ["www", "mail", "webmail", "portal", "app", "api", "dev",
                   "staging", "test", "admin", "vpn", "remote", "shop",
                   "blog", "support", "help", "cloud", "secure", "login",
                   "cpanel", "ftp", "mx", "ns1", "ns2", "direct", "origin",
                   "server", "backend", "host", "www2", "m", "beta", "old"]

def _resolve_quiet(host):
    """Resolve a hostname to its global IPs, or [] — discovery helper
    that never raises and never returns non-public addresses."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except Exception:
        return []
    ips = sorted({info[4][0] for info in infos})
    out = []
    for ip in ips:
        try:
            if ipaddress.ip_address(ip).is_global:
                out.append(ip)
        except ValueError:
            continue
    return out

def discover_subdomains(base: str):
    """Passive subdomain discovery: certificate-transparency names plus
    a bounded wordlist of names that actually resolve. Returns the
    sorted candidate hostnames (base itself excluded)."""
    names = set(_crtsh_subdomains(base))
    for word in DISCOVERY_WORDS:
        candidate = f"{word}.{base}"
        if candidate not in names and _resolve_quiet(candidate):
            names.add(candidate)
    names.discard(base)
    return sorted(names)[:40]

DKIM_SELECTORS = ["google", "selector1", "selector2", "default", "mail",
                  "k1", "s1", "smtp", "dkim", "mandrill", "amazonses",
                  "protonmail", "zoho", "yandex"]

def _txt_records(resolver, name):
    try:
        answers = resolver.resolve(name, "TXT")
        return ["".join(part.decode() if isinstance(part, bytes) else part
                         for part in r.strings) if hasattr(r, "strings")
                else str(r).strip('"') for r in answers]
    except Exception:
        return []

def email_security(domain: str):
    """SPF / DMARC / DKIM-selector audit from public DNS only."""
    if dns is None:
        return {"status": "unavailable",
                "note": "dnspython not installed in this engine image."}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 4
    resolver.lifetime = 6
    try:
        mx = sorted(str(r) for r in resolver.resolve(domain, "MX"))
    except Exception:
        mx = []
    out = {"status": "ready", "has_mx": bool(mx), "mx": mx[:5]}
    spf_records = [t for t in _txt_records(resolver, domain)
                   if t.lower().startswith("v=spf1")]
    if spf_records:
        record = spf_records[0]
        tail = record.lower().rsplit("all", 1)[-1] if "all" in record.lower() else ""
        if "-all" in record.lower():
            strength = "strict"
        elif "~all" in record.lower():
            strength = "softfail"
        else:
            strength = "weak"
        out["spf"] = {"present": True, "record": record[:250],
                      "strength": strength}
    else:
        out["spf"] = {"present": False}
    dmarc_records = [t for t in _txt_records(resolver, f"_dmarc.{domain}")
                     if "v=dmarc1" in t.lower().replace(" ", "")]
    if dmarc_records:
        record = dmarc_records[0]
        m = re.search(r"p\s*=\s*(none|quarantine|reject)", record.lower())
        out["dmarc"] = {"present": True, "record": record[:250],
                        "policy": m.group(1) if m else "unknown"}
    else:
        out["dmarc"] = {"present": False}
    found = []
    for selector in DKIM_SELECTORS:
        name = f"{selector}._domainkey.{domain}"
        if _txt_records(resolver, name):
            found.append(selector)
            continue
        try:
            resolver.resolve(name, "CNAME")
            found.append(selector)
        except Exception:
            pass
    out["dkim"] = {"selectors_checked": len(DKIM_SELECTORS), "found": found}
    return out

COOKIE_FRAMEWORK_HINTS = (
    ("phpsessid", "PHP"), ("jsessionid", "Java"),
    ("asp.net_sessionid", "ASP.NET"), ("aspsessionid", "ASP.NET"),
    ("csrftoken", "Django"), ("laravel_session", "Laravel"),
    ("wordpress_", "WordPress"), ("wp-settings", "WordPress"),
    ("x-id-", "Amazon"), ("session-id", "Amazon"),
)

def tech_fingerprint(http_result):
    """Conservative technology hints from response headers and cookie
    names only — labelled as hints, never as certainties."""
    hints = []
    server = http_result.get("server")
    powered = http_result.get("powered_by")
    if server:
        hints.append(f"خادم ويب: {server}")
    if powered:
        hints.append(f"تقنية معلنة: {powered}")
    for cookie in http_result.get("cookies") or []:
        name = (cookie.get("name") or "").lower()
        for marker, label in COOKIE_FRAMEWORK_HINTS:
            if marker in name and f"إطار/منصة محتملة: {label}" not in hints:
                hints.append(f"إطار/منصة محتملة: {label}")
    return {"server": server, "powered_by": powered, "hints": hints}

RISKY_PORTS = {21: "FTP", 23: "Telnet", 2323: "Telnet-alt", 3389: "RDP",
               5900: "VNC", 6379: "Redis", 27017: "MongoDB",
               2375: "Docker API", 2376: "Docker API"}
DB_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL",
            9200: "Elasticsearch", 11211: "Memcached", 5984: "CouchDB"}

def full_score(hosts, ports_by_ip, email):
    """Transparent 0-100 posture score: every deduction is listed so
    the report can show exactly why the score is what it is."""
    score = 100
    deductions = []

    def deduct(points, label, cap_bucket, caps):
        if caps.get(cap_bucket, 0) >= caps["_caps"][cap_bucket]:
            return
        take = min(points, caps["_caps"][cap_bucket] - caps.get(cap_bucket, 0))
        if take <= 0:
            return
        caps[cap_bucket] = caps.get(cap_bucket, 0) + take
        nonlocal_score[0] -= take
        deductions.append({"points": take, "label": label})

    caps = {"_caps": {"nuclei": 40, "tls": 16, "headers": 12,
                      "ports": 24, "email": 22}}
    nonlocal_score = [score]
    sev_points = {"critical": (15, "نتيجة Nuclei حرجة"), "high": (8, "نتيجة Nuclei عالية"),
                  "medium": (3, "نتيجة Nuclei متوسطة"), "low": (1, "نتيجة Nuclei منخفضة")}
    for host in hosts:
        nuc = host.get("nuclei") or {}
        for sev, count in (nuc.get("counts") or {}).items():
            if sev in sev_points and count:
                pts, label = sev_points[sev]
                deduct(pts * count, f"{label} على {host['host']} (×{count})",
                       "nuclei", caps)
        http = host.get("http") or {}
        tls = host.get("tls") or {}
        if http.get("status") == "ready":
            missing = len(http.get("missing") or [])
            if missing >= 4:
                deduct(4, f"ترويسات أمان ناقصة ({missing}) على {host['host']}",
                       "headers", caps)
            elif missing >= 2:
                deduct(2, f"ترويسات أمان ناقصة ({missing}) على {host['host']}",
                       "headers", caps)
            if http.get("scheme") == "http" and tls.get("status") != "ready":
                deduct(4, f"{host['host']} يخدم HTTP بلا TLS", "tls", caps)
        if tls.get("status") == "ready":
            legacy = [k for k, v in (tls.get("legacy_protocols") or {}).items() if v]
            if legacy:
                deduct(6, f"بروتوكولات TLS قديمة على {host['host']}: {', '.join(legacy)}",
                       "tls", caps)
            days = tls.get("days_left")
            if days is not None and days < 15:
                deduct(5, f"شهادة {host['host']} تنتهي بعد {days} يوماً",
                       "tls", caps)
    for entry in ports_by_ip:
        for port in entry.get("ports") or []:
            if port.get("state") != "open":
                continue
            try:
                number = int(port.get("port"))
            except (TypeError, ValueError):
                continue
            if number in RISKY_PORTS:
                deduct(6, f"منفذ حساس مفتوح {number} ({RISKY_PORTS[number]}) على {entry['ip']}",
                       "ports", caps)
            elif number in DB_PORTS:
                deduct(3, f"منفذ قاعدة بيانات مفتوح {number} ({DB_PORTS[number]}) على {entry['ip']}",
                       "ports", caps)
    if email.get("status") == "ready" and email.get("has_mx"):
        spf = email.get("spf") or {}
        dmarc = email.get("dmarc") or {}
        if not spf.get("present"):
            deduct(8, "لا سجل SPF — انتحال البريد ممكن", "email", caps)
        elif spf.get("strength") in ("softfail", "weak"):
            deduct(4, "سجل SPF ضعيف الإنهاء (ليس -all)", "email", caps)
        if not dmarc.get("present"):
            deduct(8, "لا سجل DMARC — لا حماية من انتحال النطاق", "email", caps)
        elif dmarc.get("policy") == "none":
            deduct(4, "سياسة DMARC عند p=none (مراقبة فقط)", "email", caps)
        if not (email.get("dkim") or {}).get("found"):
            deduct(2, "لم يُعثر على مفاتيح DKIM للمحددات الشائعة المفحوصة",
                   "email", caps)
    final = max(0, nonlocal_score[0])
    grade = ("ممتاز" if final >= 90 else "جيد" if final >= 75 else
             "متوسط" if final >= 55 else "ضعيف" if final >= 35 else "حرج")
    deductions.sort(key=lambda d: -d["points"])
    return {"score": final, "grade": grade, "deductions": deductions[:12]}

@app.post("/scans/full")
def full_scan(request: FullScanRequest, authorization: Optional[str] = Header(default=None), x_scan_approval: Optional[str] = Header(default=None)):
    require_auth(authorization)
    if not request.confirm_authorized: raise HTTPException(status_code=400, detail="Explicit authorization confirmation is required.")
    host, ips = check_full_target(request.target_host, x_scan_approval)
    started = time.time()
    base = host[4:] if host.startswith("www.") else host

    discovered = discover_subdomains(base)
    candidates = []
    for name in [host, base] + discovered:
        if name not in candidates:
            candidates.append(name)
    assessed, all_ips = [], []
    for name in candidates[:10]:
        resolved = _resolve_quiet(name)
        if not resolved:
            continue
        for ip in resolved:
            if ip not in all_ips:
                all_ips.append(ip)
        http = http_probe(name)
        tls = tls_probe(name) if http.get("status") == "ready" else {"status": "skipped"}
        assessed.append({"host": name, "ips": resolved, "http": http,
                         "tls": tls, "tech": tech_fingerprint(http),
                         "nuclei": {"status": "skipped"}})
    live = [h for h in assessed if (h.get("http") or {}).get("status") == "ready"]
    nuclei_done = 0
    for entry in live:
        if nuclei_done >= 3 or time.time() - started > 1000:
            entry["nuclei"] = {"status": "skipped_budget"}
            continue
        entry["nuclei"] = nuclei_scan(entry["host"], deep=False)
        nuclei_done += 1
    ports_by_ip = []
    for ip in all_ips[:4]:
        if time.time() - started > 1250:
            break
        try:
            data = nmap_data(ip, 100)
            ports_by_ip.append({"ip": ip, "ports": data["ports"],
                                "summary": data["summary"]})
        except HTTPException as exc:
            ports_by_ip.append({"ip": ip, "ports": [],
                                "error": exc.detail})
    email = email_security(base)
    score = full_score(assessed, ports_by_ip, email)
    priorities = [d["label"] for d in score["deductions"][:8]]
    return {"status": "completed", "target": host, "base_domain": base,
            "resolved_ips": ips,
            "authorization_reference": request.authorization_reference,
            "profile": "approved-full-assessment-v1",
            "elapsed_seconds": int(time.time() - started),
            "discovery": {"subdomains_found": discovered,
                          "hosts_assessed": [h["host"] for h in assessed]},
            "dns": dns_records(host),
            "hosts": assessed, "ports_by_ip": ports_by_ip,
            "email": email, "score": score, "priorities": priorities,
            "limitations": ["Detection only: identical guardrails to the web assessment (curated Nuclei templates, no intrusive tags, no exploitation).",
                            "Discovery is passive (certificate transparency + resolving wordlist); subdomains that exist but are neither in CT logs nor in the wordlist will not appear.",
                            "Bounds: at most 10 hosts probed, 3 hosts get a full Nuclei run, 4 IPs get a top-100 port scan, within one time budget; anything beyond is reported as skipped, never silently dropped.",
                            "The score is a transparent heuristic: every deduction is listed with its reason; it prioritizes fixes, it is not a certification."]}
