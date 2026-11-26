import base64, hashlib, hmac, ipaddress, json, os, secrets, shutil, socket, sqlite3, subprocess, time, urllib.request, urllib.error, xml.etree.ElementTree as ET
from typing import Optional
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

app = FastAPI(title="Cyber Security AI Agent Engine", version="0.13.0")
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
    return {"available":[{"name":"Nmap TCP/service discovery","state":"ready" if NMAP_PATH else "unavailable","profile":"top 100 ports, conservative timing, no exploit scripts"},{"name":"RDAP allocation lookup","state":"ready"},{"name":"RIPEstat ASN/routing lookup","state":"ready"},{"name":"Reverse DNS","state":"ready"},{"name":"IP geolocation","state":"ready"},{"name":"AbuseIPDB reputation","state":"ready" if ABUSEIPDB_KEY else "optional_api_key_required"},{"name":"Nuclei vulnerability detection (curated, no intrusive tags)","state":"ready" if NUCLEI_PATH else "unavailable"},{"name":"TLS deep probe (certificate, protocols, legacy)","state":"ready"},{"name":"HTTP security headers & cookies analysis","state":"ready"},{"name":"DNS records inventory","state":"ready" if dns else "unavailable"},{"name":"Katana deep crawl (deep mode)","state":"ready" if KATANA_PATH else "unavailable"},{"name":"Nuclei CVE tree, per-year batches (deep mode)","state":"ready" if NUCLEI_PATH else "unavailable"},{"name":"Origin discovery behind CDNs (deep mode)","state":"ready"},{"name":"Origin-direct web assessment","state":"ready"},{"name":"Owner-agreed CDN pass fingerprint","state":"ready"},{"name":"Full attack-surface assessment (subdomains, per-host web, ports, score)","state":"ready"},{"name":"Email security audit (SPF / DMARC / DKIM selectors)","state":"ready" if dns else "unavailable"},{"name":"Android APK static analysis (manifest, permissions, components, embedded secrets, signer)","state":"ready" if _AndroAPK else "unavailable"},{"name":"Subdomain takeover detection (dangling CNAME fingerprints)","state":"ready" if dns else "unavailable"},{"name":"Deep DNS audit (AXFR attempt, DNSSEC, CAA)","state":"ready" if dns else "unavailable"},{"name":"API surface & GraphQL introspection check","state":"ready"},{"name":"JavaScript mining (exposed secrets, API endpoints, internal addresses)","state":"ready"},{"name":"Cloud storage exposure check (S3 / Azure Blob / GCS)","state":"ready"},{"name":"Dependency vulnerability analysis (SCA via OSV.dev)","state":"ready"},{"name":"Version-to-CVE matching (NVD, strict applicability filter)","state":"ready"},{"name":"Sensitive content exposure (signature-verified paths)","state":"ready"},{"name":"Expanded passive subdomain sources (crt.sh, HackerTarget, urlscan, Wayback)","state":"ready"}]}

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

def _hackertarget_subdomains(base):
    text = _fetch_text(
        f"https://api.hackertarget.com/hostsearch/?q={base}",
        timeout=10, cap=262144)
    names = set()
    for line in (text or "").splitlines():
        host = line.split(",")[0].strip().lower()
        if host.endswith(base) and "@" not in host:
            names.add(host)
    return sorted(names)[:60]

def _urlscan_subdomains(base):
    try:
        data = fetch_json(
            f"https://urlscan.io/api/v1/search/?q=domain%3A{base}&size=100",
            timeout=12)
    except Exception:
        return []
    names = set()
    if isinstance(data, dict):
        for row in data.get("results") or []:
            domain = ((row.get("page") or {}).get("domain") or "").lower()
            if domain.endswith(base):
                names.add(domain)
    return sorted(names)[:60]

def _wayback_subdomains(base):
    try:
        data = fetch_json(
            f"https://web.archive.org/cdx/search/cdx?url=*.{base}"
            "&output=json&fl=original&collapse=urlkey&limit=500",
            timeout=15)
    except Exception:
        return []
    names = set()
    if isinstance(data, list):
        for row in data[1:]:
            if row:
                host = (urllib.parse.urlparse(row[0]).hostname
                        or "").lower()
                if host.endswith(base):
                    names.add(host)
    return sorted(names)[:60]

def discover_subdomains(base: str):
    """Passive subdomain discovery: certificate-transparency names,
    public scan/archive indexes (HackerTarget, urlscan, Wayback), plus
    a bounded wordlist of names that actually resolve. Returns the
    sorted candidate hostnames (base itself excluded)."""
    names = set(_crtsh_subdomains(base))
    for source in (_hackertarget_subdomains, _urlscan_subdomains,
                   _wayback_subdomains):
        names.update(source(base))
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

# --------------------------- Phase C1: takeover detection + deep DNS audit
try:
    import dns.query as _dns_query
    import dns.zone as _dns_zone
except Exception:
    _dns_query = None
    _dns_zone = None

# Dangling-CNAME services and the body fingerprints of their unclaimed-site
# pages. A candidate is only ever reported with its evidence level:
# "confirmed" when the service's own unclaimed page answered, "likely"
# when the alias target no longer resolves at all. A name that answers
# normally is in use and is never reported.
TAKEOVER_SERVICES = [
    ("github.io", "GitHub Pages",
     ["There isn't a GitHub Pages site here"]),
    ("herokuapp.com", "Heroku", ["No such app"]),
    ("s3.amazonaws.com", "Amazon S3",
     ["NoSuchBucket", "The specified bucket does not exist"]),
    ("blob.core.windows.net", "Azure Blob Storage",
     ["BlobNotFound", "ContainerNotFound",
      "The specified blob does not exist",
      "The specified container does not exist"]),
    ("azurewebsites.net", "Azure App Service",
     ["404 Web Site not found"]),
    ("myshopify.com", "Shopify",
     ["Sorry, this shop is currently unavailable"]),
    ("ghost.io", "Ghost",
     ["The thing you were looking for is no longer here"]),
    ("surge.sh", "Surge", ["project not found"]),
    ("bitbucket.io", "Bitbucket", ["Repository not found"]),
    ("fastly.net", "Fastly", ["Fastly error: unknown domain"]),
    ("pantheonsite.io", "Pantheon", ["404 Unknown Site"]),
    ("netlify.app", "Netlify", ["Not Found - Request ID"]),
    ("gitlab.io", "GitLab Pages",
     ["The page you're looking for could not be found"]),
    ("wordpress.com", "WordPress.com", ["Do you want to register"]),
]

def _dns_resolver():
    resolver = dns.resolver.Resolver()
    resolver.timeout = 4
    resolver.lifetime = 6
    return resolver

def _cname_chain(resolver, name, depth=5):
    chain, current = [], name
    for _ in range(depth):
        try:
            answers = resolver.resolve(current, "CNAME")
        except Exception:
            break
        target = str(answers[0].target).rstrip(".").lower()
        if not target or target in chain:
            break
        chain.append(target)
        current = target
    return chain

def _fetch_text(url, timeout=5, cap=65536):
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "CyberSecurityAI-Agent/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(cap).decode("utf-8", "ignore")
    except urllib.error.HTTPError as exc:
        try:
            return exc.read(cap).decode("utf-8", "ignore")
        except Exception:
            return ""
    except Exception:
        return ""

def _takeover_match(chain):
    for target in chain:
        for suffix, service, markers in TAKEOVER_SERVICES:
            if target == suffix or target.endswith("." + suffix):
                return target, service, markers
    return None, None, []

def subdomain_takeover_check(hosts):
    """Dangling-CNAME / subdomain-takeover detection over the already
    discovered names. Detection only: at most one bounded HTTP fetch per
    candidate, and every verdict is labelled by its evidence strength."""
    if dns is None:
        return {"status": "unavailable",
                "note": "dnspython not installed in this engine image."}
    resolver = _dns_resolver()
    findings, checked = [], 0
    for host in hosts[:20]:
        chain = _cname_chain(resolver, host)
        if not chain:
            continue
        checked += 1
        target, service, markers = _takeover_match(chain)
        if not service:
            continue
        evidence = None
        for scheme in ("https", "http"):
            body = _fetch_text(f"{scheme}://{host}/")
            if body:
                evidence = next((m for m in markers if m in body), None)
                break
        if evidence:
            findings.append({"host": host, "service": service,
                             "cname_target": target, "verdict": "confirmed",
                             "evidence": evidence})
        elif not _resolve_quiet(host) and not _resolve_quiet(target):
            findings.append({"host": host, "service": service,
                             "cname_target": target, "verdict": "likely",
                             "evidence": "alias target no longer resolves"})
    return {"status": "ready", "checked": checked, "findings": findings}

def _try_axfr(domain, ns_host):
    """One bounded zone-transfer attempt against one of the domain's own
    nameservers. Returns (allowed, record_count)."""
    if _dns_zone is None or _dns_query is None:
        return False, 0
    ns_ips = _resolve_quiet(ns_host)
    if not ns_ips:
        return False, 0
    try:
        zone = _dns_zone.from_xfr(
            _dns_query.xfr(ns_ips[0], domain, timeout=5, lifetime=8))
        return True, sum(1 for _ in zone.iterate_rdatasets())
    except Exception:
        return False, 0

def _record_texts(resolver, name, rtype):
    try:
        return [r.to_text() for r in resolver.resolve(name, rtype)]
    except Exception:
        return []

def dns_deep_audit(domain):
    """Deep DNS audit: zone-transfer attempts against the domain's own
    nameservers only, DNSSEC signing state, and CAA issuance policy."""
    if dns is None:
        return {"status": "unavailable",
                "note": "dnspython not installed in this engine image."}
    resolver = _dns_resolver()
    nameservers = sorted({t.rstrip(".").lower() for t in
                          _record_texts(resolver, domain, "NS")})
    ds = _record_texts(resolver, domain, "DS")
    dnskey = _record_texts(resolver, domain, "DNSKEY")
    caa = _record_texts(resolver, domain, "CAA")
    attempts = []
    for ns_host in nameservers[:3]:
        allowed, count = _try_axfr(domain, ns_host)
        attempts.append({"nameserver": ns_host, "allowed": allowed,
                         "records": count if allowed else 0})
    return {"status": "ready",
            "nameservers": nameservers[:6],
            "axfr": {"vulnerable": any(a["allowed"] for a in attempts),
                     "attempts": attempts},
            "dnssec": {"signed": bool(ds or dnskey),
                       "ds_present": bool(ds),
                       "dnskey_present": bool(dnskey)},
            "caa": {"present": bool(caa), "records": caa[:5]}}

# --------------------- Phase C2: API surface / GraphQL + JavaScript mining
def _http_get(url, timeout=5, cap=262144):
    """(status, text) for one bounded GET; (None, "") on transport
    failure. HTTP error statuses still return their body — detectors
    need it."""
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "CyberSecurityAI-Agent/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(cap).decode("utf-8", "ignore")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, exc.read(cap).decode("utf-8", "ignore")
        except Exception:
            return exc.code, ""
    except Exception:
        return None, ""

def _http_post_json(url, payload, timeout=5, cap=65536):
    try:
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(), method="POST",
            headers={"User-Agent": "CyberSecurityAI-Agent/1.0",
                     "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(cap).decode("utf-8", "ignore")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, exc.read(cap).decode("utf-8", "ignore")
        except Exception:
            return exc.code, ""
    except Exception:
        return None, ""

OPENAPI_PATHS = ["/openapi.json", "/swagger.json", "/v3/api-docs",
                 "/swagger/v1/swagger.json", "/api-docs"]
API_DOC_PAGES = ["/swagger-ui.html", "/swagger-ui/", "/redoc"]
GRAPHQL_PATHS = ["/graphql", "/api/graphql"]
_INTROSPECTION_QUERY = {"query": "{__schema{queryType{name}}}"}

def api_surface_check(host, scheme):
    """Public API documentation exposure + GraphQL introspection state.
    Detection only: reads public schema documents and asks a GraphQL
    endpoint the minimal schema question; never calls business
    endpoints and never pulls API data."""
    base = f"{scheme}://{host}"
    out = {"status": "ready", "openapi": [], "doc_pages": [], "graphql": []}
    for path in OPENAPI_PATHS:
        status, text = _http_get(base + path, cap=1048576)
        if status != 200 or not text:
            continue
        try:
            doc = json.loads(text)
        except Exception:
            continue
        if isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc):
            info = doc.get("info") or {}
            out["openapi"].append({
                "path": path,
                "title": str(info.get("title", ""))[:80],
                "version": str(info.get("version", ""))[:20],
                "endpoints": len(doc.get("paths") or {})})
    for path in API_DOC_PAGES:
        status, text = _http_get(base + path, cap=65536)
        lowered = (text or "").lower()
        if status == 200 and ("swagger" in lowered or "redoc" in lowered):
            out["doc_pages"].append(path)
    for path in GRAPHQL_PATHS:
        status, text = _http_post_json(base + path, _INTROSPECTION_QUERY)
        if status is None or not text:
            continue
        try:
            doc = json.loads(text)
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        data = doc.get("data") or {}
        if isinstance(data, dict) and "__schema" in data:
            out["graphql"].append({"path": path, "introspection": True})
        elif "errors" in doc:
            out["graphql"].append({"path": path, "introspection": False})
    return out

_SCRIPT_SRC_RE = re.compile(
    r"<script[^>]+src\s*=\s*[\"']([^\"']+)[\"']", re.I)
_API_PATH_RE = re.compile(
    r"[\"'](/(?:api|rest|v\d)/[A-Za-z0-9_\-./{}:$]{1,80})[\"']")
_PRIVATE_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")

def js_mining(host, scheme):
    """Mine the site's own public JavaScript for exposed secret
    patterns, API endpoint paths and internal addresses. Same-host
    scripts only, bounded in count and size; secrets are reported by
    6-character prefix only (the shared APK secret scanner)."""
    base = f"{scheme}://{host}"
    status, html = _http_get(base + "/", cap=524288)
    if status is None or not html:
        return {"status": "unavailable"}
    srcs = []
    for raw in _SCRIPT_SRC_RE.findall(html):
        url = urllib.parse.urljoin(base + "/", raw)
        if urllib.parse.urlparse(url).netloc.lower() == host.lower() \
                and url not in srcs:
            srcs.append(url)
    out = {"status": "ready", "files_checked": 0, "secrets": [],
           "api_endpoints": [], "internal_addresses": [],
           "external_domains": []}
    endpoints, internal, domains = set(), set(), set()
    for url in srcs[:8]:
        s2, text = _http_get(url, cap=1572864)
        if s2 is None or not text:
            continue
        out["files_checked"] += 1
        name = urllib.parse.urlparse(url).path.rsplit("/", 1)[-1] or url
        out["secrets"] += _scan_text_for_secrets(text, name)
        endpoints.update(_API_PATH_RE.findall(text))
        internal.update(_PRIVATE_IP_RE.findall(text))
        for link in _URL_RE.findall(text):
            domain = urllib.parse.urlparse(link).netloc.lower()
            if domain and domain != host.lower():
                domains.add(domain)
    out["secrets"] = out["secrets"][:10]
    out["api_endpoints"] = sorted(endpoints)[:15]
    out["internal_addresses"] = sorted(internal)[:10]
    out["external_domains"] = sorted(domains)[:15]
    return out

# --------------------- Phase C3: cloud storage exposure + SCA (OSV.dev)
_BUCKET_SUFFIXES = ["", "-assets", "-backup", "-backups", "-files",
                    "-media", "-static", "-data", "-uploads", "-images",
                    "-docs", "-public"]

def cloud_storage_check(base):
    """Public cloud-storage exposure for bucket names derived from the
    domain: Amazon S3, Google Cloud Storage, Azure Blob. A bucket is
    reported as exposed ONLY when an anonymous listing actually
    succeeds; buckets that exist but are private are counted as an
    informational note, never flagged as findings."""
    label = base.split(".")[0].lower()
    nodash = label.replace("-", "")
    names = []
    for suffix in _BUCKET_SUFFIXES:
        candidate = label + suffix
        if candidate not in names:
            names.append(candidate)
    out = {"status": "ready", "exposed": [], "private_existing": 0,
           "candidates_checked": 0}
    for name in names:
        out["candidates_checked"] += 1
        status, text = _http_get(f"https://{name}.s3.amazonaws.com/",
                                 timeout=4, cap=32768)
        if status == 200 and "ListBucketResult" in (text or ""):
            out["exposed"].append({
                "provider": "Amazon S3", "name": name,
                "url": f"https://{name}.s3.amazonaws.com/",
                "evidence": "anonymous listing succeeded"})
        elif status == 403:
            out["private_existing"] += 1
        status, text = _http_get(
            f"https://storage.googleapis.com/{name}",
            timeout=4, cap=32768)
        if status == 200 and "ListBucketResult" in (text or ""):
            out["exposed"].append({
                "provider": "Google Cloud Storage", "name": name,
                "url": f"https://storage.googleapis.com/{name}",
                "evidence": "anonymous listing succeeded"})
        elif status == 403:
            out["private_existing"] += 1
    account = nodash[:24]
    if len(account) >= 3:
        out["candidates_checked"] += 1
        status, _ = _http_get(
            f"https://{account}.blob.core.windows.net/?comp=list",
            timeout=4, cap=8192)
        if status is not None and status != 404:
            account_private = False
            for name in names:
                status, text = _http_get(
                    f"https://{account}.blob.core.windows.net/{name}"
                    "?resttype=container&comp=list",
                    timeout=4, cap=32768)
                if status == 200 and "EnumerationResults" in (text or ""):
                    out["exposed"].append({
                        "provider": "Azure Blob Storage", "name": name,
                        "url": f"https://{account}.blob.core.windows.net/"
                               f"{name}",
                        "evidence": "anonymous listing succeeded"})
                elif status == 403:
                    account_private = True
            if account_private:
                out["private_existing"] += 1
    return out

# --- SCA: dependency-file parsing + OSV.dev matching -------------------
_DEP_ECOSYSTEMS = {
    "requirements.txt": "PyPI", "pipfile.lock": "PyPI",
    "package-lock.json": "npm", "yarn.lock": "npm",
    "go.mod": "Go", "gemfile.lock": "RubyGems",
    "composer.lock": "Packagist",
}

def _parse_requirements(text):
    deps = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([^\s;\]]+)", line)
        if m:
            deps.append((m.group(1), m.group(2).strip()))
    return deps

def _parse_package_lock(text):
    doc = json.loads(text)
    deps = []
    packages = doc.get("packages")
    if isinstance(packages, dict):
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if version:
                deps.append((path.split("node_modules/")[-1],
                             str(version)))
    legacy = doc.get("dependencies")
    if isinstance(legacy, dict):
        for name, meta in legacy.items():
            if isinstance(meta, dict) and meta.get("version"):
                deps.append((name, str(meta["version"])))
    return deps

def _parse_yarn_lock(text):
    deps, current = [], []
    for line in text.splitlines():
        if line and not line.startswith((" ", "#")) \
                and line.rstrip().endswith(":"):
            current = [h.strip().strip('"') for h in
                       line.rstrip()[:-1].split(", ")]
        elif line.strip().startswith('version "') and current:
            version = line.split('"')[1]
            for header in current:
                idx = header.rfind("@")
                if idx > 0 and version:
                    deps.append((header[:idx], version))
            current = []
    return deps

def _parse_go_mod(text):
    deps, in_block = [], False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            line = line[len("require "):].strip()
        elif not in_block:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith("v"):
            deps.append((parts[0], parts[1].lstrip("v")))
    return deps

def _parse_gemfile_lock(text):
    deps, in_specs = [], False
    for line in text.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs:
            if line and not line.startswith(" "):
                in_specs = False
                continue
            m = re.match(r"^    ([A-Za-z0-9_\-]+) \(([^)]+)\)", line)
            if m:
                deps.append((m.group(1), m.group(2).split()[0]))
    return deps

def _parse_pipfile_lock(text):
    doc = json.loads(text)
    deps = []
    for section in ("default", "develop"):
        for name, meta in (doc.get(section) or {}).items():
            if isinstance(meta, dict):
                version = str(meta.get("version") or "").lstrip("=").strip()
                if version and version != "*":
                    deps.append((name, version))
    return deps

def _parse_composer_lock(text):
    doc = json.loads(text)
    deps = []
    for section in ("packages", "packages-dev"):
        for pkg in doc.get(section) or []:
            if pkg.get("name") and pkg.get("version"):
                deps.append((pkg["name"],
                             str(pkg["version"]).lstrip("v")))
    return deps

_DEP_PARSERS = {
    "requirements.txt": _parse_requirements,
    "pipfile.lock": _parse_pipfile_lock,
    "package-lock.json": _parse_package_lock,
    "yarn.lock": _parse_yarn_lock,
    "go.mod": _parse_go_mod,
    "gemfile.lock": _parse_gemfile_lock,
    "composer.lock": _parse_composer_lock,
}

def parse_dependencies(filename, data):
    """(canonical_name, [{name, version}]) or (None, None) when the
    file type is unsupported. Exact pinned versions only — ranges in a
    bare manifest cannot be matched honestly, so they never reach OSV."""
    name = (filename or "").lower().rsplit("/", 1)[-1]
    parser = _DEP_PARSERS.get(name)
    if not parser:
        return None, None
    try:
        raw = parser(data.decode("utf-8", "replace"))
    except Exception:
        return name, []
    seen, deps = set(), []
    for pkg, version in raw:
        key = (pkg.lower(), version)
        if key not in seen:
            seen.add(key)
            deps.append({"name": pkg, "version": version})
    return name, deps[:200]

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"

def _osv_lookup(ecosystem, deps):
    queries = [{"package": {"name": d["name"], "ecosystem": ecosystem},
                "version": d["version"]} for d in deps]
    status, text = _http_post_json(OSV_BATCH_URL, {"queries": queries},
                                   timeout=20, cap=4194304)
    if status != 200 or not text:
        return None
    try:
        doc = json.loads(text)
    except Exception:
        return None
    out = {}
    for i, entry in enumerate(doc.get("results") or []):
        ids = [v.get("id") for v in (entry or {}).get("vulns") or []
               if v.get("id")]
        if ids:
            out[i] = ids
    return out

def _cvss3_base_score(vector):
    """CVSS v3.0/3.1 base score per the FIRST specification, or None."""
    try:
        metrics = dict(part.split(":", 1) for part in
                       str(vector).split("/") if ":" in part)
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
        ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        scope = metrics["S"]
        pr = ({"N": 0.85, "L": 0.62, "H": 0.27} if scope == "U"
              else {"N": 0.85, "L": 0.68, "H": 0.5})[metrics["PR"]]
        ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        vals = {"N": 0.0, "L": 0.22, "H": 0.56}
        iss = 1 - (1 - vals[metrics["C"]]) * (1 - vals[metrics["I"]]) \
            * (1 - vals[metrics["A"]])
        impact = 6.42 * iss if scope == "U" else \
            7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        exploit = 8.22 * av * ac * pr * ui

        def roundup(value):
            scaled = int(value * 100000 + 0.5)
            if scaled % 10000 == 0:
                return scaled / 100000.0
            return (scaled // 10000 + 1) / 10.0

        if impact <= 0:
            return 0.0
        if scope == "U":
            return roundup(min(impact + exploit, 10))
        return roundup(min(1.08 * (impact + exploit), 10))
    except Exception:
        return None

_SEV_FROM_SCORE = [(9.0, "حرجة"), (7.0, "عالية"), (4.0, "متوسطة"),
                   (0.1, "منخفضة"), (0.0, "لا تأثير")]
_SEV_FROM_LABEL = {"critical": "حرجة", "high": "عالية",
                    "moderate": "متوسطة", "medium": "متوسطة",
                    "low": "منخفضة"}

def _osv_vuln_detail(vuln_id):
    status, text = _http_get(OSV_VULN_URL + vuln_id, timeout=8,
                             cap=1048576)
    if status != 200 or not text:
        return {"id": vuln_id}
    try:
        doc = json.loads(text)
    except Exception:
        return {"id": vuln_id}
    score = None
    for sev in doc.get("severity") or []:
        if str(sev.get("type", "")).startswith("CVSS"):
            score = _cvss3_base_score(sev.get("score", ""))
            if score is not None:
                break
    label = None
    specific = doc.get("database_specific") or {}
    if isinstance(specific.get("severity"), str):
        label = _SEV_FROM_LABEL.get(specific["severity"].lower())
    if score is not None:
        label = next(lbl for edge, lbl in _SEV_FROM_SCORE
                     if score >= edge)
    fixed = []
    for affected in doc.get("affected") or []:
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if event.get("fixed"):
                    fixed.append(str(event["fixed"]))
    return {"id": vuln_id, "summary": str(doc.get("summary", ""))[:200],
            "cvss": score, "severity": label,
            "fixed": fixed[:3],
            "aliases": [str(a) for a in (doc.get("aliases") or [])[:3]]}

def analyze_dependencies(filename, data):
    name, deps = parse_dependencies(filename, data)
    if name is None:
        return {"status": "unsupported"}
    if not deps:
        return {"status": "empty", "filename": name}
    ecosystem = _DEP_ECOSYSTEMS[name]
    matches = _osv_lookup(ecosystem, deps)
    if matches is None:
        return {"status": "unavailable", "filename": name,
                "ecosystem": ecosystem, "packages_checked": len(deps)}
    wanted = []
    for ids in matches.values():
        for vid in ids:
            if vid not in wanted:
                wanted.append(vid)
    details = {vid: _osv_vuln_detail(vid) for vid in wanted[:25]}
    counts = {"حرجة": 0, "عالية": 0, "متوسطة": 0, "منخفضة": 0,
              "غير مصنّفة": 0}
    vulnerable, total = [], 0
    for idx in sorted(matches):
        vulns = []
        for vid in matches[idx]:
            d = details.get(vid) or {"id": vid}
            sev = d.get("severity") or "غير مصنّفة"
            counts[sev if sev in counts else "غير مصنّفة"] += 1
            total += 1
            vulns.append({"id": vid, "severity": sev,
                          "cvss": d.get("cvss"),
                          "summary": d.get("summary", ""),
                          "fixed": d.get("fixed", []),
                          "aliases": d.get("aliases", [])})
        vulns.sort(key=lambda v: -(v["cvss"] or 0))
        vulnerable.append({"name": deps[idx]["name"],
                           "version": deps[idx]["version"],
                           "vulns": vulns})
    points = {"حرجة": 15, "عالية": 8, "متوسطة": 3, "منخفضة": 1,
              "غير مصنّفة": 2}
    lost = min(70, sum(points[k] * v for k, v in counts.items()))
    score = 100 - lost
    grade = ("ممتاز" if score >= 90 else "جيد" if score >= 75 else
             "متوسط" if score >= 55 else "ضعيف" if score >= 35 else "حرج")
    return {"status": "ready", "filename": name, "ecosystem": ecosystem,
            "packages_checked": len(deps), "vulnerable": vulnerable,
            "counts": counts, "total_vulns": total,
            "details_capped": len(wanted) > 25,
            "score": {"score": score, "grade": grade}}

def valid_sca_permit(value: Optional[str], sha256: str) -> bool:
    if not value or not PERMIT_SECRET: return False
    try:
        payload, signature = value.split(".", 1)
        expected = hmac.new(PERMIT_SECRET.encode(), payload.encode(), hashlib.sha256).digest()
        supplied = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        if not hmac.compare_digest(expected, supplied): return False
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return (data.get("kind") == "sca" and data.get("sha256") == sha256
                and bool(data.get("id")) and isinstance(data.get("exp"), (int, float))
                and data["exp"] > time.time() * 1000)
    except Exception: return False

SCA_MAX_BYTES = 10 * 1024 * 1024
SCA_SUPPORTED = ("requirements.txt, Pipfile.lock, package-lock.json, "
                 "yarn.lock, go.mod, Gemfile.lock, composer.lock")

@app.post("/scans/sca")
async def sca_scan(request: Request, authorization: Optional[str] = Header(default=None), x_scan_approval: Optional[str] = Header(default=None), x_dependency_filename: Optional[str] = Header(default=None)):
    require_auth(authorization)
    data = await request.body()
    if not data: raise HTTPException(status_code=400, detail="Empty dependency file.")
    if len(data) > SCA_MAX_BYTES: raise HTTPException(status_code=413, detail="Dependency file exceeds the 10MB analysis cap.")
    digest = hashlib.sha256(data).hexdigest()
    if not valid_sca_permit(x_scan_approval, digest):
        raise HTTPException(status_code=403, detail="File requires a bot-issued permit bound to its exact SHA-256.")
    result = analyze_dependencies(x_dependency_filename or "", data)
    if result.get("status") == "unsupported":
        raise HTTPException(status_code=400, detail=f"Unsupported dependency file. Supported: {SCA_SUPPORTED}.")
    return {"status": "completed", "profile": "sca-osv-v1", **result}

# ------------- Phase C4: version-to-CVE matching + sensitive content
def _version_key(v):
    m = re.match(r"(\d+(?:\.\d+)*)(.*)", str(v).strip())
    if not m:
        return ((), str(v))
    return (tuple(int(x) for x in m.group(1).split(".")),
            m.group(2).strip())

def _version_cmp(a, b):
    ka, kb = _version_key(a), _version_key(b)
    n = max(len(ka[0]), len(kb[0]))
    ta = ka[0] + (0,) * (n - len(ka[0]))
    tb = kb[0] + (0,) * (n - len(kb[0]))
    if ta != tb:
        return -1 if ta < tb else 1
    if ka[1] == kb[1]:
        return 0
    return -1 if ka[1] < kb[1] else 1

def _cve_applies(cve, vendor, product, version):
    """Strict applicability: some cpeMatch in the CVE's configuration
    tree must be marked vulnerable, name our exact product, and either
    pin our exact version or carry a version range covering it. NVD's
    raw cpeName candidates include 'running on' noise — this filter is
    what makes the match a finding instead of a guess."""
    def walk(nodes):
        for node in nodes or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                parts = str(match.get("criteria", "")).split(":")
                if len(parts) < 7:
                    continue
                if parts[3] != vendor or parts[4] != product:
                    continue
                crit_v, crit_u = parts[5], parts[6]
                if crit_v not in ("*", "-"):
                    kc, kv = _version_key(crit_v), _version_key(version)
                    n = max(len(kc[0]), len(kv[0]))
                    numeric_equal = (
                        kc[0] + (0,) * (n - len(kc[0]))
                        == kv[0] + (0,) * (n - len(kv[0])))
                    if crit_u in ("*", "-", ""):
                        suffix_ok = kc[1] == kv[1]
                    else:
                        # e.g. OpenSSH: criteria version 9.6 + update
                        # p1 must equal a detected "9.6p1".
                        suffix_ok = kv[1] == crit_u
                    if numeric_equal and suffix_ok:
                        return True
                    continue
                ok = True
                if "versionStartIncluding" in match:
                    ok &= _version_cmp(
                        version, match["versionStartIncluding"]) >= 0
                if "versionStartExcluding" in match:
                    ok &= _version_cmp(
                        version, match["versionStartExcluding"]) > 0
                if "versionEndIncluding" in match:
                    ok &= _version_cmp(
                        version, match["versionEndIncluding"]) <= 0
                if "versionEndExcluding" in match:
                    ok &= _version_cmp(
                        version, match["versionEndExcluding"]) < 0
                if ok:
                    return True
            if walk(node.get("children")):
                return True
        return False

    for config in cve.get("configurations") or []:
        if walk(config.get("nodes")):
            return True
    return False

def _cpe_version(product, version):
    v = str(version).strip().split("-")[0].split("_")[0]
    if product == "openssh":
        v = re.sub(r"p\d+$", "", v)
    return v

def _nvd_pause():
    time.sleep(6)

def _nvd_cves_for_cpe(cpe):
    url = ("https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName="
           + urllib.parse.quote(cpe) + "&resultsPerPage=2000")
    status, text = _http_get(url, timeout=25, cap=16777216)
    if status != 200 or not text:
        return None
    try:
        doc = json.loads(text)
    except Exception:
        return None
    return [v.get("cve") or {} for v in doc.get("vulnerabilities") or []]

def _cve_score(cve):
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entry in metrics.get(key) or []:
            data = entry.get("cvssData") or {}
            if isinstance(data.get("baseScore"), (int, float)):
                return float(data["baseScore"]), \
                    data.get("baseSeverity") or entry.get("baseSeverity")
    return None, None

_BANNER_PATTERNS = [
    (re.compile(r"Apache/(\d[\w.\-]*)"), "apache", "http_server",
     "Apache httpd"),
    (re.compile(r"nginx/(\d[\w.\-]*)"), "nginx", "nginx", "nginx"),
    (re.compile(r"OpenSSL/(\d[\w.\-]*)"), "openssl", "openssl", "OpenSSL"),
    (re.compile(r"PHP/(\d[\w.\-]*)"), "php", "php", "PHP"),
    (re.compile(r"Microsoft-IIS/(\d[\w.\-]*)"), "microsoft",
     "internet_information_services", "Microsoft IIS"),
]
_NMAP_PRODUCT_MAP = [
    ("apache httpd", "apache", "http_server", "Apache httpd"),
    ("openssh", "openbsd", "openssh", "OpenSSH"),
    ("nginx", "nginx", "nginx", "nginx"),
    ("openssl", "openssl", "openssl", "OpenSSL"),
    ("microsoft iis", "microsoft", "internet_information_services",
     "Microsoft IIS"),
    ("mariadb", "mariadb", "mariadb", "MariaDB"),
    ("mysql", "oracle", "mysql", "MySQL"),
    ("postgresql", "postgresql", "postgresql", "PostgreSQL"),
    ("vsftpd", "vsftpd", "vsftpd", "vsftpd"),
    ("proftpd", "proftpd", "proftpd", "ProFTPD"),
    ("exim", "exim", "exim", "Exim"),
    ("dovecot", "dovecot", "dovecot", "Dovecot"),
    ("isc bind", "isc", "bind", "ISC BIND"),
    ("postfix", "postfix", "postfix", "Postfix"),
    ("redis", "redis", "redis", "Redis"),
    ("mongodb", "mongodb", "mongodb", "MongoDB"),
    ("elasticsearch", "elastic", "elasticsearch", "Elasticsearch"),
    ("php", "php", "php", "PHP"),
]

def collect_version_pairs(assessed, ports_by_ip):
    pairs, seen = [], set()

    def add(vendor, product, display, version, source):
        version = str(version or "").strip()
        if not version:
            return
        key = (vendor, product, version)
        if key in seen:
            return
        seen.add(key)
        pairs.append({"vendor": vendor, "product": product,
                      "display": display, "version": version,
                      "source": source})

    for entry in ports_by_ip:
        for port in entry.get("ports") or []:
            if port.get("state") != "open":
                continue
            product_name = (port.get("product") or "").lower()
            for marker, vendor, product, display in _NMAP_PRODUCT_MAP:
                if marker in product_name:
                    add(vendor, product, display, port.get("version"),
                        f"منفذ {entry.get('ip')}:{port.get('port')}")
                    break
    for host in assessed:
        http = host.get("http") or {}
        for text in (http.get("server"), http.get("powered_by")):
            if not text:
                continue
            for pattern, vendor, product, display in _BANNER_PATTERNS:
                m = pattern.search(text)
                if m:
                    add(vendor, product, display, m.group(1),
                        f"ترويسة {host.get('host')}")
    return pairs

def version_cve_check(pairs):
    """Match detected product versions against NVD. Anonymous NVD
    access allows ~5 requests per 30s, so calls are paced and the
    product list is capped; every kept CVE passed the strict
    applicability filter above."""
    out = {"status": "ready", "checked": len(pairs), "products": [],
           "clean": [], "unmatched": []}
    first = True
    for pair in pairs[:5]:
        vendors = [(pair["vendor"], pair["product"])]
        if (pair["vendor"], pair["product"]) == ("nginx", "nginx"):
            vendors.append(("f5", "nginx"))
        found, seen_ids, queried = [], set(), False
        for vendor, product in vendors:
            cpe = (f"cpe:2.3:a:{vendor}:{product}:"
                   f"{_cpe_version(product, pair['version'])}")
            if not first:
                _nvd_pause()
            first = False
            cves = _nvd_cves_for_cpe(cpe)
            if cves is None:
                continue
            queried = True
            for cve in cves:
                cid = cve.get("id")
                if not cid or cid in seen_ids:
                    continue
                if _cve_applies(cve, vendor, product, pair["version"]):
                    seen_ids.add(cid)
                    score, sev = _cve_score(cve)
                    desc = ""
                    for d in cve.get("descriptions") or []:
                        if d.get("lang") == "en":
                            desc = str(d.get("value", ""))[:220]
                            break
                    found.append({"id": cid, "cvss": score,
                                  "severity": sev, "summary": desc})
        if not queried:
            out["unmatched"].append(pair["display"])
        elif found:
            found.sort(key=lambda v: -(v["cvss"] or 0))
            out["products"].append({
                "product": pair["display"], "version": pair["version"],
                "source": pair["source"], "total": len(found),
                "top": found[:5]})
        else:
            out["clean"].append(
                f"{pair['display']} {pair['version']}")
    return out

def _http_get_bytes(url, timeout=5, cap=262144):
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "CyberSecurityAI-Agent/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(cap)
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, exc.read(cap)
        except Exception:
            return exc.code, b""
    except Exception:
        return None, b""

def _sensitive_signature(kind, body):
    head = body[:300].lower()
    if b"<html" in head or b"<!doctype" in head:
        return False
    if kind == "git_head":
        return body.startswith(b"ref: refs/") or bool(
            re.fullmatch(rb"[0-9a-f]{40}\s*", body[:64].strip()))
    if kind == "git_config":
        return b"[core]" in body
    if kind == "env":
        lines = body.decode("utf-8", "ignore").splitlines()
        hits = sum(1 for ln in lines
                   if re.match(r"^[A-Z][A-Z0-9_]{2,}=", ln.strip()))
        return hits >= 2
    if kind == "archive":
        return body[:4] == b"PK\x03\x04" or body[:2] == b"\x1f\x8b"
    if kind == "sql":
        upper = body[:65536].upper()
        return b"CREATE TABLE" in upper or b"INSERT INTO" in upper
    if kind == "dsstore":
        return body[4:8] == b"Bud1"
    if kind == "config":
        return b"DB_PASSWORD" in body or (b"define" in body
                                          and b"DB_" in body)
    if kind == "svn":
        return b"wc-entries" in body[:512]
    if kind == "hg":
        return b"[paths]" in body
    if kind == "status":
        return b"Apache Server Status" in body
    return False

SENSITIVE_PATHS = [
    ("/.git/HEAD", "git_head"), ("/.git/config", "git_config"),
    ("/.env", "env"), ("/.env.local", "env"),
    ("/.env.production", "env"),
    ("/backup.zip", "archive"), ("/backup.tar.gz", "archive"),
    ("/www.zip", "archive"),
    ("/db.sql", "sql"), ("/dump.sql", "sql"),
    ("/database.sql", "sql"),
    ("/.DS_Store", "dsstore"),
    ("/wp-config.php.bak", "config"), ("/config.php.bak", "config"),
    ("/.svn/entries", "svn"), ("/.hg/hgrc", "hg"),
    ("/server-status", "status"),
]

def hidden_content_check(host, scheme):
    """Sensitive-path exposure, proven by content signature. A random
    nonexistent path is fetched first: a candidate whose body equals
    the baseline (catch-all sites) is never reported."""
    base = f"{scheme}://{host}"
    token = secrets.token_hex(4)
    bstatus, bbody = _http_get_bytes(
        base + f"/probe-{token}-nonexistent", timeout=5, cap=65536)
    baseline = hashlib.sha256(bbody).hexdigest() if bbody else None
    findings = []
    for path, kind in SENSITIVE_PATHS:
        status, body = _http_get_bytes(base + path, timeout=5,
                                       cap=262144)
        if status != 200 or not body:
            continue
        if baseline and hashlib.sha256(body).hexdigest() == baseline:
            continue
        if _sensitive_signature(kind, body):
            findings.append({"path": path, "kind": kind})
    return {"status": "ready", "findings": findings,
            "catch_all": bstatus == 200}

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

def full_score(hosts, ports_by_ip, email, dns_audit=None, takeover=None,
               cloud=None, version_cves=None):
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
                      "ports": 24, "email": 22, "takeover": 20, "dns": 12,
                      "surface": 16, "cloud": 14, "versions": 18}}
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
    if takeover and takeover.get("status") == "ready":
        for f in takeover.get("findings") or []:
            if f.get("verdict") == "confirmed":
                deduct(12, f"استيلاء مؤكد على نطاق فرعي: {f.get('host')} "
                           f"يشير لخدمة غير مُدّعاة ({f.get('service')})",
                       "takeover", caps)
            else:
                deduct(6, f"احتمال استيلاء على نطاق فرعي: {f.get('host')} "
                          f"يشير لخدمة ({f.get('service')}) لم تعد تُحلّ",
                       "takeover", caps)
    if dns_audit and dns_audit.get("status") == "ready":
        if (dns_audit.get("axfr") or {}).get("vulnerable"):
            deduct(10, "نقل المنطقة (AXFR) مفتوح — خريطة DNS كاملة مكشوفة "
                       "لأي شخص", "dns", caps)
        if not (dns_audit.get("caa") or {}).get("present"):
            deduct(2, "لا سجلات CAA — أي هيئة شهادات تستطيع إصدار شهادات "
                      "لهذا النطاق", "dns", caps)
    for host in hosts:
        api = host.get("api") or {}
        if api.get("status") == "ready":
            for g in api.get("graphql") or []:
                if g.get("introspection"):
                    deduct(5, f"استبطان GraphQL مفعّل على "
                              f"{host['host']}{g.get('path')} — مخطط الواجهة "
                              "مكشوف لأي شخص", "surface", caps)
            for doc in api.get("openapi") or []:
                deduct(2, f"وثائق API مكشوفة علناً على "
                          f"{host['host']}{doc.get('path')}", "surface", caps)
        js = host.get("js") or {}
        if js.get("status") == "ready":
            for s in js.get("secrets") or []:
                deduct(8, f"سرّ محتمل داخل JavaScript على {host['host']}: "
                          f"{s.get('type')} ({s.get('preview')})",
                       "surface", caps)
            if js.get("internal_addresses"):
                deduct(3, f"عناوين داخلية داخل JavaScript على "
                          f"{host['host']}: "
                          f"{', '.join(js['internal_addresses'][:3])}",
                       "surface", caps)
        hidden = host.get("hidden") or {}
        if hidden.get("status") == "ready":
            kind_points = {"git_head": 8, "git_config": 8, "env": 8,
                           "archive": 5, "sql": 5, "config": 5,
                           "svn": 4, "hg": 4, "status": 3, "dsstore": 2}
            for f in hidden.get("findings") or []:
                deduct(kind_points.get(f.get("kind"), 3),
                       f"محتوى حسّاس مكشوف على {host['host']}: "
                       f"{f.get('path')}", "surface", caps)
    if version_cves and version_cves.get("status") == "ready":
        sev_points_v = {"CRITICAL": 8, "HIGH": 5, "MEDIUM": 2}
        for prod in version_cves.get("products") or []:
            top = (prod.get("top") or [{}])[0]
            pts = sev_points_v.get((top.get("severity") or "").upper())
            if pts:
                deduct(pts, f"ثغرات معروفة منطبقة على "
                            f"{prod.get('product')} {prod.get('version')} "
                            f"(أخطرها {top.get('id')} — CVSS "
                            f"{top.get('cvss')})", "versions", caps)
    if cloud and cloud.get("status") == "ready":
        for b in cloud.get("exposed") or []:
            deduct(10, f"مخزن سحابي مفتوح للعامة: {b.get('name')} "
                       f"({b.get('provider')}) — قائمة الملفات قابلة "
                       "للقراءة دون مصادقة", "cloud", caps)
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
                         "nuclei": {"status": "skipped"},
                         "api": {"status": "skipped"},
                         "js": {"status": "skipped"},
                         "hidden": {"status": "skipped"}})
    live = [h for h in assessed if (h.get("http") or {}).get("status") == "ready"]
    nuclei_done = 0
    for entry in live:
        if nuclei_done >= 3 or time.time() - started > 1000:
            entry["nuclei"] = {"status": "skipped_budget"}
            entry["api"] = {"status": "skipped_budget"}
            entry["js"] = {"status": "skipped_budget"}
            entry["hidden"] = {"status": "skipped_budget"}
            continue
        entry["nuclei"] = nuclei_scan(entry["host"], deep=False)
        nuclei_done += 1
        if time.time() - started <= 1150:
            scheme = (entry.get("http") or {}).get("scheme") or "https"
            entry["api"] = api_surface_check(entry["host"], scheme)
            entry["js"] = js_mining(entry["host"], scheme)
            entry["hidden"] = hidden_content_check(entry["host"], scheme)
        else:
            entry["api"] = {"status": "skipped_budget"}
            entry["js"] = {"status": "skipped_budget"}
            entry["hidden"] = {"status": "skipped_budget"}
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
    dns_audit = dns_deep_audit(base)
    takeover = subdomain_takeover_check(candidates)
    cloud = cloud_storage_check(base) if time.time() - started <= 1250 \
        else {"status": "skipped_budget"}
    pairs = collect_version_pairs(assessed, ports_by_ip)
    if pairs and time.time() - started <= 1300:
        version_cves = version_cve_check(pairs)
    elif pairs:
        version_cves = {"status": "skipped_budget"}
    else:
        version_cves = {"status": "ready", "checked": 0, "products": [],
                        "clean": [], "unmatched": []}
    score = full_score(assessed, ports_by_ip, email, dns_audit, takeover,
                       cloud, version_cves)
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
            "email": email, "dns_audit": dns_audit, "takeover": takeover,
            "cloud": cloud, "version_cves": version_cves,
            "score": score, "priorities": priorities,
            "limitations": ["Detection only: identical guardrails to the web assessment (curated Nuclei templates, no intrusive tags, no exploitation).",
                            "Discovery is passive (certificate transparency, public scan/archive indexes, resolving wordlist); subdomains that exist but are in none of those sources will not appear.",
                            "Bounds: at most 10 hosts probed, 3 hosts get a full Nuclei run, 4 IPs get a top-100 port scan, within one time budget; anything beyond is reported as skipped, never silently dropped.",
                            "The score is a transparent heuristic: every deduction is listed with its reason; it prioritizes fixes, it is not a certification.",
                            "Deep DNS audit attempts a zone transfer only against the domain's own nameservers; takeover verdicts are labelled confirmed (the service's unclaimed page answered) or likely (the alias target no longer resolves).",
                            "API/GraphQL checks read public schema documents and ask a GraphQL endpoint only its minimal schema question; JavaScript mining covers same-host scripts only (up to 8 files per host), and secrets are shown by short prefix only.",
                            "Cloud storage checks probe bucket names derived from the domain on S3, GCS and Azure Blob; a bucket counts as exposed only when an anonymous listing actually succeeds.",
                            "Version-to-CVE matching uses NVD with a strict applicability filter (vulnerable flag + exact product + exact version or covering range). It matches the ADVERTISED version: Linux distributions may backport a fix without changing the version string, so confirm against the distribution's changelog before treating a match as final.",
                            "Sensitive-content findings are proven by content signature and cross-checked against a random-path baseline, so catch-all sites do not produce them."]}

# ------------------------------------------------- Android APK static analysis
import io, zipfile
try:
    from loguru import logger as _loguru_logger
    _loguru_logger.disable("androguard")
except Exception:
    pass
try:
    from androguard.core.apk import APK as _AndroAPK
except Exception:
    _AndroAPK = None

APK_MAX_BYTES = 80 * 1024 * 1024

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS", "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS", "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG", "android.permission.CALL_PHONE",
    "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO", "android.permission.GET_ACCOUNTS",
    "android.permission.READ_PHONE_STATE", "android.permission.READ_PHONE_NUMBERS",
    "android.permission.USE_BIOMETRIC", "android.permission.USE_FINGERPRINT",
    "android.permission.BODY_SENSORS", "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.SCHEDULE_EXACT_ALARM",
}

_SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("GitHub token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("Stripe live secret", re.compile(r"sk_live_[0-9A-Za-z]{16,}")),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("Private key block",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Firebase database URL",
     re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\."
                       r"[A-Za-z0-9_\-]{8,}")),
    ("Generic secret assignment",
     re.compile(r"(?i)(api[_-]?key|secret|passwd|password)\s*[:=]\s*"
                r"[\"'][0-9A-Za-z\-_/+]{12,}[\"']")),
]
_URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+")
_NOISE_DOMAINS = ("www.w3.org", "schemas.android.com", "apache.org",
                  "example.com", "localhost", "127.0.0.1",
                  "xmlpull.org", "ns.adobe.com")
_SDK_SIGNATURES = [
    ("Firebase", "com/google/firebase"),
    ("Facebook SDK", "com/facebook"),
    ("AdMob", "com/google/android/gms/ads"),
    ("Google Analytics", "com/google/android/gms/analytics"),
    ("Crashlytics", "com/google/firebase/crashlytics"),
    ("Sentry", "io/sentry"), ("OneSignal", "com/onesignal"),
    ("Adjust", "com/adjust/sdk"), ("AppsFlyer", "com/appsflyer"),
    ("Mixpanel", "com/mixpanel"), ("Stripe", "com/stripe/android"),
    ("OkHttp", "okhttp3"), ("Retrofit", "retrofit2"),
    ("Glide", "com/bumptech/glide"), ("Room", "androidx/room"),
    ("Koin", "org/koin"),
]
_STRING_RE = re.compile(rb"[\x20-\x7e]{6,}")

def valid_apk_permit(value: Optional[str], sha256: str) -> bool:
    if not value or not PERMIT_SECRET: return False
    try:
        payload, signature = value.split(".", 1)
        expected = hmac.new(PERMIT_SECRET.encode(), payload.encode(), hashlib.sha256).digest()
        supplied = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        if not hmac.compare_digest(expected, supplied): return False
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return (data.get("kind") == "apk" and data.get("sha256") == sha256
                and bool(data.get("id")) and isinstance(data.get("exp"), (int, float))
                and data["exp"] > time.time() * 1000)
    except Exception: return False

def _scan_text_for_secrets(text: str, where: str):
    found = []
    for label, pattern in _SECRET_PATTERNS:
        m = pattern.search(text)
        if m:
            # Only a short prefix is reported — a report must never
            # republish the very secret it found.
            found.append({"type": label, "where": where,
                          "preview": m.group(0)[:6] + "…"})
    return found

def _extract_strings(blob: bytes, cap=12_000_000) -> str:
    parts = []
    total = 0
    for m in _STRING_RE.finditer(blob):
        s = m.group(0).decode("ascii", "replace")
        parts.append(s)
        total += len(s)
        if total > cap:
            break
    return "\n".join(parts)

def _apk_facts(data: bytes):
    """Parse an APK into a plain facts dict (androguard + zip inventory
    + manifest DOM walk for exported components). Raises ValueError
    for input that is not a parseable APK."""
    if _AndroAPK is None:
        raise RuntimeError("androguard is not installed in this engine image.")
    try:
        zipf = zipfile.ZipFile(io.BytesIO(data))
        names = zipf.namelist()
    except Exception:
        raise ValueError("File is not a ZIP/APK archive.")
    if "AndroidManifest.xml" not in names:
        raise ValueError("AndroidManifest.xml missing — not an APK.")
    dex_names = [n for n in names if re.fullmatch(r"classes\d*\.dex", n)]
    so_names = [n for n in names if n.endswith(".so")]
    abis = sorted({n.split("/")[1] for n in names
                   if n.startswith("lib/") and n.count("/") >= 2})
    try:
        apk = _AndroAPK(data, raw=True)
    except Exception as exc:
        raise ValueError(f"APK parse failed: {type(exc).__name__}")
    ns = "{http://schemas.android.com/apk/res/android}"
    counts = {"activities": 0, "services": 0, "receivers": 0, "providers": 0}
    exported_open, exported_guarded = [], 0
    flags = {"debuggable": False, "allow_backup": False,
             "cleartext_traffic": False, "network_config": False}
    try:
        root = apk.get_android_manifest_xml()
        app_el = root.find("application")
        if app_el is not None:
            flags["debuggable"] = app_el.get(ns + "debuggable") == "true"
            flags["allow_backup"] = app_el.get(ns + "allowBackup") == "true"
            flags["cleartext_traffic"] = \
                app_el.get(ns + "usesCleartextTraffic") == "true"
            flags["network_config"] = \
                app_el.get(ns + "networkSecurityConfig") is not None
        tag_map = {"activity": "activities", "activity-alias": "activities",
                   "service": "services", "receiver": "receivers",
                   "provider": "providers"}
        for tag, key in tag_map.items():
            for el in root.iter(tag):
                counts[key] += 1
                exp = el.get(ns + "exported")
                has_filter = el.find("intent-filter") is not None
                exported = (exp == "true") if exp else \
                    (has_filter and tag != "provider")
                if exported:
                    if el.get(ns + "permission"):
                        exported_guarded += 1
                    else:
                        exported_open.append(el.get(ns + "name") or "?")
    except Exception:
        counts = {"activities": len(apk.get_activities()),
                  "services": len(apk.get_services()),
                  "receivers": len(apk.get_receivers()),
                  "providers": len(apk.get_providers())}
    cert = None
    try:
        certs = apk.get_certificates()
        if certs:
            c = certs[0]
            cert = {"subject": str(c.subject.human_friendly),
                    "issuer": str(c.issuer.human_friendly),
                    "self_signed": c.issuer == c.subject,
                    "sha256": str(c.sha256_fingerprint).replace(" ", "")
                              .replace(":", "").lower(),
                    "not_after": str(getattr(c, "not_valid_after_utc", None)
                                     or getattr(c, "not_valid_after", ""))[:10]}
    except Exception:
        cert = None
    per_file_text = {}
    for name in dex_names:
        try:
            per_file_text[name] = _extract_strings(zipf.read(name))
        except Exception:
            continue
    return {"package": apk.get_package(), "app_name": apk.get_app_name(),
            "version_name": apk.get_androidversion_name(),
            "version_code": apk.get_androidversion_code(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version(),
            "main_activity": apk.get_main_activity(),
            "permissions": sorted(set(apk.get_permissions())),
            "components": counts,
            "exported_open": exported_open,
            "exported_guarded": exported_guarded,
            "flags": flags, "certificate": cert,
            "dex_files": dex_names, "native_abis": abis,
            "native_libs": len(so_names),
            "file_count": len(names), "per_file_text": per_file_text}

def apk_score(facts):
    """Transparent 0-100 static-analysis score; every deduction is
    listed with its reason, bucketed so no single category dominates."""
    caps = {"config": 39, "secrets": 20, "components": 16,
            "permissions": 12, "platform": 14}
    spent = {k: 0 for k in caps}
    deductions = []

    def deduct(points, label, bucket):
        take = min(points, caps[bucket] - spent[bucket])
        if take > 0:
            spent[bucket] += take
            deductions.append({"points": take, "label": label})

    flags = facts.get("flags") or {}
    if flags.get("debuggable"):
        deduct(25, "التطبيق قابل للتصحيح (debuggable) — خطر جسيم في نسخة إنتاج",
               "config")
    if flags.get("cleartext_traffic"):
        deduct(10, "حركة HTTP الواضحة مسموحة (usesCleartextTraffic)", "config")
    if flags.get("allow_backup"):
        deduct(4, "النسخ الاحتياطي مسموح (allowBackup) — بيانات التطبيق "
                  "قابلة للاستخراج عبر ADB", "config")
    secret_types = {s["type"] for s in facts.get("secrets") or []}
    for t in sorted(secret_types):
        deduct(10, f"نمط سرّي مدمج محتمل: {t}", "secrets")
    for name in facts.get("exported_open") or []:
        deduct(4, f"مكوّن مكشوف بلا حماية: {name}", "components")
    dangerous = facts.get("dangerous_permissions") or []
    for perm in dangerous:
        deduct(2, f"صلاحية خطيرة: {perm.split('.')[-1]}", "permissions")
    try:
        target = int(facts.get("target_sdk") or 0)
    except (TypeError, ValueError):
        target = 0
    if 0 < target < 26:
        deduct(6, f"SDK الهدف قديم ({target}) — بلا حمايات المنصة الحديثة",
               "platform")
    cert = facts.get("certificate") or {}
    if cert.get("not_after") and cert["not_after"] < \
            time.strftime("%Y-%m-%d", time.gmtime()):
        deduct(8, "شهادة توقيع التطبيق منتهية الصلاحية", "platform")
    final = max(0, 100 - sum(spent.values()))
    grade = ("ممتاز" if final >= 90 else "جيد" if final >= 75 else
             "متوسط" if final >= 55 else "ضعيف" if final >= 35 else "حرج")
    deductions.sort(key=lambda d: -d["points"])
    return {"score": final, "grade": grade, "deductions": deductions[:12]}

def analyze_apk(data: bytes):
    facts = _apk_facts(data)
    sha = hashlib.sha256(data).hexdigest()
    facts["dangerous_permissions"] = [
        p for p in facts["permissions"] if p in DANGEROUS_PERMISSIONS]
    secrets = []
    blob = ""
    for name, text in (facts.get("per_file_text") or {}).items():
        secrets += _scan_text_for_secrets(text, name)
        blob += text + "\n"
    urls = set(_URL_RE.findall(blob))
    urls = {u.rstrip(".,;") for u in urls
            if not any(d in u for d in _NOISE_DOMAINS)}
    cleartext = sorted(u for u in urls if u.startswith("http://"))[:15]
    domains = {}
    for u in urls:
        try:
            host = urllib.parse.urlparse(u).netloc
        except Exception:
            continue
        if host:
            domains[host] = domains.get(host, 0) + 1
    top_domains = sorted(domains.items(), key=lambda kv: -kv[1])[:8]
    sdks = [label for label, path in _SDK_SIGNATURES
            if ("L" + path) in blob or path.replace("/", ".") in blob]
    facts.pop("per_file_text", None)
    facts["secrets"] = secrets
    score = apk_score(facts)
    return {"status": "completed",
            "profile": "approved-apk-static-analysis-v1",
            "sha256": sha, "size_bytes": len(data),
            "app": {k: facts.get(k) for k in
                    ("package", "app_name", "version_name", "version_code",
                     "min_sdk", "target_sdk", "main_activity")},
            "permissions": {"total": len(facts["permissions"]),
                            "dangerous": facts["dangerous_permissions"],
                            "all": facts["permissions"][:60]},
            "components": {**facts["components"],
                           "exported_open": facts["exported_open"][:15],
                           "exported_guarded": facts["exported_guarded"]},
            "flags": facts["flags"],
            "secrets": secrets[:10],
            "urls": {"total": len(urls), "cleartext": cleartext,
                     "top_domains": top_domains},
            "sdks": sdks,
            "native_abis": facts["native_abis"],
            "dex_files": len(facts["dex_files"]),
            "certificate": facts["certificate"],
            "score": score,
            "limitations": [
                "Static analysis only: the app is never installed or run; "
                "runtime behaviour, server-side logic and obfuscated code "
                "can hide things a static pass cannot see.",
                "Secret patterns are candidates for the owner to verify; "
                "only a 6-character prefix is ever reported.",
                "Exported-component defaults follow the manifest rules "
                "(explicit attribute, else intent-filter presence)."]}

@app.post("/scans/apk")
async def apk_scan(request: Request, authorization: Optional[str] = Header(default=None), x_scan_approval: Optional[str] = Header(default=None)):
    require_auth(authorization)
    body = await request.body()
    if not body:
        raise HTTPException(status_code=400, detail="Empty upload.")
    if len(body) > APK_MAX_BYTES:
        raise HTTPException(status_code=413, detail="APK exceeds the analysis size cap.")
    sha = hashlib.sha256(body).hexdigest()
    if not valid_apk_permit(x_scan_approval, sha):
        raise HTTPException(status_code=403, detail="Target requires an active admin approval bound to this exact file (SHA-256).")
    if _AndroAPK is None:
        raise HTTPException(status_code=503, detail="APK analysis library is not installed in this engine image.")
    try:
        return analyze_apk(body)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
