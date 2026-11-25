import base64, hashlib, hmac, ipaddress, json, os, secrets, shutil, socket, sqlite3, subprocess, time, urllib.request, urllib.error, xml.etree.ElementTree as ET
from typing import Optional
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

app = FastAPI(title="Cyber Security AI Agent Engine", version="0.5.0")
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
    return {"available":[{"name":"Nmap TCP/service discovery","state":"ready" if NMAP_PATH else "unavailable","profile":"top 100 ports, conservative timing, no exploit scripts"},{"name":"RDAP allocation lookup","state":"ready"},{"name":"RIPEstat ASN/routing lookup","state":"ready"},{"name":"Reverse DNS","state":"ready"},{"name":"IP geolocation","state":"ready"},{"name":"AbuseIPDB reputation","state":"ready" if ABUSEIPDB_KEY else "optional_api_key_required"},{"name":"Nuclei vulnerability detection (curated, no intrusive tags)","state":"ready" if NUCLEI_PATH else "unavailable"},{"name":"TLS deep probe (certificate, protocols, legacy)","state":"ready"},{"name":"HTTP security headers & cookies analysis","state":"ready"},{"name":"DNS records inventory","state":"ready" if dns else "unavailable"}]}

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
import re, ssl
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

def http_probe(host: str):
    result = {"status": "unavailable"}
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        recorder = _RedirectRecorder()
        opener = urllib.request.build_opener(recorder)
        req = urllib.request.Request(url, headers={"User-Agent": "CyberSecurityAI-Agent/0.5"})
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

def tls_probe(host: str):
    out = {"status": "unavailable"}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as raw:
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
            with socket.create_connection((host, 443), timeout=6) as raw:
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

def nuclei_scan(host: str):
    if not NUCLEI_PATH:
        return {"status": "unavailable", "note": "Nuclei binary is not installed in this engine image."}
    command = [NUCLEI_PATH, "-u", f"https://{host}", "-u", f"http://{host}",
               "-jsonl", "-silent", "-nc", "-ni", "-duc",
               "-severity", "low,medium,high,critical",
               "-etags", "dos,intrusive,fuzz,brute-force",
               "-rl", "25", "-c", "10", "-timeout", "6", "-retries", "1",
               "-max-host-error", "3"]
    if os.path.isdir(NUCLEI_TEMPLATES):
        # Load only the web-assessment categories: pointing Nuclei at the
        # full 14k-template tree costs minutes of startup on small CPUs.
        chosen = [os.path.join(NUCLEI_TEMPLATES, d)
                  for d in ("http", "ssl", "dns", "network")]
        chosen = [d for d in chosen if os.path.isdir(d)]
        if chosen:
            for d in chosen:
                command += ["-t", d]
        else:
            command += ["-t", NUCLEI_TEMPLATES]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=480, check=False, shell=False)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "note": "Nuclei exceeded the 480s engine cap; partial results discarded."}
    findings, counts = parse_nuclei_jsonl(result.stdout)
    return {"status": "ready", "findings": findings, "counts": counts,
            "total": sum(counts.values())}

@app.post("/scans/web")
def web_scan(request: WebScanRequest, authorization: Optional[str] = Header(default=None), x_scan_approval: Optional[str] = Header(default=None)):
    require_auth(authorization)
    if not request.confirm_authorized: raise HTTPException(status_code=400, detail="Explicit authorization confirmation is required.")
    host, ips = check_web_target(request.target_host, x_scan_approval)
    return {"status": "completed", "target": host, "resolved_ips": ips,
            "authorization_reference": request.authorization_reference,
            "profile": "approved-web-assessment-v1",
            "dns": dns_records(host), "http": http_probe(host),
            "tls": tls_probe(host), "nuclei": nuclei_scan(host),
            "limitations": ["Detection only: curated Nuclei templates with dos/intrusive/fuzz/brute-force tags excluded; no exploitation is attempted.",
                            "TLS and HTTP probes are single-shot observations from the engine's network vantage point.",
                            "Findings are scanner reports, not confirmed vulnerabilities; the admin reviews them before acting."]}
