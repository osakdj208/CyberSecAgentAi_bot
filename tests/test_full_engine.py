import base64, hashlib, hmac, json, os, sys, time, unittest
from unittest import mock

os.environ["ENGINE_API_TOKEN"] = "test-engine-token"
os.environ["SCAN_APPROVAL_SECRET"] = "test-approval-secret-at-least-32-bytes"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import main


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def mint(payload: dict) -> str:
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    s = b64url(hmac.new(os.environ["SCAN_APPROVAL_SECRET"].encode(),
                        p.encode(), hashlib.sha256).digest())
    return p + "." + s


def full_permit(host="example.com", ips=("1.1.1.1",), kind="full", exp_ms=None):
    return mint({"host": host, "ips": list(ips), "kind": kind, "id": "r1",
                 "exp": exp_ms or int((time.time() + 300) * 1000)})


class FullPermitTests(unittest.TestCase):
    def test_valid_full_permit(self):
        self.assertTrue(main.valid_full_permit(
            full_permit(), "example.com", ["1.1.1.1"]))

    def test_web_kind_rejected(self):
        self.assertFalse(main.valid_full_permit(
            full_permit(kind="web"), "example.com", ["1.1.1.1"]))

    def test_subset_and_host_rules(self):
        self.assertFalse(main.valid_full_permit(
            full_permit(), "example.com", ["9.9.9.9"]))
        self.assertFalse(main.valid_full_permit(
            full_permit(), "other.com", ["1.1.1.1"]))

    def test_expired_rejected(self):
        old = full_permit(exp_ms=int((time.time() - 10) * 1000))
        self.assertFalse(main.valid_full_permit(old, "example.com", ["1.1.1.1"]))


class FakeTxt:
    def __init__(self, text):
        self.strings = [text.encode()]


class FakeResolver:
    TXT = {}
    MX = {}

    def resolve(self, name, rtype):
        if rtype == "MX":
            if not FakeResolver.MX.get(name):
                raise Exception("no mx")
            return [FakeResolver.MX[name]]
        if rtype == "TXT":
            vals = FakeResolver.TXT.get(name)
            if not vals:
                raise Exception("no txt")
            return [FakeTxt(v) for v in vals]
        raise Exception("no record")


class MxAnswer:
    def __str__(self):
        return "10 mail.example.com."


class EmailSecurityTests(unittest.TestCase):
    def run_audit(self, txt, mx):
        FakeResolver.TXT = txt
        FakeResolver.MX = mx
        with mock.patch.object(main.dns.resolver, "Resolver", FakeResolver):
            return main.email_security("example.com")

    def test_strong_posture(self):
        out = self.run_audit(
            {"example.com": ["v=spf1 include:_spf.google.com -all"],
             "_dmarc.example.com": ["v=DMARC1; p=reject;"],
             "google._domainkey.example.com": ["v=DKIM1; k=rsa; p=ABC"]},
            {"example.com": MxAnswer()})
        self.assertTrue(out["has_mx"])
        self.assertTrue(out["spf"]["present"])
        self.assertEqual(out["spf"]["strength"], "strict")
        self.assertEqual(out["dmarc"]["policy"], "reject")
        self.assertIn("google", out["dkim"]["found"])

    def test_no_records(self):
        out = self.run_audit({}, {})
        self.assertFalse(out["has_mx"])
        self.assertFalse(out["spf"]["present"])
        self.assertFalse(out["dmarc"]["present"])
        self.assertEqual(out["dkim"]["found"], [])

    def test_softfail_and_monitor_only(self):
        out = self.run_audit(
            {"example.com": ["v=spf1 +a ~all"],
             "_dmarc.example.com": ["v=DMARC1; p=none;"]},
            {"example.com": MxAnswer()})
        self.assertEqual(out["spf"]["strength"], "softfail")
        self.assertEqual(out["dmarc"]["policy"], "none")


def host_with(nuclei=None, http=None, tls=None):
    return {"host": "h.example.com", "ips": ["1.1.1.1"],
            "nuclei": nuclei or {"status": "ready", "counts": {}},
            "http": http or {"status": "ready", "missing": []},
            "tls": tls or {"status": "ready", "legacy_protocols": {},
                           "days_left": 90}}


class FullScoreTests(unittest.TestCase):
    def test_clean_is_100(self):
        email = {"status": "ready", "has_mx": True,
                 "spf": {"present": True, "strength": "strict"},
                 "dmarc": {"present": True, "policy": "reject"},
                 "dkim": {"found": ["google"]}}
        out = main.full_score([host_with()], [], email)
        self.assertEqual(out["score"], 100)
        self.assertEqual(out["grade"], "ممتاز")

    def test_email_gaps_cost_18(self):
        email = {"status": "ready", "has_mx": True,
                 "spf": {"present": False}, "dmarc": {"present": False},
                 "dkim": {"found": []}}
        out = main.full_score([], [], email)
        self.assertEqual(out["score"], 82)

    def test_criticals_and_risky_ports(self):
        host = host_with(nuclei={"status": "ready",
                                 "counts": {"critical": 2}})
        ports = [{"ip": "1.1.1.1", "ports": [
            {"port": "3389", "state": "open"},
            {"port": "3306", "state": "open"},
            {"port": "443", "state": "open"}]}]
        email = {"status": "ready", "has_mx": False}
        out = main.full_score([host], ports, email)
        self.assertEqual(out["score"], 100 - 30 - 6 - 3)

    def test_legacy_tls_and_missing_headers(self):
        host = host_with(
            http={"status": "ready", "missing": ["a", "b", "c", "d"]},
            tls={"status": "ready",
                 "legacy_protocols": {"TLSv1.0": True}, "days_left": 90})
        out = main.full_score([host], [], {"status": "ready", "has_mx": False})
        self.assertEqual(out["score"], 100 - 4 - 6)

    def test_bucket_caps_limit_single_category(self):
        # Nuclei bucket is capped at 40 and email at 22 by design, so
        # those two alone can never take the score below 42.
        hosts = [host_with(nuclei={"status": "ready",
                                   "counts": {"critical": 9, "high": 9}})
                 for _ in range(4)]
        email = {"status": "ready", "has_mx": True,
                 "spf": {"present": False}, "dmarc": {"present": False},
                 "dkim": {"found": []}}
        out = main.full_score(hosts, [], email)
        self.assertEqual(out["score"], 42)

    def test_floor_zero(self):
        hosts = [host_with(
            nuclei={"status": "ready", "counts": {"critical": 9}},
            http={"status": "ready", "missing": ["a", "b", "c", "d"]},
            tls={"status": "ready",
                 "legacy_protocols": {"TLSv1.0": True, "TLSv1.1": True},
                 "days_left": 3}) for _ in range(4)]
        ports = [{"ip": "1.1.1.1", "ports": [
            {"port": str(p), "state": "open"}
            for p in (21, 23, 3389, 5900, 6379, 27017)]}]
        email = {"status": "ready", "has_mx": True,
                 "spf": {"present": False}, "dmarc": {"present": False},
                 "dkim": {"found": []}}
        out = main.full_score(hosts, ports, email)
        self.assertEqual(out["score"], 0)


class TechFingerprintTests(unittest.TestCase):
    def test_cookie_hints(self):
        out = main.tech_fingerprint(
            {"server": "nginx", "powered_by": None,
             "cookies": [{"name": "PHPSESSID"}, {"name": "csrftoken"}]})
        self.assertIn("خادم ويب: nginx", out["hints"])
        self.assertTrue(any("PHP" in h for h in out["hints"]))
        self.assertTrue(any("Django" in h for h in out["hints"]))

    def test_empty(self):
        out = main.tech_fingerprint({"status": "unavailable"})
        self.assertEqual(out["hints"], [])


class FullScanOrchestrationTests(unittest.TestCase):
    def test_end_to_end_shape_with_stubbed_stages(self):
        req = main.FullScanRequest(
            target_host="example.com",
            authorization_reference="ref-1234", confirm_authorized=True)
        http = {"status": "ready", "scheme": "https", "http_status": 200,
                "missing": [], "server": "nginx", "cookies": []}
        tls = {"status": "ready", "tls_version": "TLSv1.3",
               "legacy_protocols": {}, "days_left": 60}
        email = {"status": "ready", "has_mx": True,
                 "spf": {"present": True, "strength": "strict"},
                 "dmarc": {"present": True, "policy": "reject"},
                 "dkim": {"found": ["google"]}}
        with mock.patch.object(main, "check_full_target",
                               return_value=("example.com", ["1.1.1.1"])), \
             mock.patch.object(main, "discover_subdomains",
                               return_value=["mail.example.com"]), \
             mock.patch.object(main, "_resolve_quiet",
                               return_value=["1.1.1.1"]), \
             mock.patch.object(main, "http_probe", return_value=dict(http)), \
             mock.patch.object(main, "tls_probe", return_value=dict(tls)), \
             mock.patch.object(main, "nuclei_scan",
                               return_value={"status": "ready", "findings": [],
                                             "counts": {}, "total": 0}), \
             mock.patch.object(main, "nmap_data",
                               return_value={"ports": [], "summary": {}}), \
             mock.patch.object(main, "email_security", return_value=email), \
             mock.patch.object(main, "dns_deep_audit",
                               return_value={"status": "ready",
                                             "axfr": {"vulnerable": False,
                                                      "attempts": []},
                                             "dnssec": {"signed": True},
                                             "caa": {"present": True,
                                                     "records": []}}), \
             mock.patch.object(main, "subdomain_takeover_check",
                               return_value={"status": "ready", "checked": 0,
                                             "findings": []}), \
             mock.patch.object(main, "dns_records",
                               return_value={"status": "ready", "records": {}}):
            out = main.full_scan(req, authorization="Bearer test-engine-token",
                                 x_scan_approval="permit")
        self.assertEqual(out["status"], "completed")
        self.assertEqual(out["profile"], "approved-full-assessment-v1")
        self.assertEqual(out["score"]["score"], 100)
        self.assertEqual(len(out["hosts"]), 2)
        self.assertEqual(out["discovery"]["subdomains_found"],
                         ["mail.example.com"])
        self.assertEqual(len(out["ports_by_ip"]), 1)


if __name__ == "__main__":
    unittest.main()
