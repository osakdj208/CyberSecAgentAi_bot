import json, os, sys, unittest
from unittest import mock

os.environ["ENGINE_API_TOKEN"] = "test-engine-token"
os.environ["SCAN_APPROVAL_SECRET"] = "test-approval-secret-at-least-32-bytes"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import main


def cpe_match(vendor, product, version="*", vulnerable=True, update="*",
              **ranges):
    m = {"criteria": f"cpe:2.3:a:{vendor}:{product}:{version}:{update}"
                     ":*:*:*:*:*:*",
         "vulnerable": vulnerable}
    m.update(ranges)
    return m


def cve_with(matches, cid="CVE-0000-0001"):
    return {"id": cid,
            "configurations": [{"nodes": [{"cpeMatch": matches}]}]}


class ApplicabilityTests(unittest.TestCase):
    def test_exact_version_match(self):
        cve = cve_with([cpe_match("apache", "http_server", "2.4.7")])
        self.assertTrue(main._cve_applies(cve, "apache", "http_server",
                                          "2.4.7"))
        self.assertFalse(main._cve_applies(cve, "apache", "http_server",
                                           "2.4.9"))

    def test_range_match(self):
        cve = cve_with([cpe_match("apache", "http_server", "*",
                                  versionStartIncluding="2.4.0",
                                  versionEndExcluding="2.4.10")])
        self.assertTrue(main._cve_applies(cve, "apache", "http_server",
                                          "2.4.7"))
        self.assertFalse(main._cve_applies(cve, "apache", "http_server",
                                           "2.4.10"))
        self.assertFalse(main._cve_applies(cve, "apache", "http_server",
                                           "2.3.9"))

    def test_running_on_noise_rejected(self):
        # The Ragnarok pattern: vulnerable match for ANOTHER product,
        # our product present only as a non-vulnerable platform node.
        cve = {"id": "CVE-2007-4723", "configurations": [{"nodes": [
            {"cpeMatch": [cpe_match("ragnarok", "control_panel", "4.3.4")]},
            {"operator": "AND", "children": [{"cpeMatch": [
                cpe_match("apache", "http_server", "*", vulnerable=False),
            ]}]},
        ]}]}
        self.assertFalse(main._cve_applies(cve, "apache", "http_server",
                                           "2.4.7"))

    def test_openssh_update_field(self):
        cve = cve_with([cpe_match("openbsd", "openssh", "9.6",
                                  update="p1")])
        self.assertTrue(main._cve_applies(cve, "openbsd", "openssh",
                                          "9.6p1"))
        self.assertFalse(main._cve_applies(cve, "openbsd", "openssh",
                                           "9.6p2"))

    def test_version_cmp(self):
        self.assertEqual(main._version_cmp("2.4.7", "2.4.7"), 0)
        self.assertLess(main._version_cmp("2.4.7", "2.4.10"), 0)
        self.assertGreater(main._version_cmp("1.1.1k", "1.1.1a"), 0)
        self.assertLess(main._version_cmp("9.6", "9.6p1"), 0)


NVD_DOC = {"vulnerabilities": [
    {"cve": {"id": "CVE-2014-0118",
             "descriptions": [{"lang": "en", "value": "mod_deflate DoS"}],
             "metrics": {"cvssMetricV31": [{"cvssData": {
                 "baseScore": 5.0, "baseSeverity": "MEDIUM"}}]},
             "configurations": [{"nodes": [{"cpeMatch": [
                 {"criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*",
                  "vulnerable": True,
                  "versionStartIncluding": "2.4.0",
                  "versionEndExcluding": "2.4.10"}]}]}]}},
    {"cve": {"id": "CVE-2007-4723",
             "descriptions": [{"lang": "en", "value": "unrelated"}],
             "metrics": {},
             "configurations": [{"nodes": [{"cpeMatch": [
                 {"criteria": "cpe:2.3:a:ragnarok:control_panel:4.3.4:"
                              "*:*:*:*:*:*:*",
                  "vulnerable": True}]}]}]}},
]}


class VersionCveCheckTests(unittest.TestCase):
    def run_check(self, pairs, doc):
        def fake_get(url, timeout=5, cap=262144):
            return (200, json.dumps(doc))
        with mock.patch.object(main, "_http_get", fake_get), \
             mock.patch.object(main, "_nvd_pause", lambda: None):
            return main.version_cve_check(pairs)

    def test_filters_and_reports(self):
        pairs = [{"vendor": "apache", "product": "http_server",
                  "display": "Apache httpd", "version": "2.4.7",
                  "source": "ترويسة example.com"}]
        out = self.run_check(pairs, NVD_DOC)
        self.assertEqual(len(out["products"]), 1)
        prod = out["products"][0]
        self.assertEqual(prod["total"], 1)
        self.assertEqual(prod["top"][0]["id"], "CVE-2014-0118")
        self.assertEqual(prod["top"][0]["cvss"], 5.0)

    def test_no_applicable_is_clean(self):
        pairs = [{"vendor": "apache", "product": "http_server",
                  "display": "Apache httpd", "version": "2.4.60",
                  "source": "x"}]
        out = self.run_check(pairs, NVD_DOC)
        self.assertEqual(out["products"], [])
        self.assertEqual(out["clean"], ["Apache httpd 2.4.60"])

    def test_collect_pairs(self):
        assessed = [{"host": "example.com",
                     "http": {"server": "Apache/2.4.7 (Ubuntu) "
                                        "OpenSSL/1.0.1f",
                              "powered_by": "PHP/7.4.3"}}]
        ports = [{"ip": "1.1.1.1", "ports": [
            {"port": "22", "state": "open", "product": "OpenSSH",
             "version": "9.6p1"},
            {"port": "443", "state": "open", "product": "Apache httpd",
             "version": "2.4.7"}]}]
        pairs = main.collect_version_pairs(assessed, ports)
        keys = {(p["vendor"], p["product"], p["version"]) for p in pairs}
        self.assertIn(("apache", "http_server", "2.4.7"), keys)
        self.assertIn(("openssl", "openssl", "1.0.1f"), keys)
        self.assertIn(("php", "php", "7.4.3"), keys)
        self.assertIn(("openbsd", "openssh", "9.6p1"), keys)
        self.assertEqual(len(pairs), 4)  # banner/port Apache deduped


def router_bytes(routes):
    def fake(url, timeout=5, cap=262144, headers=None):
        for key, result in routes.items():
            if url.endswith(key):
                return result
        return (404, b"")
    return fake


class HiddenContentTests(unittest.TestCase):
    def test_git_and_archive_found_env_html_rejected(self):
        routes = {
            "/.git/HEAD": (200, b"ref: refs/heads/main\n"),
            "/.env": (200, b"<html><body>spa fallback</body></html>"),
            "/backup.zip": (200, b"PK\x03\x04" + b"\x00" * 100),
        }
        with mock.patch.object(main, "_http_get_bytes",
                               router_bytes(routes)):
            out = main.hidden_content_check("example.com", "https")
        paths = [f["path"] for f in out["findings"]]
        self.assertIn("/.git/HEAD", paths)
        self.assertIn("/backup.zip", paths)
        self.assertNotIn("/.env", paths)

    def test_env_file_found(self):
        routes = {"/.env": (200, b"APP_KEY=base64:xyz\nDB_PASS=s3cret\n")}
        with mock.patch.object(main, "_http_get_bytes",
                               router_bytes(routes)):
            out = main.hidden_content_check("example.com", "https")
        self.assertEqual([f["kind"] for f in out["findings"]], ["env"])

    def test_catch_all_baseline_suppresses(self):
        body = b"ref: refs/heads/main\n"

        def fake(url, timeout=5, cap=262144, headers=None):
            return (200, body)  # every path returns the same body

        with mock.patch.object(main, "_http_get_bytes", fake):
            out = main.hidden_content_check("example.com", "https")
        self.assertEqual(out["findings"], [])
        self.assertTrue(out["catch_all"])


class PhaseC4ScoreTests(unittest.TestCase):
    EMAIL_OFF = {"status": "ready", "has_mx": False}

    def test_version_critical_costs_8(self):
        vc = {"status": "ready", "products": [
            {"product": "Apache httpd", "version": "2.4.7",
             "top": [{"id": "CVE-1", "cvss": 9.8,
                      "severity": "CRITICAL"}]}]}
        out = main.full_score([], [], self.EMAIL_OFF, None, None, None,
                              vc)
        self.assertEqual(out["score"], 92)

    def test_hidden_git_costs_8_in_surface(self):
        host = {"host": "h.example.com", "ips": ["1.1.1.1"],
                "nuclei": {"status": "ready", "counts": {}},
                "http": {"status": "ready", "missing": []},
                "tls": {"status": "ready", "legacy_protocols": {},
                        "days_left": 90},
                "hidden": {"status": "ready", "findings": [
                    {"path": "/.git/HEAD", "kind": "git_head"}]}}
        out = main.full_score([host], [], self.EMAIL_OFF)
        self.assertEqual(out["score"], 92)


class SubdomainSourceTests(unittest.TestCase):
    def test_hackertarget_parse(self):
        text = "api.example.com,1.1.1.1\nmail.example.com,1.1.1.2\n"
        with mock.patch.object(main, "_fetch_text", return_value=text):
            out = main._hackertarget_subdomains("example.com")
        self.assertEqual(out, ["api.example.com", "mail.example.com"])

    def test_wayback_parse(self):
        doc = [["original"], ["http://dev.example.com/a"],
               ["https://blog.example.com/"], ["http://other.org/"]]
        with mock.patch.object(main, "fetch_json", return_value=doc):
            out = main._wayback_subdomains("example.com")
        self.assertEqual(out, ["blog.example.com", "dev.example.com"])


if __name__ == "__main__":
    unittest.main()
