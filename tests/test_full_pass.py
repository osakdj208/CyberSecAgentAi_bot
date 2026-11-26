"""Pass fingerprint (identification header) on the full assessment +
wildcard-DNS detection. The header must reach every request the
assessment sends to the target's own hosts, must be reported as used,
and must stay one-shot in the bot's memory — the Wolt/HackerOne rule
that motivates this: testing without the header can forfeit a bounty.
"""
import os, sys, tempfile, unittest
from unittest import mock

os.environ["ENGINE_API_TOKEN"] = "test-engine-token"
os.environ["SCAN_APPROVAL_SECRET"] = "test-approval-secret-at-least-32-bytes"
os.environ["BOT_DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import bot
import main


HDR = {"X-HackerOne-Research": "harisai-ye"}
HDR_LIST = ["X-HackerOne-Research: harisai-ye"]


def _stages(captured):
    """Stub stage functions that record the headers they received."""
    def probe(host, extra_headers=None):
        captured["probe"] = extra_headers
        return {"status": "ready", "scheme": "https", "http_status": 200,
                "missing": [], "server": "nginx", "cookies": []}

    def nuclei(host, deep=False, headers=None, **kw):
        captured["nuclei"] = headers
        return {"status": "ready", "findings": [], "counts": {}, "total": 0}

    def api(host, scheme, headers=None):
        captured["api"] = headers
        return {"status": "ready", "openapi": [], "doc_pages": [],
                "graphql": []}

    def js(host, scheme, headers=None):
        captured["js"] = headers
        return {"status": "ready", "files_checked": 0, "secrets": [],
                "api_endpoints": [], "internal_addresses": [],
                "external_domains": []}

    def hidden(host, scheme, headers=None):
        captured["hidden"] = headers
        return {"status": "ready", "findings": [], "catch_all": False}

    def takeover(hosts, headers=None):
        captured["takeover"] = headers
        return {"status": "ready", "checked": 0, "findings": []}

    return probe, nuclei, api, js, hidden, takeover


def _run_full(req, captured):
    probe, nuclei, api, js, hidden, takeover = _stages(captured)
    email = {"status": "ready", "has_mx": True,
             "spf": {"present": True, "strength": "strict"},
             "dmarc": {"present": True, "policy": "reject"},
             "dkim": {"found": ["google"]}}
    dns_audit = {"status": "ready", "axfr": {"vulnerable": False,
                                             "attempts": []},
                 "dnssec": {"signed": True},
                 "caa": {"present": True, "records": []}}
    with mock.patch.object(main, "check_full_target",
                           return_value=("example.com", ["1.1.1.1"])), \
         mock.patch.object(main, "discover_subdomains", return_value=[]), \
         mock.patch.object(main, "detect_wildcard_dns", return_value=[]), \
         mock.patch.object(main, "_resolve_quiet",
                           return_value=["1.1.1.1"]), \
         mock.patch.object(main, "http_probe", side_effect=probe), \
         mock.patch.object(main, "tls_probe",
                           return_value={"status": "ready"}), \
         mock.patch.object(main, "nuclei_scan", side_effect=nuclei), \
         mock.patch.object(main, "nmap_data",
                           return_value={"ports": [], "summary": {}}), \
         mock.patch.object(main, "email_security", return_value=email), \
         mock.patch.object(main, "dns_deep_audit", return_value=dns_audit), \
         mock.patch.object(main, "subdomain_takeover_check",
                           side_effect=takeover), \
         mock.patch.object(main, "api_surface_check", side_effect=api), \
         mock.patch.object(main, "js_mining", side_effect=js), \
         mock.patch.object(main, "cloud_storage_check",
                           return_value={"status": "ready", "exposed": [],
                                         "private_existing": 0,
                                         "candidates_checked": 12}), \
         mock.patch.object(main, "hidden_content_check",
                           side_effect=hidden), \
         mock.patch.object(main, "dns_records",
                           return_value={"status": "ready", "records": {}}):
        return main.full_scan(req, authorization="Bearer test-engine-token",
                              x_scan_approval="permit")


class EnginePassHeaderTests(unittest.TestCase):
    def test_request_fields_and_pass_headers_helper(self):
        req = main.FullScanRequest(
            target_host="example.com", authorization_reference="ref-1234",
            confirm_authorized=True,
            pass_header_name="X-HackerOne-Research",
            pass_header_value="harisai-ye")
        self.assertEqual(main._pass_headers(req), HDR)
        plain = main.FullScanRequest(
            target_host="example.com", authorization_reference="ref-1234",
            confirm_authorized=True)
        self.assertEqual(main._pass_headers(plain), {})

    def test_invalid_header_name_rejected(self):
        req = main.FullScanRequest(
            target_host="example.com", authorization_reference="ref-1234",
            confirm_authorized=True, pass_header_name="Bad Name!",
            pass_header_value="x")
        with self.assertRaises(Exception):
            main._pass_headers(req)

    def test_header_reaches_every_target_stage(self):
        captured = {}
        req = main.FullScanRequest(
            target_host="example.com", authorization_reference="ref-1234",
            confirm_authorized=True,
            pass_header_name="X-HackerOne-Research",
            pass_header_value="harisai-ye")
        out = _run_full(req, captured)
        self.assertTrue(out["pass_used"])
        self.assertEqual(captured["probe"], HDR)
        self.assertEqual(captured["nuclei"], HDR_LIST)
        self.assertEqual(captured["api"], HDR)
        self.assertEqual(captured["js"], HDR)
        self.assertEqual(captured["hidden"], HDR)
        self.assertEqual(captured["takeover"], HDR)

    def test_no_header_means_no_header_anywhere(self):
        captured = {}
        req = main.FullScanRequest(
            target_host="example.com", authorization_reference="ref-1234",
            confirm_authorized=True)
        out = _run_full(req, captured)
        self.assertFalse(out["pass_used"])
        for key in ("probe", "nuclei", "api", "js", "hidden", "takeover"):
            self.assertIsNone(captured[key], key)


class WildcardDnsTests(unittest.TestCase):
    def test_detected_when_random_name_resolves(self):
        with mock.patch.object(main, "_resolve_quiet",
                               return_value=["9.9.9.9"]) as rq:
            self.assertEqual(main.detect_wildcard_dns("example.com"),
                             ["9.9.9.9"])
            probed = rq.call_args[0][0]
            self.assertTrue(probed.startswith("probe-"))
            self.assertTrue(probed.endswith(".example.com"))

    def test_not_detected_when_random_name_does_not_resolve(self):
        with mock.patch.object(main, "_resolve_quiet", return_value=[]):
            self.assertEqual(main.detect_wildcard_dns("example.com"), [])

    def test_full_scan_reports_wildcard(self):
        captured = {}
        req = main.FullScanRequest(
            target_host="example.com", authorization_reference="ref-1234",
            confirm_authorized=True)
        probe, nuclei, api, js, hidden, takeover = _stages(captured)
        with mock.patch.object(main, "check_full_target",
                               return_value=("example.com", ["1.1.1.1"])), \
             mock.patch.object(main, "discover_subdomains",
                               return_value=[]), \
             mock.patch.object(main, "detect_wildcard_dns",
                               return_value=["5.5.5.5"]), \
             mock.patch.object(main, "_resolve_quiet",
                               return_value=["1.1.1.1"]), \
             mock.patch.object(main, "http_probe", side_effect=probe), \
             mock.patch.object(main, "tls_probe",
                               return_value={"status": "ready"}), \
             mock.patch.object(main, "nuclei_scan", side_effect=nuclei), \
             mock.patch.object(main, "nmap_data",
                               return_value={"ports": [], "summary": {}}), \
             mock.patch.object(main, "email_security",
                               return_value={
                                   "status": "ready", "has_mx": True,
                                   "spf": {"present": True,
                                           "strength": "strict"},
                                   "dmarc": {"present": True,
                                             "policy": "reject"},
                                   "dkim": {"found": ["google"]}}), \
             mock.patch.object(main, "dns_deep_audit",
                               return_value={
                                   "status": "ready",
                                   "axfr": {"vulnerable": False,
                                            "attempts": []},
                                   "dnssec": {"signed": True},
                                   "caa": {"present": True,
                                           "records": []}}), \
             mock.patch.object(main, "subdomain_takeover_check",
                               side_effect=takeover), \
             mock.patch.object(main, "api_surface_check",
                               side_effect=api), \
             mock.patch.object(main, "js_mining", side_effect=js), \
             mock.patch.object(main, "cloud_storage_check",
                               return_value={"status": "ready",
                                             "exposed": [],
                                             "private_existing": 0,
                                             "candidates_checked": 12}), \
             mock.patch.object(main, "hidden_content_check",
                               side_effect=hidden), \
             mock.patch.object(main, "dns_records",
                               return_value={"status": "ready",
                                             "records": {}}):
            out = main.full_scan(
                req, authorization="Bearer test-engine-token",
                x_scan_approval="permit")
        self.assertEqual(out["discovery"]["wildcard"],
                         {"detected": True, "ips": ["5.5.5.5"]})


class HelperThreadingTests(unittest.TestCase):
    def test_api_surface_check_threads_headers(self):
        seen = []

        def fake_get(url, timeout=5, cap=0, headers=None):
            seen.append(headers)
            return 404, ""

        def fake_post(url, payload, timeout=5, cap=0, headers=None):
            seen.append(headers)
            return 404, ""

        with mock.patch.object(main, "_http_get", side_effect=fake_get), \
             mock.patch.object(main, "_http_post_json",
                               side_effect=fake_post):
            main.api_surface_check("example.com", "https", headers=HDR)
        self.assertTrue(seen)
        self.assertTrue(all(h == HDR for h in seen))

    def test_hidden_content_check_threads_headers(self):
        seen = []

        def fake_bytes(url, timeout=5, cap=0, headers=None):
            seen.append(headers)
            return 404, b""

        with mock.patch.object(main, "_http_get_bytes",
                               side_effect=fake_bytes):
            out = main.hidden_content_check("example.com", "https",
                                            headers=HDR)
        self.assertEqual(out["findings"], [])
        self.assertTrue(seen)
        self.assertTrue(all(h == HDR for h in seen))

    def test_takeover_check_threads_headers(self):
        seen = []

        def fake_fetch(url, timeout=5, cap=0, headers=None):
            seen.append(headers)
            return "There isn't a GitHub Pages site here."

        with mock.patch.object(main, "_cname_chain",
                               return_value=["user.github.io"]), \
             mock.patch.object(main, "_fetch_text",
                               side_effect=fake_fetch), \
             mock.patch.object(main, "_resolve_quiet",
                               return_value=["1.1.1.1"]):
            out = main.subdomain_takeover_check(["old.example.com"],
                                                headers=HDR)
        self.assertEqual(out["findings"][0]["verdict"], "confirmed")
        self.assertEqual(seen, [HDR])


CANNED = {
    "base_domain": "example.com", "profile": "approved-full-assessment-v1",
    "elapsed_seconds": 321, "pass_used": True,
    "score": {"score": 90, "grade": "ممتاز", "deductions": []},
    "priorities": [],
    "discovery": {"subdomains_found": ["mail.example.com"],
                  "hosts_assessed": ["example.com"],
                  "wildcard": {"detected": True, "ips": ["5.5.5.5"]}},
    "email": {"status": "unavailable"},
    "hosts": [], "ports_by_ip": [],
}


class BotPassTests(unittest.TestCase):
    def setUp(self):
        bot.STATE.clear()
        bot.PASS_SECRETS.clear()
        self.sent = []
        p1 = mock.patch.object(
            bot, "send", lambda cid, text, kb=None: self.sent.append(text))
        p1.start()
        self.addCleanup(p1.stop)
        p2 = mock.patch.object(bot, "notify_admin", lambda req: None)
        p2.start()
        self.addCleanup(p2.stop)

    def msg(self, text):
        return {"chat": {"id": 7}, "from": {"id": 42, "username": "u"},
                "text": text}

    def _drive_to_pass_step(self):
        bot.STATE[7] = {"step": "f_await_host"}
        bot.handle_message(self.msg("example.com"))
        bot.handle_message(self.msg("domain-verification-42"))
        bot.handle_message(self.msg("تخطي"))
        self.assertEqual(bot.STATE[7]["step"], "f_await_pass")

    def _new_rows(self, before_ids):
        return [r for r in bot.list_requests(42)
                if r["id"] not in before_ids]

    def test_flow_stores_pass_pair_one_shot(self):
        before = {r["id"] for r in bot.list_requests(42)}
        self._drive_to_pass_step()
        bot.handle_message(self.msg("X-HackerOne-Research: harisai-ye"))
        new = self._new_rows(before)
        self.assertEqual(len(new), 1)
        self.assertEqual(bot.PASS_SECRETS.get(new[0]["id"]),
                         ("X-HackerOne-Research", "harisai-ye"))

    def test_flow_skip_pass_stores_nothing(self):
        before = {r["id"] for r in bot.list_requests(42)}
        self._drive_to_pass_step()
        bot.handle_message(self.msg("تخطي"))
        new = self._new_rows(before)
        self.assertEqual(len(new), 1)
        self.assertEqual(bot.PASS_SECRETS, {})

    def test_run_full_scan_sends_and_pops_pair(self):
        captured = {}

        def fake_engine_call(method, path, body=None, permit=None,
                             timeout=60):
            captured.update(method=method, path=path, body=body)
            return {"status": "completed"}

        req = {"id": "reqpass1", "ip": "example.com", "auth_ref": "ref-1"}
        bot.PASS_SECRETS["reqpass1"] = ("X-HackerOne-Research",
                                         "harisai-ye")
        with mock.patch.object(bot, "engine_call",
                               side_effect=fake_engine_call), \
             mock.patch.object(bot, "resolve_host_ips",
                               return_value=["1.1.1.1"]):
            bot.run_approved_full_scan(req)
        self.assertEqual(captured["path"], "/scans/full")
        self.assertEqual(captured["body"]["pass_header_name"],
                         "X-HackerOne-Research")
        self.assertEqual(captured["body"]["pass_header_value"],
                         "harisai-ye")
        self.assertNotIn("reqpass1", bot.PASS_SECRETS)

    def test_report_shows_pass_and_wildcard_lines(self):
        req = {"ip": "example.com", "auth_ref": "ref-123"}
        text = bot.format_full_report(req, CANNED)
        self.assertIn("بصمة مرور", text)
        self.assertIn("Wildcard DNS", text)
        self.assertIn("5.5.5.5", text)

    def test_report_without_new_keys_stays_clean(self):
        canned = dict(CANNED)
        canned.pop("pass_used")
        canned["discovery"] = {"subdomains_found": [],
                               "hosts_assessed": []}
        req = {"ip": "example.com", "auth_ref": "ref-123"}
        text = bot.format_full_report(req, canned)
        self.assertNotIn("Wildcard DNS", text)


if __name__ == "__main__":
    unittest.main()
