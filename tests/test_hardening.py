"""Hardening (engine v0.14.1): the full assessment runs under ONE hard
wall-clock deadline. Every stage gate and subprocess cap derives from
the time actually left, so the engine always answers — with honest
skipped_budget declarations — instead of running until the caller or
the host instance gives up (the wolt.com incident of 2026-11-26)."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import main


class NucleiCapTests(unittest.TestCase):
    def test_cap_is_passed_to_the_curated_run(self):
        seen = {}

        def fake_run(targets, dirs, cookie, cap, headers=None):
            seen["cap"] = cap
            return {"status": "ready", "findings": [], "counts": {},
                    "total": 0}

        with mock.patch.object(main, "NUCLEI_PATH", "/fake/nuclei"), \
             mock.patch.object(main, "_template_dirs",
                               return_value=["/tpl"]), \
             mock.patch.object(main, "_run_nuclei", side_effect=fake_run):
            out = main.nuclei_scan("example.com", deep=False, cap=123)
        self.assertEqual(out["status"], "ready")
        self.assertEqual(seen["cap"], 123)

    def test_default_cap_is_480(self):
        seen = {}

        def fake_run(targets, dirs, cookie, cap, headers=None):
            seen["cap"] = cap
            return {"status": "ready", "findings": [], "counts": {},
                    "total": 0}

        with mock.patch.object(main, "NUCLEI_PATH", "/fake/nuclei"), \
             mock.patch.object(main, "_template_dirs",
                               return_value=["/tpl"]), \
             mock.patch.object(main, "_run_nuclei", side_effect=fake_run):
            main.nuclei_scan("example.com", deep=False)
        self.assertEqual(seen["cap"], 480)


class StageDeadlineTests(unittest.TestCase):
    PAIRS = [{"vendor": "apache", "product": "http_server",
              "version": "2.4.7", "display": "Apache httpd",
              "source": "banner"},
             {"vendor": "openssh", "product": "openssh",
              "version": "8.9", "display": "OpenSSH",
              "source": "nmap"}]

    def test_version_check_past_deadline_queries_nothing(self):
        calls = []

        def fake_nvd(cpe):
            calls.append(cpe)
            return []

        with mock.patch.object(main, "_nvd_cves_for_cpe",
                               side_effect=fake_nvd):
            out = main.version_cve_check(self.PAIRS, deadline_ts=1)
        self.assertEqual(calls, [])
        self.assertEqual(out["unmatched"], ["Apache httpd", "OpenSSH"])
        self.assertEqual(out["products"], [])

    def test_cloud_check_past_deadline_probes_nothing(self):
        calls = []

        def fake_get(url, timeout=5, cap=0, headers=None):
            calls.append(url)
            return None, None

        with mock.patch.object(main, "_http_get", side_effect=fake_get):
            out = main.cloud_storage_check("example.com", deadline_ts=1)
        self.assertEqual(calls, [])
        self.assertEqual(out["candidates_checked"], 0)
        self.assertEqual(out["status"], "ready")

    def test_takeover_past_deadline_checks_nothing(self):
        calls = []

        def fake_chain(resolver, host):
            calls.append(host)
            return ["x.github.io"]

        with mock.patch.object(main, "_cname_chain",
                               side_effect=fake_chain):
            out = main.subdomain_takeover_check(
                ["a.example.com", "b.example.com"], deadline_ts=1)
        self.assertEqual(calls, [])
        self.assertEqual(out["checked"], 0)


class ExhaustedClockScanTests(unittest.TestCase):
    """With the clock already past the deadline, full_scan must still
    complete instantly, assess only the first candidate, and declare
    every remaining stage skipped_budget — never hang or vanish."""

    def test_full_scan_completes_under_exhausted_clock(self):
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
        t0 = 1_000_000.0
        calls = {"n": 0}

        def fake_time():
            calls["n"] += 1
            return t0 if calls["n"] == 1 else t0 + 1600

        with mock.patch.object(main, "check_full_target",
                               return_value=("example.com", ["1.1.1.1"])), \
             mock.patch.object(main, "discover_subdomains",
                               return_value=["mail.example.com"]), \
             mock.patch.object(main, "_resolve_quiet",
                               return_value=["1.1.1.1"]), \
             mock.patch.object(main, "http_probe", return_value=dict(http)), \
             mock.patch.object(main, "tls_probe", return_value=dict(tls)), \
             mock.patch.object(main, "nuclei_scan",
                               return_value={"status": "ready",
                                             "findings": [], "counts": {},
                                             "total": 0}) as nuclei_mock, \
             mock.patch.object(main, "nmap_data",
                               return_value={"ports": [],
                                             "summary": {}}), \
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
             mock.patch.object(main, "api_surface_check",
                               return_value={"status": "ready"}), \
             mock.patch.object(main, "js_mining",
                               return_value={"status": "ready"}), \
             mock.patch.object(main, "hidden_content_check",
                               return_value={"status": "ready"}), \
             mock.patch.object(main, "cloud_storage_check",
                               return_value={"status": "ready",
                                             "exposed": [],
                                             "private_existing": 0,
                                             "candidates_checked": 0}), \
             mock.patch.object(main, "dns_records",
                               return_value={"status": "ready",
                                             "records": {}}), \
             mock.patch.object(main.time, "time", side_effect=fake_time):
            out = main.full_scan(req,
                                 authorization="Bearer test-engine-token",
                                 x_scan_approval="permit")
        self.assertEqual(out["status"], "completed")
        self.assertEqual(out["deadline_seconds"],
                         main._full_scan_bounds()[1]["deadline"])
        self.assertEqual(len(out["hosts"]), 1)
        host = out["hosts"][0]
        self.assertEqual(host["nuclei"]["status"], "skipped_budget")
        self.assertEqual(host["api"]["status"], "skipped_budget")
        self.assertEqual(host["js"]["status"], "skipped_budget")
        self.assertEqual(host["hidden"]["status"], "skipped_budget")
        self.assertEqual(out["ports_by_ip"], [])
        self.assertEqual(out["cloud"]["status"], "skipped_budget")
        nuclei_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
