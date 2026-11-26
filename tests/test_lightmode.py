"""Light mode (engine v0.14.2): the full assessment's bounds are a
profile switch (FULL_SCAN_PROFILE), defaulting to "light" — sized so
a run actually completes on the free 512MB / 0.1-CPU instance. Every
stage and tool still runs; only per-run breadth narrows. "full"
restores the original bounds on a real server. Stage boundaries are
logged to stdout so a production incident is diagnosable from the
host's logs instead of guesswork."""
import contextlib
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("ENGINE_API_TOKEN", "test-engine-token")
os.environ.setdefault("SCAN_APPROVAL_SECRET",
                      "test-approval-secret-at-least-32-bytes")
os.environ.setdefault("BOT_DB_PATH",
                      os.path.join(tempfile.mkdtemp(), "test.db"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import main
import bot


class BoundsTests(unittest.TestCase):
    def test_default_profile_is_light(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FULL_SCAN_PROFILE", None)
            name, b = main._full_scan_bounds()
        self.assertEqual(name, "light")
        self.assertEqual(b["deadline"], 720)
        self.assertEqual(b["hosts"], 6)
        self.assertEqual(b["nuclei_hosts"], 2)
        self.assertEqual(b["nuclei_cap"], 180)
        self.assertEqual(b["ports_ips"], 2)

    def test_full_profile_restores_original_bounds(self):
        with mock.patch.dict(os.environ,
                             {"FULL_SCAN_PROFILE": "full"}):
            name, b = main._full_scan_bounds()
        self.assertEqual(name, "full")
        self.assertEqual(b["deadline"], 1500)
        self.assertEqual(b["hosts"], 10)
        self.assertEqual(b["nuclei_cap"], 480)
        self.assertEqual(b["ports_ips"], 4)

    def test_unknown_profile_falls_back_to_light(self):
        with mock.patch.dict(os.environ,
                             {"FULL_SCAN_PROFILE": "banana"}):
            name, b = main._full_scan_bounds()
        self.assertEqual(name, "light")
        self.assertEqual(b["deadline"], 720)


def _run_scan(captured_caps):
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

    def fake_nuclei(host, deep=False, headers=None, cap=None):
        captured_caps.append(cap)
        return {"status": "ready", "findings": [], "counts": {},
                "total": 0}

    buf = io.StringIO()
    with mock.patch.object(main, "check_full_target",
                           return_value=("example.com", ["1.1.1.1"])), \
         mock.patch.object(main, "discover_subdomains",
                           return_value=["mail.example.com"]), \
         mock.patch.object(main, "_resolve_quiet",
                           return_value=["1.1.1.1"]), \
         mock.patch.object(main, "http_probe", return_value=dict(http)), \
         mock.patch.object(main, "tls_probe", return_value=dict(tls)), \
         mock.patch.object(main, "nuclei_scan", side_effect=fake_nuclei), \
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
         mock.patch.object(main, "api_surface_check",
                           return_value={"status": "ready", "openapi": [],
                                         "doc_pages": [],
                                         "graphql": []}), \
         mock.patch.object(main, "js_mining",
                           return_value={"status": "ready",
                                         "files_checked": 0,
                                         "secrets": [],
                                         "api_endpoints": [],
                                         "internal_addresses": [],
                                         "external_domains": []}), \
         mock.patch.object(main, "hidden_content_check",
                           return_value={"status": "ready",
                                         "findings": [],
                                         "catch_all": False}), \
         mock.patch.object(main, "cloud_storage_check",
                           return_value={"status": "ready",
                                         "exposed": [],
                                         "private_existing": 0,
                                         "candidates_checked": 12}), \
         mock.patch.object(main, "dns_records",
                           return_value={"status": "ready",
                                         "records": {}}), \
         contextlib.redirect_stdout(buf):
        out = main.full_scan(req,
                             authorization="Bearer test-engine-token",
                             x_scan_approval="permit")
    return out, buf.getvalue()


class ProfileRunTests(unittest.TestCase):
    def test_light_run_uses_light_bounds_and_logs_stages(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FULL_SCAN_PROFILE", None)
            caps = []
            out, logs = _run_scan(caps)
        self.assertEqual(out["status"], "completed")
        self.assertEqual(out["scan_profile"], "light")
        self.assertEqual(out["deadline_seconds"], 720)
        self.assertEqual(caps, [180, 180])
        self.assertIn("[full-scan] start", logs)
        self.assertIn("[full-scan] discovery", logs)
        self.assertIn("[full-scan] probing", logs)
        self.assertIn("[full-scan] done", logs)
        self.assertIn("light profile", out["limitations"][2])

    def test_full_run_uses_full_bounds(self):
        with mock.patch.dict(os.environ,
                             {"FULL_SCAN_PROFILE": "full"}):
            caps = []
            out, logs = _run_scan(caps)
        self.assertEqual(out["scan_profile"], "full")
        self.assertEqual(out["deadline_seconds"], 1500)
        self.assertEqual(caps, [480, 480])


CANNED = {
    "base_domain": "example.com", "profile": "approved-full-assessment-v1",
    "elapsed_seconds": 300, "scan_profile": "light",
    "score": {"score": 90, "grade": "ممتاز", "deductions": []},
    "priorities": [],
    "discovery": {"subdomains_found": [], "hosts_assessed": ["example.com"]},
    "email": {"status": "ready", "has_mx": True,
              "spf": {"present": True, "strength": "strict"},
              "dmarc": {"present": True, "policy": "reject"},
              "dkim": {"selectors_checked": 15, "found": ["google"]}},
    "hosts": [], "ports_by_ip": [],
}


class BotLightLineTests(unittest.TestCase):
    def test_light_profile_line_rendered(self):
        req = {"ip": "example.com", "auth_ref": "ref-123"}
        text = bot.format_full_report(req, dict(CANNED))
        self.assertIn("وضع التشغيل: خفيف", text)

    def test_legacy_result_has_no_light_line(self):
        req = {"ip": "example.com", "auth_ref": "ref-123"}
        legacy = dict(CANNED)
        legacy.pop("scan_profile")
        text = bot.format_full_report(req, legacy)
        self.assertNotIn("وضع التشغيل: خفيف", text)


if __name__ == "__main__":
    unittest.main()
