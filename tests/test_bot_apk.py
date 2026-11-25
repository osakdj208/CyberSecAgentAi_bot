import hashlib, io, json, os, sys, tempfile, time, unittest
from unittest import mock

os.environ["ENGINE_API_TOKEN"] = "test-engine-token"
os.environ["SCAN_APPROVAL_SECRET"] = "test-approval-secret-at-least-32-bytes"
os.environ["BOT_DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import bot
import main as engine


class ApkPermitCompatTests(unittest.TestCase):
    def test_bot_permit_passes_engine_check(self):
        sha = hashlib.sha256(b"fake-apk-bytes").hexdigest()
        permit = bot.create_apk_permit(sha, "r1",
                                       int((time.time() + 300) * 1000))
        self.assertTrue(engine.valid_apk_permit(permit, sha))
        self.assertFalse(engine.valid_apk_permit(
            permit, hashlib.sha256(b"other").hexdigest()))


class FakeResp:
    def __init__(self, data):
        self._data = data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=-1):
        return self._data if n < 0 else self._data[:n]


class DownloadTests(unittest.TestCase):
    def test_link_download(self):
        payload = b"PK" + b"x" * 4096
        with mock.patch.object(bot.urllib.request, "urlopen",
                               return_value=FakeResp(payload)):
            data = bot.download_apk_bytes(
                {"type": "link", "url": "https://x.co/a.apk"})
        self.assertEqual(data, payload)

    def test_tiny_file_rejected(self):
        with mock.patch.object(bot.urllib.request, "urlopen",
                               return_value=FakeResp(b"tiny")):
            with self.assertRaises(RuntimeError):
                bot.download_apk_bytes(
                    {"type": "link", "url": "https://x.co/a.apk"})


FULL_CANNED = {
    "base_domain": "example.com", "profile": "approved-full-assessment-v1",
    "elapsed_seconds": 100,
    "score": {"score": 90, "grade": "ممتاز", "deductions": []},
    "priorities": [],
    "discovery": {"subdomains_found": [], "hosts_assessed": ["example.com"]},
    "email": {"status": "ready", "has_mx": False,
              "spf": {"present": False}, "dmarc": {"present": False},
              "dkim": {"selectors_checked": 15, "found": []}},
    "hosts": [], "ports_by_ip": [],
}

APK_CANNED = {
    "status": "completed", "sha256": "ab" * 32,
    "app": {"app_name": "Example", "package": "com.example.app",
            "version_name": "2.0", "target_sdk": "34", "min_sdk": "24"},
    "permissions": {"total": 5,
                    "dangerous": ["android.permission.CAMERA"]},
    "components": {"activities": 3, "services": 1, "receivers": 0,
                   "providers": 0, "exported_open": [".MainActivity"],
                   "exported_guarded": 0},
    "flags": {"debuggable": False, "allow_backup": True,
              "cleartext_traffic": False, "network_config": False},
    "secrets": [{"type": "AWS access key", "where": "classes.dex",
                 "preview": "AKIAIO…"}],
    "urls": {"total": 4, "cleartext": [],
             "top_domains": [["api.example.com", 3]]},
    "sdks": ["Firebase"],
    "certificate": {"subject": "CN=Dev", "not_after": "2030-01-01",
                    "self_signed": True},
    "score": {"score": 50, "grade": "ضعيف",
              "deductions": [{"points": 10,
                              "label": "نمط سرّي مدمج محتمل: AWS access key"}]},
}


class UnifiedWithApkTests(unittest.TestCase):
    def req(self):
        return {"id": "r1", "ip": "example.com", "auth_ref": "ref-1",
                "store_link": None,
                "apk_ref": json.dumps({"type": "link",
                                       "url": "https://x.co/a.apk"})}

    def test_bundle_and_merged_report(self):
        with mock.patch.object(bot, "run_approved_full_scan",
                               return_value=FULL_CANNED), \
             mock.patch.object(bot, "download_apk_bytes",
                               return_value=b"PK-fake-apk"), \
             mock.patch.object(bot, "engine_apk_call",
                               return_value=APK_CANNED):
            bundle = bot.run_approved_unified_scan(self.req())
        self.assertEqual(bundle["apk_analysis"]["status"], "completed")
        text = bot.format_unified_report(self.req(), bundle)
        # merged = round(0.6*90 + 0.4*50) = 74
        for needle in ("🧮 الدرجة الموحّدة: 74/100",
                       "📱 تحليل التطبيق", "com.example.app",
                       "درجة التطبيق: 50/100", "AWS access key",
                       "Firebase", "شهادة التوقيع"):
            self.assertIn(needle, text)

    def test_analysis_failure_is_reported_honestly(self):
        with mock.patch.object(bot, "run_approved_full_scan",
                               return_value=FULL_CANNED), \
             mock.patch.object(bot, "download_apk_bytes",
                               side_effect=RuntimeError("boom")):
            bundle = bot.run_approved_unified_scan(self.req())
        self.assertEqual(bundle["apk_analysis"]["status"], "failed")
        text = bot.format_unified_report(self.req(), bundle)
        self.assertIn("تعذّر تحليله", text)
        self.assertNotIn("الدرجة الموحّدة", text)


if __name__ == "__main__":
    unittest.main()
