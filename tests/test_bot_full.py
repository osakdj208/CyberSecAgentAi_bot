import base64, json, os, sys, tempfile, unittest
from unittest import mock

os.environ["ENGINE_API_TOKEN"] = "test-engine-token"
os.environ["SCAN_APPROVAL_SECRET"] = "test-approval-secret-at-least-32-bytes"
os.environ["BOT_DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import bot
import main as engine


class FullPermitCompatTests(unittest.TestCase):
    def test_bot_permit_passes_engine_check(self):
        permit = bot.create_full_permit("example.com", ["1.1.1.1"], "r1",
                                        int((__import__("time").time() + 300) * 1000))
        self.assertTrue(engine.valid_full_permit(permit, "example.com",
                                                 ["1.1.1.1"]))
        self.assertFalse(engine.valid_full_permit(permit, "example.com",
                                                  ["8.8.8.8"]))

    def test_payload_shape(self):
        permit = bot.create_full_permit("example.com", ["1.1.1.1"], "r9",
                                        9999999999999)
        payload = permit.split(".")[0]
        data = json.loads(base64.urlsafe_b64decode(
            payload + "=" * (-len(payload) % 4)))
        self.assertEqual(data["kind"], "full")
        self.assertEqual(data["host"], "example.com")
        self.assertEqual(data["id"], "r9")


CANNED = {
    "base_domain": "example.com", "profile": "approved-full-assessment-v1",
    "elapsed_seconds": 321,
    "score": {"score": 74, "grade": "جيد",
              "deductions": [{"points": 8, "label": "لا سجل DMARC — لا حماية"}]},
    "priorities": ["لا سجل DMARC — لا حماية"],
    "discovery": {"subdomains_found": ["mail.example.com", "dev.example.com"],
                  "hosts_assessed": ["example.com", "mail.example.com"]},
    "email": {"status": "ready", "has_mx": True,
              "spf": {"present": True, "strength": "strict"},
              "dmarc": {"present": False},
              "dkim": {"selectors_checked": 15, "found": ["google"]}},
    "hosts": [{"host": "example.com", "ips": ["1.1.1.1"],
               "http": {"status": "ready", "http_status": 200,
                        "scheme": "https", "score": "5/6"},
               "tech": {"hints": ["خادم ويب: nginx"]},
               "tls": {"status": "ready", "tls_version": "TLSv1.3",
                       "days_left": 40, "legacy_protocols": {}},
               "nuclei": {"status": "ready", "counts": {"low": 1},
                          "findings": [{"severity": "low", "name": "X",
                                        "matched_at": "https://example.com/a"}]}}],
    "ports_by_ip": [{"ip": "1.1.1.1", "ports": [
        {"port": "443", "protocol": "tcp", "state": "open",
         "service": "https", "product": "nginx", "version": "1.24"}]}],
}


class FullReportTests(unittest.TestCase):
    def test_report_sections(self):
        req = {"ip": "example.com", "auth_ref": "ref-123"}
        text = bot.format_full_report(req, CANNED)
        for needle in ("🏢 اكتمل التقييم الشامل", "74/100", "أولويات الإصلاح",
                       "mail.example.com", "📧 أمان البريد", "SPF: موجود",
                       "DMARC: ❌ غائب", "DKIM: مفاتيح معلنة",
                       "🖥️ المضيفون", "نتائج Nuclei", "🔌 المنافذ",
                       "443/tcp"):
            self.assertIn(needle, text)


class FullFlowTests(unittest.TestCase):
    def setUp(self):
        bot.STATE.clear()
        self.sent = []
        patcher = mock.patch.object(
            bot, "send", lambda cid, text, kb=None: self.sent.append(text))
        patcher.start()
        self.addCleanup(patcher.stop)
        admin = mock.patch.object(bot, "notify_admin", lambda req: None)
        admin.start()
        self.addCleanup(admin.stop)

    def msg(self, text):
        return {"chat": {"id": 7}, "from": {"id": 42, "username": "u"},
                "text": text}

    def test_flow_creates_full_request(self):
        bot.STATE[7] = {"step": "f_await_host"}
        bot.handle_message(self.msg("example.com"))
        self.assertEqual(bot.STATE[7]["step"], "f_await_ref")
        bot.handle_message(self.msg("domain-verification-42"))
        self.assertEqual(bot.STATE[7]["step"], "f_await_proof")
        bot.handle_message(self.msg("تخطي"))
        rows = bot.list_requests(42)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "full")
        self.assertEqual(rows[0]["ip"], "example.com")
        self.assertEqual(rows[0]["status"], "pending")

    def test_flow_rejects_bad_domain(self):
        bot.STATE[7] = {"step": "f_await_host"}
        bot.handle_message(self.msg("8.8.8.8"))
        self.assertEqual(bot.STATE[7]["step"], "f_await_host")


if __name__ == "__main__":
    unittest.main()
