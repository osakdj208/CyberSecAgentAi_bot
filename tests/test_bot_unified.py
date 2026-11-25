import json, os, sys, tempfile, unittest
from unittest import mock

os.environ["ENGINE_API_TOKEN"] = "test-engine-token"
os.environ["SCAN_APPROVAL_SECRET"] = "test-approval-secret-at-least-32-bytes"
os.environ["BOT_DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import bot

PLAY = "https://play.google.com/store/apps/details?id=com.example.app&hl=en"
APPLE = "https://apps.apple.com/us/app/example/id123456789"


class StoreLinkTests(unittest.TestCase):
    def test_play(self):
        info = bot.parse_store_link(PLAY)
        self.assertEqual(info["store"], "google_play")
        self.assertEqual(info["package"], "com.example.app")

    def test_apple(self):
        info = bot.parse_store_link(APPLE)
        self.assertEqual(info["store"], "app_store")
        self.assertEqual(info["app_id"], "123456789")

    def test_junk(self):
        self.assertIsNone(bot.parse_store_link("https://example.com/app"))
        self.assertIsNone(bot.parse_store_link(
            "https://play.google.com/store/apps/details"))
        self.assertIsNone(bot.parse_store_link(""))


class StorePageTests(unittest.TestCase):
    def test_apple_title_suffixes(self):
        page = ('<meta property="og:title" content="Telegram Messenger '
                'App - App Store">')
        card = bot.parse_store_page(
            page, {"store": "app_store", "app_id": "686449807",
                   "url": APPLE})
        self.assertEqual(card["title"], "Telegram Messenger")

    def test_og_parse_and_suffix_strip(self):
        page = ('<meta property="og:title" content="My App - Apps on '
                'Google Play"><meta property="og:description" '
                'content="Does useful things.">')
        card = bot.parse_store_page(
            page, {"store": "google_play", "package": "com.example.app",
                   "url": PLAY})
        self.assertEqual(card["title"], "My App")
        self.assertEqual(card["description"], "Does useful things.")
        self.assertEqual(card["package"], "com.example.app")


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


class UnifiedRunAndReportTests(unittest.TestCase):
    def test_bundle_and_report(self):
        req = {"ip": "example.com", "auth_ref": "ref-9",
               "store_link": PLAY,
               "apk_ref": json.dumps({"type": "file", "file_id": "F1",
                                       "name": "app.apk",
                                       "size": 5_000_000})}
        card = {"status": "ready", "store": "google_play",
                "package": "com.example.app", "app_id": None,
                "title": "My App", "description": "Does useful things."}
        with mock.patch.object(bot, "run_approved_full_scan",
                               return_value=FULL_CANNED), \
             mock.patch.object(bot, "fetch_store_card", return_value=card), \
             mock.patch.object(bot, "download_apk_bytes",
                               side_effect=RuntimeError("no file in test")):
            bundle = bot.run_approved_unified_scan(req)
        self.assertEqual(bundle["store"]["title"], "My App")
        self.assertEqual(bundle["apk"]["name"], "app.apk")
        # Phase B: an attached file is now really analyzed; a download
        # failure is reported honestly instead of a "received" note.
        self.assertEqual(bundle["apk_analysis"]["status"], "failed")
        text = bot.format_unified_report(req, bundle)
        for needle in ("🧩 التقرير الموحّد", "📱 بطاقة التطبيق من المتجر",
                       "My App", "com.example.app",
                       "📦 ملف التطبيق: تعذّر تحليله",
                       "🏆 درجة الأمان الإجمالية: 90/100"):
            self.assertIn(needle, text)

    def test_link_apk_line(self):
        req = {"ip": "example.com", "auth_ref": "r", "store_link": None,
               "apk_ref": json.dumps({"type": "link",
                                       "url": "https://x.co/a.apk"})}
        bundle = {"full": FULL_CANNED, "store": None,
                  "apk": {"type": "link", "url": "https://x.co/a.apk"}}
        text = bot.format_unified_report(req, bundle)
        self.assertIn("رابط ملف التطبيق مستلم", text)


class UnifiedFlowTests(unittest.TestCase):
    def setUp(self):
        bot.STATE.clear()
        patcher = mock.patch.object(bot, "send", lambda *a, **k: None)
        patcher.start()
        self.addCleanup(patcher.stop)
        admin = mock.patch.object(bot, "notify_admin", lambda req: None)
        admin.start()
        self.addCleanup(admin.stop)

    def msg(self, text=None, document=None):
        m = {"chat": {"id": 9}, "from": {"id": 43, "username": "u2"}}
        if text is not None:
            m["text"] = text
        if document is not None:
            m["document"] = document
        return m

    def test_full_flow_with_store_and_apk_file(self):
        bot.STATE[9] = {"step": "u_await_host"}
        bot.handle_message(self.msg("example.com"))
        self.assertEqual(bot.STATE[9]["step"], "u_await_store")
        bot.handle_message(self.msg(PLAY))
        self.assertEqual(bot.STATE[9]["step"], "u_await_apk")
        bot.handle_message(self.msg(document={
            "file_id": "F1", "file_name": "app.apk",
            "file_size": 5_000_000}))
        self.assertEqual(bot.STATE[9]["step"], "u_await_ref")
        bot.handle_message(self.msg("owner-proof-1"))
        self.assertEqual(bot.STATE[9]["step"], "u_await_proof")
        bot.handle_message(self.msg("تخطي"))
        rows = [r for r in bot.list_requests(43)
                if r["kind"] == "unified"
                and r["auth_ref"] == "owner-proof-1"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["store_link"], PLAY)
        apk = json.loads(rows[0]["apk_ref"])
        self.assertEqual(apk["type"], "file")
        self.assertEqual(apk["name"], "app.apk")

    def test_flow_with_apk_link_and_store_skip(self):
        bot.STATE[9] = {"step": "u_await_host"}
        bot.handle_message(self.msg("example.com"))
        bot.handle_message(self.msg("تخطي"))
        bot.handle_message(self.msg("https://files.example.com/app.apk"))
        bot.handle_message(self.msg("owner-proof-2"))
        bot.handle_message(self.msg("تخطي"))
        rows = [r for r in bot.list_requests(43)
                if r["kind"] == "unified"
                and r["auth_ref"] == "owner-proof-2"]
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["store_link"])
        self.assertEqual(json.loads(rows[0]["apk_ref"])["type"], "link")

    def test_bad_store_link_rejected(self):
        bot.STATE[9] = {"step": "u_await_store", "ip": "example.com"}
        bot.handle_message(self.msg("https://random-site.com/app"))
        self.assertEqual(bot.STATE[9]["step"], "u_await_store")


if __name__ == "__main__":
    unittest.main()
