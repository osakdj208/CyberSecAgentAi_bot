import os, sys, tempfile, types, unittest
from unittest import mock

os.environ["SCAN_APPROVAL_SECRET"] = "test-approval-secret-at-least-32-bytes"
os.environ["BOT_DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import bot
import tgdeep


def stub_deep(configured=True, result=None):
    mod = types.ModuleType("tgdeep")
    mod.configured = lambda: configured
    mod.deep_lookup = lambda query: result
    return mod


class TgDeepConfigTests(unittest.TestCase):
    def test_not_configured_without_env(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            for k in ("TG_API_ID", "TG_API_HASH", "TG_SESSION"):
                os.environ.pop(k, None)
            self.assertFalse(tgdeep.configured())
            self.assertIsNone(tgdeep.deep_lookup(("username", "telegram")))

    def test_configured_with_env(self):
        with mock.patch.dict(os.environ, {
                "TG_API_ID": "12345", "TG_API_HASH": "h", "TG_SESSION": "s"}):
            self.assertTrue(tgdeep.configured())


class DeepCardTests(unittest.TestCase):
    def setUp(self):
        self._saved = sys.modules.get("tgdeep")

    def tearDown(self):
        if self._saved is not None:
            sys.modules["tgdeep"] = self._saved

    def _card(self, stub, query=("username", "someuser"), is_admin=False,
              page=""):
        def fake_tg(method, **params):
            raise RuntimeError("chat not found")
        sys.modules["tgdeep"] = stub
        with mock.patch.object(bot, "tg", fake_tg), \
                mock.patch.object(bot, "fetch_tme_page", return_value=page):
            return bot.tg_card_lookup(query, is_admin=is_admin)

    def test_deep_user_card_shows_id_flags_photos(self):
        stub = stub_deep(result={
            "id": 964567764, "kind": "user", "name": "Mohammed",
            "username": "someuser", "verified": False, "scam": True,
            "fake": False, "photos": 3, "about": "deep bio"})
        card = self._card(stub)
        self.assertIn("964567764", card)
        self.assertIn("2020 – 2021", card)          # estimate from the ID
        self.assertIn("احتيالي", card)               # official scam flag
        self.assertIn("صور الملف الشخصي العامة: 3", card)
        self.assertIn("deep bio", card)
        self.assertIn("🔬 من البحث العميق:", card)

    def test_deep_channel_card_marked_id_and_linked(self):
        stub = stub_deep(result={
            "id": 111222333, "marked_id": -100111222333, "kind": "channel",
            "name": "Chan", "username": "chan", "verified": True,
            "scam": False, "fake": False, "participants": 777,
            "linked_username": "chandiscussion", "about": None})
        card = self._card(stub, query=("username", "chan"))
        self.assertIn("-100111222333", card)
        self.assertIn("777", card)
        self.assertIn("موثّق رسمياً", card)
        self.assertIn("@chandiscussion", card)
        self.assertNotIn("تاريخ الإنشاء التقديري", card)  # no estimate for -100

    def test_extra_line_suppressed_for_user_pages(self):
        page = ('<meta property="og:title" content="Some User">'
                '<div class="tgme_page_extra">'
                'If you have Telegram, you can contact @someuser right away.'
                '</div>')
        card = self._card(stub_deep(configured=False), page=page)
        self.assertNotIn("إحصائية عامة", card)
        self.assertIn("Some User", card)

    def test_admin_hint_when_deep_off(self):
        card = self._card(stub_deep(configured=False), is_admin=True)
        self.assertIn("غير مفعّل بعد", card)
        card_user = self._card(stub_deep(configured=False), is_admin=False)
        self.assertNotIn("غير مفعّل بعد", card_user)

    def test_flood_note(self):
        stub = stub_deep(result={"error": "flood"})
        card = self._card(stub)
        self.assertIn("مقيّد مؤقتاً", card)

    def test_deep_failure_degrades_to_public(self):
        stub = stub_deep(result={"error": "BoomError"})
        page = '<meta property="og:title" content="Public Name">'
        card = self._card(stub, page=page)
        self.assertIn("Public Name", card)


if __name__ == "__main__":
    unittest.main()
