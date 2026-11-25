import os, sys, tempfile, unittest
from unittest import mock

os.environ["SCAN_APPROVAL_SECRET"] = "test-approval-secret-at-least-32-bytes"
os.environ["BOT_DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import bot


CHANNEL_PAGE = """
<html><head>
<meta property="og:title" content="Telegram News">
<meta property="og:description" content="Official channel &amp; updates">
</head><body>
<div class="tgme_page_extra">128 450 subscribers</div>
</body></html>
"""

GROUP_PAGE = """
<html><head>
<meta content="Dev Chat" property="og:title">
</head><body>
<div class="tgme_page_extra">3 210 members, 145 online</div>
</body></html>
"""

BOT_PAGE = """
<html><head>
<meta property="og:title" content="Sample Bot">
</head><body>
<div class="tgme_page_description">What can this bot do?</div>
<div class="tgme_page_description">I echo messages &amp; help.</div>
</body></html>
"""


class ParseQueryTests(unittest.TestCase):
    def test_at_username(self):
        self.assertEqual(bot.parse_tg_query("@Sahmology"),
                         ("username", "Sahmology"))

    def test_tme_link(self):
        self.assertEqual(bot.parse_tg_query("https://t.me/telegram"),
                         ("username", "telegram"))

    def test_bare_username(self):
        self.assertEqual(bot.parse_tg_query("some_channel"),
                         ("username", "some_channel"))

    def test_numeric_id(self):
        self.assertEqual(bot.parse_tg_query("964567764"), ("id", 964567764))

    def test_channel_id(self):
        self.assertEqual(bot.parse_tg_query("-1001234567890"),
                         ("id", -1001234567890))

    def test_garbage(self):
        self.assertIsNone(bot.parse_tg_query("a b!"))
        self.assertIsNone(bot.parse_tg_query("ab"))
        self.assertIsNone(bot.parse_tg_query(""))


class EstimateTests(unittest.TestCase):
    def test_old_account(self):
        self.assertEqual(bot.estimate_creation_period(5_000_000), "2013 – 2014")

    def test_admin_era(self):
        # Mohammed's own ID 964567764 falls in the 700M-1.1B band.
        self.assertEqual(bot.estimate_creation_period(964_567_764), "2020 – 2021")

    def test_recent(self):
        self.assertEqual(bot.estimate_creation_period(8_000_000_000), "2024 – 2026")

    def test_invalid(self):
        self.assertIsNone(bot.estimate_creation_period(0))
        self.assertIsNone(bot.estimate_creation_period(-100123))
        self.assertIsNone(bot.estimate_creation_period("123"))


class ParsePageTests(unittest.TestCase):
    def test_channel_page(self):
        info = bot.parse_tme_page(CHANNEL_PAGE)
        self.assertEqual(info["name"], "Telegram News")
        self.assertEqual(info["description"], "Official channel & updates")
        self.assertEqual(info["kind_hint"], "channel")
        self.assertIn("subscribers", info["extra"])

    def test_group_page_reversed_meta_order(self):
        info = bot.parse_tme_page(GROUP_PAGE)
        self.assertEqual(info["name"], "Dev Chat")
        self.assertEqual(info["kind_hint"], "group")

    def test_bot_page(self):
        info = bot.parse_tme_page(BOT_PAGE)
        self.assertEqual(info["kind_hint"], "bot")

    def test_empty_and_generic(self):
        self.assertEqual(bot.parse_tme_page(""), {})
        self.assertEqual(bot.parse_tme_page(
            '<meta property="og:title" content="Telegram">'), {})


class LookupTests(unittest.TestCase):
    def test_channel_card_from_api(self):
        def fake_tg(method, **params):
            if method == "getChat":
                return {"ok": True, "result": {
                    "id": -100111222333, "type": "channel",
                    "title": "أخبار التقنية", "username": "technews",
                    "description": "قناة أخبار"}}
            if method == "getChatMemberCount":
                return {"ok": True, "result": 54321}
            raise AssertionError(method)
        with mock.patch.object(bot, "tg", fake_tg), \
                mock.patch.object(bot, "fetch_tme_page", return_value=""):
            card = bot.tg_card_lookup(("username", "technews"))
        self.assertIn("أخبار التقنية", card)
        self.assertIn("@technews", card)
        self.assertIn("قناة", card)
        self.assertIn("54,321", card)
        self.assertIn("قناة أخبار", card)

    def test_user_card_from_page_only(self):
        def fake_tg(method, **params):
            raise RuntimeError("chat not found")
        page = ('<meta property="og:title" content="Mohammed S">'
                '<meta property="og:description" content="public bio">')
        with mock.patch.object(bot, "tg", fake_tg), \
                mock.patch.object(bot, "fetch_tme_page", return_value=page):
            card = bot.tg_card_lookup(("username", "someuser"))
        self.assertIn("Mohammed S", card)
        self.assertIn("مستخدم", card)
        self.assertIn("public bio", card)

    def test_id_card_has_estimate(self):
        def fake_tg(method, **params):
            raise RuntimeError("chat not found")
        with mock.patch.object(bot, "tg", fake_tg):
            card = bot.tg_card_lookup(("id", 964567764))
        self.assertIn("964567764", card)
        self.assertIn("2020 – 2021", card)
        self.assertIn("تقدير", card)

    def test_not_found(self):
        def fake_tg(method, **params):
            raise RuntimeError("chat not found")
        with mock.patch.object(bot, "tg", fake_tg), \
                mock.patch.object(bot, "fetch_tme_page", return_value=""):
            card = bot.tg_card_lookup(("username", "no_such_name_zz"))
        self.assertIn("لم أجد بيانات عامة", card)


if __name__ == "__main__":
    unittest.main()
