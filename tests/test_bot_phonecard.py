import os, sys, tempfile, types, unittest
from unittest import mock

os.environ["SCAN_APPROVAL_SECRET"] = "test-approval-secret-at-least-32-bytes"
os.environ["BOT_DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import bot


def stub_tgdeep(configured=True, phone_result=None):
    mod = types.ModuleType("tgdeep")
    mod.configured = lambda: configured
    mod.deep_lookup = lambda query: None
    mod.phone_lookup = lambda phone: phone_result
    return mod


class ParsePhoneTests(unittest.TestCase):
    def test_yemen_mobile(self):
        info = bot.parse_phone_number("+967737467773")
        self.assertTrue(info["valid"])
        self.assertEqual(info["e164"], "+967737467773")
        self.assertEqual(info["country"], "اليمن")
        self.assertEqual(info["type"], "جوال")

    def test_uk_fixed_line(self):
        info = bot.parse_phone_number("+442071838750")
        self.assertTrue(info["valid"])
        self.assertEqual(info["type"], "ثابت")

    def test_00_prefix(self):
        info = bot.parse_phone_number("00967737467773")
        self.assertTrue(info["valid"])
        self.assertEqual(info["e164"], "+967737467773")

    def test_no_country_code_rejected(self):
        self.assertIsNone(bot.parse_phone_number("737467773"))

    def test_garbage_rejected(self):
        self.assertIsNone(bot.parse_phone_number("hello"))


class PhoneCardTests(unittest.TestCase):
    def test_card_r1_lines(self):
        with mock.patch.dict(sys.modules, {"tgdeep": stub_tgdeep(
                phone_result={"found": False})}):
            card = bot.phone_card_lookup("+967737467773")
        self.assertIn("بطاقة رقم هاتف", card)
        self.assertIn("اليمن", card)
        self.assertIn("نوع الخط: جوال", card)
        self.assertIn("صالح وفق خطة الترقيم", card)

    def test_card_telegram_found(self):
        result = {"found": True, "id": 6805192587, "username": "mskjsll",
                  "name": "djvdj Ail", "is_bot": False,
                  "verified": False, "scam": False, "fake": False}
        with mock.patch.dict(sys.modules, {"tgdeep": stub_tgdeep(
                phone_result=result)}):
            card = bot.phone_card_lookup("+967737467773")
        self.assertIn("تيليجرام: يوجد حساب عام — @mskjsll", card)
        self.assertIn("المعرف الرقمي: 6805192587", card)

    def test_card_telegram_not_discoverable(self):
        with mock.patch.dict(sys.modules, {"tgdeep": stub_tgdeep(
                phone_result={"found": False})}):
            card = bot.phone_card_lookup("+967737467773")
        self.assertIn("لا حساب قابل للاكتشاف بهذا الرقم", card)

    def test_card_telegram_scam_flag(self):
        result = {"found": True, "id": 123, "username": "badactor",
                  "name": None, "is_bot": False,
                  "verified": False, "scam": True, "fake": False}
        with mock.patch.dict(sys.modules, {"tgdeep": stub_tgdeep(
                phone_result=result)}):
            card = bot.phone_card_lookup("+967737467773")
        self.assertIn("موسوم «احتيالي»", card)

    def test_card_honest_platform_lines(self):
        with mock.patch.dict(sys.modules, {"tgdeep": stub_tgdeep(
                phone_result={"found": False})}):
            card = bot.phone_card_lookup("+967737467773")
        self.assertIn("واتساب: لا يوفر تحققاً عاماً موثوقاً", card)
        self.assertIn("سيغنال: لا يوفر أي تحقق عام", card)

    def test_card_deep_off_admin_hint(self):
        with mock.patch.dict(sys.modules, {"tgdeep": stub_tgdeep(
                configured=False)}):
            card = bot.phone_card_lookup("+967737467773", is_admin=True)
        self.assertIn("يتطلب البحث العميق المفعّل", card)

    def test_card_invalid_number(self):
        card = bot.phone_card_lookup("12345")
        self.assertTrue(card.startswith("❌"))

    def test_card_flood_note(self):
        with mock.patch.dict(sys.modules, {"tgdeep": stub_tgdeep(
                phone_result={"error": "flood"})}):
            card = bot.phone_card_lookup("+967737467773")
        self.assertIn("مقيّد مؤقتاً", card)


if __name__ == "__main__":
    unittest.main()
