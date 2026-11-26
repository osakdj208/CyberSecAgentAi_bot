import os, sys, tempfile, unittest
from unittest import mock

os.environ["ENGINE_API_TOKEN"] = "test-engine-token"
os.environ["SCAN_APPROVAL_SECRET"] = "test-approval-secret-at-least-32-bytes"
os.environ["BOT_DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import bot

JSON_ROUTES = {
    "ipwho.is": {"success": True, "type": "IPv4", "city": "Mountain View",
                 "country": "United States",
                 "connection": {"asn": 15169, "org": "Google LLC",
                                "isp": "Google LLC"}},
    "network-info": {"data": {"prefix": "8.8.8.0/24", "asns": ["15169"]}},
    "as-overview": {"data": {"holder": "GOOGLE - Google LLC",
                             "announced": True}},
    "announced-prefixes": {"data": {"prefixes": [{"prefix": "8.8.8.0/24"},
                                                 {"prefix": "8.8.4.0/24"},
                                                 {"prefix": "1.1.1.0/24"}]}},
    "routing-status": {"data": {
        "visibility": {"v4": {"ris_peers_seeing": 300,
                              "total_ris_peers": 320}},
        "first_seen": {"time": "2009-01-01T00:00:00"}}},
    "ip-api.com": {"status": "success", "proxy": False, "hosting": True,
                   "mobile": False},
}
TEXT_ROUTES = {
    "torbulkexitlist": "1.2.3.4\n8.8.8.8\n",
    "reverseiplookup": "dns.google\nexample.com\n"
                       "0.0.8.8.in-addr.arpa\nnot a domain\n",
}


def fake_json(url, timeout=12):
    for key, doc in JSON_ROUTES.items():
        if key in url:
            return doc
    raise RuntimeError("no route")


def fake_text(url, timeout=12, cap=524288):
    for key, doc in TEXT_ROUTES.items():
        if key in url:
            return doc
    raise RuntimeError("no route")


def run_lookup(ip, dnsbl):
    with mock.patch.object(bot, "_bot_get_json", fake_json), \
         mock.patch.object(bot, "_bot_get_text", fake_text), \
         mock.patch.object(bot, "_ptr_lookup",
                           return_value="dns.google"), \
         mock.patch.object(bot, "_dnsbl_lookup", return_value=dnsbl), \
         mock.patch.object(bot, "_TOR_EXIT_CACHE",
                           {"at": 10**12, "ips": {"1.2.3.4"}}):
        return bot.ip_deep_lookup(ip)


class IpDeepCardTests(unittest.TestCase):
    def test_full_card(self):
        card = run_lookup("8.8.8.8", [("Spamhaus ZEN", "clean"),
                                      ("SpamCop", "clean"),
                                      ("Barracuda", "clean"),
                                      ("SORBS", "clean")])
        self.assertIn("بطاقة بحث عميق — 8.8.8.8", card)
        self.assertIn("dns.google", card)
        self.assertIn("AS15169", card)
        self.assertIn("GOOGLE - Google LLC", card)
        self.assertIn("8.8.8.0/24", card)
        self.assertIn("بادئات يعلنها هذا النظام عالمياً: 3", card)
        self.assertIn("300 من 320", card)
        self.assertIn("2009-01-01", card)
        self.assertIn("ليس عقدة خروج Tor", card)
        self.assertIn("استضافة/مركز بيانات", card)
        self.assertIn("نطاقات مستضافة", card)
        self.assertIn("example.com", card)
        self.assertNotIn("in-addr.arpa", card)
        self.assertIn("غير مُدرج", card)

    def test_tor_exit_and_listed(self):
        card = run_lookup("1.2.3.4", [("Spamhaus ZEN", "listed"),
                                      ("SpamCop", "clean"),
                                      ("Barracuda", "blocked"),
                                      ("SORBS", "unknown")])
        self.assertIn("عقدة خروج Tor حالياً", card)
        self.assertIn("مُدرج في Spamhaus ZEN", card)
        self.assertIn("الرفض ليس إدراجاً", card)

    def test_private_ip_rejected(self):
        card = bot.ip_deep_lookup("192.168.1.1")
        self.assertIn("❌", card)

    def test_garbage_rejected(self):
        card = bot.ip_deep_lookup("not-an-ip")
        self.assertIn("❌", card)

    def test_all_sources_down_still_answers(self):
        def boom(*a, **k):
            raise RuntimeError("down")
        with mock.patch.object(bot, "_bot_get_json", boom), \
             mock.patch.object(bot, "_bot_get_text", boom), \
             mock.patch.object(bot, "_ptr_lookup", return_value=None), \
             mock.patch.object(bot, "_dnsbl_lookup", return_value=[]):
            card = bot.ip_deep_lookup("8.8.8.8")
        self.assertIn("بطاقة بحث عميق — 8.8.8.8", card)
        self.assertIn("تعذّر جلب القائمة الرسمية", card)
        self.assertIn("تعذّر جلب مؤشرات التصنيف", card)

    def test_dnsbl_states(self):
        # Spamhaus-style refusal answers must read as blocked.
        self.assertIsNone(bot._dnsbl_lookup("2001:4860:4860::8888"))


if __name__ == "__main__":
    unittest.main()
