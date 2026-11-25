import os, sys, tempfile, unittest

os.environ["ENGINE_API_TOKEN"] = "test-engine-token"
os.environ["SCAN_APPROVAL_SECRET"] = "test-approval-secret-at-least-32-bytes"
os.environ["BOT_DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import bot

REQ = {"ip": "example.com", "auth_ref": "مرجع-١"}

BASE_RESULT = {
    "base_domain": "example.com", "profile": "approved-full-assessment-v1",
    "elapsed_seconds": 400,
    "score": {"score": 70, "grade": "متوسط", "deductions": []},
    "priorities": [],
    "discovery": {"subdomains_found": ["dead.example.com"],
                  "hosts_assessed": ["example.com"]},
    "email": {"status": "ready", "has_mx": False},
    "hosts": [], "ports_by_ip": [],
}


class PhaseC1ReportTests(unittest.TestCase):
    def test_vulnerable_sections_render(self):
        result = dict(BASE_RESULT)
        result["dns_audit"] = {
            "status": "ready", "nameservers": ["ns1.example.com"],
            "axfr": {"vulnerable": True,
                     "attempts": [{"nameserver": "ns1.example.com",
                                   "allowed": True, "records": 321}]},
            "dnssec": {"signed": False, "ds_present": False,
                       "dnskey_present": False},
            "caa": {"present": False, "records": []}}
        result["takeover"] = {
            "status": "ready", "checked": 3,
            "findings": [{"host": "dead.example.com",
                          "service": "GitHub Pages",
                          "cname_target": "x.github.io",
                          "verdict": "confirmed",
                          "evidence": "There isn't a GitHub Pages site here"}]}
        text = bot.format_full_report(REQ, result)
        self.assertIn("تدقيق DNS العميق", text)
        self.assertIn("AXFR مفتوح", text)
        self.assertIn("321", text)
        self.assertIn("فحص الاستيلاء", text)
        self.assertIn("مؤكد: dead.example.com", text)
        self.assertIn("GitHub Pages", text)

    def test_clean_sections_render(self):
        result = dict(BASE_RESULT)
        result["dns_audit"] = {
            "status": "ready", "nameservers": ["ns1.example.com"],
            "axfr": {"vulnerable": False,
                     "attempts": [{"nameserver": "ns1.example.com",
                                   "allowed": False, "records": 0}]},
            "dnssec": {"signed": True, "ds_present": True,
                       "dnskey_present": True},
            "caa": {"present": True,
                    "records": ['0 issue "letsencrypt.org"']}}
        result["takeover"] = {"status": "ready", "checked": 2,
                              "findings": []}
        text = bot.format_full_report(REQ, result)
        self.assertIn("مرفوض من كل خوادم الأسماء", text)
        self.assertIn("DNSSEC: موقّع", text)
        self.assertIn("letsencrypt.org", text)
        self.assertIn("لا نطاقات معلّقة", text)

    def test_old_results_without_new_keys_still_render(self):
        text = bot.format_full_report(REQ, dict(BASE_RESULT))
        self.assertIn("اكتمل التقييم الشامل", text)
        self.assertNotIn("🛡️ تدقيق DNS العميق:", text)
        self.assertNotIn("فحص الاستيلاء", text)


if __name__ == "__main__":
    unittest.main()
