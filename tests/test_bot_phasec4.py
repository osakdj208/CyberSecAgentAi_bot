import os, sys, tempfile, unittest

os.environ["ENGINE_API_TOKEN"] = "test-engine-token"
os.environ["SCAN_APPROVAL_SECRET"] = "test-approval-secret-at-least-32-bytes"
os.environ["BOT_DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import bot

REQ = {"ip": "example.com", "auth_ref": "مرجع-٤"}


def result_with(host_extra=None, vc=None):
    host = {"host": "example.com", "ips": ["1.1.1.1"],
            "http": {"status": "ready", "http_status": 200,
                     "scheme": "https", "score": "6/6"},
            "tech": {"hints": []},
            "tls": {"status": "ready", "tls_version": "TLSv1.3",
                    "days_left": 80, "legacy_protocols": {}},
            "nuclei": {"status": "ready", "counts": {}, "findings": []}}
    host.update(host_extra or {})
    result = {"base_domain": "example.com",
              "profile": "approved-full-assessment-v1",
              "elapsed_seconds": 10,
              "score": {"score": 84, "grade": "جيد", "deductions": []},
              "priorities": [],
              "discovery": {"subdomains_found": [],
                            "hosts_assessed": ["example.com"]},
              "email": {"status": "ready", "has_mx": False},
              "hosts": [host], "ports_by_ip": []}
    if vc is not None:
        result["version_cves"] = vc
    return result


class PhaseC4ReportTests(unittest.TestCase):
    def test_hidden_lines_render(self):
        result = result_with({"hidden": {
            "status": "ready", "catch_all": False,
            "findings": [{"path": "/.git/HEAD", "kind": "git_head"},
                         {"path": "/.env", "kind": "env"}]}})
        text = bot.format_full_report(REQ, result)
        self.assertIn("محتوى حسّاس مكشوف", text)
        self.assertIn("/.git/HEAD", text)
        self.assertIn("مستودع Git مكشوف", text)
        self.assertIn("ملف بيئة (.env)", text)

    def test_version_section_renders(self):
        vc = {"status": "ready", "checked": 2,
              "products": [{"product": "Apache httpd", "version": "2.4.7",
                            "source": "ترويسة example.com", "total": 121,
                            "top": [{"id": "CVE-2016-5385", "cvss": 8.1,
                                     "severity": "HIGH"},
                                    {"id": "CVE-2014-0118", "cvss": 5.0,
                                     "severity": "MEDIUM"}]}],
              "clean": ["nginx 1.24.0"], "unmatched": []}
        text = bot.format_full_report(REQ, result_with(vc=vc))
        self.assertIn("مطابقة الإصدارات مع CVE", text)
        self.assertIn("121 ثغرة مؤكدة التطابق", text)
        self.assertIn("CVE-2016-5385", text)
        self.assertIn("nginx 1.24.0", text)
        self.assertIn("backport", text)

    def test_absent_sections_render_fine(self):
        text = bot.format_full_report(REQ, result_with())
        self.assertIn("اكتمل التقييم الشامل", text)
        self.assertNotIn("مطابقة الإصدارات", text)


if __name__ == "__main__":
    unittest.main()
