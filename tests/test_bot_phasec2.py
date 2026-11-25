import os, sys, tempfile, unittest

os.environ["ENGINE_API_TOKEN"] = "test-engine-token"
os.environ["SCAN_APPROVAL_SECRET"] = "test-approval-secret-at-least-32-bytes"
os.environ["BOT_DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import bot

REQ = {"ip": "example.com", "auth_ref": "مرجع-٢"}


def result_with(host_extra):
    host = {"host": "example.com", "ips": ["1.1.1.1"],
            "http": {"status": "ready", "http_status": 200,
                     "scheme": "https", "score": "6/6"},
            "tech": {"hints": []},
            "tls": {"status": "ready", "tls_version": "TLSv1.3",
                    "days_left": 80, "legacy_protocols": {}},
            "nuclei": {"status": "ready", "counts": {}, "findings": []}}
    host.update(host_extra)
    return {"base_domain": "example.com",
            "profile": "approved-full-assessment-v1", "elapsed_seconds": 10,
            "score": {"score": 90, "grade": "ممتاز", "deductions": []},
            "priorities": [],
            "discovery": {"subdomains_found": [],
                          "hosts_assessed": ["example.com"]},
            "email": {"status": "ready", "has_mx": False},
            "hosts": [host], "ports_by_ip": []}


class PhaseC2ReportTests(unittest.TestCase):
    def test_api_and_js_lines_render(self):
        result = result_with({
            "api": {"status": "ready",
                    "openapi": [{"path": "/openapi.json",
                                 "title": "Shop API", "version": "2.1",
                                 "endpoints": 42}],
                    "doc_pages": ["/swagger-ui.html"],
                    "graphql": [{"path": "/graphql",
                                 "introspection": True}]},
            "js": {"status": "ready", "files_checked": 3,
                   "secrets": [{"type": "AWS access key",
                                "preview": "AKIAIO…", "where": "app.js"}],
                   "api_endpoints": ["/api/users"],
                   "internal_addresses": ["192.168.1.10"],
                   "external_domains": []}})
        text = bot.format_full_report(REQ, result)
        self.assertIn("وثائق API مكشوفة: /openapi.json", text)
        self.assertIn("42 نقطة نهاية", text)
        self.assertIn("صفحة وثائق API منشورة: /swagger-ui.html", text)
        self.assertIn("الاستبطان مفعّل", text)
        self.assertIn("فُحصت 3 ملفات", text)
        self.assertIn("AWS access key", text)
        self.assertIn("192.168.1.10", text)
        self.assertIn("نقاط API مستخرجة: 1", text)

    def test_introspection_closed_line(self):
        result = result_with({
            "api": {"status": "ready", "openapi": [], "doc_pages": [],
                    "graphql": [{"path": "/graphql",
                                 "introspection": False}]},
            "js": {"status": "ready", "files_checked": 0, "secrets": [],
                   "api_endpoints": [], "internal_addresses": [],
                   "external_domains": []}})
        text = bot.format_full_report(REQ, result)
        self.assertIn("الاستبطان مغلق", text)
        self.assertNotIn("فُحصت", text)

    def test_missing_sections_render_fine(self):
        text = bot.format_full_report(REQ, result_with({}))
        self.assertIn("اكتمل التقييم الشامل", text)


if __name__ == "__main__":
    unittest.main()
