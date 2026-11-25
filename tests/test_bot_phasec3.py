import os, sys, tempfile, unittest

os.environ["ENGINE_API_TOKEN"] = "test-engine-token"
os.environ["SCAN_APPROVAL_SECRET"] = "test-approval-secret-at-least-32-bytes"
os.environ["BOT_DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import bot
import main as engine

REQ = {"ip": "example.com", "auth_ref": "مرجع-٣"}


class ScaPermitCompatTests(unittest.TestCase):
    def test_bot_permit_passes_engine_check(self):
        import hashlib, time
        data = b"requests==2.19.1\n"
        digest = hashlib.sha256(data).hexdigest()
        permit = bot.create_sca_permit(
            digest, "r1", int((time.time() + 300) * 1000))
        self.assertTrue(engine.valid_sca_permit(permit, digest))
        self.assertFalse(engine.valid_sca_permit(
            permit, hashlib.sha256(b"other").hexdigest()))


class ScaReportTests(unittest.TestCase):
    def test_vulnerable_report(self):
        result = {"status": "ready", "filename": "requirements.txt",
                  "ecosystem": "PyPI", "packages_checked": 12,
                  "total_vulns": 2,
                  "counts": {"حرجة": 1, "عالية": 1, "متوسطة": 0,
                             "منخفضة": 0, "غير مصنّفة": 0},
                  "score": {"score": 77, "grade": "جيد"},
                  "details_capped": False,
                  "vulnerable": [
                      {"name": "requests", "version": "2.19.1",
                       "vulns": [{"id": "GHSA-xxxx", "severity": "حرجة",
                                  "cvss": 9.8, "summary": "Bad thing",
                                  "fixed": ["2.20.0"], "aliases": []},
                                 {"id": "GHSA-yyyy", "severity": "عالية",
                                  "cvss": 7.5, "summary": "",
                                  "fixed": [], "aliases": []}]}]}
        text = bot.format_sca_report(result)
        self.assertIn("فحص تبعيات المشروع", text)
        self.assertIn("77/100", text)
        self.assertIn("requests @ 2.19.1", text)
        self.assertIn("GHSA-xxxx", text)
        self.assertIn("CVSS 9.8", text)
        self.assertIn("2.20.0", text)

    def test_clean_report(self):
        result = {"status": "ready", "filename": "go.mod",
                  "ecosystem": "Go", "packages_checked": 5,
                  "total_vulns": 0,
                  "counts": {"حرجة": 0, "عالية": 0, "متوسطة": 0,
                             "منخفضة": 0, "غير مصنّفة": 0},
                  "score": {"score": 100, "grade": "ممتاز"},
                  "details_capped": False, "vulnerable": []}
        text = bot.format_sca_report(result)
        self.assertIn("لا ثغرات معروفة", text)

    def test_unavailable_report(self):
        text = bot.format_sca_report({"status": "unavailable"})
        self.assertIn("لم تُجب", text)


def full_result(cloud):
    return {"base_domain": "example.com",
            "profile": "approved-full-assessment-v1", "elapsed_seconds": 5,
            "score": {"score": 90, "grade": "ممتاز", "deductions": []},
            "priorities": [],
            "discovery": {"subdomains_found": [],
                          "hosts_assessed": ["example.com"]},
            "email": {"status": "ready", "has_mx": False},
            "cloud": cloud,
            "hosts": [], "ports_by_ip": []}


class CloudReportTests(unittest.TestCase):
    def test_exposed_renders(self):
        text = bot.format_full_report(REQ, full_result(
            {"status": "ready", "candidates_checked": 25,
             "private_existing": 1,
             "exposed": [{"name": "myco-assets", "provider": "Amazon S3",
                          "url": "https://myco-assets.s3.amazonaws.com/"}]}))
        self.assertIn("التخزين السحابي", text)
        self.assertIn("مفتوح للعامة: myco-assets", text)
        self.assertIn("موجودة لكنها خاصة", text)

    def test_clean_renders(self):
        text = bot.format_full_report(REQ, full_result(
            {"status": "ready", "candidates_checked": 25,
             "private_existing": 0, "exposed": []}))
        self.assertIn("لا مخازن مكشوفة", text)


if __name__ == "__main__":
    unittest.main()
