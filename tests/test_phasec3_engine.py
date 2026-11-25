import json, os, sys, unittest
from unittest import mock

os.environ["ENGINE_API_TOKEN"] = "test-engine-token"
os.environ["SCAN_APPROVAL_SECRET"] = "test-approval-secret-at-least-32-bytes"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import main


def router_get(routes):
    def fake(url, timeout=5, cap=262144):
        for key, result in routes.items():
            if key in url:
                return result
        return (404, "")
    return fake


class CloudStorageTests(unittest.TestCase):
    def test_s3_public_listing_is_exposed(self):
        routes = {"myco-assets.s3.amazonaws.com":
                  (200, "<ListBucketResult><Name>myco-assets</Name>")}
        with mock.patch.object(main, "_http_get", router_get(routes)):
            out = main.cloud_storage_check("myco.com")
        self.assertEqual(len(out["exposed"]), 1)
        self.assertEqual(out["exposed"][0]["provider"], "Amazon S3")
        self.assertEqual(out["exposed"][0]["name"], "myco-assets")

    def test_private_bucket_counted_not_flagged(self):
        routes = {"myco.s3.amazonaws.com": (403, "AccessDenied")}
        with mock.patch.object(main, "_http_get", router_get(routes)):
            out = main.cloud_storage_check("myco.com")
        self.assertEqual(out["exposed"], [])
        self.assertEqual(out["private_existing"], 1)

    def test_nothing_anywhere(self):
        with mock.patch.object(main, "_http_get", router_get({})):
            out = main.cloud_storage_check("myco.com")
        self.assertEqual(out["exposed"], [])
        self.assertEqual(out["private_existing"], 0)
        self.assertGreaterEqual(out["candidates_checked"], 12)

    def test_gcs_public_listing(self):
        routes = {"storage.googleapis.com/myco-media":
                  (200, "<ListBucketResult/>")}
        with mock.patch.object(main, "_http_get", router_get(routes)):
            out = main.cloud_storage_check("myco.com")
        providers = [e["provider"] for e in out["exposed"]]
        self.assertIn("Google Cloud Storage", providers)

    def test_cloud_score_deduction_and_cap(self):
        cloud = {"status": "ready", "exposed": [
            {"name": "a", "provider": "Amazon S3"},
            {"name": "b", "provider": "Amazon S3"},
            {"name": "c", "provider": "Amazon S3"}]}
        email = {"status": "ready", "has_mx": False}
        out = main.full_score([], [], email, None, None, cloud)
        self.assertEqual(out["score"], 86)  # bucket capped at 14


class ParserTests(unittest.TestCase):
    def parse(self, name, text):
        return main.parse_dependencies(name, text.encode())

    def test_requirements(self):
        name, deps = self.parse(
            "requirements.txt",
            "flask==0.12.2\nrequests>=2.0\n# comment\ndjango==2.2\n")
        self.assertEqual(name, "requirements.txt")
        self.assertEqual(deps, [{"name": "flask", "version": "0.12.2"},
                                {"name": "django", "version": "2.2"}])

    def test_package_lock_v3(self):
        doc = {"packages": {
            "": {"name": "root"},
            "node_modules/lodash": {"version": "4.17.4"},
            "node_modules/@babel/core": {"version": "7.0.0"}}}
        name, deps = self.parse("package-lock.json", json.dumps(doc))
        self.assertIn({"name": "lodash", "version": "4.17.4"}, deps)
        self.assertIn({"name": "@babel/core", "version": "7.0.0"}, deps)
        self.assertEqual(len(deps), 2)

    def test_yarn_lock(self):
        text = ('lodash@^4.17.4:\n  version "4.17.21"\n\n'
                '"@babel/core@^7.0.0":\n  version "7.1.0"\n')
        name, deps = self.parse("yarn.lock", text)
        self.assertIn({"name": "lodash", "version": "4.17.21"}, deps)
        self.assertIn({"name": "@babel/core", "version": "7.1.0"}, deps)

    def test_go_mod(self):
        text = ("module example.com/x\n\nrequire (\n"
                "\tgithub.com/gin-gonic/gin v1.7.0\n"
                "\tgolang.org/x/crypto v0.1.0 // indirect\n)\n")
        name, deps = self.parse("go.mod", text)
        self.assertIn({"name": "github.com/gin-gonic/gin",
                       "version": "1.7.0"}, deps)
        self.assertEqual(len(deps), 2)

    def test_gemfile_lock(self):
        text = ("GEM\n  remote: https://rubygems.org/\n  specs:\n"
                "    rack (2.0.8)\n      mustermann (~> 1.0)\n"
                "    rails (6.0.0)\n")
        name, deps = self.parse("Gemfile.lock", text)
        self.assertIn({"name": "rack", "version": "2.0.8"}, deps)
        self.assertIn({"name": "rails", "version": "6.0.0"}, deps)
        self.assertEqual(len(deps), 2)

    def test_pipfile_lock(self):
        doc = {"default": {"flask": {"version": "==0.12.2"}},
               "develop": {"pytest": {"version": "==6.0"}}}
        name, deps = self.parse("Pipfile.lock", json.dumps(doc))
        self.assertEqual(len(deps), 2)

    def test_composer_lock(self):
        doc = {"packages": [{"name": "guzzlehttp/guzzle",
                             "version": "v7.0.0"}]}
        name, deps = self.parse("composer.lock", json.dumps(doc))
        self.assertEqual(deps, [{"name": "guzzlehttp/guzzle",
                                 "version": "7.0.0"}])

    def test_unsupported(self):
        name, deps = main.parse_dependencies("package.json", b"{}")
        self.assertIsNone(name)
        self.assertIsNone(deps)


class CvssTests(unittest.TestCase):
    def test_network_all_high_is_98(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        self.assertEqual(main._cvss3_base_score(v), 9.8)

    def test_scope_changed_all_high_is_100(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        self.assertEqual(main._cvss3_base_score(v), 10.0)

    def test_no_impact_is_zero(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        self.assertEqual(main._cvss3_base_score(v), 0.0)

    def test_garbage_is_none(self):
        self.assertIsNone(main._cvss3_base_score("not-a-vector"))


VULN_DETAIL = json.dumps({
    "summary": "Bad thing in requests",
    "severity": [{"type": "CVSS_V3",
                  "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [{"ranges": [{"events": [{"introduced": "0"},
                                          {"fixed": "2.20.0"}]}]}],
    "aliases": ["CVE-2018-18074"]})


class ScaFlowTests(unittest.TestCase):
    def test_end_to_end_with_stubbed_osv(self):
        batch = json.dumps({"results": [
            {"vulns": [{"id": "GHSA-xxxx"}]}, {}]})

        def fake_post(url, payload, timeout=5, cap=65536):
            return (200, batch)

        def fake_get(url, timeout=5, cap=262144):
            return (200, VULN_DETAIL)

        with mock.patch.object(main, "_http_post_json", fake_post), \
             mock.patch.object(main, "_http_get", fake_get):
            out = main.analyze_dependencies(
                "requirements.txt",
                b"requests==2.19.1\nflask==2.0.0\n")
        self.assertEqual(out["status"], "ready")
        self.assertEqual(out["packages_checked"], 2)
        self.assertEqual(out["total_vulns"], 1)
        self.assertEqual(out["counts"]["حرجة"], 1)
        vuln = out["vulnerable"][0]["vulns"][0]
        self.assertEqual(vuln["cvss"], 9.8)
        self.assertEqual(vuln["fixed"], ["2.20.0"])
        self.assertEqual(out["score"]["score"], 85)

    def test_osv_down_is_unavailable(self):
        with mock.patch.object(main, "_http_post_json",
                               return_value=(None, "")):
            out = main.analyze_dependencies(
                "requirements.txt", b"requests==2.19.1\n")
        self.assertEqual(out["status"], "unavailable")

    def test_permit_binding(self):
        import base64, hashlib, hmac, time

        def b64(b):
            return base64.urlsafe_b64encode(b).decode().rstrip("=")

        def mint(kind, sha):
            p = b64(json.dumps({"sha256": sha, "kind": kind, "id": "r1",
                                "exp": int((time.time() + 300) * 1000)},
                               separators=(",", ":")).encode())
            s = b64(hmac.new(
                os.environ["SCAN_APPROVAL_SECRET"].encode(),
                p.encode(), hashlib.sha256).digest())
            return p + "." + s

        self.assertTrue(main.valid_sca_permit(mint("sca", "abc"), "abc"))
        self.assertFalse(main.valid_sca_permit(mint("apk", "abc"), "abc"))
        self.assertFalse(main.valid_sca_permit(mint("sca", "abc"), "xyz"))


if __name__ == "__main__":
    unittest.main()
