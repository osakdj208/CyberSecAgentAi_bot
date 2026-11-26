import json, os, sys, unittest
from unittest import mock

os.environ["ENGINE_API_TOKEN"] = "test-engine-token"
os.environ["SCAN_APPROVAL_SECRET"] = "test-approval-secret-at-least-32-bytes"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import main

OPENAPI_DOC = json.dumps({
    "openapi": "3.0.1",
    "info": {"title": "Shop API", "version": "2.1"},
    "paths": {"/users": {}, "/orders": {}, "/pay": {}}})


def router_get(routes):
    def fake(url, timeout=5, cap=262144, headers=None):
        for suffix, result in routes.items():
            if url.endswith(suffix):
                return result
        return (404, "")
    return fake


def router_post(routes):
    def fake(url, payload, timeout=5, cap=65536, headers=None):
        for suffix, result in routes.items():
            if url.endswith(suffix):
                return result
        return (404, "")
    return fake


class ApiSurfaceTests(unittest.TestCase):
    def test_openapi_doc_found_with_endpoint_count(self):
        routes = {"/openapi.json": (200, OPENAPI_DOC),
                  "/swagger-ui.html": (200, "<div id=swagger-ui></div>")}
        with mock.patch.object(main, "_http_get", router_get(routes)), \
             mock.patch.object(main, "_http_post_json", router_post({})):
            out = main.api_surface_check("example.com", "https")
        self.assertEqual(len(out["openapi"]), 1)
        doc = out["openapi"][0]
        self.assertEqual(doc["title"], "Shop API")
        self.assertEqual(doc["endpoints"], 3)
        self.assertEqual(out["doc_pages"], ["/swagger-ui.html"])
        self.assertEqual(out["graphql"], [])

    def test_non_openapi_json_ignored(self):
        routes = {"/swagger.json": (200, '{"hello": "world"}')}
        with mock.patch.object(main, "_http_get", router_get(routes)), \
             mock.patch.object(main, "_http_post_json", router_post({})):
            out = main.api_surface_check("example.com", "https")
        self.assertEqual(out["openapi"], [])

    def test_graphql_introspection_enabled(self):
        body = json.dumps({"data": {"__schema":
                                    {"queryType": {"name": "Query"}}}})
        with mock.patch.object(main, "_http_get", router_get({})), \
             mock.patch.object(main, "_http_post_json", router_post(
                 {"https://example.com/graphql": (200, body)})):
            out = main.api_surface_check("example.com", "https")
        self.assertEqual(out["graphql"],
                         [{"path": "/graphql", "introspection": True}])

    def test_graphql_present_introspection_disabled(self):
        body = json.dumps({"errors": [{"message": "introspection disabled"}]})
        with mock.patch.object(main, "_http_get", router_get({})), \
             mock.patch.object(main, "_http_post_json", router_post(
                 {"https://example.com/graphql": (400, body)})):
            out = main.api_surface_check("example.com", "https")
        self.assertEqual(out["graphql"],
                         [{"path": "/graphql", "introspection": False}])

    def test_nothing_found(self):
        with mock.patch.object(main, "_http_get", router_get({})), \
             mock.patch.object(main, "_http_post_json", router_post({})):
            out = main.api_surface_check("example.com", "https")
        self.assertEqual(out, {"status": "ready", "openapi": [],
                               "doc_pages": [], "graphql": []})


APP_JS = ('var k="AKIAIOSFODNN7EXAMPLE";'
          'fetch("/api/users/list");'
          'var internal="http://192.168.1.10:8080/admin";'
          'load("https://cdn.other.net/lib.js");')
HOME = ('<html><script src="/static/app.js"></script>'
        '<script src="https://cdn.other.net/ext.js"></script>'
        '<script src="/static/vendor.js"></script></html>')


class JsMiningTests(unittest.TestCase):
    def test_mines_secrets_endpoints_and_internal(self):
        routes = {"example.com/": (200, HOME),
                  "/static/app.js": (200, APP_JS),
                  "/static/vendor.js": (200, "var x = 1;")}
        with mock.patch.object(main, "_http_get", router_get(routes)):
            out = main.js_mining("example.com", "https")
        self.assertEqual(out["status"], "ready")
        # The external script is never fetched: only same-host files.
        self.assertEqual(out["files_checked"], 2)
        types = [s["type"] for s in out["secrets"]]
        self.assertIn("AWS access key", types)
        previews = [s["preview"] for s in out["secrets"]]
        self.assertTrue(all(p.endswith("…") and len(p) <= 8
                            for p in previews))
        self.assertIn("/api/users/list", out["api_endpoints"])
        self.assertIn("192.168.1.10", out["internal_addresses"])
        self.assertIn("cdn.other.net", out["external_domains"])

    def test_homepage_down_is_unavailable(self):
        with mock.patch.object(main, "_http_get",
                               return_value=(None, "")):
            out = main.js_mining("example.com", "https")
        self.assertEqual(out["status"], "unavailable")


def host_with(api=None, js=None):
    h = {"host": "h.example.com", "ips": ["1.1.1.1"],
         "nuclei": {"status": "ready", "counts": {}},
         "http": {"status": "ready", "missing": []},
         "tls": {"status": "ready", "legacy_protocols": {},
                 "days_left": 90}}
    if api is not None:
        h["api"] = api
    if js is not None:
        h["js"] = js
    return h


class PhaseC2ScoreTests(unittest.TestCase):
    EMAIL_OFF = {"status": "ready", "has_mx": False}

    def test_introspection_and_doc_cost_7(self):
        api = {"status": "ready",
               "openapi": [{"path": "/openapi.json"}],
               "doc_pages": [],
               "graphql": [{"path": "/graphql", "introspection": True}]}
        out = main.full_score([host_with(api=api)], [], self.EMAIL_OFF)
        self.assertEqual(out["score"], 93)

    def test_js_secret_and_internal_cost_11(self):
        js = {"status": "ready", "files_checked": 2,
              "secrets": [{"type": "AWS access key", "preview": "AKIAIO…",
                           "where": "app.js"}],
              "internal_addresses": ["10.0.0.5"], "api_endpoints": [],
              "external_domains": []}
        out = main.full_score([host_with(js=js)], [], self.EMAIL_OFF)
        self.assertEqual(out["score"], 89)

    def test_surface_bucket_capped_at_16(self):
        js = {"status": "ready", "files_checked": 1,
              "secrets": [{"type": "Generic secret assignment",
                           "preview": "x…", "where": "a.js"}
                          for _ in range(5)],
              "internal_addresses": [], "api_endpoints": [],
              "external_domains": []}
        out = main.full_score([host_with(js=js)], [], self.EMAIL_OFF)
        self.assertEqual(out["score"], 84)


if __name__ == "__main__":
    unittest.main()
