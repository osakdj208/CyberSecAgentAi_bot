import os, sys, types, unittest
from unittest import mock

os.environ["ENGINE_API_TOKEN"] = "test-engine-token"
os.environ["SCAN_APPROVAL_SECRET"] = "test-approval-secret-at-least-32-bytes"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import main


class FakeRdata:
    def __init__(self, text, target=None):
        self._text = text
        self.target = target

    def to_text(self):
        return self._text


class FakeResolver:
    RECORDS = {}

    def resolve(self, name, rtype):
        vals = FakeResolver.RECORDS.get((name, rtype))
        if not vals:
            raise Exception("nxdomain")
        return vals


def run_with_records(records, fn, *args):
    FakeResolver.RECORDS = records
    with mock.patch.object(main.dns.resolver, "Resolver", FakeResolver):
        return fn(*args)


class TakeoverTests(unittest.TestCase):
    def test_confirmed_by_service_page(self):
        records = {("dead.example.com", "CNAME"):
                   [FakeRdata("x.github.io.", target="x.github.io.")]}
        with mock.patch.object(main, "_fetch_text",
                               return_value="There isn't a GitHub Pages "
                                            "site here."):
            out = run_with_records(records, main.subdomain_takeover_check,
                                   ["dead.example.com"])
        self.assertEqual(out["status"], "ready")
        self.assertEqual(out["checked"], 1)
        self.assertEqual(len(out["findings"]), 1)
        f = out["findings"][0]
        self.assertEqual(f["verdict"], "confirmed")
        self.assertEqual(f["service"], "GitHub Pages")
        self.assertEqual(f["cname_target"], "x.github.io")

    def test_likely_when_target_gone(self):
        records = {("old.example.com", "CNAME"):
                   [FakeRdata("gone.herokuapp.com.",
                              target="gone.herokuapp.com.")]}
        with mock.patch.object(main, "_fetch_text", return_value=""), \
             mock.patch.object(main, "_resolve_quiet", return_value=[]):
            out = run_with_records(records, main.subdomain_takeover_check,
                                   ["old.example.com"])
        self.assertEqual(len(out["findings"]), 1)
        self.assertEqual(out["findings"][0]["verdict"], "likely")
        self.assertEqual(out["findings"][0]["service"], "Heroku")

    def test_in_use_service_not_reported(self):
        records = {("live.example.com", "CNAME"):
                   [FakeRdata("me.github.io.", target="me.github.io.")]}
        with mock.patch.object(main, "_fetch_text",
                               return_value="<html>my real site</html>"), \
             mock.patch.object(main, "_resolve_quiet",
                               return_value=["185.199.108.153"]):
            out = run_with_records(records, main.subdomain_takeover_check,
                                   ["live.example.com"])
        self.assertEqual(out["checked"], 1)
        self.assertEqual(out["findings"], [])

    def test_no_cname_not_checked(self):
        out = run_with_records({}, main.subdomain_takeover_check,
                               ["plain.example.com"])
        self.assertEqual(out["checked"], 0)
        self.assertEqual(out["findings"], [])

    def test_unrelated_cname_ignored(self):
        records = {("cdn.example.com", "CNAME"):
                   [FakeRdata("d123.cloudfront.net.",
                              target="d123.cloudfront.net.")]}
        out = run_with_records(records, main.subdomain_takeover_check,
                               ["cdn.example.com"])
        self.assertEqual(out["checked"], 1)
        self.assertEqual(out["findings"], [])


class AxfrTests(unittest.TestCase):
    def test_transfer_success_counts_records(self):
        class FakeZone:
            def iterate_rdatasets(self):
                return iter([1, 2, 3, 4])
        fake_zone = types.SimpleNamespace(from_xfr=lambda q: FakeZone())
        fake_query = types.SimpleNamespace(xfr=lambda *a, **k: object())
        with mock.patch.object(main, "_dns_zone", fake_zone), \
             mock.patch.object(main, "_dns_query", fake_query), \
             mock.patch.object(main, "_resolve_quiet",
                               return_value=["1.2.3.4"]):
            allowed, count = main._try_axfr("example.com",
                                            "ns1.example.com")
        self.assertTrue(allowed)
        self.assertEqual(count, 4)

    def test_transfer_refused(self):
        def boom(q):
            raise Exception("refused")
        fake_zone = types.SimpleNamespace(from_xfr=boom)
        fake_query = types.SimpleNamespace(xfr=lambda *a, **k: object())
        with mock.patch.object(main, "_dns_zone", fake_zone), \
             mock.patch.object(main, "_dns_query", fake_query), \
             mock.patch.object(main, "_resolve_quiet",
                               return_value=["1.2.3.4"]):
            self.assertEqual(main._try_axfr("example.com", "ns1.example.com"),
                             (False, 0))


class DnsDeepAuditTests(unittest.TestCase):
    RECORDS = {
        ("example.com", "NS"): [FakeRdata("ns1.example.com."),
                                FakeRdata("ns2.example.com.")],
        ("example.com", "DS"): [FakeRdata("12345 8 2 ABCD")],
        ("example.com", "DNSKEY"): [FakeRdata("256 3 8 AwEAA...")],
        ("example.com", "CAA"): [FakeRdata('0 issue "letsencrypt.org"')],
    }

    def test_signed_caa_and_axfr_refused(self):
        with mock.patch.object(main, "_try_axfr", return_value=(False, 0)):
            out = run_with_records(self.RECORDS, main.dns_deep_audit,
                                   "example.com")
        self.assertEqual(out["status"], "ready")
        self.assertEqual(out["nameservers"],
                         ["ns1.example.com", "ns2.example.com"])
        self.assertTrue(out["dnssec"]["signed"])
        self.assertTrue(out["caa"]["present"])
        self.assertFalse(out["axfr"]["vulnerable"])
        self.assertEqual(len(out["axfr"]["attempts"]), 2)

    def test_axfr_vulnerable(self):
        with mock.patch.object(main, "_try_axfr",
                               return_value=(True, 321)):
            out = run_with_records(self.RECORDS, main.dns_deep_audit,
                                   "example.com")
        self.assertTrue(out["axfr"]["vulnerable"])
        self.assertEqual(out["axfr"]["attempts"][0]["records"], 321)

    def test_unsigned_and_no_caa(self):
        records = {("example.com", "NS"): [FakeRdata("ns1.example.com.")]}
        with mock.patch.object(main, "_try_axfr", return_value=(False, 0)):
            out = run_with_records(records, main.dns_deep_audit,
                                   "example.com")
        self.assertFalse(out["dnssec"]["signed"])
        self.assertFalse(out["caa"]["present"])


class PhaseC1ScoreTests(unittest.TestCase):
    EMAIL_OFF = {"status": "ready", "has_mx": False}

    def test_confirmed_takeover_costs_12(self):
        takeover = {"status": "ready", "findings": [
            {"host": "dead.example.com", "service": "GitHub Pages",
             "verdict": "confirmed"}]}
        out = main.full_score([], [], self.EMAIL_OFF, None, takeover)
        self.assertEqual(out["score"], 88)

    def test_takeover_bucket_capped_at_20(self):
        takeover = {"status": "ready", "findings": [
            {"host": f"h{i}.example.com", "service": "Heroku",
             "verdict": "confirmed"} for i in range(4)]}
        out = main.full_score([], [], self.EMAIL_OFF, None, takeover)
        self.assertEqual(out["score"], 80)

    def test_axfr_and_missing_caa_cost_12(self):
        audit = {"status": "ready",
                 "axfr": {"vulnerable": True, "attempts": []},
                 "caa": {"present": False, "records": []}}
        out = main.full_score([], [], self.EMAIL_OFF, audit, None)
        self.assertEqual(out["score"], 88)

    def test_clean_dns_costs_nothing(self):
        audit = {"status": "ready",
                 "axfr": {"vulnerable": False, "attempts": []},
                 "caa": {"present": True, "records": []}}
        takeover = {"status": "ready", "findings": []}
        out = main.full_score([], [], self.EMAIL_OFF, audit, takeover)
        self.assertEqual(out["score"], 100)


if __name__ == "__main__":
    unittest.main()
