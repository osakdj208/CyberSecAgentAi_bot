import asyncio, base64, hashlib, hmac, io, json, os, sys, time, unittest, zipfile
from unittest import mock

os.environ["ENGINE_API_TOKEN"] = "test-engine-token"
os.environ["SCAN_APPROVAL_SECRET"] = "test-approval-secret-at-least-32-bytes"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import main
from fastapi import HTTPException


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def mint(payload: dict) -> str:
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    s = b64url(hmac.new(os.environ["SCAN_APPROVAL_SECRET"].encode(),
                        p.encode(), hashlib.sha256).digest())
    return p + "." + s


def apk_permit(sha, kind="apk", exp_ms=None):
    return mint({"sha256": sha, "kind": kind, "id": "r1",
                 "exp": exp_ms or int((time.time() + 300) * 1000)})


SHA = "a" * 64


class ApkPermitTests(unittest.TestCase):
    def test_valid(self):
        self.assertTrue(main.valid_apk_permit(apk_permit(SHA), SHA))

    def test_wrong_hash_and_kind(self):
        self.assertFalse(main.valid_apk_permit(apk_permit(SHA), "b" * 64))
        self.assertFalse(main.valid_apk_permit(
            apk_permit(SHA, kind="full"), SHA))

    def test_expired_and_garbage(self):
        old = apk_permit(SHA, exp_ms=int((time.time() - 10) * 1000))
        self.assertFalse(main.valid_apk_permit(old, SHA))
        self.assertFalse(main.valid_apk_permit("junk", SHA))
        self.assertFalse(main.valid_apk_permit(None, SHA))


class SecretScanTests(unittest.TestCase):
    def test_patterns_found_and_redacted(self):
        text = ("key1 = AKIAIOSFODNN7EXAMPLE and "
                "AIzaSyA123456789012345678901234567890123 and "
                "api_key = 'supersecretvalue99'")
        found = main._scan_text_for_secrets(text, "classes.dex")
        types = {f["type"] for f in found}
        self.assertIn("AWS access key", types)
        self.assertIn("Google API key", types)
        self.assertIn("Generic secret assignment", types)
        for f in found:
            self.assertLessEqual(len(f["preview"]), 7)
            self.assertNotIn("supersecretvalue99", f["preview"])
            self.assertEqual(f["where"], "classes.dex")

    def test_clean_text(self):
        self.assertEqual(main._scan_text_for_secrets(
            "hello world, nothing here", "classes.dex"), [])


def facts(**over):
    base = {"flags": {"debuggable": False, "allow_backup": False,
                      "cleartext_traffic": False, "network_config": False},
            "secrets": [], "exported_open": [],
            "dangerous_permissions": [], "target_sdk": "34",
            "certificate": None}
    base.update(over)
    return base


class ApkScoreTests(unittest.TestCase):
    def test_clean_100(self):
        out = main.apk_score(facts())
        self.assertEqual(out["score"], 100)

    def test_debuggable_is_heaviest(self):
        f = facts()
        f["flags"]["debuggable"] = True
        self.assertEqual(main.apk_score(f)["score"], 75)

    def test_secret_bucket_cap(self):
        f = facts(secrets=[{"type": t} for t in
                           ("AWS access key", "Google API key", "JWT",
                            "Slack token")])
        self.assertEqual(main.apk_score(f)["score"], 80)

    def test_exported_and_permissions(self):
        f = facts(exported_open=["a.A", "b.B"],
                  dangerous_permissions=["android.permission.CAMERA"])
        self.assertEqual(main.apk_score(f)["score"], 100 - 8 - 2)


MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
  <application android:allowBackup="true">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter><action android:name="android.intent.action.MAIN"/></intent-filter>
    </activity>
    <service android:name=".SyncService" android:exported="true"
             android:permission="android.permission.BIND_JOB_SERVICE"/>
  </application>
</manifest>"""


class FakeAPK:
    def __init__(self, data, raw=False):
        pass

    def get_package(self):
        return "com.example.app"

    def get_app_name(self):
        return "Example"

    def get_androidversion_name(self):
        return "2.0"

    def get_androidversion_code(self):
        return "200"

    def get_min_sdk_version(self):
        return "24"

    def get_target_sdk_version(self):
        return "34"

    def get_main_activity(self):
        return ".MainActivity"

    def get_permissions(self):
        return ["android.permission.INTERNET", "android.permission.CAMERA"]

    def get_activities(self):
        return [".MainActivity"]

    def get_services(self):
        return [".SyncService"]

    def get_receivers(self):
        return []

    def get_providers(self):
        return []

    def get_android_manifest_xml(self):
        from lxml import etree
        return etree.fromstring(MANIFEST.encode())

    def get_certificates(self):
        return []


def synthetic_apk() -> bytes:
    dex = (b"\x00\x01binarynoise "
           b"AKIAIOSFODNN7EXAMPLE\x00 "
           b"http://api.myservice.dev/v1/data\x00 "
           b"Lcom/google/firebase/FirebaseApp;\x00 "
           b"https://api.myservice.dev/secure\x00")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", b"\x00\x01\x02")
        z.writestr("classes.dex", dex)
        z.writestr("lib/arm64-v8a/libx.so", b"\x7fELF")
    return buf.getvalue()


class AnalyzeApkTests(unittest.TestCase):
    def test_end_to_end_with_stubbed_parser(self):
        data = synthetic_apk()
        with mock.patch.object(main, "_AndroAPK", FakeAPK):
            out = main.analyze_apk(data)
        self.assertEqual(out["status"], "completed")
        self.assertEqual(out["app"]["package"], "com.example.app")
        self.assertEqual(out["sha256"],
                         hashlib.sha256(data).hexdigest())
        self.assertEqual(out["permissions"]["dangerous"],
                         ["android.permission.CAMERA"])
        self.assertIn(".MainActivity",
                      out["components"]["exported_open"])
        self.assertEqual(out["components"]["exported_guarded"], 1)
        types = {s["type"] for s in out["secrets"]}
        self.assertIn("AWS access key", types)
        self.assertIn("http://api.myservice.dev/v1/data",
                      out["urls"]["cleartext"])
        self.assertIn("Firebase", out["sdks"])
        self.assertEqual(out["native_abis"], ["arm64-v8a"])
        # deductions: allowBackup 4 + exported 4 + AWS secret 10 + CAMERA 2
        self.assertEqual(out["score"]["score"], 100 - 4 - 4 - 10 - 2)

    def test_not_an_apk(self):
        with mock.patch.object(main, "_AndroAPK", FakeAPK):
            with self.assertRaises(ValueError):
                main.analyze_apk(b"this is not a zip at all")


class FakeReq:
    def __init__(self, data):
        self._data = data

    async def body(self):
        return self._data


class ApkEndpointTests(unittest.TestCase):
    def run_ep(self, data, permit):
        return asyncio.run(main.apk_scan(
            FakeReq(data), authorization="Bearer test-engine-token",
            x_scan_approval=permit))

    def test_no_permit_403(self):
        with self.assertRaises(HTTPException) as ctx:
            self.run_ep(synthetic_apk(), None)
        self.assertEqual(ctx.exception.status_code, 403)

    def test_valid_permit_completes(self):
        data = synthetic_apk()
        permit = apk_permit(hashlib.sha256(data).hexdigest())
        with mock.patch.object(main, "_AndroAPK", FakeAPK):
            out = self.run_ep(data, permit)
        self.assertEqual(out["status"], "completed")


if __name__ == "__main__":
    unittest.main()
