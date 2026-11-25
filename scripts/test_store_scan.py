#!/usr/bin/env python3
"""Tests for store_scan.py. Run: python3 -m unittest scripts/test_store_scan.py (from the skill folder)."""

from __future__ import annotations

import datetime as dt
import http.server
import tempfile
import textwrap
import threading
import unittest
from pathlib import Path

import store_scan

TODAY = dt.date(2026, 11, 18)


def write(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")


def ids(report: store_scan.Report, severity: str | None = None) -> set[str]:
    return {f.id for f in report.findings if severity is None or f.severity == severity}


MANIFEST_OK = """
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.INTERNET" />
    <application android:label="Demo">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter><action android:name="android.intent.action.MAIN" /></intent-filter>
        </activity>
    </application>
</manifest>
"""


class AndroidTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        write(self.root, "settings.gradle.kts", 'include(":app")\n')
        write(self.root, "build.gradle.kts", "plugins {\n    alias(libs.plugins.android.application) apply false\n}\n")

    def tearDown(self):
        self.tmp.cleanup()

    def gradle(self, body: str, target: int = 36) -> None:
        write(self.root, "app/build.gradle.kts", f"""
            plugins {{ id("com.android.application") }}
            android {{
                defaultConfig {{ targetSdk = {target}
                    versionCode = 3 }}
                signingConfigs {{ create("release") {{ storePassword = props.getProperty("storePassword") }} }}
                buildTypes {{ release {{ isMinifyEnabled = true
                    ndk {{ debugSymbolLevel = "FULL" }}
                    signingConfig = signingConfigs.getByName("release")
                }} }}
            {body}
        """)

    def scan(self, stores=("play", "huawei")):
        report, _ = store_scan.scan(self.root, set(stores), [], TODAY)
        return report

    def test_root_build_file_with_apply_false_is_not_a_module(self):
        self.gradle("}")
        write(self.root, "app/src/main/AndroidManifest.xml", MANIFEST_OK)
        roots = store_scan.detect(store_scan.Tree(self.root))
        self.assertEqual([p.name for p in roots.android_modules], ["app"])

    def test_low_target_sdk_is_critical(self):
        self.gradle("}", target=33)
        write(self.root, "app/src/main/AndroidManifest.xml", MANIFEST_OK)
        self.assertIn("AND-TARGET-SDK", ids(self.scan(), "CRITICAL"))

    def test_target_requirement_moves_with_date(self):
        self.assertEqual(store_scan.target_requirement(dt.date(2026, 8, 30)), 35)
        self.assertEqual(store_scan.target_requirement(dt.date(2026, 8, 31)), 36)

    def test_gms_without_huawei_flavor_is_critical(self):
        self.gradle('}\ndependencies {\n    implementation("com.google.firebase:firebase-messaging:24.0.0")\n}')
        write(self.root, "app/src/main/AndroidManifest.xml", MANIFEST_OK)
        self.assertIn("HW-NO-STORE-FLAVOR", ids(self.scan(), "CRITICAL"))

    def test_gms_scoped_to_play_flavor_passes(self):
        self.gradle('    productFlavors { create("play") {}\n create("huawei") {} }\n}\n'
                    'dependencies {\n    "playImplementation"(libs.credentials.play)\n}')
        write(self.root, "gradle/libs.versions.toml", '[libraries]\ncredentials-play = { module = "androidx.credentials:credentials-play-services-auth", version = "1.5.0" }\n')
        write(self.root, "app/src/main/AndroidManifest.xml", MANIFEST_OK)
        found = ids(self.scan())
        self.assertNotIn("HW-NO-STORE-FLAVOR", found)
        self.assertNotIn("HW-GMS-DEPENDENCY", found)

    def test_shared_gms_with_flavor_is_high_via_version_catalog(self):
        self.gradle('    productFlavors { create("huawei") {} }\n}\ndependencies {\n    implementation(libs.billing)\n}')
        write(self.root, "gradle/libs.versions.toml", '[libraries]\nbilling = { group = "com.android.billingclient", name = "billing-ktx", version = "7.0.0" }\n')
        write(self.root, "app/src/main/AndroidManifest.xml", MANIFEST_OK)
        report = self.scan()
        self.assertIn("HW-GMS-DEPENDENCY", ids(report, "HIGH"))
        self.assertIn("HW-IAP", ids(report, "CRITICAL"))

    def test_missing_exported_and_sensitive_permission(self):
        self.gradle("}")
        write(self.root, "app/src/main/AndroidManifest.xml", """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <uses-permission android:name="android.permission.READ_SMS" />
                <application android:usesCleartextTraffic="true">
                    <activity android:name=".Main"><intent-filter><action android:name="android.intent.action.MAIN" /></intent-filter></activity>
                </application>
            </manifest>
        """)
        report = self.scan()
        self.assertIn("AND-EXPORTED", ids(report, "CRITICAL"))
        self.assertIn("AND-SENSITIVE-PERMISSION", ids(report, "HIGH"))
        self.assertIn("AND-CLEARTEXT", ids(report, "HIGH"))

    def test_hardcoded_password_flagged_but_property_lookup_not(self):
        self.gradle("}")
        write(self.root, "app/src/main/AndroidManifest.xml", MANIFEST_OK)
        self.assertNotIn("AND-SIGNING-SECRET", ids(self.scan()))
        text = (self.root / "app/build.gradle.kts").read_text().replace('storePassword = props.getProperty("storePassword")', 'storePassword = "hunter22"')
        (self.root / "app/build.gradle.kts").write_text(text)
        self.assertIn("AND-SIGNING-SECRET", ids(self.scan()))

    def test_huawei_store_links_and_wording(self):
        self.gradle('    productFlavors { create("huawei") {} }\n}')
        write(self.root, "app/src/main/AndroidManifest.xml", MANIFEST_OK)
        write(self.root, "app/src/main/java/demo/Rate.kt", 'val url = "market://details?id=demo"\n')
        write(self.root, "app/src/main/res/values/strings.xml", "<resources><string name=\"rate\">Rate us on Google Play</string></resources>")
        found = ids(self.scan(stores=("huawei",)))
        self.assertIn("HW-STORE-LINKS", found)
        self.assertIn("HW-GOOGLE-WORDING", found)

    def test_login_without_account_deletion_is_critical(self):
        self.gradle("}")
        write(self.root, "app/src/main/AndroidManifest.xml", MANIFEST_OK)
        write(self.root, "app/src/main/java/demo/Auth.kt", "fun signIn(email: String) {}\nval privacyUrl = \"https://x/privacy\"\n")
        self.assertIn("X-ACCOUNT-DELETION", ids(self.scan(), "CRITICAL"))
        write(self.root, "app/src/main/java/demo/Account.kt", "fun deleteAccount() {}\n")
        self.assertNotIn("X-ACCOUNT-DELETION", ids(self.scan()))


class IOSTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "Demo.xcodeproj").mkdir()
        write(self.root, "Demo/Info.plist", "<plist><dict><key>CFBundleName</key><string>Demo</string></dict></plist>")

    def tearDown(self):
        self.tmp.cleanup()

    def scan(self):
        report, _ = store_scan.scan(self.root, {"apple"}, [], TODAY)
        return report

    def test_missing_manifest_purpose_string_and_siwa(self):
        write(self.root, "Demo/Camera.swift", "import AVFoundation\nlet d = AVCaptureDevice.default(for: .video)\nlet x = UserDefaults.standard\n")
        write(self.root, "Demo/Login.swift", "import GoogleSignIn\nGIDSignIn.sharedInstance.signIn()\n")
        report = self.scan()
        critical = ids(report, "CRITICAL")
        self.assertTrue({"IOS-PRIVACY-MANIFEST", "IOS-PURPOSE-STRING", "IOS-SIGN-IN-WITH-APPLE"} <= critical)

    def test_complete_project_has_no_critical(self):
        write(self.root, "Demo/Info.plist", """
            <plist><dict>
            <key>NSCameraUsageDescription</key><string>Demo uses the camera to scan a document into your note.</string>
            <key>ITSAppUsesNonExemptEncryption</key><false/>
            </dict></plist>
        """)
        write(self.root, "Demo/PrivacyInfo.xcprivacy", "<plist><dict><key>NSPrivacyAccessedAPITypes</key><array><string>NSPrivacyAccessedAPICategoryUserDefaults</string></array></dict></plist>")
        write(self.root, "Demo/Camera.swift", "let d = AVCaptureDevice.default(for: .video)\nlet x = UserDefaults.standard\n")
        write(self.root, "Demo/Login.swift", "GIDSignIn.sharedInstance.signIn()\nASAuthorizationAppleIDProvider().createRequest()\nfunc deleteAccount() {}\nlet privacy = URL(string: \"https://x/privacy\")\n")
        self.assertEqual(ids(self.scan(), "CRITICAL"), set())
        self.assertNotIn("IOS-REQUIRED-REASON-API", ids(self.scan()))

    def test_paid_signals_without_billing(self):
        write(self.root, "Demo/Paywall.swift", 'Text("Upgrade to Pro")\n')
        self.assertIn("X-PAID-SIGNALS", ids(self.scan()))


class _AgentFilter(http.server.BaseHTTPRequestHandler):
    def version_string(self):
        return "cloudflare"

    def do_GET(self):  # noqa: N802
        agent = self.headers.get("User-Agent", "")
        status = 403 if agent.startswith("Java/1.8") else 200
        body = ("Privacy policy " * 100).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("CF-RAY", "test")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class URLTests(unittest.TestCase):
    def test_java8_only_block_is_reported_for_huawei(self):
        server = http.server.HTTPServer(("127.0.0.1", 0), _AgentFilter)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            report = store_scan.Report(project="/")
            store_scan.check_urls(report, [f"http://127.0.0.1:{server.server_port}/privacy-policy"])
        finally:
            server.shutdown()
            server.server_close()
        blocked = [f for f in report.findings if f.id == "URL-BLOCKED"]
        self.assertEqual(len(blocked), 1)
        self.assertEqual(blocked[0].stores, ["huawei"])
        self.assertIn("Cloudflare", blocked[0].title)
        self.assertIn("URL-NOT-HTTPS", {f.id for f in report.findings})



class FlutterPluginPurposeTests(unittest.TestCase):
    """A purpose string required only because a plugin links the API."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.root = base / "app"
        self.plugin = base / "pub-cache" / "some_picker-1.0.0"
        write(self.root, "pubspec.yaml", "name: demo\ndependencies:\n  flutter:\n    sdk: flutter\n")
        (self.root / "ios" / "Runner.xcodeproj").mkdir(parents=True)
        write(self.root, "ios/Runner/Info.plist", "<plist><dict><key>CFBundleName</key><string>Demo</string></dict></plist>")
        write(self.root, "ios/Podfile", "platform :ios, '15.0'\n")

    def tearDown(self):
        self.tmp.cleanup()

    def photo_findings(self):
        report, _ = store_scan.scan(self.root, {"apple"}, [], TODAY)
        return [f for f in report.findings if f.id == "IOS-PURPOSE-STRING" and "NSPhotoLibraryUsageDescription" in f.title]

    def register_plugin(self, name="some_picker"):
        write(self.plugin, "ios/Classes/Plugin.m", "UIImagePickerController *picker = [UIImagePickerController new];\n")
        (self.root / ".flutter-plugins-dependencies").write_text(
            '{"plugins": {"ios": [{"name": "%s", "path": "%s/"}]}}' % (name, self.plugin), encoding="utf-8")

    def test_plugin_native_code_needs_the_key(self):
        self.register_plugin()
        found = self.photo_findings()
        self.assertEqual(len(found), 1)
        self.assertIn("native dependency", found[0].title)

    def test_file_picker_package_needs_the_key(self):
        write(self.root, "pubspec.yaml", "name: demo\ndependencies:\n  flutter:\n    sdk: flutter\n  file_picker: ^8.1.7\n")
        self.assertEqual(len(self.photo_findings()), 1)

    def test_file_picker_with_media_off_is_clean(self):
        write(self.root, "pubspec.yaml", "name: demo\ndependencies:\n  flutter:\n    sdk: flutter\n  file_picker: ^8.1.7\n")
        write(self.root, "ios/Podfile", "Pod::PICKER_MEDIA = false\nplatform :ios, '15.0'\n")
        self.plugin = self.plugin.parent / "file_picker-8.1.7"
        self.register_plugin("file_picker")
        self.assertEqual(self.photo_findings(), [])

    def test_key_present_is_clean(self):
        self.register_plugin()
        write(self.root, "ios/Runner/Info.plist",
              "<plist><dict><key>NSPhotoLibraryUsageDescription</key><string>Pick a photo for the product you sell.</string></dict></plist>")
        self.assertEqual(self.photo_findings(), [])


if __name__ == "__main__":
    unittest.main()
