#!/usr/bin/env python3
"""Store compliance scanner for Apple App Store, Google Play and Huawei AppGallery.

Reads a mobile project (native iOS/Android, Flutter, React Native/Expo, Capacitor) and reports
rejection risks with a fix for each. Never modifies the project. Standard library only.

Usage:
    python3 store_scan.py PROJECT_DIR [--stores apple,play,huawei] [--urls URL ...] [--json]

Exit codes: 2 = at least one CRITICAL, 1 = at least one HIGH, 0 = otherwise.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "INFO"]
ALL_STORES = ["apple", "play", "huawei"]

EXCLUDED_DIRS = {
    ".git", "node_modules", "Pods", "build", ".gradle", "DerivedData", ".dart_tool", "vendor",
    "dist", ".next", ".expo", ".idea", ".build", "Carthage", ".swiftpm", "xcuserdata", ".cxx",
    "storage", "bootstrap", ".venv", "venv", "__pycache__", ".turbo", "coverage", "intermediates",
}
CODE_EXT = {".swift", ".m", ".mm", ".h", ".kt", ".java", ".dart", ".js", ".jsx", ".ts", ".tsx", ".vue"}
TEXT_EXT = CODE_EXT | {
    ".xml", ".plist", ".json", ".yml", ".yaml", ".gradle", ".kts", ".strings", ".xcstrings",
    ".properties", ".toml", ".pbxproj", ".entitlements", ".xcprivacy", ".html", ".arb", ".md",
}
MAX_FILE_BYTES = 2_000_000
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
TOOLS_NS = "{http://schemas.android.com/tools}"


@dataclass
class Finding:
    id: str
    severity: str
    stores: list[str]
    title: str
    fix: str
    file: str = ""
    line: int = 0
    detail: str = ""


@dataclass
class Report:
    project: str
    platforms: list[str] = field(default_factory=list)
    profile: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)


# ---------------------------------------------------------------- file helpers


class Tree:
    """Cached view of the text files under a root directory."""

    def __init__(self, root: Path):
        self.root = root
        self.files: list[Path] = []
        self._cache: dict[Path, str] = {}
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS and not d.endswith(".xcassets")]
            for name in filenames:
                path = Path(dirpath) / name
                if path.suffix.lower() in TEXT_EXT or name in {"Podfile", "Info.plist", "Package.swift"}:
                    self.files.append(path)
                elif path.suffix.lower() in {".jks", ".keystore", ".p12", ".p8", ".mobileprovision"}:
                    self.files.append(path)

    def read(self, path: Path) -> str:
        if path not in self._cache:
            try:
                if path.stat().st_size > MAX_FILE_BYTES or path.suffix.lower() in {".jks", ".keystore", ".p12", ".p8", ".mobileprovision"}:
                    self._cache[path] = ""
                else:
                    self._cache[path] = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                self._cache[path] = ""
        return self._cache[path]

    def under(self, root: Path) -> list[Path]:
        return [p for p in self.files if root == p or root in p.parents]

    def search(self, pattern: re.Pattern, files: list[Path]) -> tuple[Path, int, str] | None:
        for path in files:
            text = self.read(path)
            match = pattern.search(text)
            if match:
                return path, text.count("\n", 0, match.start()) + 1, match.group(0)
        return None

    def search_all(self, pattern: re.Pattern, files: list[Path]) -> list[tuple[Path, int, str]]:
        hits = []
        for path in files:
            text = self.read(path)
            for match in pattern.finditer(text):
                hits.append((path, text.count("\n", 0, match.start()) + 1, match.group(0)))
        return hits


def code_files(files: list[Path]) -> list[Path]:
    return [p for p in files if p.suffix.lower() in CODE_EXT and not _is_test(p)]


def _is_test(path: Path) -> bool:
    parts = {part.lower() for part in path.parts}
    return bool(parts & {"test", "tests", "androidtest", "uitests", "__tests__"}) or path.stem.endswith(("Tests", "Test", "_test", ".test", ".spec"))


def rel(report_root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(report_root))
    except ValueError:
        return str(path)


# ---------------------------------------------------------------- detection


@dataclass
class AppRoots:
    ios: list[Path] = field(default_factory=list)
    android_modules: list[Path] = field(default_factory=list)
    flutter: list[Path] = field(default_factory=list)
    react_native: list[Path] = field(default_factory=list)
    capacitor: list[Path] = field(default_factory=list)

    def apps(self) -> list[Path]:
        """Top-most app roots used for cross-platform checks."""
        candidates = sorted(set(self.flutter + self.react_native + self.capacitor + self.ios + self.android_modules), key=lambda p: len(p.parts))
        tops: list[Path] = []
        for candidate in candidates:
            if not any(top in candidate.parents for top in tops):
                tops.append(candidate)
        return tops


def detect(tree: Tree) -> AppRoots:
    roots = AppRoots()
    ios_dirs: set[Path] = set()
    for dirpath, dirnames, _ in os.walk(tree.root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        for d in list(dirnames):
            if d.endswith(".xcodeproj"):
                ios_dirs.add(Path(dirpath))
    for path in tree.files:
        name = path.name
        text = None
        if name == "project.yml":
            text = tree.read(path)
            if re.search(r"platform:\s*iOS", text):
                ios_dirs.add(path.parent)
        elif name in {"build.gradle", "build.gradle.kts"}:
            text = tree.read(path)
            applies = [line for line in text.splitlines()
                       if re.search(r"com\.android\.application|android\.application\b", line) and "apply false" not in line]
            if applies:
                roots.android_modules.append(path.parent)
        elif name == "pubspec.yaml":
            if re.search(r"^\s*flutter:", tree.read(path), re.M):
                roots.flutter.append(path.parent)
        elif name == "package.json":
            text = tree.read(path)
            if re.search(r'"(react-native|expo)"\s*:', text):
                roots.react_native.append(path.parent)
            if re.search(r'"@capacitor/core"\s*:', text):
                roots.capacitor.append(path.parent)
    # keep only the outermost iOS project dirs (an .xcodeproj inside a project.yml dir is the same app)
    for d in sorted(ios_dirs, key=lambda p: len(p.parts)):
        if not any(existing in d.parents for existing in roots.ios):
            roots.ios.append(d)
    return roots


# ---------------------------------------------------------------- iOS checks

PURPOSE_RULES = [
    # (code regex, cross-platform package regex, Info.plist key, label)
    (r"AVCaptureDevice|UIImagePickerController\.SourceType\.camera|\.sourceType\s*=\s*\.camera|DataScannerViewController", r"image_picker|\bcamera\b|expo-camera|react-native-vision-camera|react-native-image-picker|mobile_scanner|qr_code_scanner", "NSCameraUsageDescription", "camera"),
    # App Store Connect scans the binary: referencing UIImagePickerController or
    # PHPhotoLibrary at all (even in a plugin, even unused) needs the key
    # (ITMS-90683). file_picker links them unless the Podfile sets PICKER_MEDIA = false.
    (r"PHPhotoLibrary|PHAsset\.fetch|UIImagePickerController", r"photo_manager|expo-media-library|@react-native-camera-roll|\bimage_picker\b|\bfile_picker\b", "NSPhotoLibraryUsageDescription", "photo library"),
    (r"CLLocationManager", r"geolocator|\blocation:|expo-location|react-native-geolocation|@react-native-community/geolocation", "NSLocationWhenInUseUsageDescription", "location"),
    (r"AVAudioRecorder|requestRecordPermission|AVAudioApplication\.requestRecordPermission|SFSpeechAudioBufferRecognitionRequest", r"\brecord:|flutter_sound|speech_to_text|expo-av|react-native-audio-recorder|@react-native-voice", "NSMicrophoneUsageDescription", "microphone"),
    (r"CNContactStore", r"flutter_contacts|contacts_service|expo-contacts|react-native-contacts", "NSContactsUsageDescription", "contacts"),
    (r"LAContext\(\)|\.deviceOwnerAuthenticationWithBiometrics", r"local_auth|expo-local-authentication|react-native-biometrics", "NSFaceIDUsageDescription", "Face ID"),
    (r"ATTrackingManager", r"app_tracking_transparency|expo-tracking-transparency|react-native-tracking-transparency", "NSUserTrackingUsageDescription", "tracking (ATT)"),
    (r"EKEventStore", r"device_calendar|expo-calendar|react-native-calendar-events", "NSCalendarsUsageDescription", "calendar"),
    (r"SFSpeechRecognizer", r"speech_to_text|@react-native-voice", "NSSpeechRecognitionUsageDescription", "speech recognition"),
    (r"CBCentralManager|CBPeripheralManager", r"flutter_blue|flutter_reactive_ble|react-native-ble", "NSBluetoothAlwaysUsageDescription", "Bluetooth"),
    (r"HKHealthStore", r"\bhealth:|react-native-health", "NSHealthShareUsageDescription", "HealthKit"),
]

REQUIRED_REASON_RULES = [
    (r"\bUserDefaults\b|@AppStorage|NSUserDefaults", "NSPrivacyAccessedAPICategoryUserDefaults", "UserDefaults"),
    (r"\.creationDate\b|\.modificationDate\b|contentModificationDate|creationDateKey|NSFileCreationDate|NSFileModificationDate|attributesOfItem\(", "NSPrivacyAccessedAPICategoryFileTimestamp", "file timestamp"),
    (r"systemUptime|mach_absolute_time", "NSPrivacyAccessedAPICategorySystemBootTime", "system boot time"),
    (r"volumeAvailableCapacity|NSFileSystemFreeSize|systemFreeSize", "NSPrivacyAccessedAPICategoryDiskSpace", "disk space"),
    (r"activeInputModes", "NSPrivacyAccessedAPICategoryActiveKeyboards", "active keyboards"),
]

THIRD_PARTY_LOGIN = r"GIDSignIn|GoogleSignIn\b|FBSDKLoginKit|LoginManager\(\)|google_sign_in|@react-native-google-signin|flutter_facebook_auth|react-native-fbsdk|expo-auth-session/providers/google|TwitterKit|LineSDK|SnapKit\b"
APPLE_LOGIN = r"ASAuthorizationAppleIDProvider|SignInWithAppleButton|sign_in_with_apple|expo-apple-authentication|react-native-apple-authentication|com\.apple\.developer\.applesignin"
TRACKING_SDK = r"advertisingIdentifier|ASIdentifierManager|AppsFlyerLib|\bAdjust\.appDidLaunch|FBSDKCoreKit|GADMobileAds|GoogleMobileAds|google_mobile_ads|react-native-google-mobile-ads|appsflyer|adjust_sdk"
APPLE_BILLING = r"Product\.products\(|SKProductsRequest|SKPaymentQueue|Transaction\.updates|\.purchase\(\s*options|in_app_purchase|react-native-iap|expo-in-app-purchases|RevenueCat|purchases_flutter|react-native-purchases"
EXTERNAL_PAY = r"\bStripe\b|stripe_ios|flutter_stripe|@stripe/stripe-react-native|PayPal|Braintree|checkout\.stripe\.com"


def native_dependency_files(tree: Tree, root: Path, app_root: Path) -> list[Path]:
    """Native iOS sources of the app's dependencies, which the main walk skips.

    App Store Connect checks the compiled binary, so an API referenced only
    inside a plugin still needs its purpose string. Covers Flutter plugins
    (listed in .flutter-plugins-dependencies, usually in the pub cache) and an
    installed ios/Pods folder.
    """
    dirs: list[Path] = []
    for base in {app_root, root, root.parent}:
        deps = base / ".flutter-plugins-dependencies"
        if deps.is_file():
            try:
                plugins = json.loads(deps.read_text(encoding="utf-8")).get("plugins", {})
            except (OSError, ValueError):
                plugins = {}
            for plugin in plugins.get("ios", []) or []:
                path = Path(plugin.get("path", ""))
                dirs += [path / "ios", path / "darwin"]
    for base in {root, app_root, app_root / "ios"}:
        dirs.append(base / "Pods")
    files: list[Path] = []
    seen: set[Path] = set()
    for directory in dirs:
        if not directory.is_dir() or directory in seen:
            continue
        seen.add(directory)
        for dirpath, dirnames, filenames in os.walk(directory):
            dirnames[:] = [d for d in dirnames if d not in {"Target Support Files", "Headers", ".git"} and not d.endswith(".xcframework") and not d.endswith(".framework")]
            for name in filenames:
                if name.endswith((".m", ".mm", ".swift")):
                    files.append(Path(dirpath) / name)
    return files


def check_ios(report: Report, tree: Tree, root: Path, app_root: Path, stores: set[str]) -> None:
    if "apple" not in stores:
        return
    files = tree.under(root)
    app_files = tree.under(app_root)
    swift = [p for p in code_files(files) if p.suffix in {".swift", ".m", ".mm"}]
    plist_corpus = [p for p in app_files if p.name in {"Info.plist", "project.yml", "project.pbxproj", "app.json", "InfoPlist.strings", "InfoPlist.xcstrings", "Info.plist.in"} or fnmatch.fnmatch(p.name, "app.config.*")]
    plist_text = "\n".join(tree.read(p) for p in plist_corpus)
    deps_text = "\n".join(tree.read(p) for p in app_files if p.name in {"pubspec.yaml", "package.json", "Podfile", "Package.swift", "project.yml"})
    where = rel(report_root(report), root)

    # Privacy manifest
    manifests = [p for p in files if p.suffix == ".xcprivacy"]
    manifest_text = "\n".join(tree.read(p) for p in manifests) + ("\n" + plist_text if "privacyManifests" in plist_text else "")
    if not manifests and "privacyManifests" not in plist_text:
        report.add(Finding("IOS-PRIVACY-MANIFEST", "CRITICAL", ["apple"], "No PrivacyInfo.xcprivacy in the iOS app",
                           "Add PrivacyInfo.xcprivacy to the app target with NSPrivacyTracking, NSPrivacyCollectedDataTypes and NSPrivacyAccessedAPITypes (Expo: ios.privacyManifests in app.json).",
                           file=where))
    for pattern, category, label in REQUIRED_REASON_RULES:
        hit = tree.search(re.compile(pattern), swift)
        if hit and category not in manifest_text:
            report.add(Finding("IOS-REQUIRED-REASON-API", "HIGH", ["apple"], f"Uses a required-reason API ({label}) not declared in the privacy manifest",
                               f"Add {category} with an approved reason code to NSPrivacyAccessedAPITypes (ITMS-91053).",
                               file=rel(report_root(report), hit[0]), line=hit[1]))

    # Purpose strings
    native = native_dependency_files(tree, root, app_root)
    picker_media_off = re.search(r"PICKER_MEDIA\s*=\s*false", deps_text) is not None
    for code_rx, pkg_rx, key, label in PURPOSE_RULES:
        if key in plist_text:
            continue
        hit = tree.search(re.compile(code_rx), swift)
        dep_hit = None
        if not hit:
            dep_files = native
            if key == "NSPhotoLibraryUsageDescription" and picker_media_off:
                dep_files = [p for p in native if "file_picker" not in str(p)]
            dep_hit = tree.search(re.compile(code_rx), dep_files)
        pkg_hit = None
        if not hit and not dep_hit:
            deps_for_rule = deps_text
            if key == "NSPhotoLibraryUsageDescription" and picker_media_off:
                deps_for_rule = re.sub(r"\bfile_picker\b", "", deps_text)
            pkg_hit = re.search(pkg_rx, deps_for_rule)
        if hit or dep_hit or pkg_hit:
            if hit:
                src, line, why = rel(report_root(report), hit[0]), hit[1], f"Uses {label}"
            elif dep_hit:
                src, line = str(dep_hit[0]), dep_hit[1]
                why = f"A native dependency references {label} APIs ({dep_hit[2]})"
            else:
                src, line, why = "dependencies", 0, f"Uses {label} (package {pkg_hit.group(0)})"
            report.add(Finding("IOS-PURPOSE-STRING", "CRITICAL", ["apple"], f"{why} but {key} is missing",
                               f"Add {key} to Info.plist (or project.yml / app.json infoPlist) with a specific, localized explanation. App Store Connect rejects the upload (ITMS-90683) even when the API is only linked by a library and never called; missing keys also crash the app (5.1.1).",
                               file=src, line=line))
    for match in re.finditer(r"<key>(NS\w+UsageDescription)</key>\s*<string>([^<]*)</string>|(NS\w+UsageDescription):\s*[\"']?([^\n\"']*)", plist_text):
        key = match.group(1) or match.group(3)
        value = (match.group(2) if match.group(1) else match.group(4)) or ""
        if value.startswith("$(") or value.strip() == "":
            continue
        if len(value.strip()) < 25:
            report.add(Finding("IOS-VAGUE-PURPOSE", "MEDIUM", ["apple"], f"{key} text is very short: \"{value.strip()}\"",
                               "Explain what is accessed and why, with an example (e.g. 'The app uses the camera to scan a document into your prompt.')."))

    if "ITSAppUsesNonExemptEncryption" not in plist_text:
        report.add(Finding("IOS-ENCRYPTION-FLAG", "MEDIUM", ["apple"], "ITSAppUsesNonExemptEncryption not set",
                           "Set ITSAppUsesNonExemptEncryption = NO if you only use HTTPS/OS crypto; avoids the export-compliance question on every build.", file=where))
    if re.search(r"NSAllowsArbitraryLoads</key>\s*<true/>|NSAllowsArbitraryLoads:\s*(true|YES)", plist_text):
        report.add(Finding("IOS-ATS-DISABLED", "HIGH", ["apple"], "App Transport Security disabled (NSAllowsArbitraryLoads)",
                           "Use HTTPS everywhere or add narrow NSExceptionDomains; review asks for justification."))

    all_ios_code = "\n".join(tree.read(p) for p in code_files(app_files)) + "\n" + deps_text + "\n" + plist_text + "\n" + "\n".join(tree.read(p) for p in files if p.suffix == ".entitlements")
    if re.search(THIRD_PARTY_LOGIN, all_ios_code) and not re.search(APPLE_LOGIN, all_ios_code):
        report.add(Finding("IOS-SIGN-IN-WITH-APPLE", "CRITICAL", ["apple"], "Third-party login offered without Sign in with Apple",
                           "Add Sign in with Apple (Guideline 4.8) with equal prominence, plus the entitlement and backend audience."))
    if re.search(TRACKING_SDK, all_ios_code) and not re.search(r"ATTrackingManager|app_tracking_transparency|expo-tracking-transparency|react-native-tracking-transparency", all_ios_code):
        report.add(Finding("IOS-ATT-MISSING", "HIGH", ["apple"], "Tracking/ads SDK present without App Tracking Transparency",
                           "Request ATT before tracking (NSUserTrackingUsageDescription + ATTrackingManager) or configure the SDK not to track; answer App Privacy 'tracking' accordingly (5.1.2)."))
    if re.search(EXTERNAL_PAY, all_ios_code) and not re.search(APPLE_BILLING, all_ios_code):
        report.add(Finding("IOS-EXTERNAL-PAYMENTS", "MEDIUM", ["apple"], "External payment SDK without StoreKit",
                           "Allowed only for physical goods/services. Digital content or features must use In-App Purchase (3.1.1)."))
    if re.search(r"UISupportedInterfaceOrientations~ipad|TARGETED_DEVICE_FAMILY\s*[=:]\s*\"?1,2|deviceFamily|supportsTablet\"?\s*:\s*true", plist_text):
        report.add(Finding("IOS-IPAD-SUPPORT", "INFO", ["apple"], "App supports iPad",
                           "Test layouts on iPad (2.4.1) and upload 13\" iPad screenshots."))


def report_root(report: Report) -> Path:
    return Path(report.project)


# ---------------------------------------------------------------- Android checks

SENSITIVE_PERMISSIONS = {
    "READ_SMS": "SMS & Call Log policy — declaration required, only default SMS/assistant apps",
    "SEND_SMS": "SMS & Call Log policy — declaration required",
    "RECEIVE_SMS": "SMS & Call Log policy — declaration required",
    "READ_CALL_LOG": "SMS & Call Log policy — declaration required",
    "WRITE_CALL_LOG": "SMS & Call Log policy — declaration required",
    "PROCESS_OUTGOING_CALLS": "SMS & Call Log policy — declaration required",
    "ACCESS_BACKGROUND_LOCATION": "Background location — declaration + video, prominent disclosure",
    "MANAGE_EXTERNAL_STORAGE": "All files access — declaration, only file managers/backup apps",
    "QUERY_ALL_PACKAGES": "Package visibility — declaration; use <queries> instead",
    "REQUEST_INSTALL_PACKAGES": "Install packages — declaration, restricted use",
    "BIND_ACCESSIBILITY_SERVICE": "Accessibility API — declaration + disclosure",
    "READ_MEDIA_IMAGES": "Photo & video permissions — declaration; prefer the Photo Picker",
    "READ_MEDIA_VIDEO": "Photo & video permissions — declaration; prefer the Photo Picker",
    "USE_EXACT_ALARM": "Exact alarms — only alarm/calendar apps",
    "USE_FULL_SCREEN_INTENT": "Full-screen intent — only calling/alarm apps, declaration",
    "READ_CONTACTS": "Personal data — prominent disclosure; consider the contact picker",
    "READ_PHONE_STATE": "Device identifiers — justify or remove",
    "BODY_SENSORS": "Health — declaration",
    "ACTIVITY_RECOGNITION": "Health/fitness — justify",
    "SYSTEM_ALERT_WINDOW": "Overlay — justify; reviewed for tapjacking",
}
DEPRECATED_STORAGE = {"READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE"}

HARD_GMS = [
    (r"com\.google\.android\.gms:play-services-(?!base\b)[\w-]+", "Google Play services"),
    (r"com\.google\.firebase:firebase-messaging", "Firebase Cloud Messaging (push)"),
    (r"com\.google\.android\.gms:play-services-maps|com\.google\.maps\.android", "Google Maps"),
    (r"com\.android\.billingclient:billing", "Google Play Billing"),
    (r"com\.google\.android\.play:[\w-]+", "Play Core (review/update/asset delivery)"),
    (r"androidx\.credentials:credentials-play-services-auth", "Credential Manager Play services backend (Google Sign-In)"),
    (r"com\.google\.android\.gms:play-services-auth", "Google Sign-In"),
    (r"com\.google\.android\.gms:play-services-ads|com\.google\.android\.gms:play-services-ads-lite", "AdMob"),
]
SOFT_GMS = [
    (r"com\.google\.android\.libraries\.identity\.googleid:googleid", "Google ID token library"),
    (r"com\.google\.firebase:firebase-(analytics|crashlytics|auth|firestore|database|config)[\w-]*", "Firebase (partly GMS-dependent)"),
    (r"com\.google\.firebase:firebase-bom", "Firebase BoM"),
]


def parse_version_catalog(tree: Tree, project_root: Path) -> dict[str, str]:
    """Maps `libs.foo.bar` accessors to `group:name` coordinates from gradle/libs.versions.toml."""
    catalog: dict[str, str] = {}
    for path in tree.files:
        if path.name != "libs.versions.toml":
            continue
        section = ""
        for line in tree.read(path).splitlines():
            stripped = line.strip()
            if stripped.startswith("["):
                section = stripped.strip("[]")
                continue
            if section != "libraries":
                continue
            m = re.match(r'([\w.-]+)\s*=\s*(.+)', stripped)
            if not m:
                continue
            alias, value = m.group(1), m.group(2)
            coord = None
            mm = re.search(r'module\s*=\s*"([^"]+)"', value)
            if mm:
                coord = mm.group(1)
            else:
                g = re.search(r'group\s*=\s*"([^"]+)"', value)
                n = re.search(r'name\s*=\s*"([^"]+)"', value)
                if g and n:
                    coord = f"{g.group(1)}:{n.group(1)}"
                else:
                    s = re.match(r'"([^":]+:[^":]+)(:[^"]*)?"', value)
                    if s:
                        coord = s.group(1)
            if coord:
                catalog["libs." + re.sub(r"[-_]", ".", alias)] = coord
    return catalog


def gradle_dependencies(text: str, catalog: dict[str, str]) -> list[tuple[str, str, int]]:
    """Returns (configuration, coordinate, line) for dependency lines."""
    deps = []
    for index, line in enumerate(text.splitlines(), start=1):
        m = re.match(r'\s*"?([A-Za-z]+)"?\s*\(?\s*(?:platform\()?\s*(.+)', line)
        if not m:
            continue
        config, rest = m.group(1), m.group(2)
        if not (config.endswith("mplementation") or config.endswith("Api") or config == "api" or config.endswith("ompileOnly")):
            continue
        lit = re.search(r'["\']([\w.\-]+:[\w.\-]+)(?::[^"\']*)?["\']', rest)
        if lit:
            deps.append((config, lit.group(1), index))
            continue
        acc = re.search(r'(libs(?:\.[\w]+)+)', rest)
        if acc and acc.group(1) in catalog:
            deps.append((config, catalog[acc.group(1)], index))
    return deps


def target_requirement(as_of: dt.date) -> int:
    # Google Play: API 35 for new apps/updates since 2025-08-31, API 36 from 2026-08-31.
    if as_of >= dt.date(2027, 8, 31):
        return 37
    if as_of >= dt.date(2026, 8, 31):
        return 36
    if as_of >= dt.date(2025, 8, 31):
        return 35
    return 34


def parse_manifest(path: Path) -> ET.Element | None:
    try:
        return ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return None


def check_android(report: Report, tree: Tree, module: Path, app_root: Path, stores: set[str], as_of: dt.date, catalog: dict[str, str]) -> None:
    root_dir = report_root(report)
    files = tree.under(module)
    gradle_file = next((p for p in [module / "build.gradle.kts", module / "build.gradle"] if p.exists()), None)
    gradle = tree.read(gradle_file) if gradle_file else ""
    gfile = rel(root_dir, gradle_file) if gradle_file else rel(root_dir, module)
    android_stores = [s for s in ("play", "huawei") if s in stores]
    if not android_stores:
        return

    # targetSdk
    m = re.search(r"targetSdk(?:Version)?\s*(?:=|\s)\s*(\w[\w.]*)", gradle)
    required = target_requirement(as_of)
    if m and m.group(1).isdigit():
        target = int(m.group(1))
        if target < required:
            report.add(Finding("AND-TARGET-SDK", "CRITICAL", ["play"] + (["huawei"] if "huawei" in stores else []),
                               f"targetSdk {target} is below the Play requirement ({required} as of {as_of.isoformat()})",
                               f"Raise targetSdk to {required}+ and test the behavior changes.", file=gfile, line=gradle.count("\n", 0, m.start()) + 1))
        elif target == required and required < 37:
            report.add(Finding("AND-TARGET-SDK-NEXT", "INFO", ["play"], f"targetSdk {target} meets today's floor; Play raises it every August",
                               "Plan the next targetSdk bump before 31 August.", file=gfile))
    else:
        report.add(Finding("AND-TARGET-SDK-UNKNOWN", "INFO", android_stores, "targetSdk not set literally (variable or Flutter/RN default)",
                           f"Confirm the resolved targetSdk is ≥ {required}.", file=gfile))

    if not re.search(r"versionCode", gradle) and not (module.parent / "pubspec.yaml").exists():
        report.add(Finding("AND-VERSION-CODE", "INFO", android_stores, "versionCode not found in module Gradle file",
                           "Make sure versionCode increases on every upload to each store.", file=gfile))

    # Signing
    if not re.search(r"signingConfig", gradle):
        report.add(Finding("AND-RELEASE-SIGNING", "HIGH", android_stores, "No release signingConfig",
                           "Add a release signingConfig reading a keystore from a gitignored keystore.properties.", file=gfile))
    lit_pw = re.search(r'(?<![\w."\'(])(storePassword|keyPassword)\s*=?\s*["\'][^"\'$\n]{3,}["\']', gradle)
    if lit_pw:
        report.add(Finding("AND-SIGNING-SECRET", "HIGH", android_stores, "Keystore password hard-coded in Gradle",
                           "Move passwords to keystore.properties / environment variables and rotate the key if this was pushed.",
                           file=gfile, line=gradle.count("\n", 0, lit_pw.start()) + 1))

    release_block = re.search(r"(release\s*\{.*?\n\s*\})", gradle, re.S)
    if release_block and not re.search(r"isMinifyEnabled\s*=\s*true|minifyEnabled\s+true", release_block.group(1)):
        report.add(Finding("AND-MINIFY", "MEDIUM", android_stores, "Release build not minified (R8)",
                           "Enable isMinifyEnabled/isShrinkResources with keep rules; smaller and harder to tamper.", file=gfile))
    has_native = any(p.suffix == ".so" for p in files) or re.search(r"externalNativeBuild|ndkVersion", gradle) is not None
    if not re.search(r"debugSymbolLevel", gradle):
        report.add(Finding("AND-DEBUG-SYMBOLS", "MEDIUM" if has_native else "INFO", ["play"], "Native debug symbols not configured",
                           "Add ndk { debugSymbolLevel = \"FULL\" } to the release build type (Play warns otherwise).", file=gfile))
    if has_native:
        report.add(Finding("AND-16KB-PAGES", "HIGH", ["play"], "Module contains native code",
                           "Verify 16 KB page-size compatibility (NDK r28+/AGP 8.5.1+, updated native SDKs) — required for targetSdk ≥ 35.", file=gfile))

    # Manifests
    manifests = [p for p in files if p.name == "AndroidManifest.xml"]
    merged = [p for p in (module / "build" / "intermediates").rglob("AndroidManifest.xml")
              if "merged_manifest" in str(p) and "release" in str(p).lower()] if (module / "build" / "intermediates").exists() else []
    permissions: dict[str, str] = {}
    for manifest in manifests + merged:
        el = parse_manifest(manifest)
        if el is None:
            continue
        label = rel(root_dir, manifest) + (" (merged, includes SDKs)" if manifest in merged else "")
        is_flavor = "src" in manifest.parts and manifest.parent.name not in {"main"} and manifest not in merged
        for perm in el.iter("uses-permission"):
            name = perm.get(ANDROID_NS + "name", "")
            if perm.get(TOOLS_NS + "node") == "remove" or is_flavor:
                continue
            permissions.setdefault(name.split(".")[-1], label)
        app = el.find("application")
        if app is not None and manifest not in merged:
            if app.get(ANDROID_NS + "usesCleartextTraffic") == "true":
                report.add(Finding("AND-CLEARTEXT", "HIGH", android_stores, "usesCleartextTraffic=\"true\"",
                                   "Use HTTPS only (Huawei App Security and Play security review flag cleartext).", file=label))
            if app.get(ANDROID_NS + "allowBackup") == "true" and not (app.get(ANDROID_NS + "dataExtractionRules") or app.get(ANDROID_NS + "fullBackupContent")):
                report.add(Finding("AND-BACKUP", "MEDIUM", android_stores, "allowBackup=true without backup rules",
                                   "Add dataExtractionRules/fullBackupContent that exclude tokens and secrets, or set allowBackup=false.", file=label))
            for comp in list(app):
                if comp.tag in {"activity", "activity-alias", "service", "receiver", "provider"} and comp.find("intent-filter") is not None and comp.get(ANDROID_NS + "exported") is None:
                    report.add(Finding("AND-EXPORTED", "CRITICAL", android_stores, f"<{comp.tag} {comp.get(ANDROID_NS + 'name', '')}> has an intent-filter but no android:exported",
                                       "Set android:exported explicitly (required for targetSdk 31+; upload is rejected).", file=label))
                if comp.tag == "service" and comp.get(ANDROID_NS + "foregroundServiceType") is None and any(p.startswith("FOREGROUND_SERVICE") for p in permissions):
                    report.add(Finding("AND-FGS-TYPE", "HIGH", ["play"], f"Service {comp.get(ANDROID_NS + 'name', '')} without foregroundServiceType",
                                       "Declare foregroundServiceType and the matching FOREGROUND_SERVICE_* permission; justify it in Play Console.", file=label))
    for name, label in sorted(permissions.items()):
        if name in SENSITIVE_PERMISSIONS:
            report.add(Finding("AND-SENSITIVE-PERMISSION", "HIGH", android_stores, f"{name}: {SENSITIVE_PERMISSIONS[name]}",
                               "Remove it if not core (tools:node=\"remove\" for SDK-merged ones) or complete the Play permission declaration; explain it in Huawei privacy section.", file=label))
        elif name in DEPRECATED_STORAGE:
            report.add(Finding("AND-LEGACY-STORAGE", "MEDIUM", android_stores, f"{name} is obsolete on modern Android",
                               "Use scoped storage / Photo Picker; add maxSdkVersion if kept for old devices.", file=label))
        elif name == "AD_ID":
            report.add(Finding("AND-AD-ID", "INFO", ["play"], "AD_ID permission present",
                               "Answer the Advertising ID declaration (Yes) and the Data safety 'Device or other IDs'; remove it if you show no ads.", file=label))

    # Huawei readiness
    if "huawei" in stores:
        check_huawei(report, tree, module, app_root, gradle, gfile, catalog)


def check_huawei(report: Report, tree: Tree, module: Path, app_root: Path, gradle: str, gfile: str, catalog: dict[str, str]) -> None:
    root_dir = report_root(report)
    deps = gradle_dependencies(gradle, catalog)
    has_flavor = re.search(r'create\(\s*"huawei"\s*\)|\bhuawei\s*\{|"huawei"\s*\{', gradle) is not None
    hard, soft = [], []
    for config, coord, line in deps:
        scoped_other = config.lower().startswith(("play", "google", "gms"))
        if scoped_other:
            continue
        for rx, label in HARD_GMS:
            if re.search(rx, coord):
                hard.append((config, coord, line, label))
                break
        else:
            for rx, label in SOFT_GMS:
                if re.search(rx, coord):
                    soft.append((config, coord, line, label))
                    break
    if re.search(r"com\.google\.gms\.google-services|google\.services\b|libs\.plugins\.google\.services", gradle):
        hard.append(("plugin", "com.google.gms.google-services", 0, "google-services plugin (Firebase/GMS config)"))

    if hard and not has_flavor:
        listed = ", ".join(sorted({h[3] for h in hard}))
        report.add(Finding("HW-NO-STORE-FLAVOR", "CRITICAL", ["huawei"], f"GMS dependencies in the only build ({listed})",
                           "Create play/huawei product flavors; move GMS deps to playImplementation, use HMS kits (Push, Account, IAP, Map, Location) or hide the feature in the huawei flavor.",
                           file=gfile))
    else:
        for config, coord, line, label in hard:
            report.add(Finding("HW-GMS-DEPENDENCY", "HIGH", ["huawei"], f"{label} ({coord}) via '{config}' is included in the Huawei build",
                               "Move it to playImplementation or make the feature optional at runtime on devices without GMS.", file=gfile, line=line))
    for config, coord, line, label in soft:
        report.add(Finding("HW-GMS-SOFT", "MEDIUM", ["huawei"], f"{label} ({coord}) shared with the Huawei build",
                           "Fine if inert without GMS — make sure the related UI (e.g. Google button) is hidden on the huawei flavor.", file=gfile, line=line))

    app_files = tree.under(app_root)
    code = code_files(app_files)
    if re.search(r"com\.android\.billingclient|billingclient:billing|in_app_purchase|react-native-iap", "\n".join(c[1] for c in deps) + "\n".join(tree.read(p) for p in app_files if p.name in {"pubspec.yaml", "package.json"})) \
            and not re.search(r"com\.huawei\.hms:iap", gradle):
        report.add(Finding("HW-IAP", "CRITICAL", ["huawei"], "Google Play Billing without HUAWEI IAP",
                           "Virtual goods on AppGallery must use HUAWEI IAP (IAP Kit) in the huawei flavor, or ship the Huawei build without paid content.", file=gfile))
    google_ui = tree.search(re.compile(r"GetGoogleIdOption|GetSignInWithGoogleOption|GoogleSignIn\b|GoogleSignInClient|google_sign_in|@react-native-google-signin"), code)
    if google_ui and not tree.search(re.compile(r"(?i)huawei|BuildConfig\.STORE|isGmsAvailable|GoogleApiAvailability"), code):
        report.add(Finding("HW-GOOGLE-SIGNIN-UI", "HIGH", ["huawei"], "Google Sign-In used with no store/GMS check",
                           "Hide the Google button when the store is Huawei or GMS is unavailable; offer email or HUAWEI ID instead.",
                           file=rel(root_dir, google_ui[0]), line=google_ui[1]))
    market = tree.search(re.compile(r"market://details|play\.google\.com/store/apps"), code)
    if market and not tree.search(re.compile(r"appmarket://|appgallery\.huawei\.com|appgallery\.cloud\.huawei\.com"), code):
        report.add(Finding("HW-STORE-LINKS", "HIGH", ["huawei"], "Store links point only to Google Play",
                           "Use appmarket://details?id=<package> and https://appgallery.huawei.com/app/C<appId> in the huawei build.",
                           file=rel(root_dir, market[0]), line=market[1]))
    strings_files = [p for p in app_files if (p.suffix == ".xml" and "values" in p.parent.name) or p.suffix in {".arb", ".strings", ".xcstrings"} or (p.suffix == ".json" and "lang" in str(p).lower())]
    wording = tree.search(re.compile(r"Google Play|جوجل بلاي|غوغل بلاي|Get it on Google"), [p for p in strings_files if "huawei" not in str(p).lower()] + code)
    if wording:
        report.add(Finding("HW-GOOGLE-WORDING", "MEDIUM", ["huawei"], f"'{wording[2]}' appears in app text",
                           "AppGallery rejects references to other stores — override the string in the huawei flavor.", file=rel(root_dir, wording[0]), line=wording[1]))
    if re.search(r"com\.huawei\.(hms|agconnect)", gradle) and not any(p.name == "agconnect-services.json" for p in tree.under(module)):
        report.add(Finding("HW-AGCONNECT-JSON", "HIGH", ["huawei"], "HMS dependencies without agconnect-services.json",
                           "Download agconnect-services.json from AppGallery Connect into the module (or src/huawei/).", file=gfile))


# ---------------------------------------------------------------- cross-platform checks

AUTH_SIGNALS = r"(?i)\b(sign[\s_-]?in|log[\s_-]?in|sign[\s_-]?up|register|createUserWith|signInWith|ASAuthorizationAppleIDProvider|FirebaseAuth|GoogleSignIn)\b"
DELETE_SIGNALS = r"(?i)delete[\s_-]?(my[\s_-]?)?account|account[\s_-]?deletion|deleteUser|delete_me|destroyAccount|removeAccount|حذف\s*الحساب|حذف\s*حسابي|\.delete\(\s*\)\s*;?\s*//\s*account|DELETE[^\n]{0,60}[\"'/]me[\"'/]|delete\(\s*[\"'](/?api/)?(v\d/)?me[\"']"
PAID_SIGNALS = r"(?i)[\"'>]\s*[^\"'<\n]{0,40}\b(upgrade to pro|go pro|get pro|premium plan|subscribe now|unlock (all|pro|premium)|buy credits|remove ads)\b"
BILLING_ANY = APPLE_BILLING + r"|billingclient|com\.huawei\.hms:iap|RevenueCat"
SECRETS = r"sk_live_[0-9A-Za-z]{10,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-proj-[A-Za-z0-9_-]{20,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"
AI_SDKS = (r"api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|aiplatform\.googleapis\.com|api\.deepseek\.com|api\.x\.ai|api\.mistral\.ai|openrouter\.ai/api"
           r"|\"openai\"\s*:|@anthropic-ai/sdk|dart_openai|google_generative_ai|@google/generative-ai|@google/genai|com\.aallam\.openai|com\.openai:openai-java"
           r"|com\.anthropic:anthropic-java|com\.google\.ai\.client\.generativeai|firebase-vertexai|firebase-ai\b|FirebaseAI|MacPaw/OpenAI|SwiftAnthropic|GoogleGenerativeAI")


def git_ignored(path: Path) -> bool:
    try:
        result = subprocess.run(["git", "check-ignore", "-q", str(path)], cwd=path.parent, capture_output=True, timeout=5)
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def check_cross(report: Report, tree: Tree, app_root: Path, stores: set[str]) -> None:
    root_dir = report_root(report)
    files = tree.under(app_root)
    code = code_files(files)
    texts = [p for p in files if p.suffix in CODE_EXT | {".xml", ".json", ".strings", ".xcstrings", ".arb"} and not _is_test(p)]
    where = rel(root_dir, app_root)
    store_list = sorted(stores)

    auth = tree.search(re.compile(AUTH_SIGNALS), code)
    deletion = tree.search(re.compile(DELETE_SIGNALS), texts)
    if auth and not deletion:
        report.add(Finding("X-ACCOUNT-DELETION", "CRITICAL", store_list, "Sign-in/sign-up found but no in-app account deletion",
                           "Add Account → Delete account (confirm, delete server-side, sign out) and a public /delete-account page. Apple 5.1.1(v), Play account deletion policy, AppGallery privacy review.",
                           file=rel(root_dir, auth[0]), line=auth[1]))
    elif auth:
        report.add(Finding("X-ACCOUNT-DELETION-OK", "INFO", store_list, "Account deletion flow detected",
                           "Make sure it deletes server-side data and that the web deletion URL is in Play Data safety and Huawei privacy section.",
                           file=rel(root_dir, deletion[0]), line=deletion[1]))

    if not tree.search(re.compile(r"(?i)privacy"), texts):
        report.add(Finding("X-PRIVACY-LINK", "HIGH", store_list, "No privacy policy link found in the app",
                           "Add a Settings/About row that opens the public privacy policy URL (all stores require it in-app).", file=where))

    paid = tree.search(re.compile(PAID_SIGNALS), texts)
    all_text_blob = "\n".join(tree.read(p) for p in files if p.suffix in CODE_EXT | {".gradle", ".kts", ".toml", ".json", ".yaml", ".yml"})
    if paid and not re.search(BILLING_ANY, all_text_blob):
        report.add(Finding("X-PAID-SIGNALS", "MEDIUM", store_list, f"Paid-looking wording without store billing: '{paid[2].strip()[:60]}'",
                           "Remove PRO/upgrade/credits UI if the app is free (Apple 2.1(b) business-model questions) or implement IAP/Play Billing/HUAWEI IAP.",
                           file=rel(root_dir, paid[0]), line=paid[1]))

    for path, line, match in tree.search_all(re.compile(SECRETS), [p for p in files if p.suffix in TEXT_EXT and p.suffix != ".md"])[:5]:
        report.add(Finding("X-SECRET-IN-SOURCE", "HIGH", store_list, f"Secret-looking value in source ({match[:12]}…)",
                           "Never ship server secrets in an app binary; move the call to your backend and rotate the key.",
                           file=rel(root_dir, path), line=line))
    for path in files:
        if path.suffix.lower() in {".jks", ".keystore", ".p12", ".p8", ".mobileprovision"} and not git_ignored(path):
            report.add(Finding("X-SIGNING-FILE-TRACKED", "HIGH", store_list, f"Signing/key file inside the project: {path.name}",
                               "Move it outside the repo (or gitignore it) and back it up securely.", file=rel(root_dir, path)))

    http_hits = tree.search_all(re.compile(r"[\"']http://(?!localhost|127\.0\.0\.1|10\.0\.2\.2|0\.0\.0\.0|schemas\.|www\.w3\.org|ns\.adobe|xmlpull|apple\.com/DTDs)[\w.-]+"), code)
    if http_hits:
        path, line, _ = http_hits[0]
        report.add(Finding("X-CLEARTEXT-URL", "MEDIUM", store_list, f"{len(http_hits)} plain http:// URL(s) in code",
                           "Use HTTPS (ATS on iOS, cleartext blocked on Android 9+, flagged by Huawei security review).", file=rel(root_dir, path), line=line))

    ai = tree.search(re.compile(AI_SDKS), code + [p for p in files if p.name in {"package.json", "pubspec.yaml"} or p.suffix in {".kts", ".gradle", ".toml"}])
    if ai:
        report.add(Finding("X-GENERATIVE-AI", "INFO", store_list, "App talks to a generative-AI service",
                           "Play: in-app reporting of offensive AI output. Apple 5.1.2(i): disclose the AI provider and get consent before sending personal data. Huawei: answer the Generative AI question (Yes) and expect extra review.",
                           file=rel(root_dir, ai[0]), line=ai[1]))
    ugc = tree.search(re.compile(r"(?i)\b(comment|post|chat|message|upload)s?\b.{0,30}\b(create|send|publish|submit)|createPost|sendMessage|postComment"), code)
    if ugc and not tree.search(re.compile(r"(?i)\breport\b|\bblock(ed)?[\s_-]?user|flag[\s_-]?content|إبلاغ|حظر"), texts):
        report.add(Finding("X-UGC-MODERATION", "HIGH", store_list, "Possible user-generated content without report/block",
                           "If users see each other's content: add report, block, filtering and terms (Apple 1.2, Play UGC, AppGallery content). Ignore if content is private.",
                           file=rel(root_dir, ugc[0]), line=ugc[1]))


# ---------------------------------------------------------------- URL check

USER_AGENTS = {
    "browser": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
    "googlebot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "curl": "curl/8.7.1",
    "java 8 (AppGallery checker)": "Java/1.8.0_292",
    "java 17": "Java/17.0.2",
    "okhttp": "okhttp/4.12.0",
}
JAVA_AGENTS = {"java 8 (AppGallery checker)", "java 17", "okhttp"}


def fetch(url: str, agent: str, timeout: float = 15.0) -> tuple[int, str, dict]:
    request = urllib.request.Request(url, headers={"User-Agent": agent, "Accept": "text/html,*/*"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(200_000).decode("utf-8", errors="ignore")
            return response.status, body, dict(response.headers)
    except urllib.error.HTTPError as error:
        body = error.read(50_000).decode("utf-8", errors="ignore") if error.fp else ""
        return error.code, body, dict(error.headers or {})
    except (urllib.error.URLError, OSError, ValueError) as error:
        return 0, str(error), {}


def check_urls(report: Report, urls: list[str]) -> None:
    for url in urls:
        if not url.lower().startswith("https://"):
            report.add(Finding("URL-NOT-HTTPS", "HIGH", ALL_STORES, f"{url} is not HTTPS", "Serve store URLs over HTTPS.", file=url))
        results = {name: fetch(url, ua) for name, ua in USER_AGENTS.items()}
        failed = {name: r for name, r in results.items() if r[0] != 200}
        if not failed:
            status, body, headers = results["browser"]
            ctype = {k.lower(): v for k, v in headers.items()}.get("content-type", "")
            if "pdf" in ctype:
                report.add(Finding("URL-PDF", "HIGH", ALL_STORES, f"{url} serves a PDF", "Use an HTML page for store URLs.", file=url))
            elif len(re.sub(r"<[^>]+>", " ", body).split()) < 80:
                report.add(Finding("URL-THIN", "MEDIUM", ALL_STORES, f"{url} has very little text (JS-rendered or empty?)",
                                   "Crawlers don't run JavaScript; render the policy text server-side.", file=url))
            else:
                report.add(Finding("URL-OK", "INFO", ALL_STORES, f"{url} returns 200 for browser, Googlebot, curl, Java 8/17 and okhttp agents", "", file=url))
            continue
        lowered = {name: {k.lower(): v for k, v in r[2].items()} for name, r in failed.items()}
        cloudflare = any("cloudflare" in h.get("server", "").lower() or "cf-mitigated" in h or "cf-ray" in h for h in lowered.values())
        summary = ", ".join(f"{name}: {r[0] or r[1][:60]}" for name, r in failed.items())
        all_failed = len(failed) == len(USER_AGENTS)
        fix = ("Allow non-browser agents on this path: Cloudflare → Security → Bots: turn off Bot Fight Mode, or WAF custom rule "
               "(URI Path equals this path) → Skip. AppGallery's URL checker uses a Java user agent (e.g. 'Java/1.8.0_x', which Cloudflare blocks as a known bot signature).") if cloudflare else \
              ("Make the page public (no login/geo-block/bot challenge) and return HTTP 200." if all_failed else
               "A firewall/CDN treats some agents differently — allow store crawlers on this path.")
        stores = ALL_STORES if all_failed else (["huawei"] if set(failed) <= JAVA_AGENTS else ALL_STORES)
        report.add(Finding("URL-BLOCKED", "CRITICAL", stores, f"{url} not reachable for: {summary}" + (" (Cloudflare)" if cloudflare else ""), fix, file=url))


# ---------------------------------------------------------------- profile & output


def build_profile(tree: Tree, roots: AppRoots) -> dict:
    blob = "\n".join(tree.read(p) for p in tree.files if p.name in {"package.json", "pubspec.yaml", "Podfile", "Package.swift", "project.yml", "libs.versions.toml"} or p.suffix in {".kts", ".gradle"})
    code_blob = "\n".join(tree.read(p) for p in code_files(tree.files)[:4000])
    everything = blob + "\n" + code_blob
    signals = {
        "sign_in": [n for n, rx in {"Apple": APPLE_LOGIN, "Google": r"googleid|GoogleSignIn|google_sign_in|GetGoogleIdOption|react-native-google-signin",
                                    "Facebook": r"FBSDKLoginKit|facebook", "Huawei ID": r"com\.huawei\.hms:hwid|account kit",
                                    "Firebase Auth": r"firebase-auth|FirebaseAuth|firebase_auth"}.items() if re.search(rx, everything, re.I)],
        "billing": [n for n, rx in {"StoreKit IAP": r"Product\.products\(|SKProductsRequest|SKPaymentQueue", "Play Billing": r"billingclient", "HUAWEI IAP": r"com\.huawei\.hms:iap",
                                    "RevenueCat": r"RevenueCat|purchases_flutter|react-native-purchases", "Stripe": r"\bstripe\b"}.items() if re.search(rx, everything, re.I)],
        "ads_analytics": [n for n, rx in {"AdMob": r"play-services-ads|GoogleMobileAds|google_mobile_ads", "Firebase Analytics": r"firebase-analytics|FirebaseAnalytics",
                                          "Crashlytics": r"crashlytics", "Sentry": r"sentry", "AppsFlyer": r"appsflyer", "HMS Analytics": r"hianalytics"}.items() if re.search(rx, everything, re.I)],
        "push": [n for n, rx in {"FCM": r"firebase-messaging|FirebaseMessaging|firebase_messaging", "APNs": r"registerForRemoteNotifications|UNUserNotificationCenter",
                                 "HMS Push": r"com\.huawei\.hms:push"}.items() if re.search(rx, everything)],
        "generative_ai": bool(re.search(AI_SDKS, everything)),
    }
    return signals


def print_text(report: Report, stores: set[str]) -> None:
    print(f"Store compliance scan — {report.project}")
    print(f"Platforms: {', '.join(report.platforms) or 'none detected'} | Stores: {', '.join(sorted(stores))}")
    prof = report.profile
    print(f"Sign-in: {', '.join(prof.get('sign_in', [])) or '-'} | Billing: {', '.join(prof.get('billing', [])) or '-'} | "
          f"Ads/analytics: {', '.join(prof.get('ads_analytics', [])) or '-'} | Push: {', '.join(prof.get('push', [])) or '-'} | "
          f"Gen-AI: {'yes' if prof.get('generative_ai') else 'no'}")
    print()
    counts = {s: 0 for s in SEVERITIES}
    for severity in SEVERITIES:
        items = [f for f in report.findings if f.severity == severity]
        counts[severity] = len(items)
        for f in items:
            loc = f" ({f.file}{':' + str(f.line) if f.line else ''})" if f.file else ""
            print(f"[{severity}] {f.id} [{'/'.join(f.stores)}] {f.title}{loc}")
            if f.fix:
                print(f"    fix: {f.fix}")
    print()
    print(f"Summary: {counts['CRITICAL']} critical, {counts['HIGH']} high, {counts['MEDIUM']} medium, {counts['INFO']} info")
    if counts["CRITICAL"]:
        print("BLOCKED. Fix every [CRITICAL] item, then re-run.")
    else:
        print("NO CRITICAL CODE FINDINGS. Now walk the store-console checklists (templates/release-checklist.md) — the scanner can't see those.")


def scan(project: Path, stores: set[str] | None, urls: list[str], as_of: dt.date) -> tuple[Report, set[str]]:
    tree = Tree(project)
    roots = detect(tree)
    report = Report(project=str(project))
    if roots.ios:
        report.platforms.append("iOS")
    if roots.android_modules:
        report.platforms.append("Android")
    for name, items in (("Flutter", roots.flutter), ("React Native/Expo", roots.react_native), ("Capacitor", roots.capacitor)):
        if items:
            report.platforms.append(name)
    if stores is None:
        stores = set()
        if roots.ios or roots.react_native or roots.flutter or roots.capacitor:
            stores.add("apple")
        if roots.android_modules or roots.react_native or roots.flutter or roots.capacitor:
            stores |= {"play", "huawei"}
        if not stores:
            stores = set(ALL_STORES)
    report.profile = build_profile(tree, roots)
    catalog = parse_version_catalog(tree, project)
    apps = roots.apps()

    def owner(path: Path) -> Path:
        return next((a for a in apps if a == path or a in path.parents), path)

    for ios_root in roots.ios:
        check_ios(report, tree, ios_root, owner(ios_root), stores)
    for module in roots.android_modules:
        check_android(report, tree, module, owner(module), stores, as_of, catalog)
    for rn in roots.react_native:
        if not any(rn in m.parents for m in roots.android_modules) and "play" in stores:
            report.add(Finding("X-EXPO-PREBUILD", "INFO", ["play", "huawei"], "No native android/ folder (managed Expo?)",
                               "Run `npx expo prebuild` to audit the generated native projects, or check app.json android.permissions/blockedPermissions.",
                               file=rel(project, rn)))
    seen_apps = []
    for app in apps:
        if app not in seen_apps:
            seen_apps.append(app)
            check_cross(report, tree, app, stores)
    if urls:
        check_urls(report, urls)
    if not report.platforms:
        report.add(Finding("NO-MOBILE-PROJECT", "HIGH", ALL_STORES, "No iOS/Android/Flutter/React Native/Capacitor project found",
                           "Point the scanner at the folder that contains the app project."))
    unique: dict[tuple, Finding] = {}
    for f in report.findings:
        if set(f.stores) & stores or not f.stores:
            unique.setdefault((f.id, f.title, f.file, f.line), f)
    report.findings = list(unique.values())
    order = {s: i for i, s in enumerate(SEVERITIES)}
    report.findings.sort(key=lambda f: (order[f.severity], f.id))
    return report, stores


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Apple / Google Play / Huawei AppGallery compliance scanner")
    parser.add_argument("project", type=Path)
    parser.add_argument("--stores", help="comma list: apple,play,huawei (default: detected)")
    parser.add_argument("--urls", nargs="*", default=[], help="public URLs to test with store crawler user agents")
    parser.add_argument("--json", action="store_true", help="print JSON")
    parser.add_argument("--as-of", help="evaluate date-based rules as of YYYY-MM-DD (default today)")
    args = parser.parse_args(argv)

    project = args.project.resolve()
    if not project.is_dir():
        print(f"Not a directory: {project}", file=sys.stderr)
        return 3
    stores = None
    if args.stores:
        stores = {s.strip().lower() for s in args.stores.split(",") if s.strip()}
        unknown = stores - set(ALL_STORES)
        if unknown:
            print(f"Unknown store(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            return 3
    as_of = dt.date.fromisoformat(args.as_of) if args.as_of else dt.date.today()
    report, stores = scan(project, stores, args.urls, as_of)

    if args.json:
        print(json.dumps({"project": report.project, "platforms": report.platforms, "stores": sorted(stores),
                          "profile": report.profile, "findings": [asdict(f) for f in report.findings]}, ensure_ascii=False, indent=2))
    else:
        print_text(report, stores)
    severities = {f.severity for f in report.findings}
    return 2 if "CRITICAL" in severities else 1 if "HIGH" in severities else 0


if __name__ == "__main__":
    sys.exit(main())
