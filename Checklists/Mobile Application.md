---
tags:
  - hack-notes
  - checklist
  - mobile
---

# Mobile Application Testing Checklist

> Full-stack methodology for Android and iOS app assessments, structured on OWASP MASVS and MASTG. Covers static and dynamic analysis, network, local storage, platform interaction (IPC), resilience, auth, and the backend handoff. Use for native, Flutter, and React Native apps. Pair with [Mobile App Testing](../Cheatsheets/Mobile%20App%20Testing.md) for command detail.

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. Static Analysis](#2-static-analysis)
- [3. Dynamic Analysis Setup](#3-dynamic-analysis-setup)
- [4. Network Communication](#4-network-communication)
- [5. Local Data Storage](#5-local-data-storage)
- [6. Platform Interaction](#6-platform-interaction)
- [7. Code Quality and Resilience](#7-code-quality-and-resilience)
- [8. Authentication and Session](#8-authentication-and-session)
- [9. Backend and API Handoff](#9-backend-and-api-handoff)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

### Scope and Authorization
- [ ] **Confirm the platforms in scope:** Android, iOS, or both, and which app variants (consumer, enterprise/MDM, white-label, kiosk).
- [ ] **Confirm build channel:** App store release vs sideloaded debug/staging build. Prefer a debuggable staging build plus the production store build for comparison.
- [ ] **Get the right artifacts:** Android APK or AAB (and split APKs), iOS IPA. For App Store iOS, confirm you can obtain a decrypted IPA (see acquisition in Static Analysis).
- [ ] **Define backend scope:** Which API hosts, environments (prod/UAT), and third-party services are in scope vs out of scope. Mobile findings usually chain into the API; agree the boundary up front.
- [ ] **Confirm MASVS profile/target:** MASVS-L1 (standard) vs L1+R or L2+R (resilience) per the threat model. Resilience (R) controls are only required when the app handles high-value assets or runs on untrusted devices.
- [ ] **Confirm rules of engagement:** Test windows, rate limits, whether prod data is in scope, PII handling, and a destructive-action allowlist (no payment/transfer in prod).

### Test Devices and Lab
- [ ] **Provision a rooted Android device or emulator:** Physical Pixel with Magisk (rooted) plus a rootless option, or an AVD/Genymotion image with a writable system. Keep at least two API levels (one recent: Android 14/15, one older for legacy behavior).
- [ ] **Provision a jailbroken iOS device:** palera1n (checkm8 A9-A11, rootless), Dopamine (A12-A16 / iOS 15-16.x). Note that recent hardware and iOS 17/18 jailbreaks are limited, so plan device acquisition early. Keep a non-jailbroken device for pinning/attestation baseline behavior.
- [ ] **Note jailbreak rootless layout:** Modern jailbreaks install to `/var/jb` not `/`. Adjust paths for Frida, binaries, and dylib injection accordingly.
- [ ] **Stand up the host toolchain:** adb + platform-tools, Frida/frida-tools, objection, jadx, apktool, MobSF (Docker), and for iOS frida-ios-dump, class-dump/ipsw, and a libimobiledevice stack.
- [ ] **Confirm proxy interception path:** Burp/mitmproxy host reachable from the device, with the CA installed (see Dynamic Setup). Validate plain HTTP flows before tackling pinning.

### Accounts and Data
- [ ] **Obtain test accounts at every role/tier:** At least two same-tier users (for IDOR/horizontal checks) plus each privilege level (free, paid, admin). Confirm seed data and reset procedure.
- [ ] **Capture entitlements per role:** What each tier can see and do, to validate authz claims later from the API handoff.
- [ ] **Record device/app baseline:** App version + build number, OS version, device model, and a clean-state backup so you can reset between tests.

### Intelligence Gathering
- [ ] **Identify the app on the stores:** Package name (Android), bundle ID (iOS), publisher, version history, declared permissions, and SDK list from the listing.
- [ ] **OSINT the developer surface:** Hardcoded endpoints, leaked keys in prior versions, GitHub/Firebase exposure, and public bug-bounty scope. See [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md).

---

## 2. Static Analysis

> Goal: map the attack surface from the binary before touching the running app. Feed findings (endpoints, secrets, exported components, pinning logic) into the dynamic phase. For command detail see [Mobile App Testing](../Cheatsheets/Mobile%20App%20Testing.md).

### Acquire and Unpack
- [ ] **Android: pull the APK from the device** with `adb shell pm path <pkg>` then `adb pull`. Pull all split APKs for AAB-delivered apps.
- [ ] **Android: decompile** with jadx (`jadx-gui`) for Java/Kotlin and apktool (`apktool d app.apk`) for the manifest, resources, and smali.
- [ ] **iOS: obtain a decrypted IPA.** App Store binaries are FairPlay-encrypted; decrypt on a jailbroken device with frida-ios-dump or dump-decrypted. Confirm `cryptid 0` in the Mach-O load command before trusting strings.
- [ ] **iOS: unpack** the IPA (it is a zip), locate the `.app` bundle, and pull `Info.plist`, the Mach-O binary, embedded frameworks, and `*.car`/asset catalogs.
- [ ] **Run MobSF static scan** on the APK and IPA as a first pass. Use it as a lead generator, then verify every flagged item by hand (high false-positive rate on secrets and trackers).

### Manifest and Info.plist Review (Android)
- [ ] **Check `android:debuggable`:** If `true`, the app is debuggable in prod (run-as, JDWP, memory dumping). Finding.
- [ ] **Check `android:allowBackup`:** If `true` (or unset on older targets), local data is extractable via `adb backup`/`bmgr`. Validate what actually backs up.
- [ ] **Check `usesCleartextTraffic` and the network security config:** `cleartextTrafficPermitted="true"` or a missing/weak `network_security_config.xml` permits HTTP and may set custom trust anchors (user CAs).
- [ ] **Enumerate exported components:** Every `activity`, `service`, `receiver`, `provider` with `android:exported="true"` or an intent-filter (implicitly exported pre-Android 12; explicit `exported` is required from Android 12+). List each as a tamperable entry point.
- [ ] **Check `android:permission` on exported components:** Exported without a signature/dangerous permission gate is directly invokable by any app.
- [ ] **Review custom permissions and `protectionLevel`:** `normal`/`signature` mismatches enable permission squatting/`StrandHogg`-style abuse.
- [ ] **Enumerate deeplinks and app links:** `<intent-filter>` schemes/hosts and `android:autoVerify` (App Links). Note any wildcard hosts or schemes you control.
- [ ] **Note `minSdkVersion`/`targetSdkVersion`:** A low `targetSdk` opts out of newer platform hardening (PendingIntent mutability, exported enforcement, etc.). Flag stale targets.

### Info.plist Review (iOS)
- [ ] **Check `NSAppTransportSecurity`:** `NSAllowsArbitraryLoads` or per-domain exceptions weaken or disable ATS (cleartext / weak TLS).
- [ ] **Enumerate `CFBundleURLTypes`:** Custom URL schemes the app handles (deeplink entry points).
- [ ] **Check Associated Domains / `applinks`:** Universal Links config (entitlements + `apple-app-site-association`), and whether host validation is sound.
- [ ] **Review declared purpose strings and `UIBackgroundModes`:** Over-broad capabilities and background entry points.
- [ ] **Check the Privacy Manifest (`PrivacyInfo.xcprivacy`)** and required-reason API declarations (mandatory for App Store 2024+). Mismatch with observed behavior is a finding.

### Secrets, Crypto, and Trust Material
- [ ] **Grep for hardcoded secrets:** API keys, tokens, cloud creds, Firebase config, private keys, and signing material. Search smali, resources, `strings.xml`, assets, `Info.plist`, and the Mach-O strings.
- [ ] **Verify each "secret":** Distinguish public/client identifiers (OK) from server-side-grade keys (finding). Test live keys against their service for real impact.
- [ ] **Inspect pinning and trust logic statically:** TrustManager/OkHttp CertificatePinner/Network Security Config (Android); `SecTrustEvaluate`, AFNetworking/Alamofire pinning, or bundled `.cer`/`.der` (iOS). Note the exact class/method to hook later.
- [ ] **Review crypto usage:** Hardcoded keys/IVs, ECB mode, static salts, MD5/SHA1 for security, and home-rolled crypto. Confirm KeyStore/Keychain is used for key material, not files.
- [ ] **Inventory third-party SDKs:** Analytics, ad, payment, auth, and crash SDKs and their versions. Cross-reference versions against known CVEs and check what data each exfiltrates.
- [ ] **Decompile native libraries:** Disassemble bundled `.so`/embedded frameworks (Ghidra/r2) for secrets, custom crypto, and the real pinning/root-detection logic when it lives in native code.

---

## 3. Dynamic Analysis Setup

> Get instrumentation and interception working before testing logic. A broken proxy or pinning bypass wastes the whole engagement.

### Instrumentation
- [ ] **Stand up Frida:** Push frida-server matching the frida-tools version (Android), or run via the rootless jailbreak path (iOS). Confirm with `frida-ps -Ua`.
- [ ] **Confirm objection works:** `objection -g <pkg> explore`, then `android hooking list classes` / `ios hooking list classes` to verify attach.
- [ ] **For non-rooted Android, use Frida Gadget injection:** Patch the gadget into the APK (objection patchapk / apk-mitm) and re-sign. Note this changes the signature and may trip integrity checks.
- [ ] **Verify a hook fires:** Hook a trivial method (e.g., a logging call) and confirm output, so later silence means "not called" not "broken setup".

### Proxy Interception
- [ ] **Route device traffic through Burp/mitmproxy:** Wi-Fi proxy or transparent proxy (iptables / ProxyDroid). Confirm system browser traffic is captured first.
- [ ] **Install the proxy CA as a system-trusted root.** From Android 7+, user CAs are not trusted by apps by default. On rooted devices install the CA to the system store (`/system/etc/security/cacerts`, or Magisk module). On iOS install + fully trust the profile in Settings.
- [ ] **Decide emulator vs device:** Emulator is fast to reset and easy to root, but some apps detect emulators (and SafetyNet/Play Integrity fails). Use a physical device for attestation, biometrics, and anti-emulation logic.

### Pinning and Trust Bypass
- [ ] **Bypass certificate pinning:** Start with objection `android sslpinning disable` / `ios sslpinning disable`, or a universal Frida script (frida-multiple-unpinning, HTTPToolkit's frida-interception-and-unpinning).
- [ ] **If universal scripts fail, hook the specific class/method** found in static analysis (OkHttp `CertificatePinner.check`, custom TrustManager, `SecTrustEvaluateWithError`).
- [ ] **Handle Flutter and React Native specially** (they bypass the system proxy/trust store; see Network Communication).
- [ ] **Record the working bypass recipe** in notes so it survives app restarts and device reboots.

```bash
# Quick attach + universal unpin via objection
objection -g com.target.app explore -s "android sslpinning disable"
# Frida universal unpin
frida -U -f com.target.app -l frida-multiple-unpinning.js --no-pause
```

⚠️ Patching/re-signing the APK or injecting a gadget changes the signature and may trigger anti-tamper or attestation failures. Keep an un-modified copy for baseline behavior, and disable resilience checks (Phase 7) in a separate, clearly noted instrumented build.

---

## 4. Network Communication

> Map every channel the app uses and verify confidentiality, integrity, and trust. Once decrypted, the API surface itself is tested under the handoff (Phase 9).

### Transport Security
- [ ] **Confirm all traffic is TLS:** No cleartext HTTP for any sensitive endpoint (login, tokens, PII, payments). Catch downgrade and mixed-content (WebView) flows.
- [ ] **Check TLS version and cipher suites:** Reject TLS < 1.2, weak ciphers, and self-signed/expired certs accepted by the client.
- [ ] **Verify certificate pinning is enforced:** With your CA installed and no bypass active, does the app refuse to connect? If it connects, pinning is absent or broken (note it, then bypass to continue testing the API).
- [ ] **Test pinning bypass resistance (R profile):** Confirm whether pinning survives a clean device with only a user CA, and whether the app detects a system-CA proxy.

### Protocols and Channels
- [ ] **Enumerate all hosts/ports the app talks to:** Beyond the main API: analytics, push (FCM/APNs), CDNs, WebSocket, gRPC, MQTT, and any custom TCP.
- [ ] **Intercept non-HTTP protocols:** WebSocket and gRPC via Burp extensions; raw sockets via Frida hooks on the socket/SSL layer. Look for unauthenticated or unencrypted side channels.
- [ ] **Inspect for sensitive data in transit metadata:** Tokens in URLs/query strings, PII in headers, and verbose error responses.
- [ ] **Check request integrity / replay:** Are requests signed (HMAC)? Can they be replayed or tampered? Note any client-side signing key (it is recoverable, so it is not a real control).

### Flutter and React Native Interception
- [ ] **Flutter:** It uses BoringSSL with a bundled CA store and ignores the system proxy. Force traffic with a transparent proxy (iptables/ProxyDroid) and disable verification with a Frida script (`disable_flutter_tls_verification`) or repackage with reFlutter to point at your proxy.
- [ ] **React Native:** Extract `index.android.bundle` / `main.jsbundle`. If Hermes is enabled, decompile the bytecode (`hbctool`/`hermes-dec`) to read logic. RN respects the system proxy more readily, but TLS pinning libraries (e.g., react-native-ssl-pinning) still need a Frida hook.

---

## 5. Local Data Storage

> Anything written to the device can be read by a malicious app (with backup/root) or an attacker with the unlocked device. Verify sensitive data is encrypted, scoped, and not leaked to logs, caches, or backups.

### Storage Inventory
- [ ] **Map the app sandbox:** Android `/data/data/<pkg>/` (shared_prefs, databases, files, cache); iOS `/var/mobile/Containers/Data/Application/<UUID>/` (Documents, Library/Preferences, Library/Caches, tmp). objection `env` prints the iOS paths.
- [ ] **Exercise the app fully first**, then snapshot storage, so you capture data that is only written after login/use.

### Sensitive Data at Rest
- [ ] **Inspect SharedPreferences / NSUserDefaults / plists:** Tokens, passwords, PII, or flags stored in cleartext. NSUserDefaults is never appropriate for secrets.
- [ ] **Inspect SQLite databases:** `databases/*.db` and Core Data stores for cleartext sensitive data. Check for (and try to bypass) SQLCipher.
- [ ] **Check files, caches, and tmp:** Cached API responses, downloaded documents, images, and serialized objects containing PII.
- [ ] **Verify KeyStore (Android) / Keychain (iOS) usage:** Key material should live in KeyStore/Keychain, not in files. On iOS, dump the Keychain (objection `ios keychain dump`) and check `kSecAttrAccessible` is `WhenUnlockedThisDeviceOnly` or stricter, not `Always`.
- [ ] **Test Android hardware-backed keys:** Confirm StrongBox/TEE usage and that keys require user auth where claimed (`setUserAuthenticationRequired`).

### Leakage Channels
- [ ] **Check logs:** `adb logcat` (Android) and the device console (iOS) during use for tokens, PII, or full request/response bodies. Logging of sensitive data is a common, real finding.
- [ ] **Test local backups:** Android `adb backup` / `allowBackup`, and iOS unencrypted iTunes/Finder backup. Restore and inspect for extractable secrets.
- [ ] **Test screenshot/snapshot caching:** Backgrounding the app caches a snapshot (iOS `Library/Caches/Snapshots`, Android task thumbnail). Confirm sensitive screens are masked (`FLAG_SECURE` on Android; blur/placeholder on iOS).
- [ ] **Check the keyboard cache and autofill:** Sensitive fields should disable cache/autocorrect to avoid persisting input.
- [ ] **Check pasteboard/clipboard persistence:** Copied secrets (OTP, card numbers) left on the system clipboard (covered further in Platform Interaction).
- [ ] **Inspect WebView caches and cookies:** WebView local storage, cookies, and cached HTML may persist session material.

---

## 6. Platform Interaction

> Test every way another app or the OS can drive this app: IPC, deeplinks, WebView, and shared OS surfaces. This is where most high-impact mobile bugs live.

### Android IPC and Exported Components
- [ ] **Fuzz exported activities:** Launch each with crafted intents/extras (`am start ...` or Drozer). Look for auth bypass (reaching post-login screens), state change, or crash.
- [ ] **Test exported services and broadcast receivers:** Send intents to invoke privileged actions without authorization. Receivers often trust extras blindly.
- [ ] **Test exported / mis-permissioned ContentProviders:** Query/`openFile` for data leakage and path traversal (`content://...//../`). Check `grantUriPermissions` abuse.
- [ ] **Test PendingIntent handling:** Look for mutable PendingIntents with empty/implicit base intents that a malicious app can hijack to act with the app's identity/permissions.
- [ ] **Test for intent redirection:** A component that forwards an attacker-supplied intent (`startActivity(getIntent().getParcelableExtra(...))`) into an internal/privileged component ("intent forwarding"/"intent redirect").
- [ ] **Test task hijacking (StrandHogg / StrandHogg 2.0):** Abuse `taskAffinity`/`launchMode` so a malicious app inserts its activity into the target's task stack (overlay phishing). Flag default affinity on sensitive activities.

```bash
# Reach an exported activity directly
adb shell am start -n com.target.app/.SecretActivity --es token attacker
# Query an exported content provider
adb shell content query --uri content://com.target.app.provider/users
```

### iOS IPC and URL Handling
- [ ] **Test custom URL scheme handlers:** Send crafted `myapp://` URLs and verify input validation and auth state. Schemes are not exclusive, so another app can register the same scheme (impersonation).
- [ ] **Test Universal Links:** Verify `apple-app-site-association` host scoping and that link params cannot drive privileged actions or redirect to attacker content.
- [ ] **Test app extensions, share/action extensions, and Handoff** for data exposure across the trust boundary.

### Deeplink Abuse (Both Platforms)
- [ ] **Map every deeplink path and parameter** from the manifest/Info.plist, then test each for: auth bypass, account actions without confirmation, open redirect, and parameter injection into WebView/API.
- [ ] **Test deeplink-driven WebView loads:** A deeplink param controlling a WebView URL is an open-redirect/XSS/local-file-read primitive.

### WebView Security
- [ ] **Check `setJavaScriptEnabled` + `addJavascriptInterface`:** An exposed JS interface on attacker-controllable content is potential RCE (reflection to `Runtime.exec` on old targets; data theft generally). Identify every `@JavascriptInterface` method.
- [ ] **Check file access settings:** `setAllowFileAccess`, `setAllowFileAccessFromFileURLs`, `setAllowUniversalAccessFromFileURLs` true with loadable local/remote content enables local file theft / same-origin bypass.
- [ ] **Check what content the WebView loads:** Any attacker-influenced URL (via deeplink/intent/redirect) plus a powerful WebView config is the core WebView attack chain.
- [ ] **iOS WKWebView:** Check `WKScriptMessageHandler` bridges, `allowFileAccessFromFileURLs`, and whether arbitrary URLs can be loaded.

### Shared OS Surfaces
- [ ] **Clipboard/pasteboard:** App writing secrets to the global clipboard (readable by any app; iOS shows the paste banner). Check for `UIPasteboard.general` writes of sensitive data.
- [ ] **Notifications:** Sensitive content (OTPs, message bodies, balances) shown on the lock screen.
- [ ] **Accessibility and overlay surfaces:** Tapjacking via overlays (`SYSTEM_ALERT_WINDOW`), and abuse of accessibility services for input capture.
- [ ] **App-to-app file sharing:** Android FileProvider misconfig (exported, over-broad `path` grants) and iOS document/share handling.

---

## 7. Code Quality and Resilience

> MASVS-R controls. Only required when the threat model includes a compromised device. Test them when in scope, but rate realistically: a bypassable root check is usually Low/Info unless it gates a real security control.

### Root / Jailbreak Detection
- [ ] **Identify the detection logic:** Static review for `su`/`busybox` checks, magisk path checks, `RootBeer`, `SafetyNet`/Play Integrity calls (Android); `/var/jb`, `cydia`, `fork()`/`sysctl` checks (iOS).
- [ ] **Bypass it:** objection `android root disable` / `ios jailbreak disable`, a Frida hook on the detection method, or Magisk DenyList/Shamiko. Confirm the app then runs normally on the rooted/jailbroken device.
- [ ] **Assess what the check protects:** Does bypassing it expose a real asset, or is it just a nag screen? Rate accordingly.

### Anti-Tampering and Anti-Debug
- [ ] **Check signature/integrity verification:** Does the app verify its APK signature / bundle integrity at runtime? Repack with a Frida gadget and see if it still runs.
- [ ] **Check anti-debug / anti-instrumentation:** Frida/objection detection (named pipes, port 27042, maps scanning), `ptrace`/`isDebuggerConnected`, emulator detection. Note evasion (rename frida-server, use frida-gadget, stealth scripts).
- [ ] **Check obfuscation:** Is the code obfuscated (ProGuard/R8/DexGuard, iXGuard)? Absence of obfuscation on sensitive logic is a quality finding, not a vuln by itself.

### Build Hygiene
- [ ] **Confirm release hardening:** `debuggable=false`, no test/staging endpoints baked in, no debug logging, ProGuard/R8 enabled, and no `.dSYM`/source maps shipped.
- [ ] **Check for leftover debug/dev features:** Hidden debug menus, feature flags, or test backdoors reachable via deeplink or build config.

---

## 8. Authentication and Session

> Mobile-specific auth surface. Most authorization testing happens against the API (Phase 9), but token storage, biometrics, and mobile auth flows are tested here.

### Token and Session Handling
- [ ] **Locate where tokens are stored:** Confirm access/refresh tokens live in KeyStore/Keychain, not SharedPreferences/NSUserDefaults/plist/SQLite in cleartext.
- [ ] **Test token lifetime and revocation:** Does logout invalidate the token server-side? Can a stolen refresh token be reused after logout? Does the app rotate refresh tokens?
- [ ] **Test session fixation and reuse across devices.**
- [ ] **Check for long-lived or non-expiring tokens** and whether they are bound to the device.

### Biometric Authentication
- [ ] **Determine if biometrics gate a real secret or just UI:** A bypassable biometric prompt that only hides a screen (vs unlocking a Keychain/KeyStore-protected key) is weak. Hook the success callback with Frida to test.
- [ ] **Android:** Confirm `BiometricPrompt` with a `CryptoObject` (key unlock), not a bare boolean callback. Test `setUserAuthenticationRequired` keys.
- [ ] **iOS:** Confirm `LAContext`/Keychain ACL (`SecAccessControl` with `.biometryCurrentSet`), not just `evaluatePolicy` returning a bool (hookable). Test that changing enrolled biometrics invalidates the key.

### Mobile Auth Flows
- [ ] **Test OAuth/OIDC in the app:** Use of the system browser / `ASWebAuthenticationSession` / Custom Tabs (good) vs an embedded WebView capturing credentials (bad). Check PKCE is used and `redirect_uri` is validated.
- [ ] **Test deeplink-based auth callbacks:** OAuth redirect to a custom scheme can be intercepted by a malicious app that registers the same scheme. Confirm PKCE and state binding mitigate this.
- [ ] **Test magic-link / OTP flows:** Replay, brute force (server-side), and whether the OTP/link leaks via logs, clipboard, or notifications.
- [ ] **Test "remember me" / auto-login:** What persists and where, and whether it survives token revocation.

---

## 9. Backend and API Handoff

> The mobile client is usually a thin shell over an API. Once traffic is decrypted, the bulk of high-impact findings (authz, IDOR, injection) come from API testing. Hand off systematically; do not stop at the client.

- [ ] **Catalog every API endpoint** observed through the proxy, plus any reachable from static analysis but not exercised by the UI (hidden/admin endpoints).
- [ ] **Test authorization thoroughly:** BOLA/IDOR with two same-tier accounts, function-level authz (privileged endpoints from a low-priv token), and mass assignment. The client's role checks are not server controls.
- [ ] **Test authentication on the API:** Token validation, JWT flaws (alg/none, weak secret, missing expiry), and refresh-token handling. See [API JWT and GraphQL](../Cheatsheets/API%20JWT%20and%20GraphQL.md).
- [ ] **Test injection and input handling** on every parameter the client sends (the app's validation does not protect the server).
- [ ] **Replay and tamper requests** without the app: rebuild calls in Burp/curl to confirm server-side enforcement independent of client logic.
- [ ] **Run the full web/API methodology** against the backend: see [API Security](API%20Security.md), [Web Application](Web%20Application.md), and [Web App and Payloads](../Cheatsheets/Web%20App%20and%20Payloads.md).

---

## Recent Techniques (2024-2026)

> Verify each against the target's platform version and config; many are gated by `targetSdk`, OS version, or app settings.

### Pinning and Instrumentation Tradecraft
- [ ] **Frida 17 bridge removal (the 2025 break):** Frida 17.0.0 (May 2025, now 17.5.x) removed the Java/ObjC/Swift runtime bridges from GumJS, so old unpinning scripts throw `Java is not defined`. frida-tools 14.x re-bakes the bridges; objection needs v1.12.x (1.11 is not Frida-17 compatible). Test for: silent hook failure from a version mismatch (pin the whole chain to 16.7.19 if in doubt).
- [ ] **httptoolkit/frida-interception-and-unpinning:** Maintained suite that injects YOUR CA into the trust stores then patches known pinning + cert-transparency libs (does not globally disable TLS). Test for: a non-injected CA is still rejected, proving the bypass is scoped.
- [ ] **frida-multiple-unpinning / objection sslpinning disable:** First-line universal bypass. Test for: OkHttp `CertificatePinner`, default X509TrustManager, NSURLSession, and AFNetworking in one pass. Zero hooks firing means Flutter/native (fall back).
- [ ] **Frida Gadget injection for non-rooted devices:** Repack with `objection patchapk -s app.apk --gadget-version 16.7.19`, NickstaDB/patch-apk for split-APK bundles, or apk-mitm. Test for: instrumentation without root, accepting the signature change.
- [ ] **Anti-Frida evasion:** Rename frida-server off reserved names, move off port 27042 (`-l 127.0.0.1:5555`/unix socket), or use a patched build (Florida, strongR-frida-android, undetected-frida) against apps scanning `/proc/maps`/ports/named pipes. Test for: apps that detect default Frida.
- [ ] **Magisk DenyList + Shamiko + Zygisk:** Hide root from detection and integrity APIs. Test for: keeping root while passing basic root checks.

### Android 14 (API 34) / 15 (API 35) Platform Changes
- [ ] **Mutable PendingIntent must specify component/package (A14):** Creating a `FLAG_MUTABLE` PendingIntent with a blank base intent now throws, killing the classic hijack for 34-targeted apps. Test for: the pattern on pre-34 targets only.
- [ ] **Implicit intents must target exported components (A14):** An implicit intent resolving to a non-exported same-app component throws `ActivityNotFoundException`, shrinking intent-redirection surface. Test for: pre-34 targets and explicitly-exported components.
- [ ] **Runtime receivers must declare export state (A14):** `registerReceiver()` requires `RECEIVER_EXPORTED`/`RECEIVER_NOT_EXPORTED`. Test for: `RECEIVER_EXPORTED` added blindly to silence the crash, re-opening dynamic receivers cross-app.
- [ ] **Restricted Settings (A13, tightened A14):** Sideloaded (non-session-installer) apps are blocked from enabling Accessibility and NotificationListener until the user does App info, three-dot menu, "Allow restricted settings". Biggest blocker for accessibility-abuse PoCs; session/Play-style installs are exempt.
- [ ] **Background Activity Launch hardening (A14, stronger A15):** `PendingIntent#send()` needs `setPendingIntentBackgroundActivityStartMode(ALLOWED)`; A15 bars injecting activities into another app's task. Test for: whether the app opts back into BAL, and StrandHogg-style overlay paths the platform now blocks.
- [ ] **Min installable targetSdk = 23 (A14) / 24 (A15):** Apps below the floor fail to install (`INSTALL_FAILED_DEPRECATED_SDK_VERSION`). Bypass for legacy testing: `adb install --bypass-low-target-sdk-block app.apk`.
- [ ] **MediaProjection + sensitive-content redaction (A14/A15):** Each screen capture needs fresh consent; A15 auto-hides password fields and OTP notifications during screen share. Test for: views not marked via `setContentSensitivity()`, and RAT-style OTP exfil.
- [ ] **FGS types mandatory (A14) + A15 tightening:** Every foreground service needs a `foregroundServiceType` + matching permission; A15 blocks SAW-only and restricts BOOT_COMPLETED-started FGS types. Test for: mis-declared FGS abuse.
- [ ] **A15 Conscrypt disables TLS 1.0/1.1; force-stop cancels all PendingIntents:** Test for: persistence that relied on a surviving PendingIntent, and downgrade attempts against 35-targets.
- [ ] **Zip path-traversal prevention (A14):** `ZipFile`/`ZipInputStream` throw on `..`/`/` entries. Test for: `ZipPathValidator.clearCallback()` opt-out or pre-34 targets for Zip-Slip arbitrary write.
- [ ] **Credential Manager + passkeys (A14 GA):** Unified passwords/passkeys/federated sign-in replacing Smart Lock. Test for: insecure password fallback, RP-ID/`allowCredentials` handling, malicious credential-provider registration.

### iOS 17 / 18 Platform Changes
- [ ] **Privacy Manifests + required-reason APIs (enforced May 2024):** `PrivacyInfo.xcprivacy` declares data types and justifies file-timestamp/boot-time/disk/UserDefaults API use. Test for: parse it as a self-disclosed data-flow map, then Frida-hook the required-reason APIs and report manifest-vs-runtime mismatches.
- [ ] **App Attest / DeviceCheck attestation:** Secure-Enclave attestation of a genuine build. Test the SERVER side: token/assertion replay (missing one-time nonce or freshness), missing assertion-counter checks, device-farm relay, runtime patching of the check. Accepting a replayed attestation proves missing nonce enforcement.
- [ ] **Lockdown Mode (kernel-enforced, iOS 17):** Blocks loading unsigned/external dylibs and JIT, so Frida/objection injection dies with it ON. Disable on test devices; conversely assess the app's resilience under it.
- [ ] **TrollStore 1/2 (CoreTrust CVE-2023-41991 / CVE-2022-26766):** Permanent unsigned-app install on iOS 14.0-16.6.1 + 17.0 (dead on 17.1+/18). Use for: perma-signing a Frida-gadget IPA with full entitlements on a stock device, no 7-day re-sign.
- [ ] **Rootless jailbreaks (Dopamine A12-A16 ≤16.6.1, palera1n checkm8 A9-A11 any iOS, roothide Dopamine hidden):** Files at `/var/jb`; use the rootless Frida build (≥16.1.5) and fix LaunchDaemon plist paths. Test for: path-based jailbreak detection that only checks legacy `/`. Note: no public stable iOS 18 / modern-chip jailbreak as of 2025, plan the bench accordingly.
- [ ] **iOS 18 inactivity reboot / Stolen Device Protection:** A device reboots into Before-First-Unlock after ~3-4 days, refusing USB/accessory data and most keychain classes. Acquire while After-First-Unlock and unlocked.
- [ ] **Pasteboard privacy (iOS 16+):** Cross-app reads trigger an "Allow Paste?" prompt (MASTG-KNOW-0083). Test for: an app that triggers the prompt on launch/foreground (covert clipboard harvesting); hook the `UIPasteboard.general` getters to confirm.

### IPC, Deeplink, and Task-Hijack Bugs
- [ ] **Intent redirection / unsafe intent launch (CWE-927):** Exported component unparcels a nested intent from `android.intent.extra.INTENT` (or extras) and dispatches it under the victim's UID, reaching private components. Behind a 2026 third-party-SDK case (MSTIC) exposing millions of Android wallets. Test for: send the exported component an intent wrapping a target at a private component, or run under `VmPolicy.detectUnsafeIntentLaunch()`.
- [ ] **Microsoft Authenticator unclaimed-deeplink ATO (CVE-2026-26123):** The `ms-msa://` scheme was not exclusively claimed, so a malicious app registering it intercepts the auth callback (full ATO, 2FA bypass; patched Mar 2026). Test for: register a competing intent-filter for a target's scheme, trigger auth, confirm the token routes to the rogue app.
- [ ] **Browsable-deeplink account takeover (Oversecured pattern):** An exported BROWSABLE activity consumes `token`/`redirect_uri`/`userId` with no origin/state check. Test: `adb shell am start -a android.intent.action.VIEW -d "scheme://host/path?token=ATTACKER&redirect_uri=evil"`.
- [ ] **StrandHogg 1.0 (taskAffinity hijack):** Malicious app declares `taskAffinity` matching the victim + `singleTask`/`allowTaskReparenting`, surfacing its overlay on victim launch. Test for: default affinity on sensitive activities.
- [ ] **StrandHogg 2.0 (CVE-2020-0096):** Purely code-driven task hijack via `startActivities` (no manifest marker), Android < 10. Test for: unpatched < 10 devices; defenders use `singleInstance`.
- [ ] **Samsung exported-component intent redirection (CVE-2022-30746, SmartThings):** Exported component forwards a nested intent without validation. Test for: invoke the exported component from a low-priv app with a wrapped intent.

### PendingIntent Bugs
- [ ] **Mutable / unflagged PendingIntent hijack:** App hands out a `FLAG_MUTABLE` (or pre-API-31 unflagged) PendingIntent wrapping a componentless intent; attacker calls `.send(ctx,0,fillInIntent)` supplying component/data, dispatched under the creator's UID to private components / file write. Test for: grab the PendingIntent from a notification action (NotificationListenerService) and redirect via fillInIntent.
- [ ] **Static scan (PITracker corpus, 72 AOSP CVEs):** Hunt `PendingIntent.getActivity/getBroadcast/getService` lacking `FLAG_IMMUTABLE` on an implicit base intent, then attempt the hijack. Samsung clusters (e.g. CVE-2021-25377) leak privileged PendingIntents for notification interception / arbitrary file write.

### WebView Bugs
- [ ] **addJavascriptInterface reflection RCE (targetSdk < 17):** JS walks the exposed object via reflection to `Runtime.exec()`. Test: `interface.getClass().forName('java.lang.Runtime')...exec(['id'])`; Metasploit `exploit/android/browser/webview_addjavascriptinterface`.
- [ ] **file:// XHR exfil via `setAllowUniversalAccessFromFileURLs`:** Default TRUE on API ≤29, FALSE ≥30; a file:// page can XHR-read arbitrary app-private files and exfil through the JS bridge. Test: deliver malicious file:// HTML via an exported activity/deeplink, `fetch('file:///data/data/<pkg>/...')`, POST out.
- [ ] **WebView Universal XSS (CVE-2020-6506, Chromium < 83.0.4103.106):** file:// top page + `setJavaScriptCanOpenWindowsAutomatically` + `setAllowUniversalAccessFromFileURLs` lets a cross-origin iframe run JS in the top doc, no interaction (also GHSA-36j3-xxf7-4pqg for Cordova/RN-WebView). Test for: cross-origin iframe in the file:// page reaching the parent origin/bridge.
- [ ] **File-based XSS to native bridge:** Exported WebView loading attacker file:// content turns file XSS into `@JavascriptInterface` invocation + SOP bypass (Google Play flags "file-based XSS"). Test: drop a poisoned HTML file the app opens via file://, call the exposed bridge methods.
- [ ] **ContentProvider path traversal / SQL injection:** Exported providers with `openFile` traversal or unescaped `query` selections. Test for: cross-app data read.

### Mobile App Stack Specifics
- [ ] **Flutter TLS bypass (reFlutter / disable-flutter-tls-verification):** Flutter ignores the system proxy and statically links BoringSSL with its own CA. Test: `reflutter app.apk` (patches socket.cc to a hardcoded Burp IP + ssl_x509.cc verify bypass) and repackage, OR the NVISO Frida script that pattern-scans libflutter.so + ProxyDroid/iptables redirect.
- [ ] **React Native Hermes bytecode decompilation:** Extract `assets/index.android.bundle` (Hermes magic `0x1F1903C1`); `hermes-dec` to recover pseudo-JS, `hbctool disasm/asm` to patch (e.g. flip a pinning check). Test for: hardcoded keys/endpoints in the bundle.
- [ ] **Play Integrity verdict tiering + bypass (Google policy, May 2025):** A rooted/unlocked A13+ device defaults to BASIC-only. PlayIntegrityFork (osm0sis, successor to the discontinued PlayIntegrityFix) reaches MEETS_DEVICE; TrickyStore + a `keybox.xml` can reach MEETS_STRONG but valid keyboxes are scarce and revoked within days. Test for: server trusting only BASIC/DEVICE, or no verdict at all. STRONG resists bypass (hardware-provisioned OEM keys).
- [ ] **Apple App Attest / DeviceCheck bypass:** Jailbroken device with the jailbreak hidden + Frida hook on `DCAppAttestService.attestKey` to capture a genuine Secure-Enclave token, plus attestation-object replay where the server lacks nonce/freshness. Test: capture one valid attestation, replay it on a fresh session.
- [ ] **Janus (CVE-2017-13156):** Prepend a DEX to a v1(JAR)-signed APK; the signature still verifies on Android 5.0-8.1 v1-only apps. Test: Metasploit `exploit/android/local/janus` or manual prepend, reinstall over the legit app.

### Notable Mobile CVEs (2024-2026)
- [ ] **Android System zero-click RCE (CVE-2025-48593):** Critical, no interaction, Android 13-16 (Nov 2025 bulletin). Test for: device patch level ≥ 2025-11-01.
- [ ] **Android Bluetooth/HFP RCE (CVE-2025-0084) + proximity System RCE (CVE-2025-48539):** Memory corruption from a BT/Wi-Fi-proximate attacker, no interaction. Test for: patch level; lab-fuzz HFP from a malicious BT peer.
- [ ] **Android Framework in-the-wild pair (CVE-2025-48633 info disclosure + CVE-2025-48572 privesc):** Signs of targeted exploitation (Dec 2025 bulletin, Android 13-16). Test for: Dec-2025 patch level.
- [ ] **Chromium/V8 WebView 0-days (CVE-2025-6554, CVE-2025-5419, CVE-2025-10585):** V8 type-confusion/OOB RCEs; System WebView shares the engine, so any app rendering untrusted web content inherits exposure. Test for: System WebView/Chrome version vs the fixed build; load the public PoC in an outdated WebView.
- [ ] **Samsung Dialer exported-component privesc (CVE-2026-20983, +21011/21012):** Privileged Dialer exports activities without permission checks. Test: `am start` the exported Dialer activity from an unprivileged app.

---

## Reporting and Evidence

### Evidence to Capture per Finding
- [ ] **Static findings:** The exact file + line/class/method (smali/jadx path, `Info.plist` key), the decompiled snippet, and the manifest entry.
- [ ] **Dynamic findings:** The Frida/objection command or script, console output proving the hook fired, and before/after behavior.
- [ ] **Network findings:** The raw HTTP request/response pair (save to file at capture time, not from memory), or a proxy screenshot. Include the host and the working pinning-bypass note.
- [ ] **Storage findings:** The on-device path and a dump of the cleartext data (`adb pull` / objection), redacted in the report.
- [ ] **IPC findings:** The exact `am start`/`adb` command or PoC app that triggers it, and the resulting state change.
- [ ] **Device context:** OS version, device model, app version+build, and root/jailbreak state, since many findings are version-gated.

### Severity Guidance
| Severity | Mobile examples |
| --- | --- |
| Critical | Pre-auth RCE via WebView/JS bridge; remote account takeover via deeplink/OAuth flaw; server-side authz bypass reachable from the client |
| High | Hardcoded prod credentials/keys with real access; exported component giving auth bypass or sensitive data; cleartext transmission of credentials/PII |
| Medium | Sensitive data in local storage/logs; weak/absent pinning (data exposure on hostile network); IDOR requiring same-tier account |
| Low | Bypassable root/jailbreak or anti-debug check that gates no real asset; missing FLAG_SECURE; clipboard/screenshot caching of low-value data |
| Info | Missing obfuscation; outdated SDK with no proven impact; verbose-but-harmless logging |

### Common False Positives to Rule Out
- [ ] **"Hardcoded secret" that is a public client ID / API key** meant to be shipped (Firebase config, OAuth public client). Confirm real privilege before reporting.
- [ ] **"No pinning" rated High** when the data is non-sensitive or already public. Rate by the data exposed on a hostile network.
- [ ] **MobSF auto-flags** (trackers, permissions, CVSS) reported without manual verification.
- [ ] **Bypassable resilience control reported as a vuln** when it protects nothing of value. Frame as defense-in-depth.
- [ ] **"Exported component"** that is intentionally public and properly permission-gated, or that does nothing sensitive.
- [ ] **Cleartext flag set but no cleartext traffic** actually observed, or vice versa. Confirm at runtime.

---

## Tools and References

| Category | Tools |
| --- | --- |
| Static / decompile | jadx (1.5.x), apktool (3.0.x), MobSF (4.4.x), Ghidra (12.x), radare2/r2frida, class-dump, ipsw, hbctool, hermes-dec, reFlutter, Quark-Engine, apkleaks, APKLab |
| Dynamic / instrumentation | Frida (17.5.x, or pin 16.7.19), objection (1.12.x), RMS (Runtime Mobile Security), Medusa (Ch0pin, incl. Flutter modules), house, Drozer (ReversecLabs/WithSecure v3.1.0, not the b3nac fork) |
| Network | Burp Suite, mitmproxy, httptoolkit/frida-interception-and-unpinning, disable-flutter-tls-verification, apk-mitm, ProxyDroid |
| Device / acquisition | adb + platform-tools, libimobiledevice, frida-ios-dump, Magisk (Shamiko/Zygisk), PlayIntegrityFork/TrickyStore, palera1n, Dopamine, TrollStore, Corellium |
| Storage / inspection | objection (env, keychain dump), sqlite3, DB Browser for SQLite |

**References**
- OWASP MASVS (Mobile Application Security Verification Standard) and the MAS Checklist.
- OWASP MASTG (Mobile Application Security Testing Guide), Android and iOS test cases.
- OWASP Mobile Top 10 (current edition).
- Android developer security guidance (App security best practices, behavior changes per API level).
- Apple Platform Security Guide and App Store privacy-manifest requirements.

---

## Related
- [Mobile App Testing](../Cheatsheets/Mobile%20App%20Testing.md)
- [API Security](API%20Security.md)
- [Web Application](Web%20Application.md)
- [Web App and Payloads](../Cheatsheets/Web%20App%20and%20Payloads.md)
- [API JWT and GraphQL](../Cheatsheets/API%20JWT%20and%20GraphQL.md)
- BypassBurrito
- [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md)
