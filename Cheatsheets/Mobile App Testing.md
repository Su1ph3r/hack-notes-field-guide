---
tags:
  - hack-notes
  - mobile
---

# Mobile App Testing Cheatsheet

## Table of Contents

- [Bench Setup](#bench-setup)
- [Android: adb Basics](#android-adb-basics)
- [Android: Static Analysis](#android-static-analysis)
- [Android: Frida Setup](#android-frida-setup)
- [Android: objection](#android-objection)
- [Android: Burp CA as System Cert](#android-burp-ca-as-system-cert)
- [Android: drozer](#android-drozer)
- [Android: Exported Components and Deep Links](#android-exported-components-and-deep-links)
- [Android: Intent Fuzzing](#android-intent-fuzzing)
- [Android: Smali Patching and Re-sign](#android-smali-patching-and-re-sign)
- [Android: Looting Storage](#android-looting-storage)
- [iOS: SSH over USB](#ios-ssh-over-usb)
- [iOS: Decrypting and Dumping](#ios-decrypting-and-dumping)
- [iOS: objection](#ios-objection)
- [iOS: Keychain and Plist Looting](#ios-keychain-and-plist-looting)
- [iOS: SSL Pinning Bypass](#ios-ssl-pinning-bypass)
- [iOS: Burp on Device](#ios-burp-on-device)
- [iOS: Frida Hooking](#ios-frida-hooking)
- [iOS: File System Loot](#ios-file-system-loot)
- [Common Workflows](#common-workflows)
- [Quick Reference](#quick-reference)

---

## Bench Setup

Reference bench: a Pixel running Android (rooted, Magisk) and a jailbroken
iPhone 6s on iOS 15.x, both driven from the host with Frida.

```bash
# Confirm the host toolchain
adb version                 # Android Debug Bridge
frida --version             # Frida CLI (host side)
objection version           # objection runtime mobile toolkit

# iOS host tools (libimobiledevice)
ideviceinfo                 # device info over USB
iproxy --help               # USB port forwarding for SSH
```

---

## Android: adb Basics

```bash
# List connected devices and emulators
adb devices
adb devices -l              # verbose, includes model and transport id

# Target a specific device when more than one is attached
adb -s <serial> shell

# Connect over TCP/IP (device must enable adb tcpip first)
adb tcpip 5555
adb connect 192.168.1.50:5555

# Install and uninstall
adb install app.apk
adb install -r app.apk      # reinstall, keep data
adb install -g app.apk      # grant all runtime permissions
adb uninstall com.example.app

# Pull and push files
adb pull /data/local/tmp/loot.db ./loot.db
adb push frida-server /data/local/tmp/

# Interactive shell and single commands
adb shell
adb shell pm list packages              # list installed packages
adb shell pm list packages -3           # third-party packages only
adb shell pm path com.example.app       # locate the base APK on disk
adb shell dumpsys package com.example.app   # manifest, permissions, components

# Logcat
adb logcat                              # full stream
adb logcat -c                           # clear the buffer
adb logcat | grep -i com.example.app    # filter by package text
adb logcat --pid=$(adb shell pidof com.example.app)   # filter by pid

# Root the adb shell (rooted device)
adb root                                # restart adbd as root
adb shell su -c id                      # run a single command as root via su
```

### Launching Activities and Components

```bash
# Start the main launcher activity
adb shell am start -n com.example.app/.MainActivity

# Start an activity with an action and data URI
adb shell am start -a android.intent.action.VIEW \
  -d "https://example.com/path" com.example.app

# Start a service
adb shell am startservice -n com.example.app/.SyncService

# Broadcast an intent
adb shell am broadcast -a com.example.app.CUSTOM_ACTION

# Invoke an exported component with extras
adb shell am start -n com.example.app/.ExportedActivity \
  --es token "value" --ez admin true --ei id 1337
```

---

## Android: Static Analysis

```bash
# Pull the APK off the device first
adb shell pm path com.example.app
adb pull /data/app/com.example.app-1/base.apk ./app.apk

# apktool: decode resources and smali, then rebuild
apktool d app.apk -o app_src         # decode to smali + resources
apktool b app_src -o app_patched.apk # build back to an APK

# jadx: decompile to Java
jadx app.apk -d jadx_out             # CLI decompile to a directory
jadx-gui app.apk                     # interactive GUI browser

# dex2jar then a Java decompiler
d2j-dex2jar app.apk -o app.jar       # convert dex to a jar

# Inspect the manifest directly
aapt dump xmltree app.apk AndroidManifest.xml
aapt dump badging app.apk            # package name, permissions, components

# MobSF (static + dynamic analysis web UI via Docker)
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
# Then open http://localhost:8000 and upload the APK
```

### What to Grep For

```bash
# Hunt secrets and endpoints in decompiled output
grep -rinE "api[_-]?key|secret|password|token|bearer" jadx_out/
grep -rinE "https?://" jadx_out/ | sort -u
grep -rin "exported=\"true\"" app_src/AndroidManifest.xml
```

---

## Android: Frida Setup

```bash
# Match the frida-server build to the device architecture and frida version
adb shell getprop ro.product.cpu.abi      # e.g. arm64-v8a
frida --version                           # match the server release

# Download the matching frida-server release, then push and run it
adb push frida-server-16.x.x-android-arm64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c /data/local/tmp/frida-server &"

# Confirm the host can see processes over USB
frida-ps -U                               # list running processes
frida-ps -Ua                              # list installed apps with names
frida-ps -Uai                             # include all installed apps

# Spawn the app under Frida and attach at launch
frida -U -f com.example.app -l hook.js    # spawn, load script, no pause
frida -U -f com.example.app --no-pause

# Attach to an already running app
frida -U -n com.example.app -l hook.js
frida -U com.example.app

# Use a community script from codeshare
frida --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida \
  -U -f com.example.app
```

### Minimal Frida Java Hook

```javascript
// hook.js
Java.perform(function () {
  var Login = Java.use("com.example.app.LoginManager");
  Login.checkPassword.implementation = function (pw) {
    console.log("[*] checkPassword called with: " + pw);
    return true;   // force success
  };
});
```

---

## Android: objection

```bash
# Patch and launch the target with the Frida gadget, or attach to a running app
objection -g com.example.app explore     # attach via the running frida-server

# Inside the objection REPL
android hooking list activities          # enumerate activities
android hooking list services
android hooking list receivers
android hooking watch class com.example.app.LoginManager
android hooking watch class_method com.example.app.LoginManager.checkPassword --dump-args --dump-return

# SSL pinning and root detection bypasses
android sslpinning disable               # disable common pinning implementations
android root disable                     # bypass common root detection checks

# Memory and heap inspection
memory list modules                      # loaded native modules
memory list exports libssl.so            # exported symbols
memory search --string "password"        # scan process memory for a string
android heap search instances com.example.app.User
android heap print fields 0x<handle>     # dump a live object's fields

# Keystore and storage
android keystore list                    # entries in the Android Keystore
android keystore clear
env                                       # app data directories
ls /data/data/com.example.app/shared_prefs
file download /data/data/com.example.app/databases/app.db ./app.db
```

---

## Android: Burp CA as System Cert

Apps targeting API 24+ ignore user-added CAs by default, so the Burp CA must
be installed as a system cert on a rooted device, or the app's network config
must be relaxed.

```bash
# Export the Burp CA from Burp, then convert DER to PEM
openssl x509 -inform DER -in cacert.der -out burp.pem

# Compute the subject hash used as the system cert filename
openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1
# -> e.g. 9a5ba575
cp burp.pem 9a5ba575.0

# Push and move into the system store (Magisk: /system may be read-only)
adb push 9a5ba575.0 /data/local/tmp/
adb shell su -c "mount -o rw,remount /system"
adb shell su -c "cp /data/local/tmp/9a5ba575.0 /system/etc/security/cacerts/"
adb shell su -c "chmod 644 /system/etc/security/cacerts/9a5ba575.0"
adb shell su -c "mount -o ro,remount /system"
adb reboot
```

### Magisk Systemless CA Trust

```bash
# On newer Android the system cert store moved to a tmpfs mount.
# Magisk modules such as MagiskTrustUserCerts or the cert-fixup approach
# copy user CAs into the runtime store without modifying /system.
# Install the module, add the Burp CA as a user cert, then reboot.
```

### network_security_config Bypass (repackaging)

```xml
<!-- res/xml/network_security_config.xml after decoding with apktool -->
<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors>
      <certificates src="system" />
      <certificates src="user" />
    </trust-anchors>
  </base-config>
</network-security-config>
```

```bash
# Rebuild and re-sign after adding the config (see smali patching section)
apktool b app_src -o app_patched.apk
```

---

## Android: drozer

```bash
# On the device, install and start the drozer agent app, then forward the port
adb forward tcp:31415 tcp:31415
drozer console connect

# Inside the drozer console
run app.package.list -f example          # find packages by filter
run app.package.info -a com.example.app  # permissions and details
run app.package.attacksurface com.example.app   # exported attack surface

# Activities
run app.activity.info -a com.example.app
run app.activity.start --component com.example.app com.example.app.ExportedActivity

# Content providers (IDOR, SQL injection, path traversal)
run app.provider.info -a com.example.app
run app.provider.finduri com.example.app
run app.provider.query content://com.example.app.provider/users
run scanner.provider.injection -a com.example.app
run scanner.provider.traversal -a com.example.app

# Services and broadcast receivers
run app.service.info -a com.example.app
run app.broadcast.info -a com.example.app
run app.broadcast.send --action com.example.app.CUSTOM_ACTION
```

---

## Android: Exported Components and Deep Links

```bash
# Dump all exported components from the manifest
adb shell dumpsys package com.example.app | grep -iE "exported|filter|action"

# Decode the manifest and look for exported attributes and intent filters
apktool d app.apk -o app_src
grep -nE "android:exported=\"true\"|<intent-filter>|android:scheme" \
  app_src/AndroidManifest.xml

# Invoke an exported activity directly
adb shell am start -n com.example.app/.ExportedActivity

# Trigger a custom-scheme deep link
adb shell am start -a android.intent.action.VIEW -d "myapp://reset?token=abc"

# Trigger an http(s) app link
adb shell am start -a android.intent.action.VIEW -d "https://example.com/u/1"

# Verify which app handles a deep link
adb shell pm get-app-links com.example.app
```

---

## Android: Intent Fuzzing

```bash
# Send extras of mixed types to probe input handling
adb shell am start -n com.example.app/.ExportedActivity \
  --es key "../../etc/passwd" \
  --ei id -1 \
  --ez admin true \
  --esa list "a,b,c"

# Broadcast fuzzing with varied actions and data
adb shell am broadcast -a com.example.app.ACTION --es payload "<script>" 

# drozer intent fuzzing module
# run intent.fuzzinozer (community module) or scripted am loops

# Scripted loop over candidate extras from the host
for v in "../../" "%00" "' OR '1'='1" "file:///etc/hosts"; do
  adb shell am start -n com.example.app/.ExportedActivity --es input "$v"
  sleep 1
done
```

---

## Android: Smali Patching and Re-sign

```bash
# Decode, edit smali, then rebuild
apktool d app.apk -o app_src
# Edit app_src/smali/.../SomeClass.smali (e.g. invert a boolean return)
apktool b app_src -o app_patched.apk

# Generate a signing keystore once
keytool -genkey -v -keystore my.keystore -alias mykey \
  -keyalg RSA -keysize 2048 -validity 10000

# Zipalign (recommended before signing with apksigner)
zipalign -p 4 app_patched.apk app_aligned.apk

# Sign with apksigner (modern, supports v2/v3 signatures)
apksigner sign --ks my.keystore --ks-key-alias mykey \
  --out app_signed.apk app_aligned.apk

# Verify the signature
apksigner verify --verbose app_signed.apk

# Install the patched build (uninstall the original first if signatures differ)
adb uninstall com.example.app
adb install app_signed.apk
```

### Common Smali Patch Targets

```smali
# Force a method to return true
.method public isRooted()Z
    const/4 v0, 0x1
    return v0
.end method
```

---

## Android: Looting Storage

```bash
# App private data directory layout
adb shell su -c "ls -la /data/data/com.example.app/"

# Shared preferences (often hold tokens, flags, PII)
adb shell su -c "cat /data/data/com.example.app/shared_prefs/*.xml"

# SQLite databases
adb pull /data/data/com.example.app/databases/app.db
sqlite3 app.db ".tables"
sqlite3 app.db "SELECT * FROM users;"

# External / cache files
adb shell run-as com.example.app ls -la files cache
adb shell run-as com.example.app cat shared_prefs/auth.xml   # debuggable apps only

# Android Keystore inspection is via objection (keys are non-exportable):
#   android keystore list
```

---

## iOS: SSH over USB

```bash
# Forward a local port to the device's SSH (OpenSSH from the jailbreak)
iproxy 2222 22                     # localhost:2222 -> device:22
ssh -p 2222 root@127.0.0.1         # default jailbreak password: alpine

# List apps and their bundle ids over USB
ideviceinstaller -l                # installed apps
frida-ps -Uai                      # apps with bundle identifiers
```

---

## iOS: Decrypting and Dumping

```bash
# Dump a decrypted IPA from a running app (App Store binaries are encrypted)
frida-ios-dump -H 127.0.0.1 -p 2222 -u root -P alpine com.example.app
# Produces a decrypted Example.ipa for static analysis

# Unzip and inspect the Mach-O
unzip Example.ipa -d ExampleApp
otool -l ExampleApp/Payload/Example.app/Example | grep -A4 LC_ENCRYPTION_INFO
# cryptid 0 == decrypted

# Class and method dump from the Objective-C runtime
class-dump ExampleApp/Payload/Example.app/Example > headers.h

# Dump classes live from the running process with Frida
frida -U com.example.app -e \
  "ObjC.classes" 
# or use the objc enumeration helpers inside a script
```

---

## iOS: objection

```bash
objection -g com.example.app explore

# Inside the objection REPL
ios info binary                    # PIE, ARC, stack canary, encryption flags
ios hooking list classes
ios hooking search classes Login
ios hooking watch method "-[LoginManager checkPassword:]" --dump-args --dump-return
ios hooking set return_value "-[LoginManager isJailbroken]" false

# SSL pinning and jailbreak detection bypass
ios sslpinning disable
ios jailbreak disable

# Storage
ios nsuserdefaults get             # dump NSUserDefaults
ios plist cat Info.plist
ios cookies get                    # WKWebView / NSHTTPCookieStorage
```

---

## iOS: Keychain and Plist Looting

```bash
# Dump the app's keychain items (passwords, tokens, refresh tokens)
objection -g com.example.app explore
ios keychain dump
ios keychain dump --json /tmp/keychain.json

# NSUserDefaults and plist files
ios nsuserdefaults get
ios plist cat Library/Preferences/com.example.app.plist

# Over SSH, read plists directly from the container
ssh -p 2222 root@127.0.0.1
plutil -p /var/mobile/Containers/Data/Application/<UUID>/Library/Preferences/com.example.app.plist
```

---

## iOS: SSL Pinning Bypass

```bash
# 1) objection (covers common AFNetworking / NSURLSession pinning)
objection -g com.example.app explore -s "ios sslpinning disable"

# 2) SSL Kill Switch 2 / 3 (system-wide tweak via Cydia/Sileo)
#    Install the package, enable in Settings, then relaunch the app.

# 3) Frida codeshare script for stubborn pinning
frida --codeshare dki/ios-ssl-bypass -U -f com.example.app
frida -U -f com.example.app -l ios-ssl-pinning-bypass.js
```

### Frida SecTrustEvaluate Stub

```javascript
// ios-ssl-pinning-bypass.js (concept: force trust evaluation to pass)
var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
Interceptor.replace(SecTrustEvaluate, new NativeCallback(function (trust, result) {
  Memory.writeU32(result, 1);   // kSecTrustResultProceed
  return 0;                      // errSecSuccess
}, "int", ["pointer", "pointer"]));
```

---

## iOS: Burp on Device

```bash
# 1) Set the device Wi-Fi HTTP proxy to the Burp listener (host_ip:8080)
# 2) On the device, browse to http://burp and download the CA cert
# 3) Install profile: Settings > General > VPN & Device Management
# 4) Trust the root: Settings > General > About > Certificate Trust Settings
#    Toggle full trust for the PortSwigger CA
# 5) Bypass pinning (objection / SSL Kill Switch) for app traffic to appear
```

---

## iOS: Frida Hooking

```bash
# Attach and run an inline expression
frida -U com.example.app

# Hook an Objective-C method from a script
frida -U -f com.example.app -l ios-hook.js --no-pause
```

```javascript
// ios-hook.js
if (ObjC.available) {
  var LoginManager = ObjC.classes.LoginManager;
  Interceptor.attach(LoginManager["- checkPassword:"].implementation, {
    onEnter: function (args) {
      console.log("[*] checkPassword: " + ObjC.Object(args[2]).toString());
    },
    onLeave: function (retval) {
      retval.replace(0x1);   // force BOOL YES
    }
  });
}
```

```bash
# Cycript is the legacy alternative on older jailbreaks
cycript -p com.example.app
# Frida is preferred on iOS 15.x benches
```

---

## iOS: File System Loot

```bash
ssh -p 2222 root@127.0.0.1

# App bundle (the installed .app) and data container live under Containers
ls /var/containers/Bundle/Application/        # app bundles
ls /var/mobile/Containers/Data/Application/   # per-app data containers

# Find the data container for a bundle id
find /var/mobile/Containers/Data/Application -name "*.plist" \
  -path "*com.example.app*"

# Typical loot inside a data container
ls Documents Library Library/Preferences Library/Caches tmp
cat Library/Preferences/com.example.app.plist
sqlite3 Documents/app.sqlite ".tables"

# Pull the whole container back to the host
scp -P 2222 -r root@127.0.0.1:/var/mobile/Containers/Data/Application/<UUID> ./loot
```

---

## Common Workflows

### Android: Provision to Loot

```bash
# 1) Provision: confirm device, root, and Frida
adb devices -l
adb root
adb push frida-server /data/local/tmp/ && adb shell su -c "/data/local/tmp/frida-server &"

# 2) Intercept TLS: install the Burp CA as a system cert (rooted)
#    (see Burp CA as System Cert section), set the device proxy to Burp

# 3) Bypass pinning and root detection
objection -g com.example.app explore -s "android sslpinning disable; android root disable"

# 4) Instrument: hook auth/crypto, watch the classes of interest
frida -U -f com.example.app -l hook.js --no-pause

# 5) Loot: pull shared_prefs, databases, dump keystore entries
adb shell su -c "cat /data/data/com.example.app/shared_prefs/*.xml"
adb pull /data/data/com.example.app/databases/app.db
```

### iOS: Provision to Loot

```bash
# 1) Provision: SSH over USB, confirm Frida sees the app
iproxy 2222 22 &
frida-ps -Uai

# 2) Intercept TLS: device proxy to Burp, install + fully trust the Burp CA

# 3) Bypass pinning and jailbreak detection
objection -g com.example.app explore -s "ios sslpinning disable; ios jailbreak disable"

# 4) Instrument: decrypt the IPA, class-dump, hook methods of interest
frida-ios-dump -H 127.0.0.1 -p 2222 -u root -P alpine com.example.app
frida -U -f com.example.app -l ios-hook.js --no-pause

# 5) Loot: keychain dump, NSUserDefaults, container files
objection -g com.example.app explore -s "ios keychain dump"
scp -P 2222 -r root@127.0.0.1:/var/mobile/Containers/Data/Application/<UUID> ./loot
```

---

## Quick Reference

```bash
# Android
adb devices -l                                   # list devices
adb shell pm list packages -3                    # third-party packages
adb pull /data/app/com.example.app-1/base.apk    # grab the APK
apktool d app.apk -o app_src                     # decode
jadx-gui app.apk                                 # decompile GUI
frida-ps -Uai                                    # apps over USB
frida -U -f com.example.app -l hook.js           # spawn + hook
objection -g com.example.app explore             # objection REPL
android sslpinning disable                        # in objection
apksigner sign --ks my.keystore app_aligned.apk  # re-sign

# iOS
iproxy 2222 22                                    # SSH over USB
ssh -p 2222 root@127.0.0.1                        # password: alpine
frida-ios-dump ... com.example.app                # decrypted IPA
class-dump Example > headers.h                    # ObjC headers
objection -g com.example.app explore              # objection REPL
ios sslpinning disable                            # in objection
ios keychain dump                                 # dump keychain
ls /var/mobile/Containers/Data/Application/       # data containers
```

---

## Related

- Checklists: [Mobile Application](../Checklists/Mobile%20Application.md)
- [Web App and Payloads](Web%20App%20and%20Payloads.md)
- [API JWT and GraphQL](API%20JWT%20and%20GraphQL.md)
- [OSINT and Recon](OSINT%20and%20Recon.md)
