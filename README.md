<p align="center">
  <img src="https://img.shields.io/badge/🐍-ApkViper-00d4aa?style=for-the-badge&labelColor=1a1b26" alt="ApkViper"/>
</p>

<h1 align="center">🐍 ApkViper v2.0.0</h1>
<h3 align="center">Advanced Android Security Assessment Platform</h3>
<h4 align="center">The Most Complete Single-File Android SAST Tool Ever Built</h4>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776ab?style=flat-square&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Platform-Windows%20|%20Linux%20|%20macOS-blue?style=flat-square" alt="Platform"/>
  <img src="https://img.shields.io/badge/Dependencies-Zero-success?style=flat-square" alt="Deps"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License"/>
  <img src="https://img.shields.io/badge/Version-2.0.0-orange?style=flat-square" alt="Version"/>
  <img src="https://img.shields.io/badge/Rules-125+-red?style=flat-square" alt="Rules"/>
  <img src="https://img.shields.io/badge/Zero--Day-75_Rules-critical?style=flat-square" alt="Zero-Day"/>
  <img src="https://img.shields.io/badge/Engines-8_Parallel-blueviolet?style=flat-square" alt="Engines"/>
  <img src="https://img.shields.io/badge/CVE_DB-38_Real_CVEs-darkred?style=flat-square" alt="CVEs"/>
  <img src="https://img.shields.io/badge/Exploits-32_PoCs-black?style=flat-square" alt="Exploits"/>
  <img src="https://img.shields.io/badge/OWASP-Mobile%20Top%2010-critical?style=flat-square" alt="OWASP"/>
  <img src="https://img.shields.io/badge/Lines-4200+-informational?style=flat-square" alt="Lines"/>
</p>

<p align="center">
  <b>125+ security rules • 8 analysis engines • 38 real CVEs • 32 exploit PoCs • 7 export formats<br/>Single file. Zero dependencies. Pure Python. 4200+ lines of security intelligence.</b>
</p>

---

## 🎯 What is ApkViper?

**ApkViper** is the most advanced single-file Static Application Security Testing (SAST) platform for Android APK files. It combines 8 parallel analysis engines — pattern matching, inter-procedural taint analysis, cross-method dataflow tracking, native binary analysis, cross-component flow analysis, CVE discovery, live threat feed, and auto-fuzzer generation — all packed into a single Python file with zero external dependencies.

> **One file. 4200+ lines. 125+ rules. 8 engines. Zero setup.**

Unlike traditional SAST tools that require complex installation, Docker containers, or cloud services, ApkViper is a **single `apkviper.py` file** that runs anywhere Python 3.8+ is available. Drop it anywhere and scan.

---

## 🏆 What Makes ApkViper Unique

| Capability | Details |
|:---|:---|
| 🧠 **8 Parallel Analysis Engines** | Pattern scanner, taint analysis, cross-method dataflow, native binary analyzer, cross-component flow, CVE discovery, live threat feed, and auto-fuzzer — all running in one scan pass |
| 🔥 **75 Zero-Day Detection Rules** | Targets 2025-2026 attack surfaces: Jetpack Compose, Kotlin Coroutines, CameraX, ML Kit, Health Connect, Credential Manager, Predictive Back, BLE GATT, VPN tunnels |
| 💀 **32 Real-World Exploit PoCs** | Not theoretical — actual working attack chains with CVE references, tool commands, Frida scripts, and ADB automation for every major finding |
| 🛡️ **38 CVE Database Entries** | CVE-2020-0096 through CVE-2026-0042, including Samsung zero-click (CVE-2024-49415), Qualcomm DSP UAF (CVE-2024-43047), Android Zygote injection (CVE-2024-31317) |
| 📡 **Live Threat Feed** | Auto-fetches latest Android CVEs from NVD (NIST) & GitHub Advisory DB, generates regex rules from descriptions, persists across restarts |
| 🎯 **Auto-PoC Generator** | Generates working bash/Frida exploit scripts per finding, personalized with real package names, plus video PoC recording automation |
| 📊 **7 Export Formats** | HTML (enterprise dashboard), PDF, Word (.docx), Excel (.xlsx), JSON, CSV, SARIF 2.1.0 |
| 🎨 **Professional GUI** | Dark-themed tkinter interface with 9 tabs: Dashboard, Findings, Source Viewer, Exploits, Bypass DB, Zero-Day, Components, Live Feed, About |

---

## ⚡ Feature Overview

### 🔬 Analysis Engines (8 Total)

| # | Engine | What It Does |
|:-:|:-------|:-------------|
| 1 | **Pattern Scanner** | 125+ regex rules across 12 categories (50 base + 75 zero-day) |
| 2 | **Taint Analysis** | Inter-procedural source→sink flow tracking (getIntent→execSQL, getExtra→loadUrl, etc.) |
| 3 | **Cross-Method Dataflow** | Tracks tainted variables across assignments, method calls, and type casts |
| 4 | **Native Binary Analyzer** | ELF inspection for PIE, stack canaries, dangerous functions (strcpy, system, popen) |
| 5 | **Cross-Component Flow** | Traces Intent extras from sender Activity to receiver's sink operations |
| 6 | **CVE Discovery Engine** | 22 zero-day patterns matching known CVE attack surfaces (Parcel mismatch, media decoder overflow, deeplink-to-RCE) |
| 7 | **Live Threat Feed** | Real-time CVE fetch from NVD + GitHub Advisory → auto-generates detection rules |
| 8 | **Auto-Fuzzer Generator** | Creates ADB fuzzing scripts + Frida hooks for all exported components |

### 🔐 Security Rules (125+ Total)

| Category | Count | Highlights |
|:---------|:-----:|:-----------|
| **Manifest Security** | 5 | Debuggable, backup, cleartext traffic, exported components, deeplinks |
| **Cryptography** | 4 | Weak hash (MD5/SHA1), insecure cipher (DES/RC4/ECB), predictable RNG, hardcoded keys |
| **Secrets & Storage** | 6 | API keys, log leaks, clipboard, SharedPrefs, file permissions, sensitive files |
| **Network Security** | 6 | Trust-all certs, cleartext NSC, insecure WebView, SSL override, cert bypass, SSL pinning |
| **Platform Abuse** | 6 | Zip traversal, mutable PendingIntent, content provider injection, broadcast theft, deeplinks, fragment injection |
| **Injection** | 3 | SQL injection, command injection, tapjacking |
| **Resilience** | 6 | Root detection, emulator detection, dynamic code loading, deserialization, obfuscation, biometric |
| **Privacy** | 4 | Dangerous permissions, tracker SDKs, hardcoded URLs, GDPR consent |
| **Authentication** | 3 | Insecure credential storage, hardcoded sessions, weak password policy |
| **Web Security** | 4 | WebView XSS, XXE injection, SSRF, open redirect |
| **Cloud** | 1 | Firebase misconfiguration |
| **Other** | 3 | Debug code, malware patterns, native libraries |
| **Zero-Day (2025-2026)** | 75 | Intent redirection, FileProvider root path, Kotlin coroutine leaks, Credential Manager phishing, BLE sniffing, ML model tampering, accessibility keylogging, VPN interception, Health Connect injection, Predictive Back auth bypass, and 65 more |
| **CVE Discovery** | 22 | Parcel mismatch (CVE-2023-20963 pattern), media buffer overflow (CVE-2024-49415 pattern), deeplink-to-WebView RCE, implicit PendingIntent escalation, and 18 more |

### 💀 Exploit Knowledge Base (32 PoCs)

Every major finding includes a **complete exploitation methodology** with:
- 🔧 Required tools (Frida, adb, mitmproxy, drozer, etc.)
- 📋 Step-by-step attack instructions
- 💻 Working Proof-of-Concept scripts (bash + Frida JS)
- 🔗 Real CVE references with exploit chains
- 🎯 Auto-personalized with the scanned app's actual package name

**Exploits included for:** Debuggable apps, backup extraction, cleartext MITM, exported components, hardcoded secrets, log leaks, SSL bypass, WebView RCE, SQL injection, command injection, crypto weakness, deeplink hijack, PendingIntent escalation, content provider injection, zip slip, fragment injection, Firebase misconfiguration, WebView XSS, deserialization, dynamic code loading, broadcast theft, SharedPrefs, clipboard theft, native library exploitation, biometric bypass, malware detection, accessibility abuse, credential manager phishing, VPN interception, notification listener theft, and more.

### 🔓 Bypass Techniques Database (7 Techniques)

| Technique | Category |
|:----------|:---------|
| SSL Pinning Bypass | Network |
| Root Detection Bypass | Resilience |
| Biometric Authentication Bypass | Auth |
| Emulator Detection Bypass | Resilience |
| Debugger Detection Bypass | Resilience |
| Tapjacking / Overlay Attack | UI |
| Intent Redirection / Task Hijacking | Platform |

### 🛡️ CVE Database (38 Real-World Vulnerabilities)

Includes detailed exploits for real Android CVEs from 2020-2026:

| CVE | Name | CVSS | Year |
|:----|:-----|:----:|:----:|
| CVE-2024-49415 | Samsung Zero-Click RCE via Audio | 9.8 | 2025 |
| CVE-2024-43047 | Qualcomm DSP Driver UAF | 9.8 | 2024 |
| CVE-2024-31317 | Zygote Command Injection | 9.8 | 2024 |
| CVE-2024-0044 | Android run-as Privilege Escalation | 9.8 | 2024 |
| CVE-2023-20963 | WorkSource Parcel Mismatch (Pinduoduo) | 9.8 | 2023 |
| CVE-2023-4863 | libwebp Heap Buffer Overflow | 9.8 | 2023 |
| CVE-2025-0097 | Samsung Galaxy Store RCE | 9.1 | 2025 |
| CVE-2025-27363 | FreeType OOB Write | 8.1 | 2025 |
| CVE-2024-53104 | USB Video Class Kernel OOB (Cellebrite) | 7.8 | 2025 |
| CVE-2025-26633 | Android Lock Screen Bypass | 7.8 | 2025 |
| | *...and 28 more* | | |

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        ApkViper v2.0.0 Engine                        │
├────────────┬────────────┬────────────┬────────────┬──────────────────┤
│  Binary    │  Pattern   │   Taint    │  Advanced  │   Output         │
│  Parsers   │  Scanner   │   Engine   │  Engines   │   Layer          │
├────────────┼────────────┼────────────┼────────────┼──────────────────┤
│ AXML Parse │ 50 Base    │ Source →   │ Cross-Meth │ HTML Dashboard   │
│ DEX Parse  │ 75 Zero-Day│ Sink Track │ Native Bin │ PDF / Word / XLS │
│ ZIP Extract│ 22 CVE Disc│ 8 Sources  │ Cross-Comp │ JSON / CSV       │
│ Pkg Extract│ Live Feed  │ 11 Sinks   │ CVE Disc   │ SARIF 2.1.0      │
├────────────┼────────────┼────────────┼────────────┼──────────────────┤
│  Exploit DB (32 PoCs)   │ Bypass DB (7 Techniques) │ Auto-PoC Gen    │
│  CVE DB (38 Real CVEs)  │ Fuzzer Script Generator  │ Video PoC Gen   │
└─────────────────────────┴──────────────────────────┴──────────────────┘
```

---

## 📋 Requirements

| Requirement | Details |
|:------------|:--------|
| **Python** | 3.8 or higher |
| **tkinter** | Included with Python (Windows/macOS). Install `python3-tk` on Linux |
| **Dependencies** | **None** — uses only Python standard library |
| **Internet** | Not required (optional for Live Threat Feed) |
| **Disk Space** | < 300 KB (single file) |

---

## 🚀 Installation

### Option 1: Clone from GitHub

```bash
git clone https://github.com/rhishinathvarma-dfx/APKViper.git
cd APKViper
python apkviper.py
```

### Option 2: Direct Download

Download `apkviper.py` and run directly — that's it:

```bash
python apkviper.py
```

### Linux Users (tkinter)

```bash
# Ubuntu / Debian
sudo apt-get install python3-tk

# Fedora / RHEL
sudo dnf install python3-tkinter

# Arch Linux
sudo pacman -S tk
```

### Verify Installation

```bash
python apkviper.py --help
```

Expected output:
```
ApkViper v2.0.0 - Android Security Assessment

Usage:
  python apkviper.py                          Launch GUI
  python apkviper.py --scan <apk>             Headless scan
  python apkviper.py --scan <apk> --format html --output report.html
  python apkviper.py --scan <apk> --format sarif
  python apkviper.py --server --port 8089     REST API

Features: 125 rules (50 base + 75 zero-day) + taint analysis + exploit DB + bypass techniques
Formats: json, html, csv, sarif
Exit: 0=pass, 1=error, 2=critical/high
```

---

## 🖥️ Usage

### GUI Mode (Default)

```bash
python apkviper.py
```

Launches the professional dark-themed GUI with **9 tabs**:

| Tab | Contents |
|:----|:---------|
| 📊 **Dashboard** | Risk gauge, severity breakdown, OWASP coverage, category chart, component stats, finding summary with hit counts |
| 🔍 **Findings** | Sortable table with ID, severity, title, CWE, hit count, location, CVSS. Click any row for full details |
| 💻 **Source Viewer** | Syntax-highlighted source code viewer for extracted APK files |
| 💣 **Exploits** | Full exploit knowledge base with personalized PoC scripts, CVE references, tool commands |
| 🔓 **Bypass DB** | SSL pinning, root detection, biometric, emulator, debugger bypass — ready-to-use Frida/objection scripts |
| ⚡ **Zero-Day** | Dedicated view of 0-day pattern matches from CVE Discovery Engine |
| 📦 **Components** | Android manifest analysis — activities, services, receivers, providers, permissions with risk classification |
| 📡 **Live Feed** | Real-time CVE fetcher from NVD + GitHub Advisory. Auto-generates detection rules. Persists across restarts |
| ℹ️ **About** | Version info, engine stats, compliance standards |

### CLI Mode (Headless Scanning)

```bash
# Basic scan — outputs JSON
python apkviper.py --scan app.apk

# Generate enterprise HTML report
python apkviper.py --scan app.apk --format html --output report.html

# SARIF report (for GitHub Code Scanning / Azure DevOps)
python apkviper.py --scan app.apk --format sarif --output results.sarif

# CSV export (for Excel / Google Sheets)
python apkviper.py --scan app.apk --format csv --output findings.csv
```

**CLI output includes:**
- Unique finding count + total occurrence count (consolidated)
- Taint flow count, cross-method dataflow, binary issues, cross-component flows, CVE patterns
- Potential 0-day vulnerability alerts with CVSS scores
- Auto-generated PoC exploit scripts in `pocs_<package>/` directory
- Video PoC demo script for screen recording
- Session auto-save to `~/.apkviper/`

### REST API Server

```bash
# Start on default port 8089
python apkviper.py --server

# Custom port
python apkviper.py --server --port 9090
```

#### API Endpoints

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/health` | Server health check + version info |
| `GET` | `/api/rules` | List all 125+ security rules |
| `POST` | `/api/scan` | Upload APK binary, receive full scan results as JSON |

#### Example API Call

```bash
# Health check
curl http://localhost:8089/api/health

# Scan APK
curl -X POST http://localhost:8089/api/scan \
  --data-binary @app.apk \
  -H "Content-Type: application/octet-stream"
```

---

## 📊 Report Formats (7 Total)

| Format | Extension | Best For | Features |
|:-------|:----------|:---------|:---------|
| **HTML** | `.html` | Executive reporting, client delivery | Full dark-themed dashboard, risk gauge, severity pie chart, OWASP coverage matrix, compliance mapping, finding cards with exploit PoCs, CVE references, bypass techniques, remediation guidance — all in one standalone file |
| **PDF** | `.pdf` | Formal assessments, print | Multi-page with executive summary, components, permissions, all findings with CVSS |
| **Word** | `.docx` | Editable reports, consulting | Full OOXML with styled headings, finding table, component analysis, methodology |
| **Excel** | `.xlsx` | Data analysis, tracking | Two-sheet workbook: Findings (sortable) + Summary (stats, components, permissions) |
| **JSON** | `.json` | CI/CD integration, custom tooling | Complete metadata, CVE enrichment, component data, all fields |
| **CSV** | `.csv` | Spreadsheets, bulk import | All findings with hit counts and location lists |
| **SARIF** | `.sarif.json` | GitHub Advanced Security, Azure DevOps | SARIF 2.1.0 compliant, multi-location support, security-severity properties |

---

## 🔄 CI/CD Integration

### Exit Codes

| Code | Meaning | Action |
|:----:|:--------|:-------|
| `0` | ✅ Pass — no critical/high findings | Pipeline continues |
| `1` | ⚠️ Error — scan failed | Investigate |
| `2` | ❌ Fail — critical or high findings detected | Block release |

### GitHub Actions

```yaml
name: Android Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Run ApkViper Security Scan
        run: |
          python apkviper.py --scan app/build/outputs/apk/release/app-release.apk \
            --format sarif --output results.sarif

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security_scan:
  stage: test
  image: python:3.11-slim
  script:
    - apt-get update && apt-get install -y python3-tk
    - python apkviper.py --scan $APK_PATH --format html --output security-report.html
  artifacts:
    paths:
      - security-report.html
      - pocs_*/
    when: always
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    python3 apkviper.py --scan ${APK_PATH} \
                      --format html --output security-report.html
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'security-report.html, pocs_*/**'
                    publishHTML([
                        reportDir: '.', reportFiles: 'security-report.html',
                        reportName: 'Security Assessment'
                    ])
                }
            }
        }
    }
}
```

---

## 🆚 Comparison with Other Tools

| Feature | ApkViper v2 | MobSF | QARK | AndroBugs | Oversecured |
|:--------|:----------:|:-----:|:----:|:---------:|:-----------:|
| Single File Deployment | ✅ | ❌ | ❌ | ❌ | ❌ |
| Zero Dependencies | ✅ | ❌ | ❌ | ❌ | ❌ |
| Security Rules | **125+** | ~60 | ~25 | ~40 | ~80 |
| Zero-Day Rules (2025-2026) | **75** | ❌ | ❌ | ❌ | ❌ |
| Analysis Engines | **8** | 2 | 1 | 1 | 3 |
| Inter-Procedural Taint | ✅ | ❌ | ❌ | ❌ | ✅ |
| Cross-Method Dataflow | ✅ | ❌ | ❌ | ❌ | ✅ |
| Native Binary Analysis | ✅ | ✅ | ❌ | ❌ | ❌ |
| Cross-Component Flow | ✅ | ❌ | ❌ | ❌ | ❌ |
| CVE Discovery Engine | ✅ | ❌ | ❌ | ❌ | ❌ |
| Live Threat Feed | ✅ | ❌ | ❌ | ❌ | ❌ |
| Exploit PoC Generation | **32 PoCs** | ❌ | ❌ | ❌ | ❌ |
| Auto-PoC Script Export | ✅ | ❌ | ❌ | ❌ | ❌ |
| Video PoC Generator | ✅ | ❌ | ❌ | ❌ | ❌ |
| Bypass Techniques DB | ✅ | ❌ | ❌ | ❌ | ❌ |
| CVE Database | **38 CVEs** | ✅ | ❌ | ❌ | ✅ |
| GUI Dashboard | ✅ (9 tabs) | ✅ | ❌ | ❌ | ✅ |
| REST API | ✅ | ✅ | ❌ | ❌ | ✅ |
| Export Formats | **7** | 2 | 1 | 1 | 2 |
| SARIF Output | ✅ | ❌ | ❌ | ❌ | ❌ |
| PDF/Word/Excel | ✅ | ❌ | ❌ | ❌ | ❌ |
| HTML Enterprise Report | ✅ | ✅ | ❌ | ❌ | ✅ |
| Binary Manifest Parse | ✅ | ✅ | ❌ | ✅ | ✅ |
| DEX Bytecode Analysis | ✅ | ✅ | ❌ | ❌ | ✅ |
| CVSS 3.1 Scoring | ✅ | ✅ | ❌ | ❌ | ✅ |
| Finding Consolidation | ✅ | ❌ | ❌ | ❌ | ✅ |
| Session Management | ✅ | ✅ | ❌ | ❌ | ✅ |
| Fuzzer Script Gen | ✅ | ❌ | ❌ | ❌ | ❌ |
| Cross-Platform | ✅ | ✅ | ✅ | ✅ | ❌ (SaaS) |
| Offline Operation | ✅ | ✅ | ✅ | ✅ | ❌ |
| Setup Time | **0 min** | 15+ min | 10+ min | 5+ min | N/A |
| Cost | **Free** | Free | Free | Free | **$$$** |

---

## 🔐 Standards & Compliance

| Standard | Coverage |
|:---------|:---------|
| ✅ **OWASP MASVS v2** | Mobile Application Security Verification Standard (L1 + L2) |
| ✅ **OWASP MASTG** | Mobile Application Security Testing Guide |
| ✅ **OWASP Mobile Top 10** | 2024 Edition — all 10 categories covered |
| ✅ **CWE/SANS Top 25** | Common Weakness Enumeration |
| ✅ **CVSS 3.1** | Common Vulnerability Scoring System — every finding scored |
| ✅ **NIST SP 800-53 r5** | Security and Privacy Controls (SC-8, SI-10, AC-3) |
| ✅ **PCI-DSS v4.0** | Payment Card Industry Data Security Standard (6.2.4, 6.5.1-10) |
| ✅ **GDPR Art. 25/32** | Data Protection Impact Assessment |
| ✅ **HIPAA §164.312** | Health Information Portability (ePHI protection) |
| ✅ **SARIF 2.1.0** | Static Analysis Results Interchange Format |

---

## 🛠️ Project Structure

```
APKViper/
├── apkviper.py          # Complete application — single standalone file (4200+ lines)
├── README.md            # This documentation
├── LICENSE              # MIT License
└── .gitignore           # Git ignore rules
```

**That's it.** The entire tool — all 8 engines, 125+ rules, 32 exploits, 38 CVEs, 7 bypass techniques, GUI, CLI, REST API, and 7 export formats — lives in a single `apkviper.py` file.

---

## 🤝 Contributing

Contributions are welcome! Here's how to get involved:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/new-rule`
3. **Add** your changes to `apkviper.py`
4. **Test** with real APK files from various domains
5. **Submit** a Pull Request

### Adding Custom Security Rules

Rules follow this structure in the `RULES` list:

```python
{
    "id": "AV-CAT-NNN",        # Unique ID (AV-[Category]-[Number])
    "name": "Rule Name",       # Human-readable title
    "sev": "HIGH",             # CRITICAL | HIGH | MEDIUM | LOW | INFO
    "cwe": "CWE-XXX",         # CWE reference number
    "owasp": "M1",            # OWASP Mobile Top 10 category
    "regex": r'pattern',       # Detection regex pattern
    "types": ["SOURCE"],       # File types: MANIFEST | SOURCE | RESOURCE
    "desc": "Description",     # What this vulnerability means
    "fix": "Remediation",      # How to fix it
    "cvss": 7.5               # CVSS 3.1 base score (0.0 - 10.0)
}
```

### Adding Exploit PoCs

```python
{
    "vuln": "Finding Name",               # Must match a rule's "name" field
    "tool": "adb, Frida, mitmproxy",      # Required tools
    "cves": ["CVE-2024-XXXX"],            # Related CVE IDs
    "steps": "1. Step one\n2. Step two",  # Attack methodology
    "poc": "#!/bin/bash\n# PoC script"    # Working exploit code
}
```

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

ApkViper is designed for **authorized security testing and educational research only**.

- ✅ Scan applications you **own** or have **written authorization** to test
- ✅ Use findings for **defensive hardening** and **responsible disclosure**
- ✅ Use exploit PoCs in **controlled lab environments** only
- ❌ Do NOT use against applications without explicit permission
- ❌ Do NOT use exploit code for unauthorized access
- ❌ Do NOT distribute captured credentials or sensitive data

The authors assume no liability for misuse of this tool or any damage caused by its use. Users are solely responsible for compliance with applicable laws and regulations.

---

## 🗺️ Roadmap

- [x] ~~50 base security rules~~ → **125+ rules**
- [x] ~~Taint analysis~~ → **3 taint engines (basic + cross-method + cross-component)**
- [x] ~~CVE database~~ → **38 real CVEs with exploits**
- [x] ~~HTML reports~~ → **7 export formats (HTML/PDF/Word/Excel/JSON/CSV/SARIF)**
- [x] ~~Exploit PoCs~~ → **32 real-world exploits**
- [x] ~~Live threat feed engine~~
- [x] ~~Native binary analysis~~
- [x] ~~Auto-PoC generator with video recording~~
- [ ] Custom YAML rule authoring
- [ ] String decryption for obfuscated apps
- [ ] MSI/DMG installer packages
- [ ] Plugin system for custom analyzers
- [ ] Multi-APK batch scanning
- [ ] Differential scan (compare APK versions)
- [ ] SBOM generation (Software Bill of Materials)
- [ ] AI-assisted false positive reduction
- [ ] Frida gadget auto-injection for dynamic analysis

---

## ☕ Support the Project

If ApkViper helped you in your security work, consider supporting development!

<p align="center">
  <a href="https://www.paypal.com/paypalme/rhishinathvarma">
    <img src="https://img.shields.io/badge/☕_Buy_Me_A_Coffee-PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white" alt="Buy Me A Coffee"/>
  </a>
</p>

---

<p align="center">
  <b>🐍 ApkViper — Enterprise Android Security Assessment in a Single File</b><br/><br/>
  <img src="https://img.shields.io/badge/⭐_Star_this_repo-if_it_helped_you-yellow?style=for-the-badge" alt="Star"/>
</p>

