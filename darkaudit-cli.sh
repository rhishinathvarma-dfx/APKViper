#!/bin/bash
# ============================================================
# DarkAudit v2.0.0 — CLI Runner (Headless Mode)
# Usage: ./darkaudit-cli --scan app.apk [--format json|html|sarif|pdf|excel] [--output report.json]
#        ./darkaudit-cli --server [--port 8089]
#        ./darkaudit-cli --help
# ============================================================

DIR="$(cd "$(dirname "$0")" && pwd)"
JAR_NAME="DarkAudit-2.0.0.jar"
JAVA_OPTS="-Xmx2g"

if [ $# -eq 0 ]; then
    echo "DarkAudit v2.0.0 — CLI Runner"
    echo ""
    echo "Usage:"
    echo "  darkaudit-cli --scan <apk_path>                          Scan APK (JSON output)"
    echo "  darkaudit-cli --scan <apk_path> --format html            Scan with HTML report"
    echo "  darkaudit-cli --scan <apk_path> --format sarif           Scan with SARIF (CI/CD)"
    echo "  darkaudit-cli --scan <apk_path> --format pdf             Scan with PDF report"
    echo "  darkaudit-cli --scan <apk_path> --format excel           Scan with Excel report"
    echo "  darkaudit-cli --scan <apk_path> --output report.json     Specify output path"
    echo "  darkaudit-cli --server --port 8089                       Start REST API server"
    echo "  darkaudit-cli --help                                     Show all options"
    echo ""
    echo "Exit codes: 0=pass, 1=error, 2=critical/high findings"
    exit 1
fi

# Find java
if [ -n "$JAVA_HOME" ] && [ -x "$JAVA_HOME/bin/java" ]; then
    JAVA_CMD="$JAVA_HOME/bin/java"
elif command -v java &>/dev/null; then
    JAVA_CMD="java"
else
    echo "[ERROR] Java not found! Install JDK 11+ or set JAVA_HOME."
    exit 1
fi

exec "$JAVA_CMD" $JAVA_OPTS -jar "$DIR/$JAR_NAME" "$@"

