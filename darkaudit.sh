#!/bin/bash
echo "============================================"
echo "  DarkAudit v2.0.0 - Android SAST Scanner"
echo "  Advanced Security Assessment Platform"
echo "  100% Offline - No Internet Required"
echo "============================================"
DIR="$(cd "$(dirname "$0")" && pwd)"
JAR_NAME="DarkAudit-2.0.0.jar"
JAVA_OPTS="-Xmx2g -Dsun.java2d.opengl=true"

# Find java
if [ -n "$JAVA_HOME" ] && [ -x "$JAVA_HOME/bin/java" ]; then
    JAVA_CMD="$JAVA_HOME/bin/java"
elif command -v java &>/dev/null; then
    JAVA_CMD="java"
else
    echo ""
    echo "[ERROR] Java not found! Install JDK 11+ or set JAVA_HOME."
    echo ""
    echo "Usage examples:"
    echo "  ./darkaudit.sh                                   Launch GUI"
    echo "  ./darkaudit.sh --scan app.apk                    Headless scan (JSON)"
    echo "  ./darkaudit.sh --scan app.apk --format html      HTML report"
    echo "  ./darkaudit.sh --scan app.apk --format sarif     CI/CD (SARIF)"
    echo "  ./darkaudit.sh --scan app.apk --format pdf       PDF report"
    echo "  ./darkaudit.sh --scan app.apk --format excel     Excel report"
    echo "  ./darkaudit.sh --server --port 8089              REST API server"
    echo "  ./darkaudit.sh --help                            Show all options"
    exit 1
fi

echo "[+] Using: $JAVA_CMD"
exec "$JAVA_CMD" $JAVA_OPTS -jar "$DIR/$JAR_NAME" "$@"

