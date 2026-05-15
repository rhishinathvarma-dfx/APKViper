DarkAudit v2.0.0 - Android Security Assessment Platform

=== FILES ===
DarkAudit.exe       - GUI (double-click, no Java needed)
DarkAudit.jar       - JAR (GUI + CLI + REST API)
DarkAudit-CLI.bat   - CLI launcher

=== USAGE ===
GUI:    Double-click DarkAudit.exe
CLI:    java -jar DarkAudit.jar --scan app.apk --format sarif --output report.sarif.json
API:    java -jar DarkAudit.jar --server --port 8089
Help:   java -jar DarkAudit.jar --help
