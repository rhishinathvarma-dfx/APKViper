DarkAudit v2.0.0 - Android Security Assessment Platform
=== Run Options ===
EXE:  Double-click DarkAudit.exe (bundled JRE, no Java needed)
JAR:  java -jar DarkAudit.jar (requires JDK 11+)
GUI:  DarkAudit-GUI.bat (auto-finds Java, launches GUI)
CLI:  DarkAudit-CLI.bat --scan app.apk --format sarif
=== CLI Formats ===
  json, html, sarif, pdf, excel, word, pptx, csv
=== CLI Examples ===
  DarkAudit-CLI.bat --scan app.apk                         JSON output
  DarkAudit-CLI.bat --scan app.apk --format html            HTML report
  DarkAudit-CLI.bat --scan app.apk --format sarif           SARIF (CI/CD)
  DarkAudit-CLI.bat --scan app.apk --format pdf             PDF report
  DarkAudit-CLI.bat --scan app.apk --format excel           Excel report
  DarkAudit-CLI.bat --scan app.apk --format word            Word report
  DarkAudit-CLI.bat --scan app.apk --format csv             CSV report
  DarkAudit-CLI.bat --server --port 8089                    REST API server
  DarkAudit-CLI.bat --help                                  All options
=== Linux/macOS ===
  ./darkaudit.sh                              GUI launcher
  ./darkaudit-cli.sh --scan app.apk           CLI scanner
Exit codes: 0=pass, 1=error, 2=critical/high findings
