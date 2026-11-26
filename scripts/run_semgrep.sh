#!/usr/bin/env bash
# Online run (uses the Semgrep registry rulesets). Output goes to evidence/static/.
set -euo pipefail
cd "$(dirname "$0")/.."; mkdir -p evidence/static
semgrep scan --metrics=off --config p/python --config p/security-audit --config p/owasp-top-ten \
  --config rules/aes-lab.yml --json -o evidence/static/semgrep-results.json \
  --sarif-output=evidence/static/semgrep.sarif aes_lab.py test_aes_lab.py
semgrep scan --metrics=off --config p/python --config p/security-audit --config p/owasp-top-ten \
  --config rules/aes-lab.yml --text -o evidence/static/semgrep-results.txt aes_lab.py test_aes_lab.py
