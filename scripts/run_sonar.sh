#!/usr/bin/env bash
# 1) docker compose -f docker-compose.sonar.yml up -d   (wait for http://localhost:9000, login admin/admin)
# 2) create a project "aes-lab", generate a token, then:  export SONAR_TOKEN=<token>
set -euo pipefail
cd "$(dirname "$0")/.."
docker run --rm --network host -e SONAR_HOST_URL=http://localhost:9000 -e SONAR_TOKEN="$SONAR_TOKEN" \
  -v "$(pwd):/usr/src" sonarsource/sonar-scanner-cli
sleep 10   # let the server finish background analysis
python3 scripts/export_sonar.py
