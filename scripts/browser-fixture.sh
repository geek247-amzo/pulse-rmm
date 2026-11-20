#!/bin/sh
# Isolated deterministic fixture only. Never supply production state or secrets.
set -eu
cd "$(dirname "$0")/.."
image=${PULSE_TEST_IMAGE:-pulse-rmm:dev}
name=pulse-rmm-browser-fixture
if docker inspect "$name" >/dev/null 2>&1; then echo 'Fixture name already in use; inspect it first.' >&2; exit 1; fi
id=$(docker run -d --name "$name" --label pulse.test=synthetic \
 -p 127.0.0.1:18081:8080 \
 -e ADMIN_USER=fixtureowner -e ADMIN_PASSWORD=fixture-only-password-2026-unique \
 -e AGENT_SECRET=fixture-only-enrollment-secret-0123456789abcdef \
 -e JWT_SECRET=fixture-only-signing-secret-0123456789abcdef \
 -e COOKIE_SECURE=false -e PUBLIC_URL=https://pulse.example.com "$image")
trap 'docker rm -f "$id" >/dev/null 2>&1 || true' EXIT HUP INT TERM
python3 - <<'PY'
import time,urllib.request
for _ in range(60):
 try:
  with urllib.request.urlopen('http://127.0.0.1:18081/api',timeout=2) as r:
   if r.status==200:break
 except OSError:pass
 time.sleep(1)
else:raise SystemExit('Fixture did not start')
PY
PULSE_SYNTHETIC_FIXTURE=1 PULSE_TEST_URL=http://127.0.0.1:18081 npm run test:browser
