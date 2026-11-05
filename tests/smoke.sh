#!/usr/bin/env bash
# Requires the Compose stack to be running. Verifies proxying AND WAF blocking.
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
http_status() {
  curl --silent --show-error --max-time 4 --output /dev/null \
    --write-out '%{http_code}' "$1"
}

status=000
for _ in $(seq 1 40); do
  status="$(http_status "${BASE_URL}/get" 2>/dev/null || true)"
  if [[ "$status" == "200" ]]; then break; fi
  sleep 2
done
if [[ "$status" != "200" ]]; then
  printf 'FAIL: benign request expected 200, got %s\n' "$status" >&2
  exit 1
fi

status="$(http_status "${BASE_URL}/__waf_test_block")"
if [[ "$status" != "403" ]]; then
  printf 'FAIL: WAF test rule expected 403, got %s\n' "$status" >&2
  exit 1
fi

# Positive OWASP CRS test: XSS is expected to reach the default blocking threshold.
status="$(http_status "${BASE_URL}/get?arg=%3Cscript%3Ealert(0)%3C%2Fscript%3E")"
if [[ "$status" != "403" ]]; then
  printf 'FAIL: CRS XSS test expected 403, got %s\n' "$status" >&2
  exit 1
fi

printf 'PASS: benign request proxied (200); custom WAF rule and CRS XSS blocked (403)\n'
