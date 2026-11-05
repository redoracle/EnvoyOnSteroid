#!/usr/bin/env bash
# Requires the Compose stack to be running. Verifies proxying AND WAF blocking.
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
http_status() {
  curl --silent --show-error --max-time 4 --output /dev/null \
    --write-out '%{http_code}' "$@"
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

# Confirm phase-2 body inspection does not disrupt ordinary JSON POSTs.
status="$(http_status --request POST --header 'Content-Type: application/json' \
  --data-binary '{"message":"hello"}' "${BASE_URL}/post")"
if [[ "$status" != "200" ]]; then
  printf 'FAIL: benign JSON POST expected 200, got %s\n' "$status" >&2
  exit 1
fi

status="$(http_status --request POST --header 'Content-Type: text/plain' \
  --data-binary '__waf_test_payload' "${BASE_URL}/post")"
if [[ "$status" != "403" ]]; then
  printf 'FAIL: phase-2 WAF body rule expected 403, got %s\n' "$status" >&2
  exit 1
fi

# An escaped slash must not bypass proxy-side normalization/security.
status="$(http_status --path-as-is "${BASE_URL}/get%2F../get")"
if [[ "$status" != "400" ]]; then
  printf 'FAIL: escaped-slash request expected 400, got %s\n' "$status" >&2
  exit 1
fi

# Requests exceeding the configured 32 KiB header limit must be rejected
# before reaching the backend. Avoid external dependencies beyond coreutils.
large_header="$(printf '%*s' 34000 '' | tr ' ' 'x')"
status="$(http_status --header "X-Test-Large: ${large_header}" "${BASE_URL}/get")"
if [[ "$status" != "431" ]]; then
  printf 'FAIL: oversized request headers expected 431, got %s\n' "$status" >&2
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

printf 'PASS: GET/POST forwarded (200); encoded path rejected (400); header overflow rejected (431); phase-1/2 WAF and CRS XSS blocked (403)\n'
