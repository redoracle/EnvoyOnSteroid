#!/usr/bin/env bash
# Integration entrypoint: wait for the real gateway, then verify behavioral
# HTTP contracts and exact Coraza rule decisions with Python unittest.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"
BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
export BASE_URL

case "${BASE_URL}" in
  http://127.0.0.1|http://127.0.0.1:*|http://localhost|http://localhost:*) ;;
  *) printf 'FAIL: BASE_URL must be a loopback HTTP origin\n' >&2; exit 2 ;;
esac

deadline=$((SECONDS + 75))
status=000
until [[ "${status}" == "200" ]]; do
  status="$(curl --silent --show-error --max-time 3 --output /dev/null \
    --write-out '%{http_code}' "${BASE_URL}/get" 2>/dev/null || true)"
  [[ "${status}" == "200" ]] && break
  if (( SECONDS >= deadline )); then
    printf 'FAIL: gateway readiness timeout, last HTTP status %s\n' "${status}" >&2
    exit 1
  fi
  sleep 0.5
done

"${PYTHON:-.venv/bin/python}" -m unittest discover -s tests/integration -p 'test_*.py' -v
