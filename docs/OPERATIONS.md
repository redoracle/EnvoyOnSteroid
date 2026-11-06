# Operations and validation runbook

This runbook is for the **demonstration configuration**, not a production SLA.

## Build and smoke test

```sh
docker compose config --quiet
docker compose build --pull
docker run --rm --entrypoint envoy envoyonsteroid:local \
  --mode validate -c /etc/envoy/envoy.yaml
docker compose up -d --no-build
bash tests/smoke.sh
docker compose logs --no-color --tail=100 envoy
docker compose down --volumes --remove-orphans
```

Expected results: harmless GET and JSON POST return 200, the phase-1 URI
and phase-2 request-body test rules return 403, the standard CRS XSS
probe returns 403, and an encoded-slash path returns 400. A successful
Envoy bootstrap alone does **not** prove the WASM WAF is inspecting
requests. Test both benign traffic and blocking behavior.

## Troubleshooting

- `docker compose ps`: confirm backend and Envoy are running.
- `docker compose logs --no-color envoy`: inspect startup and WASM errors.
- `docker compose logs --no-color backend`: inspect backend errors.
- `docker compose config`: inspect effective environment substitutions.
- `docker compose build --pull`: refresh the pinned version tags before
  reproducing failures; do not use mutable `:latest` tags.
- If benign traffic returns 403, check CRS false-positive evidence and
  tune specific rules. Do not broadly disable the WAF to make tests pass.
- If malicious traffic returns 200, stop the rollout; verify plugin loading,
  rule activation, and WAF ordering before restoring service.

## Observable signals

Request logs contain JSON fields `timestamp`, `method`, `response_code`,
`response_code_details`, `duration_ms`, `upstream_cluster`, and
`response_flags`. They intentionally do **not** contain client IP addresses,
paths, queries, or cookies. Monitor 4xx/5xx rates, 403 WAF blocks,
upstream failures, 400 path rejections, p95/p99 request latency, memory
usage, CPU saturation, and container restarts. Response details distinguish
route/backend failures from explicit local WAF decisions. Preserve diagnostic
WAF logs only in access-controlled stores with retention limits.

The Envoy admin API binds to loopback *inside* the container and must not
be published directly. Use an approved internal diagnostic path to reach
`127.0.0.1:9901/stats/prometheus` for metrics. Do not change its bind address
to `0.0.0.0` merely for convenience.

## Release and security review

The [release checklist](RELEASE.md) documents image provenance,
application compatibility and staging gates. The [threat model](THREAT_MODEL.md)
records residual risk. CI success is not a substitute for traffic testing.

## Deployment review checklist

1. Replace demo backend; define an explicit upstream trust boundary, TLS,
   allowed hostnames, and forwarded-header handling.
2. Check encoded slashes and repeated-slash handling against application
   routes. Keep WAF inspection and upstream parsing semantics consistent.
3. Start staged rollout with detection-only mode, tune against representative
   REST/JSON/upload traffic, then verify blocking and rollback paths.
4. Benchmark throughput, latency, and Coraza WASM memory stability over
   sustained traffic before setting resource budgets.
5. Pin reviewed OCI digests, document the component bill of materials,
   and require CI plus peer review for dependency upgrades.
6. Monitor false-positive rates and production traffic before increasing
   CRS paranoia levels.

## Header size and timeout regression

The reference listener rejects request headers above **32 KiB** (HTTP 431).
It allows 10 seconds to receive headers, 60 seconds of per-stream idleness
and 30 seconds to receive a complete request. The smoke test covers the
431 outcome; the exact timeouts are checked statically and via the Envoy
bootstrap validator. Configure and test larger cookies, slow uploads,
long polling, and streaming endpoints before production use.

## Integration and rule-evidence testing

`bash tests/smoke.sh` waits for the local proxy, then runs real network
integration tests from `tests/integration/test_gateway.py`. These validate
the backend's echoed HTTP method, query arguments and JSON/form payload,
exact WAF rule IDs and interruption phases, unusual path handling, and
an intentionally stopped/restarted **demo** backend.

The Compose project name is unique for each CI run and attempt. A failing
job prints a bounded diagnostic log tail and always attempts to remove its
containers, networks and volumes. The integration suite is destructive;
do not execute it against production or a shared Docker Compose project.

Raw WASM diagnostic logs may contain client IP addresses and matched request
data even when the privacy-conscious structured Envoy access log omits them.
Use synthetic probes and protect all diagnostic output. If a phase-2 test
fails despite receiving HTTP 403, examine whether another CRS rule blocked
during headers; the correct fix is to restore the intended body-processing
path, not to weaken the assertion.

## Coraza transaction correlation and negative controls

The integration WAF oracle matches a specific rule ID and the intended
`http_request_headers` or `http_request_body` denial **within one Coraza
transaction ID**. Checking the number of rule and phase lines separately
would incorrectly combine unrelated requests and can hide regressions.
Offline `tests/test_waf_event_parsing.py` exercises this parser using
adversarial synthetic logs (wrong phase, wrong rule, wrong transaction,
allow actions, malformed logs). The parser does not echo sensitive WAF
diagnostics into assertion failures.

## Repeated validation and effective container posture

CI executes the integration suite **twice** against the same isolated Compose
project; both passes exercise upstream outage/recovery and independent WAF
transaction IDs. Repeated passes are a low-cost deterministic regression
check, not a substitute for randomized parallelism, long-duration soak
testing or production traffic replay.

Runtime integration tests inspect **actual Docker container settings** via
`docker inspect`, not just YAML declarations. Both demo services must run
non-root, with read-only roots, all capabilities dropped, no-new-privileges
and positive memory/PID limits. The Envoy host port must bind to loopback,
and the demo backend must not publish host ports.

## Forwarded-header trust regression

The integration suite sends untrusted `X-Forwarded-For`,
`CF-Connecting-IP`, `Fly-Client-IP`, `X-Real-IP`, `Forwarded`
and `X-Forwarded-Proto` values. The echoed go-httpbin headers and origin
must not expose these untrusted values. The route-level stripping policy
is intentional for this **direct-entry** demo; re-evaluate it behind a
trusted ingress, because real applications may require a validated,
gateway-generated client identity and original scheme.

## Upstream non-forwarding and concurrent-request checks

Denied form and JSON traffic includes a unique synthetic URI marker.
After a rule-specific WAF decision is confirmed, an **allowed** GET is
sent as a backend logging barrier. Only when that successful GET appears
in the backend's own request logs does the test assert that the denied
marker was absent from the upstream. This avoids mistaking slow log
flushing for proof of enforcement.

The suite also sends a small controlled burst of allowed GET and blocked
form/JSON POST requests through the real Envoy/Coraza stack. It verifies
eight echoed query values plus three distinct transaction-correlated
phase-2 denials for **each** request-body rule. This is a cross-request
state-isolation regression, not load or performance certification.

## Request buffering and upstream delivery safety

A client-facing Coraza 403 is **not proof** that the upstream did not
receive the rejected request. The integration suite now tests the
backend's own request logs and uses an allowed GET as a logging
barrier after each denied form/JSON request. Envoy first buffers finite
requests to normalize chunked framing for Coraza, then uses a second
buffer after the WAF to prevent the router from transmitting rejected
request bodies upstream.

The reference uses **two 128 KiB buffers** per request; this is not
compatible with streaming uploads, WebSockets or streaming gRPC
without changing the architecture. Large payloads may receive a
4xx error, and resource pressure grows with concurrent requests.
Test content-length, chunked request handling and application
compatibility before increasing this bound. For a production ingress,
use load/capacity testing and explicitly document memory budgets.

## Transfer-encoding and size-boundary regressions

The real-container suite sends valid JSON as multiple **chunked HTTP/1.1**
frames and checks the payload echoed by go-httpbin. It also splits
synthetic malicious form and JSON bodies across chunks, requiring the
same WAF rule/phase evidence and absence of upstream delivery as for
ordinary fixed-length POST requests.

A request body larger than the configured 128 KiB Envoy buffer must
receive **HTTP 413**. Do not relax that guard to allow oversized data
silently; explicitly assess application requirements, Coraza inspection
limits and per-request memory budgets before changing it.
