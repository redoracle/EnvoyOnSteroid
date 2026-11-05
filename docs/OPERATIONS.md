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
