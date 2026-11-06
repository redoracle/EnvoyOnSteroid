# Test strategy and security acceptance gates

EnvoyOnSteroid is a **local reference gateway**. The objective of this test
suite is to prevent false-green security regressions without treating CI
as a production WAF certification.

## Executable test layers

| Layer | Files | Actual behavior / oracle |
| --- | --- | --- |
| Offline architecture invariants | [test_configuration.py](../tests/test_configuration.py) | Envoy filter order, WAF directives, two 128 KiB buffers, routing, security controls |
| Offline repository hygiene | [test_repository_quality.py](../tests/test_repository_quality.py) | Workflow action pins, templates, required files and local links |
| Offline log-parser mutations | [test_waf_event_parsing.py](../tests/test_waf_event_parsing.py) | Reject wrong rule ID, wrong phase, other transaction, allow action, malformed logs |
| Live HTTP and WAF behavior | [test_gateway.py](../tests/integration/test_gateway.py) | Real Dockerized Envoy, Coraza Proxy-WASM and go-httpbin responses |
| Live CI orchestrator | [smoke.sh](../tests/smoke.sh) | Loopback-only target guard, readiness, explicit integration discovery |
| CI workflow | [ci.yml](../.github/workflows/ci.yml) | Ruff, unit tests, Docker build, Envoy bootstrap, two independent integration passes |

## Mandatory acceptance evidence

A WAF blocking test must establish **all** of these properties:

1. A matching benign request with the same supported content type is
   accepted and reaches the real backend with correct echoed payload.
2. The malicious request returns the expected client response.
3. Coraza records the **intended rule ID, matching transaction ID,
   action=deny, and inspection phase**. An unrelated CRS block is not
   evidence of phase-2 processing.
4. The rejected request's synthetic URI marker is **absent** from the
   backend's own request logs after a subsequent benign GET appears
   as a backend logging barrier. Buffered/delayed logs alone cannot
   establish that an upstream saw no request.
5. The test fails if these independent contracts disagree.

The core regression originated with a blocked JSON POST that still
reached the backend. This is why status-only assertions are prohibited
for gateway enforcement guarantees.

## Request parsing and resource boundaries

The HTTP chain is **bounded inbound buffer → Coraza → bounded delivery
buffer → router**. Both buffers cap request bodies at 128 KiB. The
first ensures finite HTTP/1.1 chunked bodies are normalized before
CRS protocol validation; the second prevents the upstream receiving
request bodies before the WAF has inspected them.

The live suite checks allowed JSON and form submissions, split
chunked bodies, matched malicious fixed-length/chunked body rules,
encoded path rejection, spoofed client-identity headers, 431 oversized
headers, 413 oversized bodies, and backend 404/503 behavior.
Representative moderate-size allowed JSON must arrive intact; the
body-limit denial must not reach the upstream.

**Incompatibilities:** This reference is not a streaming reverse proxy.
Do not assume WebSocket upgrades, gRPC streaming, indefinite uploads,
or large request bodies are supported. Two buffering stages consume
additional memory per concurrent request, and the upstream Coraza
Proxy-WASM release reports possible memory/performance instability.
Benchmark these properties before considering a production design.

## Determinism, isolation and cleanup

- Offline `unittest discover -s tests` excludes the separate integration
  directory; default unit tests must not contact networks or start Docker.
- Integration tests only accept a loopback HTTP origin.
- CI uses a per-run and per-attempt Compose project name and performs
  complete teardown in a shell trap even on errors.
- Integration tests are intentionally serial at the suite level.
  A controlled small burst inside one test exercises concurrent
  per-request isolation; it is not a throughput benchmark.
- Backend-outage tests restart the example backend under `finally`,
  and a readiness poll verifies successful recovery.
- CI repeats the full integration suite twice against one stack to
  detect state leakage and cleanup problems.
- Polling is bounded by monotonic deadlines. WAF decisions are
  correlated by transaction rather than timing-based event counts.

## Local verification

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/ruff check tests test_support
.venv/bin/python -m unittest discover -s tests -v
bash -n tests/smoke.sh
docker compose config --quiet
docker compose build --pull
docker compose up --detach --no-build
bash tests/smoke.sh
docker compose down --volumes --remove-orphans
```

The integration suite stops and starts the demo backend during one
test. **Never execute it on a production service or shared Compose
project.** Synthetic probes are mandatory: Coraza raw WASM diagnostics
can contain source addresses, URIs, and matched data even when Envoy's
separate JSON access log intentionally excludes those fields. Treat
CI/log artifacts as sensitive.

## Additional enterprise release gates (not satisfied by this suite)

- Immutable reviewed OCI digest pinning, software bill of materials,
  dependency vulnerability assessment and signing/provenance verification.
- Repeated sustained memory/throughput soak tests with Coraza/WASM,
  performance budgets, and concurrency beyond the small regression.
- Production TLS, trusted ingress, authorization and real upstream
  behavior with representative false-positive/false-negative traffic.
- Fault injection for WASM startup failure, upstream pool exhaustion,
  memory pressure, cancellations and request timeouts.
- Platform parity, release approval, monitored rollout and rehearsed rollback.

See [release management](RELEASE.md), [operations](OPERATIONS.md),
[architecture](ARCHITECTURE.md) and the [threat model](THREAT_MODEL.md).

## OCI dependency provenance and SBOM gates

The three runtime inputs are pinned by immutable OCI image manifest digest,
and [images.lock.json](../images.lock.json) records their reviewed tag
mapping. CI fails on upstream tag drift and builds an **unpublished**
OCI artifact with SPDX SBOM and BuildKit SLSA provenance. The offline
verifier validates SHA-256 blob integrity and the links between the
attestations and the image. CI retains a compact JSON evidence artifact,
not the large image tarball.

This **build-generated provenance** is not a cryptographically authenticated
upstream publisher identity, an independent rebuild, or a vulnerability
assessment. Those remain required before production promotion.
