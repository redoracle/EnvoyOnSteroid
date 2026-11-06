# EnvoyOnSteroid

[![CI](https://github.com/redoracle/EnvoyOnSteroid/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/redoracle/EnvoyOnSteroid/actions/workflows/ci.yml)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Envoy + Coraza Proxy-WASM + OWASP Core Rule Set** — a compact, testable
reverse proxy and WAF reference deployment with security-focused defaults.

> [!IMPORTANT]
> This is a **local demonstration and evaluation project**, not a
> production-certified WAF. It uses HTTP, a demo backend, and WAF blocking rules.
> Production requires TLS, application-specific tuning, load testing, verified
> image provenance, monitored rollout, and a rollback plan.

## Features

- **Modern architecture:** Envoy v1.40.2 with v3 config, Coraza Proxy-WASM
  v0.6.0 and the embedded OWASP CRS v4.14.0.
- **Explicit HTTP handling:** path normalization, rejection of encoded
  slashes/backslashes, and downstream identity/protocol header sanitization
  before forwarding to the demonstration backend.
- **Container isolation:** non-root services, read-only filesystems, no Linux
  capabilities or privilege escalation, memory/PID limits, private backend.
- **Privacy-aware logging:** structured request outcomes without URL paths,
  queries, cookies, request headers or client IP addresses.
- **Verified CI:** GitHub Actions, pinned actions, Python lint, configuration tests,
  bootstrap validation, functional WAF regression tests, and
  scheduled bounded memory/latency soak evidence.

## Architecture

~~~text
Host 127.0.0.1:8080
   |
   v
Envoy HTTP listener (normalization, header/time limits, access logging)
   |
   v
Envoy inbound buffer (128 KiB, normalize finite chunked requests)
   |
   v
Coraza Proxy-WASM + embedded OWASP CRS
   |
   v
Envoy delivery buffer (128 KiB, withhold until WAF decision)
   |
   v
Envoy router --> backend:8080 (private go-httpbin demo)

Envoy admin: 127.0.0.1:9901 INSIDE container only
~~~

The WAF runs *before* the router. Review [Architecture](docs/ARCHITECTURE.md)
and the [Threat model](docs/THREAT_MODEL.md) for trust boundaries and risks.

## Requirements

- Docker Engine and Docker Compose v2
- Bash and curl for smoke tests
- Python 3.13 and the test dependency in `requirements-dev.txt` for local
  static checks
- Free localhost port 8080

No local Bazel/C++ toolchain or ModSecurity source compilation is needed.

## Quick start

~~~bash
git clone https://github.com/redoracle/EnvoyOnSteroid.git
cd EnvoyOnSteroid
docker compose build --pull
docker compose up --detach --no-build
curl -i http://127.0.0.1:8080/get
curl -i http://127.0.0.1:8080/__waf_test_block
bash tests/smoke.sh
docker compose down --volumes --remove-orphans
~~~

Expected status codes:

| Request | Status | Meaning |
| --- | --- | --- |
| Benign GET or JSON POST | 200 | Routed to demo backend |
| `/__waf_test_block` | 403 | Phase-1 custom WAF rule |
| Form POST with `message=__waf_test_payload` | 403 | Phase-2 rule `1000002` |
| JSON POST with `message: __waf_test_payload` | 403 | Phase-2 rule `1000003` |
| CRS XSS probe | 403 | Embedded OWASP CRS |
| Encoded slash path | 400 | Ambiguous path rejected |
| Request headers above 32 KiB | 431 | Oversized header protection |

The integration tests additionally validate the echoed backend JSON/form
payloads, rule-specific WAF denials, **effective Docker runtime restrictions**
(including localhost-only host-port mapping), and recovery after stopping
the demo backend. CI repeats the entire integration suite twice against one
stack to catch shared-state and cleanup regressions. WAF rule attribution comes from the isolated Compose service logs:
a generic HTTP 403 does **not** prove request-body inspection.
Two bounded Envoy buffers surround Coraza: the inbound buffer
normalizes complete finite chunked bodies before CRS inspection, and the
post-WAF delivery buffer keeps rejected requests from reaching the
backend. Both have **128 KiB** limits. This deliberately adds memory
overhead and is incompatible with streaming/upgrade workloads.
Allowed and malicious chunked form/JSON requests and HTTP 413 handling
are exercised in CI.
The test oracle correlates matched rule IDs and denial phases to the same
Coraza transaction ID, with offline negative tests protecting the parser. The test
entrypoint `tests/smoke.sh` performs readiness checks, then runs the
behavior-focused `tests/integration/test_gateway.py` suite.

If a blocking test unexpectedly succeeds, **stop deployment** and investigate
WASM loading, rule order, and configuration. The demo listener is bound to
`127.0.0.1:8080` by default. Do not change `ENVOY_BIND_ADDRESS` to expose
untrusted traffic without a full ingress security review.

## Quality checks

~~~bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/ruff check tests
.venv/bin/python -m unittest discover -s tests -v
bash -n tests/smoke.sh
docker compose config --quiet
docker build --pull -t envoyonsteroid:local .
docker run --rm --entrypoint envoy envoyonsteroid:local \
  --mode validate -c /etc/envoy/envoy.yaml
docker compose up -d --no-build
bash tests/smoke.sh
docker compose down --volumes --remove-orphans
~~~

CI runs these checks on Ubuntu 24.04 with Python 3.13 and SHA-pinned
`actions/checkout` v7.0.1 / `actions/setup-python` v7.1.0. CI has only
read-only repository access. A green run proves basic integration behavior,
**not** WAF completeness, stability, or production certification.

## Dependency inventory

| Component | Pinned version | Scope |
| --- | --- | --- |
| Envoy | `envoyproxy/envoy:v1.40.2@sha256:8de97e65…` | Immutable proxy image manifest |
| Coraza Proxy-WASM | `ghcr.io/corazawaf/coraza-proxy-wasm:0.6.0@sha256:d66f9448…` | Immutable WASM image; embeds Coraza 3.3.3 / CRS 4.14.0 |
| go-httpbin | `mccutchen/go-httpbin:2.26.0@sha256:873b4fdb…` | Immutable demo backend |
| PyYAML | `6.0.3` | Developer / CI tests |
| Ruff | `0.17.4` | CI-only Python lint |
| actions/checkout | `v7.0.1` | Immutable commit SHA in workflow |
| actions/setup-python | `v7.1.0` | Immutable commit SHA in workflow |

These versions were reviewed on November 5, 2026. The **upstream Coraza WASM
release warns about potential memory leaks and performance degradation**.
The embedded CRS cannot be upgraded independently from the WASM image.
All runtime images are pinned by **OCI manifest digest** in
[images.lock.json](images.lock.json) while preserving human-readable
release tags. CI resolves upstream registry tags and fails on digest
drift, and generates an SPDX SBOM and BuildKit provenance attestation
for the local build. This does not verify upstream publisher signatures.

## Configuration boundaries

`envoy.yaml` controls routing, WASM filter configuration, admin binding,
request normalization and access logging. `docker-compose.yml` is
**local-only** with illustrative resource limits, not a production manifest.
The public sample WAF rules `/__waf_test_block` and
`__waf_test_payload` are test fixtures to remove before protecting real
traffic. The phase-2 test rules inspect parsed `ARGS_POST:message` (form)
and `ARGS:json.message` (JSON), not `REQUEST_BODY`, which is not populated
by Coraza's JSON body processor.

Before production: replace the demo backend, define TLS and allowed hosts,
review the forwarded-header stripping policy against any trusted ingress,
trusted-proxy hops, URL and header-size compatibility (32 KiB),
10s header/60s idle timeouts and then tune CRS exclusions/body
limits on representative traffic, configure monitoring and audit-log retention,
stress-test the WASM filter, and prepare a rollback.

## Documentation

| Guide | Purpose |
| --- | --- |
| [Architecture](docs/ARCHITECTURE.md) | Filters and trust boundaries |
| [Threat model](docs/THREAT_MODEL.md) | Assets, threats and residual risks |
| [Operations](docs/OPERATIONS.md) | Smoke tests, logs and diagnostics |
| [Testing strategy](docs/TESTING.md) | Test layers, security oracles, CI and limits |
| [Streaming boundary](docs/STREAMING.md) | Why streaming requires a separate protocol-aware design |
| [Migration](docs/MIGRATION.md) | Breaking changes since 2019 |
| [Release process](docs/RELEASE.md) | Safe dependency/release gates |
| [Security](SECURITY.md) | Private vulnerability reporting |
| [Contributing](CONTRIBUTING.md) | Coding, validation and PR conventions |
| [Support](SUPPORT.md) | Getting help and reporting problems |
| [Code of Conduct](CODE_OF_CONDUCT.md) | Community expectations |
| [Changelog](CHANGELOG.md) | Repository history |

We welcome focused contributions and reproducible bug reports; see
[Contributing](CONTRIBUTING.md) and [Support](SUPPORT.md). **Never post
unpatched vulnerability details in public issues** — follow the
[Security policy](SECURITY.md).

Licensed under [MIT](LICENSE).
