# EnvoyOnSteroid

A compact Envoy reverse proxy with an embedded OWASP Core Rule Set (CRS) web
application firewall (WAF). The supported implementation uses **Envoy v1.40.2**
and the **Coraza Proxy-WASM v0.6.0** filter, which includes **CRS v4.14.0**.

> **Breaking change:** The 2019 prototype attempted to compile a native
> ModSecurity v3 Envoy extension. That integration was incomplete and depends
> on obsolete Envoy/Bazel APIs. This revision uses the maintained Coraza
> implementation of ModSecurity-style rules. It is **not** a drop-in migration
> for custom ModSecurity modules. See [Migration](docs/MIGRATION.md).

## Run the example

Requires Docker Engine with the Compose v2 plugin. No local compiler or Bazel
installation is needed.

```bash
docker compose build --pull
docker compose up -d
curl -i http://127.0.0.1:8080/get
curl -i http://127.0.0.1:8080/__waf_test_block
bash tests/smoke.sh
docker compose down
```

The benign GET and JSON POST should return **HTTP 200** from the internal
`httpbin` example backend; the phase-1 URI and phase-2 request-body WAF test
rules, plus the CRS XSS test, should return **HTTP 403**. Ambiguous escaped
slashes should be rejected with **HTTP 400** by Envoy.
The proxy is bound to **127.0.0.1:8080** by default; the Envoy admin interface
is loopback-only **inside the container** and is not host-published.

## Design and security

```text
host 127.0.0.1:8080 -> Envoy HTTP listener
                        -> Coraza WASM + embedded OWASP CRS
                        -> Envoy router
                        -> private backend:8080 (httpbin demo)
```

The Dockerfile copies a versioned upstream WASM artifact into a versioned Envoy
image. It does not compile toolchains or fetch moving `latest` downloads. The
Compose proxy runs without root, Linux capabilities, or a writable root
filesystem. The only exposed endpoint is the example HTTP listener.

The WAF is **in blocking mode** and uses the upstream recommended configuration
and CRS defaults. Blocking mode can cause false positives; always tune rules on
representative traffic before production. The `/__waf_test_block` rule is a
stable example and must be removed or adapted for production use.

Envoy emits JSON access logs to standard output with method, response code,
duration, and outcome, but deliberately omits client IP, request path,
query string, cookies, and other request headers. Paths are normalized
before WAF evaluation; percent-encoded slashes are rejected. Incoming
`X-Forwarded-For` chains are **not trusted** in the example. These controls
change URL semantics; review them before using this proxy with an application
that deliberately relies on encoded slashes or multiple consecutive slashes.
See the [operations guide](docs/OPERATIONS.md).

For production, replace `backend` with your real service in `envoy.yaml`, add
TLS and explicit network controls at the appropriate boundary, review request
and response body limits, set WAF exclusions/paranoia level, and monitor memory
and logs. This repository is a reference deployment, **not a production
security certification**. See [Architecture](docs/ARCHITECTURE.md) and
[Security](SECURITY.md).

## Checks

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m unittest discover -s tests -v
docker compose config --quiet
docker build --pull -t envoyonsteroid:local .
docker run --rm --entrypoint envoy envoyonsteroid:local \
  --mode validate -c /etc/envoy/envoy.yaml
docker compose up -d --no-build
bash tests/smoke.sh
docker compose down --volumes
```

GitHub Actions runs these static, bootstrap, and HTTP integration checks on
pull requests using SHA-pinned `actions/checkout` v7.0.1 and
`actions/setup-python` v7.1.0. GitHub-hosted runners support the required
Node.js 24 action runtime. The workflow uses a fixed Ubuntu 24.04 runner,
no persisted GitHub checkout credentials, and read-only repository permission.
See [contributing](CONTRIBUTING.md) for the release process. A release should also undergo longer soak and performance
benchmarking under realistic request-body sizes and concurrency.

## Dependencies

| Component | Pinned version | Why |
| --- | --- | --- |
| Envoy container | `envoyproxy/envoy:v1.40.2` | Supported v3 configuration/runtime |
| Coraza Proxy-WASM | `ghcr.io/corazawaf/coraza-proxy-wasm:0.6.0` | Prebuilt WAF integration; embedded CRS v4.14.0 |
| Example backend | `mccutchen/go-httpbin:2.26.0` | Local demo only |
| Test parser | `PyYAML==6.0.3` | CI-only static YAML validation |

The Coraza release bundles its own Coraza engine and CRS; updating the
standalone CRS to v4.30.0 **cannot** be done by swapping a file in this image.
Do not claim that embedded dependencies are current merely because the Envoy
base image was updated. See [Migration](docs/MIGRATION.md) for the limitations.

Licensed under [MIT](LICENSE).
