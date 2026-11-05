# Architecture and operational design

## Request flow

1. Envoy accepts HTTP on port `8080`. The Compose mapping defaults to localhost.
2. The Coraza Proxy-WASM HTTP filter executes before the Envoy router. Its
   embedded OWASP CRS scores inbound and outbound content and can interrupt
   malicious requests in blocking mode.
3. The Envoy router forwards allowed traffic to the private Compose DNS name
   `backend:8080`, with a 15-second upstream timeout.
4. The Envoy admin interface is reachable at `127.0.0.1:9901` only **inside**
   the Envoy container. It must never be publicly exposed without controls.

The WASM module is sourced from the upstream `0.6.0` OCI image and copied by a
multi-stage Docker build. The runtime contains no Bazel, compiler, Git, or
package manager installation step. Both OCI images use explicit version tags.

## Security boundaries

- Localhost-bound example port; no public-facing listener in Compose by default.
- Non-root uid/gid 101, read-only root filesystem, dropped Linux capabilities,
  and `no-new-privileges` for the Envoy service.
- Backend isolated on the Compose network (not published to host).
- No Docker credentials or release/publish secrets in GitHub Actions.
- Failures of the WASM configuration are checked by Envoy's `--mode validate`;
  integration tests also confirm that WAF rules actually block requests.

## Config ownership

`envoy.yaml` holds the listener, backend route, WAF chain, and admin binding.
The WAF JSON is embedded in the YAML `StringValue` for the WASM filter and is
validated as JSON by the test suite. The WAF settings are static at boot; edits
require rebuilding the image. Do not mount untrusted configuration over it.

## Production hardening checklist

- Replace the demo backend and add TLS termination with a documented trust
  boundary, access controls, and forwarded-header policy.
- Run staging in `DetectionOnly` and tune rule exclusions before enabling
  `SecRuleEngine On` for real workloads. Account for REST/JSON and upload paths.
- Review the 128 KiB request-body limit in the upstream recommended Coraza
  configuration. Rejecting oversized bodies may break legitimate clients.
- Set resource limits, exercise sustained and bursty traffic, and watch Envoy
  memory and WASM error logs. Coraza 0.6.0 explicitly warns about potential
  memory leaks/performance issues in its TinyGo-based proxy-WASM integration.
- Apply newer Coraza/CRS releases **only through** an updated, tested WASM
  module. They are not independently apt/pip/OCI base-image upgrades.
- Reassess the admin socket exposure, access/audit logging, cluster health
  checks, observability, availability and application-specific timeouts.

## Compatibility and validation

The v3 bootstrap targets Envoy `v1.40.2`; the Coraza plugin is `0.6.0` with
embedded CRS `4.14.0`. These components are not a semver-coupled product.
Every version bump needs the automated bootstrap + end-to-end smoke tests and
manual throughput/soak testing. Passing unit tests alone is insufficient.
