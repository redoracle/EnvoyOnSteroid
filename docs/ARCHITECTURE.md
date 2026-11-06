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

See the [threat model](THREAT_MODEL.md) for explicit attacker assumptions
and [release process](RELEASE.md) for promotion gates.

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

## Normalization, client identity, and observability

HTTP paths are normalized and adjacent slashes merged **before** the WAF and
upstream selection. Escaped slash/backslash characters produce HTTP 400; this
intentionally rejects ambiguous paths rather than letting the WAF and backend
interpret them differently. Applications that require encoded separators must
design and test an alternative policy instead of silently disabling it.
The example is a direct-entry edge proxy: `use_remote_address: true` with
`xff_num_trusted_hops: 0` means clients cannot assert a trusted identity
through unverified forwarding headers. Configure a different trust boundary
explicitly when deploying behind a trusted ingress.

Envoy writes low-cardinality JSON access logs to stdout: timestamp, method,
status, status detail, duration, upstream cluster, and response flags.
Deliberately absent: raw URI, query parameters, client address, request
headers, and cookies. WAF internal logs can include matched payloads;
set log retention and access policies appropriate to sensitive security data.

The demo Compose stack limits PIDs and memory on both services and gives the
backend the same read-only, non-root, dropped-capabilities posture as Envoy.
These limits are illustrative, not production sizing guidance. In particular,
soak-test the WASM filter under real traffic before setting resource ceilings.

## Header/time resource guardrails

The sample bounds request headers to **32 KiB** (HTTP 431), the header
receive window to **10 seconds**, idle streams to **60 seconds**, and whole
requests to **30 seconds**. Together with container PID/memory quotas these
reduce some untrusted-client resource exhaustion. They are not a substitute
for application-layer rate limits, network controls, or attack-resilient
capacity planning. Large cookies and streaming workloads may require
documented, separately verified exceptions.

## Phase-2 inspection contract

The recommended Coraza rules enable distinct body processors for form and
JSON requests. The raw `REQUEST_BODY` collection is not populated by JSON
processing. This reference therefore uses **phase-2** demo rules
`ARGS_POST:message` (ID `1000002`) and `ARGS:json.message`
(ID `1000003`). Each has an allowed control request with the same
content type and a blocked request with a synthetic sentinel.

CI requires a corresponding Coraza rule ID and
`phase="http_request_body"` interruption for each blocked request.
This prevents a phase-1 CRS rejection, such as disallowed `text/plain`,
from masquerading as phase-2 protection. Both demo rules should be removed
or rewritten for application-specific policies before production use.

## Direct-entry forwarded-header filtering

Envoy's trusted-client address policy and the headers forwarded to an
application are distinct. With `use_remote_address` and zero trusted XFF
hops, Envoy ignores client-supplied XFF for its own trust calculation, but
an application may still parse a spoofed first XFF element or vendor IP
header independently. The reference route explicitly removes untrusted
identity/protocol headers before proxying to the demo backend. The CI
contract checks the **actual** echoed backend headers and origin to catch
spurious trust at the application boundary. Behind a verified load
balancer/TLS ingress, adjust this direct-entry policy deliberately and
verify it with real request traces.

## Phase-2 delivery barrier and request buffering

**Discovered security finding:** an HTTP 403 from the Coraza body rule
did not guarantee the JSON POST was withheld from the demo backend.
The initial backend-observation test captured a `400 POST` upstream
access-log entry even though Envoy returned 403. The WAF filter must
not be treated as a transactional delivery barrier by itself.

Filter order is now:
`buffer (inbound)` → `Coraza Proxy-WASM` →
`buffer (delivery barrier)` → `router`.
The inbound buffer normalizes complete finite chunked requests before
CRS protocol checks. The downstream delivery buffer prevents the
terminal router from forwarding a request until after Coraza has
inspected the full bounded body. Integration tests verify both **rule attribution**
and the absence of denied request markers in backend access logs
after an allowed request confirms log flushing.

Each of the two 128 KiB buffering limits is a deliberate example cap;
their memory costs accumulate. Both may conflict with application-
specific WAF body inspection limits, large uploads, WebSockets,
gRPC streams, long-lived requests, or high concurrency.
Finite chunked form and JSON bodies are supported and tested. Review memory costs, accepted content types and
the correct request-size response codes when adapting this design.
