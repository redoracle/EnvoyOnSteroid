# Security policy

This repository is a reference example for WAF evaluation, **not a hardened
production gateway**. Report security concerns privately through the GitHub
Security Advisories interface where available; otherwise contact the repository
maintainer privately. Please avoid publishing working exploit details before
coordinated disclosure.

## Supported scope and private reporting

Maintenance focuses on the current `master` branch and reviewed changes.
Historical 2019 components, independently copied extensions and unreviewed
forks have no security-update commitment.

Use [GitHub private vulnerability reporting](https://github.com/redoracle/EnvoyOnSteroid/security/advisories/new)
**if enabled**. Otherwise seek a private reporting channel before sharing
sensitive exploit material. Include affected commit/release, impact, safe
synthetic reproduction and suggested mitigation. No response-time SLA is
promised; please coordinate disclosure.

## Deployment cautions

- HTTP is intentionally enabled for local development; add TLS and controlled
  network ingress for any real deployment.
- The example WAF uses blocking mode. Validate its false-positive rate and
  tune rules before putting it in front of legitimate traffic.
- The Coraza proxy-WASM `0.6.0` release cautions that its TinyGo runtime may
  exhibit memory leaks or degraded performance. Perform soak testing; use
  resource limits and watch logs/metrics. Do not infer production readiness
  from a successful smoke test.
- Upstream WASM bundles Coraza `3.3.3` and CRS `4.14.0`; upgrade to newer
  engine/rules only when a compatible, tested WASM artifact is available.
- Keep the Envoy admin listener bound to loopback inside the container; never
  publish it directly on an untrusted network.

## Updating dependencies

Treat each version bump as a code change: verify its upstream advisory and
compatibility, validate Envoy's bootstrap, run positive/negative HTTP tests,
and perform a staging load test. Prefer immutable OCI digests when promoting
images to production. No credentials are required for CI verification, and the
project intentionally does not publish to Docker Hub automatically.

## Request normalization and trusted proxy model

The reference listener normalizes URL paths and merges repeated slashes
**before** invoking the WAF or routing. Requests containing escaped forward
or backward slashes (`%2F` or `%5C`, regardless of letter case) receive
HTTP 400. This helps avoid ambiguous interpretation between Envoy, WAF, and
upstream; it is a compatibility change for services that legitimately use
encoded path separators. Client-supplied `X-Forwarded-For` is not trusted
(`xff_num_trusted_hops: 0`). When deploying behind another gateway, set
trusted hop counts and verify the full chain with spoofed headers before
relying on source IPs for controls.

## HTTP request exhaustion guards

The example has 32 KiB maximum request headers (HTTP 431 if exceeded),
10-second request-header reception timeout, 60-second stream idle timeout
and 30-second complete-request timeout. These limits reduce some low-cost
resource exhaustion attacks; they are not DDoS protection or rate limiting.
Large cookies, slow uploads and long-lived streams need compatibility tests.

## Downstream identity and forwarded-header boundary

The direct-entry demonstration explicitly strips unverified client-provided
identity and protocol headers (including `X-Forwarded-For`, `Forwarded`,
`X-Real-IP`, common CDN-specific IP headers and `X-Forwarded-Proto`)
**before** sending traffic to the backend. Envoy's trusted address selection
and the headers an upstream application actually receives are separate
security boundaries: `xff_num_trusted_hops: 0` alone does not prove the
upstream cannot observe client-forged headers. CI sends synthetic spoofed
identity headers and asserts the backend does not receive their values.
For deployments behind authenticated gateways or ingress proxies, define a
new explicit trusted-header policy, and retest both the Envoy trust logic
and backend identity semantics.

## Test oracles and WAF diagnostic confidentiality

Coraza's JSON body parser does not populate the raw `REQUEST_BODY` variable.
The demo instead checks parsed JSON and URL-encoded form variables and the
integration suite requires a **specific rule ID plus an actual phase-2
interruption**. An HTTP 403 caused by an unrelated phase-1 CRS policy must
never count as proof of phase-2 inspection.

**Privacy boundary:** Envoy's structured access logs omit request URIs and
client identifiers, but Coraza's *separate WASM diagnostic output* can
include client IP addresses, complete request URIs and matched body/argument
values. Production log forwarding, access controls and retention must treat
raw WAF diagnostics as sensitive. Never run the synthetic integration
suite against production or expose customer requests in CI.

## Logging and dependency integrity

Structured request logs omit client IPs, raw URI paths, query strings, cookies,
and headers by default; logs are still operational data and need retention
limits and access controls. WAF diagnostic output may contain sensitive
request evidence, so enable detailed audit logs only with explicit approval.
Dependencies are pinned to versioned containers and GitHub Actions are pinned
to full commit SHAs. Tags are not immutable: production image promotion should
record or pin verified OCI digests. Do not automatically merge Dependabot PRs
without a successful end-to-end run and compatibility review.
