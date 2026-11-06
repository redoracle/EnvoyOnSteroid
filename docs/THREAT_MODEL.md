# Threat model

## Intended scope

EnvoyOnSteroid is a **localhost-only WAF evaluation environment**. It is
not a standalone Internet-facing ingress, an authenticated API gateway, or
a production security certification.

Assume an unauthenticated HTTP client can reach the proxy's published port,
and that a developer might accidentally change the binding or forward real
traffic. The application/backend is not itself trusted to enforce the same
request parsing rules as Envoy and Coraza.

## Assets and trust boundaries

| Asset or boundary | Demonstration control | Residual risk |
| --- | --- | --- |
| Client → Envoy | Loopback-only host port; URL normalization | Plain HTTP; manual port rebind can expose it |
| Forwarded headers | Direct remote address; zero trusted XFF hops | New ingress requires a documented trust boundary |
| Proxy → WAF | WASM before router; CI verifies blocking | WASM memory/performance caveats; evasions |
| Proxy → backend | Isolated Compose service, not host published | Shared Docker host is not a high-assurance trust boundary |
| Containers | Non-root, read-only, limited memory/PIDs, no capabilities | Kernel vulnerabilities, exhaustion and host compromise |
| Admin | Loopback in proxy container, not published | Processes inside container can access it |
| CI / images | Read-only token, pinned actions, versioned images | OCI tags are mutable; provenance and digest checks remain manual |

## Attack scenarios and mitigations

**Ambiguous URLs and parser discrepancies.** Envoy normalizes paths,
merges adjacent slashes, and rejects encoded slash/backslash requests before
WAF inspection and routing. Production applications that require these
characters must explicitly agree on parsing and test the new policy.

**Client identity spoofing.** The example trusts zero inbound forwarded hops.
Never infer trusted source identity from client-supplied forwarding headers.
Behind a separate ingress, reconfigure and validate the chain first.

**Malicious request bodies.** Coraza inspects phase-2 request bodies within
its configured inspection limits. CI verifies both allowed and blocked POST.
Payloads beyond body limits, unsupported parsers or evasion techniques need
application-specific investigation.

**Excess resource use.** Envoy limits headers to 32 KiB with 10-second
header reception, 60-second stream idle and 30-second whole-request
timeouts. PID/memory ceilings limit some impact but may terminate traffic
during load. None of these provides global rate limiting or DDoS defense. Coraza's upstream 0.6.0 release warns of
TinyGo-related leaks and performance degradation; perform a sustained
representative memory and latency test.

**Supply-chain compromise.** CI actions use immutable Git SHA pins, but OCI
tags are mutable. Record verified image digests and, where available,
signatures/attestations before production promotion.

**Leakage in diagnostics.** Structured access logs intentionally omit
personal identifiers and full request paths. Coraza internal/audit messages
can still contain sensitive attack evidence: restrict access and retention.

## Out of scope

TLS termination, authorization, production upstream discovery, DDoS
protection, high availability, rate limits, security monitoring SLAs,
penetration-test certification and proof that CRS blocks every attack.

## Acceptance gates

See [Operations](OPERATIONS.md) for the executable smoke tests and
[Releases](RELEASE.md) for staging, regression, image provenance and
production readiness. Passing the smoke tests is necessary but not
sufficient to deploy on public networks.

## Test evidence and logging residual risk

CI now tests real phase-2 form and JSON rule matches and verifies backend
payload contracts, bad-path handling and recovery from a controlled backend
outage. It does not establish production false-positive rates, general WAF
coverage, memory stability or concurrency limits.

Structured Envoy access logs deliberately omit request details; separately,
Coraza WASM diagnostics may still contain client addresses, complete URI
paths and matched payload excerpts. Treat entire container logs as sensitive
unless the WASM diagnostic stream is explicitly sanitized or restricted.
