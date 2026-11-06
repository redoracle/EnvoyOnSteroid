# Release and dependency management

**No CI workflow publishes artifacts or images automatically.** A green
workflow run validates this reference stack, not production certification.

## Version inventory (checked November 5, 2026)

| Component | Reviewed version | Role |
| --- | --- | --- |
| Envoy | v1.40.2 | Runtime image |
| Coraza Proxy-WASM | 0.6.0 | WASM image; embeds CRS v4.14.0 |
| go-httpbin | v2.26.0 | Demo backend (includes WebSocket DoS fix) |
| PyYAML | 6.0.3 | CI/static tests |
| Ruff | 0.17.4 | CI Python lint |
| actions/checkout | v7.0.1 | Commit-SHA pinned CI action |
| actions/setup-python | v7.1.0 | Commit-SHA pinned CI action |

These are the most recently confirmed compatible upstream releases at the
date above, **not** a perpetual guarantee of currency. Coraza Proxy-WASM
includes its own engine and OWASP CRS, so the standalone CRS cannot be
updated simply by bumping a file version.

## Dependency update procedure

1. Read upstream release notes, advisories, compatibility guidance, and
   changes to the supported CPU/runtime architecture.
2. Pin GitHub Actions by their full verified commit SHA and record their
   human-readable release tag in a comment.
3. Pin all runtime images by reviewed OCI sha256 manifest digests.
   [images.lock.json](../images.lock.json) is the source of truth;
   CI fails if an upstream registry retags one without review.
4. Run Python lint, configuration unit tests, shell checks, Compose validation, Docker
   build, Envoy bootstrap validation and positive/negative WAF smoke tests.
5. Use realistic payload sizes, content types, concurrency and durations
   to assess latency, memory growth, false positives, and false negatives.
6. Never auto-merge risky WAF/plugin upgrades without human review.
7. Update README, security policy and migration notes if behavior changes.

## Pre-merge checklist

- [ ] GitHub Actions checks pass on the final PR commit.
- [ ] Security, compatibility, upstream provenance and risk reviewed.
- [ ] Dependency changes and docs are in the same reviewable diff.
- [ ] A real reviewer has approved significant security-sensitive changes.

## Pre-production checklist

- [ ] Real upstream, TLS, trusted proxy settings, allowed hosts and ingress
      controls are explicitly configured and verified.
- [ ] WAF exclusions and body-size limits are tuned against representative
      traffic, starting in detection-only mode as appropriate.
- [x] Immutable runtime OCI image digests recorded and tag drift tested.
- [ ] Upstream image publisher signatures and vulnerability review verified.
- [ ] The locally generated SBOM/provenance artifact reviewed for the release.
- [ ] Load/soak and fault-injection tests cover the WASM filter's stability,
      memory usage, throughput and tail latency.
- [ ] Monitoring/alerts, secrets, WAF audit-log retention and rollback
      procedures have been exercised.
- [ ] A release tag/image promotion is approved *after*, not before, these
      gates are complete.

## Versioning and rollback

Do not equate a GitHub PR or commit with a release. Use intentional release
tags, record the full Git commit and deployed OCI digests, and retain the
previous known-good manifest for rollback. Avoid publishing an unreviewed
`latest` image or automatically deploying Dependabot PRs.

## WAF memory/performance review

CI runs a short controlled throughput/latency/memory regression. The
[scheduled soak workflow](../.github/workflows/soak.yml) provides a
weekly five-minute measurement and a 10–900-second manual dispatch.
Review its numeric JSON artifact and compare trends before promoting
a release. A successful short soak **does not certify** the upstream
Coraza WASM module against memory leaks; longer staged tests with
representative traffic and controlled hardware remain mandatory.

## Streaming compatibility

No streaming support is included in this release. Do not remove the
request-body buffers or enable a generic upgrade bypass to make a
WebSocket/gRPC request succeed. Any future streaming implementation
requires its own protocol-specific security model and real integration
tests; see [streaming boundary](STREAMING.md).
