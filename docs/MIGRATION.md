# Migration from the 2019 prototype

This is a **breaking architecture replacement**, not a safe in-place
ModSecurity v3 upgrade. Review compatibility before merging.

| Area | 2019 files | Current design |
| --- | --- | --- |
| Envoy | Source build with outdated Bazel | Supported upstream `v1.40.2` OCI image |
| WAF | Unmaintained native ModSecurity Envoy extension | Coraza Proxy-WASM `0.6.0` |
| Rules | Broken download scraping for CRS 3.x | CRS `4.14.0` embedded in WASM |
| Bootstrap | v2 `lds.yaml` pointing at missing files | v3 `envoy.yaml` with complete listener and cluster |
| Compose | References 3 nonexistent Dockerfiles | Single proxy and internal example backend |
| Tests | None | Static invariants, Envoy validation, HTTP smoke test |
| CI | Travis Docker Hub password publishing | GitHub Actions read-only PR verification |

## Breaking changes

- The executable is the official Envoy binary; native ModSecurity plugins,
  extension-specific webhook fields, and the old listener schema are gone.
- The filter interprets supported ModSecurity-style rules via Coraza. Custom
  rules/operators and callbacks must be checked for compatibility, not copied
  blindly. The old rules were not working in the supplied Docker image.
- The sample's port is now `8080`, with a private upstream service. There is
  no Docker Hub deployment or implicit publishing of `latest` images.
- Production traffic must not be redirected to this example until staging
  tuning, load testing, and observability are in place.

## Dependency policy

- `envoyproxy/envoy:v1.40.2` is the supported Envoy release as of November 2026.
- `coraza-proxy-wasm:0.6.0` is its latest published OCI/release artifact, but
  embeds the older Coraza `v3.3.3` and CRS `v4.14.0`. Upstream has warned about
  TinyGo/proxy-WASM memory issues. A jump to newer standalone Coraza/CRS is
  **not** an independent, verified safe package upgrade.
- Check upstream advisories and image provenance prior to rollout. Version
  tags are explicit but are not immutable digests; pin reviewed digests in a
  deployment promotion process for stronger reproducibility.
- Do not enable automated major upgrades or untested WAF binary replacement.

## Suggested rollout

1. Review configuration and adjust actual backend, TLS and monitoring.
2. Run validation and blocking tests in CI with a supported container runner.
3. Run application-specific staging tests in `DetectionOnly`, tune false
   positives, then test blocking mode and request/response body limits.
4. Run a multi-day load/soak test, inspect memory and WAF error metrics, and
   provision a rollback to the previous production deployment.
5. Only then release and deploy the new architecture.
