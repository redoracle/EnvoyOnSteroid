# Changelog

Important changes are recorded here. There is no guaranteed release schedule.
Git commits and merged PRs are **not** production releases.

## Unreleased

### Added
- Repository contribution and review standards, issue/PR forms, conduct and
  support guidance, CODEOWNERS, and editor/Git attributes.
- Threat model, release checklist, automated repository hygiene checks.

### Test-suite reliability
- Replace ambiguous phase-2 smoke probes with exact Coraza rule IDs for
  URL-encoded form and JSON request bodies; verify the interruption phase.
- Assert real upstream method, query and body response contracts, path
  normalization, header limits, and outage/recovery behavior.
- Isolate Compose environments per CI run and limit failure diagnostics.
- Correlate WAF matches and denial phases by Coraza transaction ID;
  add deterministic parser tests that reject unrelated or malformed events.
- Assert live Docker container runtime isolation and localhost-only
  publishing; run the integration suite twice to detect state leakage.

### Security and reliability
- Second audit PR hardens URI normalization, forwarded-header trust,
  structured logging, runtime isolation, and request-body regression tests.
- Updates CI checkout/setup-python to verified commit-pinned releases.
- Bounds oversized HTTP headers and slow-client timeouts; adds 431 regression.
- Adds Ruff 0.17.4 lint, pinned as a test-time development dependency.

## November 2026 baseline (not a tagged release)

[PR #2](https://github.com/redoracle/EnvoyOnSteroid/pull/2) replaced the
incomplete 2019 ModSecurity prototype with Envoy v3 and Coraza Proxy-WASM,
GitHub Actions CI, a sample backend, and WAF smoke tests. This was a
**breaking architectural migration**, not an in-place upgrade. See
[Migration](docs/MIGRATION.md).
