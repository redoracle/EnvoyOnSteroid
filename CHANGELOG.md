# Changelog

Important changes are recorded here. There is no guaranteed release schedule.
Git commits and merged PRs are **not** production releases.

## Unreleased

### Added
- Repository contribution and review standards, issue/PR forms, conduct and
  support guidance, CODEOWNERS, and editor/Git attributes.
- Threat model, release checklist, automated repository hygiene checks.

### Security and reliability
- Second audit PR hardens URI normalization, forwarded-header trust,
  structured logging, runtime isolation, and request-body regression tests.
- Updates CI checkout/setup-python to verified commit-pinned releases.

## November 2026 baseline (not a tagged release)

[PR #2](https://github.com/redoracle/EnvoyOnSteroid/pull/2) replaced the
incomplete 2019 ModSecurity prototype with Envoy v3 and Coraza Proxy-WASM,
GitHub Actions CI, a sample backend, and WAF smoke tests. This was a
**breaking architectural migration**, not an in-place upgrade. See
[Migration](docs/MIGRATION.md).
