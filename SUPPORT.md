# Support

EnvoyOnSteroid is a reference implementation, **not** a managed security
product or a service with a support SLA.

For help, first read the [README](README.md), [operations runbook](docs/OPERATIONS.md)
and [migration guide](docs/MIGRATION.md). Verify Docker/Compose versions,
run `docker compose config --quiet` and `bash tests/smoke.sh`, and inspect
sanitized `docker compose logs`.

Use the [bug report form](.github/ISSUE_TEMPLATE/bug_report.yml) for
reproducible problems or the
[feature request form](.github/ISSUE_TEMPLATE/feature_request.yml) for
improvements. Include your environment, image versions, minimal steps,
actual/expected behavior, and sanitized diagnostics.

**Do not report vulnerabilities in public issues.** Follow
[SECURITY.md](SECURITY.md). The project does not provide emergency incident
response, application-specific WAF tuning, or production availability guarantees.
