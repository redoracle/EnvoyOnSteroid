# Contributing

## Quality gates

Changes should be reviewable, minimal, documented, and regression-tested.
Make all code/configuration changes on feature branches, not directly on
`master`. The workflow uses read-only GitHub permissions and SHA-pinned
GitHub Actions; it performs no unattended image publishing.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/ruff check tests
.venv/bin/python -m unittest discover -s tests -v
bash -n tests/smoke.sh
docker compose config --quiet
docker compose build --pull
docker run --rm --entrypoint envoy envoyonsteroid:local \
  --mode validate -c /etc/envoy/envoy.yaml
docker compose up -d --no-build
bash tests/smoke.sh
docker compose down --volumes --remove-orphans
```

CI uses Ubuntu 24.04 and Python 3.13; when changing these targets, review
runtime compatibility and keep the setup action on the latest verified,
commit-pinned release. Dependabot PRs are not automatically merged.

## WAF rules and upgrades

Keep regression tests for both allowed traffic and each request phase being
blocked. Changes to request normalization, trusted proxy hops, or body
inspection are security-sensitive: document their downstream compatibility
impact. The Coraza Proxy-WASM image contains its own CRS version and cannot
be upgraded by copying newer standalone CRS files. Only advance the plugin
when a verified compatible image exists and soak tests pass.

## Community and review

Follow the [Code of Conduct](CODE_OF_CONDUCT.md), read the
[Security Policy](SECURITY.md), and use the [bug report](.github/ISSUE_TEMPLATE/bug_report.yml)
or [feature request](.github/ISSUE_TEMPLATE/feature_request.yml)
forms. The [PR template](.github/PULL_REQUEST_TEMPLATE.md) describes
required evidence; [CODEOWNERS](.github/CODEOWNERS) identifies reviewers.
These files do not activate GitHub branch protection on their own.

## PR expectations

Include a security/compatibility impact summary, affected dependency
versions, reproducible validation commands, CI results, and any manual
production tests not yet performed. Do not claim load testing or production
readiness from passing unit and smoke tests alone.
