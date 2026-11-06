"""Repository hygiene and security-maintenance checks."""

import pathlib
import re
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]

REQUIRED = (
    "README.md", "LICENSE", "SECURITY.md", "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md", "SUPPORT.md", "CHANGELOG.md",
    ".editorconfig", ".gitattributes",
    ".github/CODEOWNERS", ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
    "docs/ARCHITECTURE.md", "docs/OPERATIONS.md",
    "docs/THREAT_MODEL.md", "docs/RELEASE.md",
    "docs/TESTING.md", "docs/STREAMING.md",
)


class RepositoryQualityTests(unittest.TestCase):
    def test_required_community_and_operational_files_exist(self):
        for file in REQUIRED:
            with self.subTest(file=file):
                self.assertTrue((ROOT / file).is_file(), file)

    def test_issue_forms_parse_and_require_reproducible_information(self):
        config = yaml.safe_load(
            (ROOT / ".github/ISSUE_TEMPLATE/config.yml").read_text()
        )
        self.assertFalse(config["blank_issues_enabled"])
        self.assertTrue(config["contact_links"])
        for filename in ("bug_report.yml", "feature_request.yml"):
            with self.subTest(file=filename):
                form = yaml.safe_load(
                    (ROOT / ".github/ISSUE_TEMPLATE" / filename).read_text()
                )
                self.assertTrue(form.get("name"))
                self.assertTrue(form.get("description"))
                self.assertTrue(form.get("body"))
                self.assertTrue(any(
                    field.get("validations", {}).get("required") is True
                    for field in form["body"]
                ))

    def test_relative_markdown_links_resolve(self):
        guides = (
            "README.md", "SECURITY.md", "CONTRIBUTING.md",
            "CODE_OF_CONDUCT.md", "SUPPORT.md", "CHANGELOG.md",
            "docs/ARCHITECTURE.md", "docs/OPERATIONS.md",
            "docs/MIGRATION.md", "docs/RELEASE.md", "docs/THREAT_MODEL.md",
            "docs/TESTING.md", "docs/STREAMING.md",
        )
        link_pattern = re.compile(r"\]\(([^)\s]+)\)")
        for guide in guides:
            for target in link_pattern.findall((ROOT / guide).read_text()):
                if target.startswith(("https:", "http:", "mailto:", "#")):
                    continue
                local = target.split("#", 1)[0]
                if not local:
                    continue
                with self.subTest(guide=guide, target=target):
                    self.assertTrue(
                        (ROOT / guide).parent.joinpath(local).is_file()
                    )

    def test_ci_uses_commit_pins_and_read_only_token(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        uses = re.findall(
            r"^\s*uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@(\S+)",
            workflow, flags=re.MULTILINE
        )
        self.assertGreaterEqual(len(uses), 2)
        for action, ref in uses:
            with self.subTest(action=action):
                self.assertRegex(ref, r"^[0-9a-f]{40}$")
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertNotIn("pull_request_target:", workflow)

    def test_readme_has_essential_sections_and_links(self):
        readme = (ROOT / "README.md").read_text()
        for heading in (
            "Features", "Architecture", "Requirements", "Quick start",
            "Quality checks", "Dependency inventory", "Security", "License"
        ):
            with self.subTest(heading=heading):
                self.assertIn(heading, readme)


if __name__ == "__main__":
    unittest.main()
