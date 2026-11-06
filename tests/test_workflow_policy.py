"""Security review of all GitHub Actions workflows, including the soak job."""

import pathlib
import re
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
PINNED = re.compile(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}\Z")


class WorkflowPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflows = {
            path.name: yaml.load(path.read_text(), Loader=yaml.BaseLoader)
            for path in (ROOT / ".github/workflows").glob("*.yml")
        }

    def test_all_workflows_have_read_only_permissions(self):
        self.assertIn("ci.yml", self.workflows)
        self.assertIn("soak.yml", self.workflows)
        for name, workflow in self.workflows.items():
            with self.subTest(name=name):
                self.assertEqual(workflow["permissions"], {"contents": "read"})
                self.assertNotIn("pull_request_target", workflow["on"])

    def test_actions_are_sha_pinned_and_jobs_time_bounded(self):
        for filename, workflow in self.workflows.items():
            for name, job in workflow["jobs"].items():
                with self.subTest(workflow=filename, job=name):
                    self.assertEqual(job["runs-on"], "ubuntu-24.04")
                    self.assertLessEqual(int(job["timeout-minutes"]), 30)
                for step in job["steps"]:
                    if "uses" in step:
                        with self.subTest(action=step["uses"]):
                            self.assertRegex(step["uses"], PINNED)

    def test_sustained_soak_is_scheduled_and_dispatchable(self):
        workflow = self.workflows["soak.yml"]
        self.assertIn("schedule", workflow["on"])
        self.assertIn("workflow_dispatch", workflow["on"])
        commands = "\n".join(
            step.get("run", "")
            for job in workflow["jobs"].values()
            for step in job["steps"]
        )
        self.assertIn("scripts/soak_gateway.py", commands)
        self.assertIn("PYTHON=python3 bash tests/smoke.sh", commands)


if __name__ == "__main__":
    unittest.main()
