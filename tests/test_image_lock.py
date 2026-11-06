"""Offline negative tests for immutable OCI image supply-chain inputs."""

import copy
import json
import pathlib
import unittest

import yaml

from scripts.verify_image_lock import validate_lock

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ImageLockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lock = json.loads((ROOT / "images.lock.json").read_text())
        cls.dockerfile = (ROOT / "Dockerfile").read_text()
        cls.compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())

    def test_three_runtime_image_refs_are_immutable_and_reviewed(self):
        self.assertTrue(
            validate_lock(self.lock, self.dockerfile, self.compose)
        )

    def test_mutable_backend_ref_is_rejected(self):
        compose = copy.deepcopy(self.compose)
        compose["services"]["backend"]["image"] = self.lock["images"][
            "backend"
        ]["tag"]
        with self.assertRaisesRegex(ValueError, "immutable"):
            validate_lock(self.lock, self.dockerfile, compose)

    def test_mismatched_dockerfile_digest_is_rejected(self):
        lock = copy.deepcopy(self.lock)
        lock["images"]["envoy"]["digest"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(ValueError, "differs"):
            validate_lock(lock, self.dockerfile, self.compose)

    def test_registry_tag_drift_fails_closed(self):
        images = self.lock["images"]
        resolved = {item["tag"]: item["digest"] for item in images.values()}
        self.assertTrue(
            validate_lock(self.lock, self.dockerfile, self.compose, resolved)
        )
        resolved[images["waf"]["tag"]] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(ValueError, "drifted"):
            validate_lock(self.lock, self.dockerfile, self.compose, resolved)


if __name__ == "__main__":
    unittest.main()
