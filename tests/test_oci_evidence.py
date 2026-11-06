"""Negative controls for checking BuildKit OCI attestations."""

import hashlib
import io
import json
import pathlib
import tarfile
import tempfile
import unittest

from scripts.verify_oci_evidence import inspect_oci_archive


def make_archive(path, *, good=True, with_sbom=True, with_provenance=True):
    blobs = {}

    def descriptor(value):
        data = json.dumps(value, separators=(",", ":")).encode()
        digest = hashlib.sha256(data).hexdigest()
        blobs[digest] = data
        return {"digest": f"sha256:{digest}", "size": len(data)}

    platform_image = descriptor({"schemaVersion": 2, "layers": []})
    platform_image["platform"] = {"os": "linux", "architecture": "amd64"}

    layers = []
    image_digest = platform_image["digest"].split(":", 1)[1]
    sbom = {
        "subject": [{"name": "example", "digest": {"sha256": image_digest}}],
        "predicateType": "https://spdx.dev/Document",
        "predicate": {"spdxVersion": "SPDX-2.3", "packages": [{"name": "example"}]},
    }
    provenance = {
        "subject": [{"name": "example", "digest": {"sha256": image_digest}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {"buildDefinition": {"buildType": "example"}},
    }
    for enabled, statement in (
        (with_sbom, sbom),
        (with_provenance, provenance),
    ):
        if enabled:
            layer = descriptor(statement)
            layer["mediaType"] = "application/vnd.in-toto+json"
            layers.append(layer)
    att = descriptor({"schemaVersion": 2, "layers": layers})
    att["platform"] = {"os": "unknown", "architecture": "unknown"}
    index = {"schemaVersion": 2, "manifests": [platform_image, att]}

    with tarfile.open(path, "w") as archive:
        content = {"index.json": json.dumps(index).encode()}
        content.update(
            {f"blobs/sha256/{name}": data for name, data in blobs.items()}
        )
        for name, data in content.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    if not good:
        with tarfile.open(path, "a") as archive:
            evil = b"not-a-verified-blob"
            key = next(iter(blobs))
            entry = tarfile.TarInfo(f"blobs/sha256/{key}")
            entry.size = len(evil)
            archive.addfile(entry, io.BytesIO(evil))


class OCIEvidenceTests(unittest.TestCase):
    def verify_fixture(self, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            file = pathlib.Path(directory) / "test.oci.tar"
            make_archive(file, **kwargs)
            return inspect_oci_archive(file)

    def test_complete_evidence_is_accepted(self):
        statements, summary = self.verify_fixture()
        self.assertEqual(set(statements), {"sbom", "provenance"})
        self.assertEqual(summary["sbom_package_count"], 1)
        self.assertFalse(summary["publisher_signatures_verified"])

    def test_missing_sbom_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "Missing required sbom"):
            self.verify_fixture(with_sbom=False)

    def test_missing_provenance_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "Missing required provenance"):
            self.verify_fixture(with_provenance=False)


if __name__ == "__main__":
    unittest.main()
