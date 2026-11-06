"""Verify a BuildKit OCI export contains meaningful SBOM and provenance.

No registry publish or trust assertion is made. OCI blob bytes are checked
against their SHA-256 content addresses before parsing. The resulting files
are evidence of a local build, not upstream publisher signatures.
"""

import argparse
import hashlib
import json
import pathlib
import re
import tarfile

_DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")


def inspect_oci_archive(path):
    with tarfile.open(path, mode="r") as archive:
        def load_file(name):
            member = archive.getmember(name)
            if member.size > 25_000_000:
                raise ValueError(f"OCI metadata exceeds size limit: {name}")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"Missing OCI data: {name}")
            return stream.read()

        def blob(descriptor):
            digest = descriptor["digest"]
            match = _DIGEST.fullmatch(digest)
            if match is None:
                raise ValueError("Invalid OCI digest syntax")
            data = load_file(f"blobs/sha256/{match.group(1)}")
            if hashlib.sha256(data).hexdigest() != match.group(1):
                raise ValueError("OCI blob digest mismatch")
            return json.loads(data)

        index = json.loads(load_file("index.json"))
        candidates = list(index.get("manifests", []))
        statements = {}
        image_manifests = []
        linked_subjects = set()
        inspected = 0

        while candidates:
            descriptor = candidates.pop()
            inspected += 1
            if inspected > 100:
                raise ValueError("OCI manifest tree is unexpectedly large")
            obj = blob(descriptor)
            if "manifests" in obj:
                candidates.extend(obj["manifests"])
                continue
            if "layers" not in obj:
                raise ValueError("OCI descriptor is not an image manifest")
            platform = descriptor.get("platform", {})
            if (
                platform.get("os") == "linux"
                and platform.get("architecture") == "amd64"
            ):
                image_manifests.append(descriptor["digest"])
            for layer in obj.get("layers", []):
                if layer.get("mediaType") != "application/vnd.in-toto+json":
                    continue
                attestation = blob(layer)
                predicate_type = attestation.get("predicateType", "")
                if predicate_type.startswith("https://spdx.dev/"):
                    kind = "sbom"
                    predicate = attestation.get("predicate", {})
                    if (
                        not predicate.get("spdxVersion", "").startswith("SPDX-")
                        or not predicate.get("packages")
                    ):
                        raise ValueError("SBOM has no meaningful SPDX packages")
                elif predicate_type.startswith("https://slsa.dev/provenance/"):
                    kind = "provenance"
                    predicate = attestation.get("predicate", {})
                    if not predicate.get("buildDefinition") and not predicate.get(
                        "builder"
                    ):
                        raise ValueError("Provenance lacks a builder or build definition")
                else:
                    continue
                # BuildKit links subjects either from in-toto statements,
                # OCI manifest subjects, or OCI index annotations.
                subjects = {
                    "sha256:" + entry.get("digest", {}).get("sha256", "")
                    for entry in attestation.get("subject", [])
                }
                linked = obj.get("subject", {}).get("digest") or descriptor.get(
                    "annotations", {}
                ).get("vnd.docker.reference.digest")
                if linked:
                    subjects.add(linked)
                valid = {item for item in subjects if _DIGEST.fullmatch(item)}
                if not valid:
                    raise ValueError(f"{kind} attestation has no valid subject")
                linked_subjects.update(valid)
                statements[kind] = attestation

        if not image_manifests:
            raise ValueError("No linux/amd64 OCI image manifest found")
        if not linked_subjects.intersection(image_manifests):
            raise ValueError("OCI attestations are not linked to built image")
        for required in ("sbom", "provenance"):
            if required not in statements:
                raise ValueError(f"Missing required {required} attestation")
        summary = {
            "image_manifests": sorted(image_manifests),
            "sbom_package_count": len(statements["sbom"]["predicate"]["packages"]),
            "predicate_types": {
                key: value["predicateType"] for key, value in statements.items()
            },
            "verified_blob_hashes": True,
            "publisher_signatures_verified": False,
        }
        return statements, summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=pathlib.Path)
    parser.add_argument("output_dir", type=pathlib.Path)
    args = parser.parse_args()
    statements, summary = inspect_oci_archive(args.archive)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, statement in statements.items():
        (args.output_dir / f"{name}.intoto.json").write_text(
            json.dumps(statement, sort_keys=True, indent=2) + "\n"
        )
    (args.output_dir / "verification-summary.json").write_text(
        json.dumps(summary, sort_keys=True, indent=2) + "\n"
    )
    print("OCI evidence verified: " + json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
