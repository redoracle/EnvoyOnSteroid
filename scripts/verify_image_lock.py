"""Validate immutable Docker stages and reviewed OCI registry manifest roots."""

import argparse
import json
import pathlib
import re

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def validate_lock(lock, dockerfile, compose, resolutions=None):
    images = lock["images"]
    if set(images) != {"waf", "envoy", "backend"}:
        raise ValueError("Image lock must list exactly three runtime inputs")
    from_stages = re.findall(
        r"^FROM\s+(\S+)", dockerfile, flags=re.IGNORECASE | re.MULTILINE
    )
    expected_stages = [
        f"{images[name]['tag']}@{images[name]['digest']}"
        for name in ("waf", "envoy")
    ]
    if from_stages != expected_stages:
        raise ValueError("Actual Dockerfile FROM stages differ from image lock")
    for name, item in images.items():
        tag, digest = item["tag"], item["digest"]
        if not _DIGEST.fullmatch(digest):
            raise ValueError(f"Malformed sha256 digest for {name}")
        if ":" not in tag or "@sha256:" in tag or tag.endswith(":latest"):
            raise ValueError(f"Invalid reviewed tag for {name}")
        reference = f"{tag}@{digest}"
        if name == "backend":
            if compose["services"]["backend"]["image"] != reference:
                raise ValueError("Backend is not pinned to reviewed immutable ref")
        elif reference not in from_stages:
            raise ValueError(f"{name} Dockerfile stage differs from image lock")
        if resolutions is not None and resolutions.get(tag) != digest:
            raise ValueError(f"Upstream registry tag drifted: {tag}")
    if resolutions is not None and set(resolutions) != {
        item["tag"] for item in images.values()
    }:
        raise ValueError("Missing or unrecognized upstream digest resolution")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("resolutions", nargs="?", type=pathlib.Path)
    args = parser.parse_args()
    resolutions = None
    if args.resolutions is not None:
        resolutions = {}
        for line in args.resolutions.read_text().splitlines():
            tokens = line.split()
            if len(tokens) != 2 or tokens[0] in resolutions:
                raise ValueError("Malformed or duplicate OCI digest resolution")
            resolutions[tokens[0]] = tokens[1]
    lock = json.loads((ROOT / "images.lock.json").read_text())
    dockerfile = (ROOT / "Dockerfile").read_text()
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    validate_lock(lock, dockerfile, compose, resolutions)
    print("Reviewed image digest pins and tag resolutions verified")


if __name__ == "__main__":
    main()
