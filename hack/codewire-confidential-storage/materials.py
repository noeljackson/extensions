#!/usr/bin/env python3
"""Validate and materialize Codewire confidential-storage build inputs."""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
import re
import stat
import struct
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import tomllib

SCHEMA = "codewire.confidential-storage.sources/v2"
SOURCE_NAMES = {
    "extensions",
    "guest_components",
    "kata_containers",
    "trustee",
    "trustee_attestation_service",
}
TRUSTEE_IMAGE_NAMES = {"attestation_service", "kbs", "rvps"}
COMBINED_TRUSTEE_IMAGE_NAMES = {"kbs", "rvps"}
TRUSTEE_IMAGE_SOURCES = {
    "attestation_service": "trustee_attestation_service",
    "kbs": "trustee",
    "rvps": "trustee",
}
TRUSTEE_IMAGE_REPOSITORIES = {
    "attestation_service": "ghcr.io/confidential-containers/staged-images/coco-as-grpc",
    "kbs": "ghcr.io/noeljackson/staged-images/kbs-grpc-as",
    "rvps": "ghcr.io/noeljackson/staged-images/kbs-grpc-as",
}
TRUSTEE_IMAGE_DOCKERFILES = {
    "attestation_service": "attestation-service/docker/as-grpc/Dockerfile",
    "kbs": "kbs/docker/coco-as-grpc/Dockerfile",
    "rvps": "kbs/docker/coco-as-grpc/Dockerfile",
}
GUEST_IMAGE_NAMES = {"container", "disk"}
GUEST_IMAGE_REPOSITORY_SUFFIXES = {
    "container": "coco-extension",
    "disk": "coco-extension-disk",
}
GUEST_IMAGE_DOCKERFILES = {
    "container": "tools/coco-extension/Dockerfile",
    "disk": "tools/coco-extension/build-erofs-image.sh",
}
GUEST_IMAGE_BUILD_FILES = {
    "container": {
        ".github/workflows/coco-extension-image.yml",
        "tools/coco-extension/Dockerfile",
        "tools/coco-extension/test-publication-contract.sh",
    },
    "disk": {
        ".github/workflows/coco-extension-image.yml",
        "tools/coco-extension/build-erofs-image.sh",
        "tools/coco-extension/test-publication-contract.sh",
    },
}
GUEST_IMAGE_ATTESTATION_PREDICATES = {
    "container": {
        "provenance": "https://slsa.dev/provenance/v1",
        "sbom": "https://spdx.dev/Document/v2.3",
    },
    "disk": {"provenance": "https://slsa.dev/provenance/v1"},
}
BUILDER_INPUT_FILES = {
    ".github/workflows/downstream-confidential-storage.yml",
    "hack/codewire-confidential-storage/base-rootfs.Dockerfile",
    "hack/codewire-confidential-storage/build.sh",
    "hack/codewire-confidential-storage/extension.Dockerfile",
    "hack/codewire-confidential-storage/materials.py",
    "hack/codewire-confidential-storage/publish.sh",
    "hack/codewire-confidential-storage/qemu-tcg-boot-smoke",
    "hack/codewire-confidential-storage/secure-ubuntu-apt-sources",
    "hack/codewire-confidential-storage/test-publication-contract.sh",
    "hack/codewire-confidential-storage/test-qemu-tcg-boot-smoke.sh",
}
TALOS_EXTENSION_NAMES = ["iscsi-tools", "util-linux-tools"]
FULL_HASH = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SHA512 = re.compile(r"^[0-9a-f]{128}$")
SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
OCI_DIGEST = re.compile(r"^(?:docker\.io|ghcr\.io)/[a-z0-9./_-]+@sha256:[0-9a-f]{64}$")
OCI_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")
SECRET_FIELD = re.compile(
    r"(^|_)(credential|password|private_key|secret|token)($|_)", re.IGNORECASE
)


class MaterialError(RuntimeError):
    pass


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MaterialError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_lock(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys
        )
    except (OSError, json.JSONDecodeError) as error:
        raise MaterialError(f"failed to read source lock {path}: {error}") from error
    if not isinstance(value, dict):
        raise MaterialError("source lock must be a JSON object")
    validate_lock(value)
    return value


def require_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise MaterialError(f"{context} keys differ: missing={missing}, extra={extra}")


def validate_no_secret_fields(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if SECRET_FIELD.search(key):
                raise MaterialError(
                    f"secret-bearing field name is forbidden at {path}.{key}"
                )
            validate_no_secret_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            validate_no_secret_fields(child, f"{path}[{index}]")


def validate_source(name: str, source: dict[str, Any]) -> None:
    require_keys(
        source,
        {"repository", "revision", "tree", "source_date_epoch", "archive"},
        f"source {name}",
    )
    repository = source["repository"]
    if not isinstance(repository, str):
        raise MaterialError(f"source {name} repository must be a string")
    parsed = urlparse(repository)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.query
        or parsed.fragment
        or repository.endswith(".git")
    ):
        raise MaterialError(
            f"source {name} repository is not a canonical HTTPS GitHub URL"
        )
    slug = parsed.path.strip("/")
    if len(slug.split("/")) != 2:
        raise MaterialError(f"source {name} repository must name one owner/repository")

    revision = source["revision"]
    tree = source["tree"]
    if not isinstance(revision, str) or not FULL_HASH.fullmatch(revision):
        raise MaterialError(f"source {name} revision must be a lowercase full Git hash")
    if not isinstance(tree, str) or not FULL_HASH.fullmatch(tree):
        raise MaterialError(f"source {name} tree must be a lowercase full Git hash")
    epoch = source["source_date_epoch"]
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch <= 0:
        raise MaterialError(
            f"source {name} source_date_epoch must be a positive integer"
        )

    archive = source["archive"]
    if not isinstance(archive, dict):
        raise MaterialError(f"source {name} archive must be an object")
    require_keys(archive, {"url", "sha256", "sha512"}, f"source {name} archive")
    expected_url = f"https://codeload.github.com/{slug}/tar.gz/{revision}"
    if archive["url"] != expected_url:
        raise MaterialError(f"source {name} archive URL must bind the exact revision")
    if not isinstance(archive["sha256"], str) or not SHA256.fullmatch(
        archive["sha256"]
    ):
        raise MaterialError(f"source {name} archive sha256 is invalid")
    if not isinstance(archive["sha512"], str) or not SHA512.fullmatch(
        archive["sha512"]
    ):
        raise MaterialError(f"source {name} archive sha512 is invalid")


def validate_trustee_image(name: str, image: Any, sources: dict[str, Any]) -> None:
    if not isinstance(image, dict):
        raise MaterialError(f"Trustee image {name} must bind source and build evidence")
    require_keys(
        image,
        {
            "reference",
            "published_tag",
            "platform",
            "platform_manifest",
            "source",
            "dockerfile",
            "build_files",
            "attestations",
        },
        f"Trustee image {name}",
    )

    reference = image["reference"]
    if (
        not isinstance(reference, str)
        or not OCI_DIGEST.fullmatch(reference)
        or reference.endswith("@sha256:" + "0" * 64)
    ):
        raise MaterialError(
            f"Trustee image {name} must use an immutable digest reference"
        )
    repository, _ = reference.split("@", 1)
    if repository != TRUSTEE_IMAGE_REPOSITORIES[name]:
        raise MaterialError(
            f"Trustee image {name} repository is not the accepted package"
        )

    source_name = image["source"]
    if source_name != TRUSTEE_IMAGE_SOURCES[name]:
        raise MaterialError(
            f"Trustee image {name} must use source {TRUSTEE_IMAGE_SOURCES[name]}"
        )
    source = sources[source_name]
    published_tag = image["published_tag"]
    if not isinstance(published_tag, str) or not OCI_TAG.fullmatch(published_tag):
        raise MaterialError(f"Trustee image {name} publication tag is invalid")
    expected_tag = source["revision"]
    if name in COMBINED_TRUSTEE_IMAGE_NAMES:
        expected_tag = f"v0.21.0-path-acl-{source['revision'][:12]}"
    if published_tag != expected_tag:
        raise MaterialError(
            f"Trustee image {name} publication tag does not bind its source revision"
        )

    if image["platform"] != "linux/amd64":
        raise MaterialError(f"Trustee image {name} must bind the linux/amd64 platform")
    if not isinstance(image["platform_manifest"], str) or not SHA256_DIGEST.fullmatch(
        image["platform_manifest"]
    ):
        raise MaterialError(f"Trustee image {name} platform manifest is invalid")

    dockerfile = image["dockerfile"]
    if dockerfile != TRUSTEE_IMAGE_DOCKERFILES[name]:
        raise MaterialError(
            f"Trustee image {name} Dockerfile is not the accepted recipe"
        )
    validate_input_files(image["build_files"], f"Trustee image {name}")
    if dockerfile not in image["build_files"]:
        raise MaterialError(f"Trustee image {name} does not hash its Dockerfile")

    attestations = image["attestations"]
    if not isinstance(attestations, dict):
        raise MaterialError(f"Trustee image {name} attestations must be an object")
    if name in COMBINED_TRUSTEE_IMAGE_NAMES:
        require_keys(
            attestations,
            {"manifest", "provenance", "sbom"},
            f"Trustee image {name} attestations",
        )
        for attestation_name, digest in attestations.items():
            if not isinstance(digest, str) or not SHA256_DIGEST.fullmatch(digest):
                raise MaterialError(
                    f"Trustee image kbs {attestation_name} attestation is invalid"
                )
    elif attestations:
        raise MaterialError(
            f"Trustee image {name} must not claim unavailable embedded attestations"
        )


def validate_guest_components_image(
    name: str, image: Any, sources: dict[str, Any]
) -> None:
    if not isinstance(image, dict):
        raise MaterialError(
            "Guest Components image must bind source and publication evidence"
        )
    require_keys(
        image,
        {
            "reference",
            "published_tag",
            "platform",
            "source",
            "dockerfile",
            "build_files",
            "attestations",
        },
        f"Guest Components {name} image",
    )

    reference = image["reference"]
    if not isinstance(reference, str) or not OCI_DIGEST.fullmatch(reference):
        raise MaterialError(
            f"Guest Components {name} image must use an immutable digest reference"
        )
    source_name = image["source"]
    if source_name != "guest_components":
        raise MaterialError("Guest Components image must use guest_components source")
    source = sources[source_name]
    expected_repository = (
        f"ghcr.io/{source['repository'].removeprefix('https://github.com/').lower()}/"
        f"{GUEST_IMAGE_REPOSITORY_SUFFIXES[name]}"
    )
    repository, _ = reference.split("@", 1)
    if repository != expected_repository:
        raise MaterialError(
            f"Guest Components {name} image repository does not match its locked source"
        )
    expected_tag = f"{source['revision']}-ubuntu26.04-amd64"
    if image["published_tag"] != expected_tag:
        raise MaterialError(
            f"Guest Components {name} image publication tag does not bind "
            "its source revision"
        )
    if image["platform"] != "linux/amd64":
        raise MaterialError(
            f"Guest Components {name} image must bind the linux/amd64 platform"
        )
    if image["dockerfile"] != GUEST_IMAGE_DOCKERFILES[name]:
        raise MaterialError(f"Guest Components {name} image recipe is not accepted")
    validate_input_files(image["build_files"], f"Guest Components {name} image")
    if set(image["build_files"]) != GUEST_IMAGE_BUILD_FILES[name]:
        raise MaterialError(
            f"Guest Components {name} image build_files must be exactly "
            f"{sorted(GUEST_IMAGE_BUILD_FILES[name])}"
        )

    attestations = image["attestations"]
    if not isinstance(attestations, dict):
        raise MaterialError("Guest Components image attestations must be an object")
    predicates = GUEST_IMAGE_ATTESTATION_PREDICATES[name]
    require_keys(
        attestations,
        set(predicates),
        f"Guest Components {name} image attestations",
    )
    for attestation_name, attestation in attestations.items():
        if not isinstance(attestation, dict):
            raise MaterialError(
                f"Guest Components image {attestation_name} attestation must be "
                "an object"
            )
        require_keys(
            attestation,
            {"manifest", "bundle"},
            f"Guest Components image {attestation_name} attestation",
        )
        for field, digest in attestation.items():
            if (
                not isinstance(digest, str)
                or not SHA256_DIGEST.fullmatch(digest)
                or digest == "sha256:" + "0" * 64
            ):
                raise MaterialError(
                    "Guest Components image "
                    f"{attestation_name} {field} digest is invalid"
                )


def input_tree_digest(input_files: dict[str, str]) -> str:
    payload = json.dumps(input_files, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def validate_lock(lock: dict[str, Any]) -> None:
    validate_no_secret_fields(lock)
    require_keys(
        lock,
        {
            "schema",
            "platforms",
            "source_date_epoch",
            "sources",
            "builder",
            "base_images",
            "guest_components_images",
            "trustee_images",
            "talos_extensions",
            "kata_build_contract",
        },
        "source lock",
    )
    if lock["schema"] != SCHEMA:
        raise MaterialError(f"unsupported schema: {lock['schema']!r}")
    if lock["platforms"] != ["linux/amd64"]:
        raise MaterialError("this Dev lock must select only linux/amd64")

    sources = lock["sources"]
    if not isinstance(sources, dict) or set(sources) != SOURCE_NAMES:
        raise MaterialError(f"sources must be exactly {sorted(SOURCE_NAMES)}")
    for name in sorted(sources):
        if not isinstance(sources[name], dict):
            raise MaterialError(f"source {name} must be an object")
        validate_source(name, sources[name])
    epochs = [source["source_date_epoch"] for source in sources.values()]
    if lock["source_date_epoch"] != max(epochs):
        raise MaterialError(
            "source_date_epoch must equal the newest locked source epoch"
        )

    builder = lock["builder"]
    if not isinstance(builder, dict):
        raise MaterialError("builder must be an object")
    require_keys(builder, {"source", "input_files", "input_tree_sha256"}, "builder")
    if builder["source"] != "extensions":
        raise MaterialError("builder must use the locked extensions source")
    validate_input_files(builder["input_files"], "builder")
    if set(builder["input_files"]) != BUILDER_INPUT_FILES:
        raise MaterialError(
            f"builder input_files must be exactly {sorted(BUILDER_INPUT_FILES)}"
        )
    if builder["input_tree_sha256"] != input_tree_digest(builder["input_files"]):
        raise MaterialError("builder input tree digest does not match its files")

    base_images = lock["base_images"]
    if not isinstance(base_images, dict):
        raise MaterialError("base_images must be an object")
    require_keys(
        base_images,
        {
            "buildkit_sbom_scanner",
            "kata_talos_extension",
            "ubuntu_apt_ca_bootstrap",
        },
        "base_images",
    )
    if not re.fullmatch(
        r"docker\.io/docker/buildkit-syft-scanner@sha256:[0-9a-f]{64}",
        base_images["buildkit_sbom_scanner"],
    ):
        raise MaterialError("BuildKit SBOM scanner must be its exact Docker Hub digest")
    if not re.fullmatch(
        r"ghcr\.io/noeljackson/kata-containers@sha256:[0-9a-f]{64}",
        base_images["kata_talos_extension"],
    ):
        raise MaterialError("Kata Talos base image must be its exact GHCR digest")
    if not re.fullmatch(
        r"docker\.io/library/golang:1\.26\.7-alpine3\.23@sha256:[0-9a-f]{64}",
        base_images["ubuntu_apt_ca_bootstrap"],
    ):
        raise MaterialError(
            "Ubuntu APT CA bootstrap must be its exact Docker Hub digest"
        )
    guest_images = lock["guest_components_images"]
    if not isinstance(guest_images, dict) or set(guest_images) != GUEST_IMAGE_NAMES:
        raise MaterialError(
            f"guest_components_images must be exactly {sorted(GUEST_IMAGE_NAMES)}"
        )
    for name, image in guest_images.items():
        validate_guest_components_image(name, image, sources)
    trustee_images = lock["trustee_images"]
    if (
        not isinstance(trustee_images, dict)
        or set(trustee_images) != TRUSTEE_IMAGE_NAMES
    ):
        raise MaterialError(
            f"trustee_images must be exactly {sorted(TRUSTEE_IMAGE_NAMES)}"
        )
    for name, image in trustee_images.items():
        validate_trustee_image(name, image, sources)
    if trustee_images["kbs"] != trustee_images["rvps"]:
        raise MaterialError(
            "Trustee KBS and RVPS must bind the same combined downstream image"
        )

    talos = lock["talos_extensions"]
    if not isinstance(talos, dict):
        raise MaterialError("talos_extensions must be an object")
    require_keys(talos, {"installer_profile", "packages"}, "talos_extensions")
    if talos["installer_profile"] != "servernet-confidential-storage-only":
        raise MaterialError(
            "Talos extensions must be restricted to the Server.net storage profile"
        )
    packages = talos["packages"]
    if (
        not isinstance(packages, list)
        or [item.get("name") for item in packages] != TALOS_EXTENSION_NAMES
    ):
        raise MaterialError(
            f"Talos extension packages must be ordered as {TALOS_EXTENSION_NAMES}"
        )
    package_keys = {
        "name",
        "version",
        "source_name",
        "source_version",
        "source_sha256",
        "source_sha512",
    }
    for item in packages:
        if not isinstance(item, dict):
            raise MaterialError("Talos extension package must be an object")
        require_keys(item, package_keys, f"Talos extension {item.get('name')}")
        if not SHA256.fullmatch(item["source_sha256"]):
            raise MaterialError(f"Talos extension {item['name']} sha256 is invalid")
        if not SHA512.fullmatch(item["source_sha512"]):
            raise MaterialError(f"Talos extension {item['name']} sha512 is invalid")

    kata = lock["kata_build_contract"]
    if not isinstance(kata, dict):
        raise MaterialError("kata_build_contract must be an object")
    require_keys(
        kata,
        {
            "guest_artifact_variant",
            "kata_version",
            "qemu_snp_overhead_memory_mib",
            "persistent_volume_max_gib",
            "cdh_api_timeout_seconds",
            "create_container_timeout_seconds",
            "input_files",
            "required_packages",
            "required_guest_tools",
        },
        "kata_build_contract",
    )
    if kata["guest_artifact_variant"] != "ubuntu26.04":
        raise MaterialError(
            "Kata guest artifact variant must select the fixed Ubuntu 26.04 image"
        )
    if (
        not isinstance(kata["kata_version"], str)
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", kata["kata_version"]) is None
    ):
        raise MaterialError("Kata version must be an exact semantic version")
    if kata["qemu_snp_overhead_memory_mib"] != 2048:
        raise MaterialError(
            "Kata QEMU-SNP guest overhead must remain the locked 2048 MiB budget"
        )
    if kata["persistent_volume_max_gib"] != 50:
        raise MaterialError("Kata persistent-volume contract must be bounded to 50 GiB")
    if kata["cdh_api_timeout_seconds"] != 1200:
        raise MaterialError(
            "Kata CDH API timeout must match the bounded 50 GiB initialization contract"
        )
    if kata["create_container_timeout_seconds"] != 1350:
        raise MaterialError(
            "Kata CreateContainer timeout must leave headroom above the CDH API timeout"
        )
    validate_input_files(kata["input_files"], "kata_build_contract")
    if kata["required_packages"] != ["cryptsetup-bin", "dmsetup", "e2fsprogs"]:
        raise MaterialError(
            "Kata required packages must include the fixed storage-tool closure"
        )
    required_tools = kata["required_guest_tools"]
    if not isinstance(required_tools, dict) or list(required_tools) != [
        "cryptsetup",
        "dmsetup",
        "mkfs.ext4",
        "resize2fs",
    ]:
        raise MaterialError("Kata required guest tools differ from the fixed allowlist")
    for name, candidates in required_tools.items():
        if (
            not isinstance(candidates, list)
            or len(candidates) != 2
            or any(
                not isinstance(path, str) or not path.startswith("/")
                for path in candidates
            )
        ):
            raise MaterialError(
                f"guest tool {name} must have two absolute path candidates"
            )


def validate_input_files(value: Any, context: str) -> None:
    if not isinstance(value, dict) or not value:
        raise MaterialError(f"{context} input_files must be a non-empty object")
    for path, digest in value.items():
        if (
            not isinstance(path, str)
            or path.startswith("/")
            or ".." in Path(path).parts
        ):
            raise MaterialError(f"{context} input path is unsafe: {path!r}")
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise MaterialError(f"{context} input digest is invalid for {path}")


def digest_file(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def lock_digest(path: Path) -> str:
    return digest_file(path, "sha256")


def verify_archives(lock: dict[str, Any], cache: Path) -> None:
    for name, source in sorted(lock["sources"].items()):
        path = cache / f"{name}.tar.gz"
        if not path.is_file():
            raise MaterialError(f"missing locked archive: {path}")
        for algorithm in ("sha256", "sha512"):
            actual = digest_file(path, algorithm)
            expected = source["archive"][algorithm]
            if actual != expected:
                raise MaterialError(
                    f"{name} archive {algorithm} mismatch: expected {expected}, got {actual}"
                )


def run_git(repo: Path, *arguments: str) -> str:
    try:
        process = subprocess.run(
            ["git", "-C", os.fspath(repo), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip() or error.stdout.strip()
        raise MaterialError(
            f"git {' '.join(arguments)} failed for {repo}: {detail}"
        ) from error
    return process.stdout.strip()


def verify_git_source(lock: dict[str, Any], source_name: str, repo: Path) -> None:
    if source_name not in lock["sources"]:
        raise MaterialError(f"unknown locked source: {source_name}")
    source = lock["sources"][source_name]
    revision = run_git(repo, "rev-parse", "HEAD")
    tree = run_git(repo, "rev-parse", "HEAD^{tree}")
    if revision != source["revision"]:
        raise MaterialError(
            f"{source_name} revision mismatch: expected {source['revision']}, got {revision}"
        )
    if tree != source["tree"]:
        raise MaterialError(
            f"{source_name} tree mismatch: expected {source['tree']}, got {tree}"
        )
    status = run_git(repo, "status", "--porcelain", "--untracked-files=no")
    if status:
        raise MaterialError(
            f"{source_name} source has tracked modifications before preparation"
        )


def verify_file_contract(repo: Path, input_files: dict[str, str], context: str) -> None:
    for relative, expected in sorted(input_files.items()):
        path = repo / relative
        if not path.is_file():
            raise MaterialError(f"{context} input is missing: {relative}")
        actual = digest_file(path, "sha256")
        if actual != expected:
            raise MaterialError(
                f"{context} input drift for {relative}: expected {expected}, got {actual}"
            )


def git_file_bytes(repo: Path, revision: str, relative: str) -> bytes:
    try:
        process = subprocess.run(
            ["git", "-C", os.fspath(repo), "show", f"{revision}:{relative}"],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as error:
        detail = error.stderr.decode(errors="replace").strip()
        raise MaterialError(
            f"Git source {revision} is missing build input {relative}: {detail}"
        ) from error
    return process.stdout


def verify_revision_file_contract(
    repo: Path,
    source: dict[str, Any],
    input_files: dict[str, str],
    context: str,
) -> None:
    actual_tree = run_git(repo, "rev-parse", f"{source['revision']}^{{tree}}")
    if actual_tree != source["tree"]:
        raise MaterialError(
            f"{context} source tree mismatch: expected {source['tree']}, got {actual_tree}"
        )
    for relative, expected in sorted(input_files.items()):
        actual = hashlib.sha256(
            git_file_bytes(repo, source["revision"], relative)
        ).hexdigest()
        if actual != expected:
            raise MaterialError(
                f"{context} source input drift for {relative}: "
                f"expected {expected}, got {actual}"
            )


def verify_builder(lock: dict[str, Any], repo: Path) -> None:
    builder = lock["builder"]
    verify_file_contract(repo, builder["input_files"], "extension builder checkout")


def verify_trustee_image_source(
    lock: dict[str, Any], component: str, repo: Path
) -> None:
    if component not in lock["trustee_images"]:
        raise MaterialError(f"unknown Trustee image component: {component}")
    image = lock["trustee_images"][component]
    source = lock["sources"][image["source"]]
    verify_revision_file_contract(
        repo, source, image["build_files"], f"Trustee image {component}"
    )
    accepted_revision = lock["sources"]["trustee"]["revision"]
    if source["revision"] != accepted_revision:
        process = subprocess.run(
            [
                "git",
                "-C",
                os.fspath(repo),
                "merge-base",
                "--is-ancestor",
                source["revision"],
                accepted_revision,
            ],
            capture_output=True,
        )
        if process.returncode != 0:
            raise MaterialError(
                f"Trustee image {component} source is not in the accepted Trustee history"
            )


def verify_guest_components_image_source(lock: dict[str, Any], repo: Path) -> None:
    source = lock["sources"]["guest_components"]
    build_files: dict[str, str] = {}
    for image in lock["guest_components_images"].values():
        for relative, digest in image["build_files"].items():
            previous = build_files.setdefault(relative, digest)
            if previous != digest:
                raise MaterialError(
                    f"Guest Components image recipe digest differs for {relative}"
                )
    verify_revision_file_contract(repo, source, build_files, "Guest Components images")


def run_skopeo(*arguments: str) -> str:
    try:
        process = subprocess.run(
            ["skopeo", *arguments],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as error:
        raise MaterialError(
            "skopeo is required to verify Trustee publications"
        ) from error
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip() or error.stdout.strip()
        raise MaterialError(f"skopeo {' '.join(arguments)} failed: {detail}") from error
    return process.stdout.strip()


def skopeo_raw(reference: str) -> dict[str, Any]:
    try:
        value = json.loads(run_skopeo("inspect", "--raw", f"docker://{reference}"))
    except json.JSONDecodeError as error:
        raise MaterialError(
            f"registry returned invalid manifest JSON for {reference}"
        ) from error
    if not isinstance(value, dict):
        raise MaterialError(f"registry returned a non-object manifest for {reference}")
    return value


def oras_blob(reference: str) -> dict[str, Any]:
    try:
        process = subprocess.run(
            ["oras", "blob", "fetch", "--output", "-", reference],
            check=True,
            capture_output=True,
        )
    except FileNotFoundError as error:
        raise MaterialError("oras is required to verify Trustee provenance") from error
    except subprocess.CalledProcessError as error:
        detail = error.stderr.decode(errors="replace").strip()
        raise MaterialError(
            f"oras blob fetch failed for {reference}: {detail}"
        ) from error
    try:
        value = json.loads(process.stdout)
    except json.JSONDecodeError as error:
        raise MaterialError(
            f"registry returned invalid provenance for {reference}"
        ) from error
    if not isinstance(value, dict):
        raise MaterialError(f"registry returned non-object provenance for {reference}")
    return value


def sigstore_statement(repository: str, bundle_digest: str) -> dict[str, Any]:
    bundle = oras_blob(f"{repository}@{bundle_digest}")
    if bundle.get("mediaType") != "application/vnd.dev.sigstore.bundle.v0.3+json":
        raise MaterialError("Guest Components attestation is not a Sigstore bundle")
    envelope = bundle.get("dsseEnvelope")
    if not isinstance(envelope, dict) or envelope.get("payloadType") != (
        "application/vnd.in-toto+json"
    ):
        raise MaterialError("Guest Components attestation lacks an in-toto envelope")
    payload = envelope.get("payload")
    signatures = envelope.get("signatures")
    if (
        not isinstance(payload, str)
        or not isinstance(signatures, list)
        or not signatures
    ):
        raise MaterialError("Guest Components attestation envelope is incomplete")
    try:
        statement = json.loads(base64.b64decode(payload, validate=True))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MaterialError(
            "Guest Components attestation payload is invalid"
        ) from error
    if not isinstance(statement, dict):
        raise MaterialError("Guest Components attestation statement is not an object")
    return statement


def oras_manifest_digest(reference: str) -> str:
    try:
        process = subprocess.run(
            ["oras", "manifest", "fetch", "--descriptor", reference],
            check=True,
            capture_output=True,
            text=True,
        )
        descriptor = json.loads(process.stdout)
    except FileNotFoundError as error:
        raise MaterialError("oras is required to resolve Guest images") from error
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip() or error.stdout.strip()
        raise MaterialError(
            f"oras manifest fetch failed for {reference}: {detail}"
        ) from error
    except json.JSONDecodeError as error:
        raise MaterialError(
            f"registry returned an invalid descriptor for {reference}"
        ) from error
    digest = descriptor.get("digest") if isinstance(descriptor, dict) else None
    if not isinstance(digest, str) or not SHA256_DIGEST.fullmatch(digest):
        raise MaterialError(f"registry returned an invalid digest for {reference}")
    return digest


def verify_guest_components_image_component(
    lock: dict[str, Any], component: str
) -> None:
    image = lock["guest_components_images"][component]
    source = lock["sources"][image["source"]]
    repository, expected_digest = image["reference"].split("@", 1)
    tag_reference = f"{repository}:{image['published_tag']}"
    actual_digest = oras_manifest_digest(tag_reference)
    if actual_digest != expected_digest:
        raise MaterialError(
            f"Guest Components {component} image tag digest mismatch: "
            f"expected {expected_digest}, got {actual_digest}"
        )

    manifest = skopeo_raw(image["reference"])
    if component == "container":
        layers = manifest.get("layers")
        if (
            not isinstance(layers, list)
            or len(layers) != 1
            or not isinstance(layers[0], dict)
            or layers[0].get("mediaType")
            not in {
                "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "application/vnd.oci.image.layer.v1.tar",
                "application/vnd.oci.image.layer.v1.tar+gzip",
            }
            or not isinstance(layers[0].get("digest"), str)
            or not SHA256_DIGEST.fullmatch(layers[0]["digest"])
        ):
            raise MaterialError(
                "Guest Components container image payload contract drifted"
            )
        config_descriptor = manifest.get("config")
        if not isinstance(config_descriptor, dict) or not isinstance(
            config_descriptor.get("digest"), str
        ):
            raise MaterialError(
                "Guest Components container image manifest lacks its config"
            )
        config = oras_blob(f"{repository}@{config_descriptor['digest']}")
        if config.get("architecture") != "amd64" or config.get("os") != "linux":
            raise MaterialError(
                "Guest Components container image config is not linux/amd64"
            )
        config_section = config.get("config")
        labels = (
            config_section.get("Labels") if isinstance(config_section, dict) else None
        )
        if not isinstance(labels, dict):
            raise MaterialError(
                "Guest Components container image config lacks source labels"
            )
        if (
            labels.get("org.opencontainers.image.source") != source["repository"]
            or labels.get("org.opencontainers.image.revision") != source["revision"]
        ):
            raise MaterialError(
                "Guest Components container image source labels drifted"
            )
    else:
        layers = manifest.get("layers")
        expected_titles = {
            "kata-containers-coco-extension.img",
            "root_hash_coco-extension.txt",
        }
        if (
            manifest.get("artifactType")
            != "application/vnd.confidential-containers.coco-extension.disk"
            or not isinstance(layers, list)
            or len(layers) != 2
            or {
                layer.get("annotations", {}).get("org.opencontainers.image.title")
                for layer in layers
                if isinstance(layer, dict)
                and isinstance(layer.get("annotations"), dict)
            }
            != expected_titles
            or any(
                not isinstance(layer, dict)
                or layer.get("mediaType") != "application/vnd.oci.image.layer.v1.tar"
                or not isinstance(layer.get("digest"), str)
                or not SHA256_DIGEST.fullmatch(layer["digest"])
                for layer in layers
            )
        ):
            raise MaterialError("Guest Components disk image payload contract drifted")

    expected_subject = expected_digest.removeprefix("sha256:")
    expected_subject_name = repository
    statements: dict[str, dict[str, Any]] = {}
    for name, predicate in GUEST_IMAGE_ATTESTATION_PREDICATES[component].items():
        locked = image["attestations"][name]
        attestation = skopeo_raw(f"{repository}@{locked['manifest']}")
        subject = attestation.get("subject")
        annotations = attestation.get("annotations")
        if (
            attestation.get("artifactType")
            != "application/vnd.dev.sigstore.bundle.v0.3+json"
            or not isinstance(subject, dict)
            or subject.get("digest") != expected_digest
            or not isinstance(annotations, dict)
            or annotations.get("dev.sigstore.bundle.predicateType") != predicate
        ):
            raise MaterialError(
                f"Guest Components {component} image {name} attestation subject drifted"
            )
        layers = attestation.get("layers")
        if (
            not isinstance(layers, list)
            or len(layers) != 1
            or not isinstance(layers[0], dict)
            or layers[0].get("mediaType")
            != "application/vnd.dev.sigstore.bundle.v0.3+json"
            or layers[0].get("digest") != locked["bundle"]
        ):
            raise MaterialError(
                f"Guest Components {component} image {name} attestation bundle drifted"
            )
        statement = sigstore_statement(repository, locked["bundle"])
        if statement.get("predicateType") != predicate:
            raise MaterialError(
                f"Guest Components {component} image {name} predicate type drifted"
            )
        subjects = statement.get("subject")
        if not isinstance(subjects, list) or not any(
            isinstance(subject, dict)
            and subject.get("name") == expected_subject_name
            and isinstance(subject.get("digest"), dict)
            and subject["digest"].get("sha256") == expected_subject
            for subject in subjects
        ):
            raise MaterialError(
                f"Guest Components {component} image {name} does not bind its manifest"
            )
        statements[name] = statement

    try:
        provenance = statements["provenance"]["predicate"]
        build_definition = provenance["buildDefinition"]
        workflow = build_definition["externalParameters"]["workflow"]
        dependencies = build_definition["resolvedDependencies"]
        builder_id = provenance["runDetails"]["builder"]["id"]
        github = build_definition["internalParameters"]["github"]
    except (KeyError, TypeError) as error:
        raise MaterialError(
            f"Guest Components {component} image provenance lacks build identity"
        ) from error
    branch = "refs/heads/downstream/confidential-storage"
    expected_workflow = (
        f"{source['repository']}/.github/workflows/coco-extension-image.yml"
    )
    expected_dependency = f"git+{source['repository']}@{branch}"
    if (
        not isinstance(workflow, dict)
        or not isinstance(dependencies, list)
        or not isinstance(github, dict)
        or not isinstance(builder_id, str)
        or build_definition.get("buildType")
        != "https://actions.github.io/buildtypes/workflow/v1"
        or workflow.get("ref") != branch
        or workflow.get("repository") != source["repository"]
        or workflow.get("path") != ".github/workflows/coco-extension-image.yml"
        or builder_id != f"{expected_workflow}@{branch}"
        or github.get("event_name") != "push"
        or github.get("runner_environment") != "github-hosted"
        or not any(
            isinstance(dependency, dict)
            and dependency.get("uri") == expected_dependency
            and isinstance(dependency.get("digest"), dict)
            and dependency["digest"].get("gitCommit") == source["revision"]
            for dependency in dependencies
        )
    ):
        raise MaterialError(
            f"Guest Components {component} image provenance source identity drifted"
        )


def verify_guest_components_image_publication(lock: dict[str, Any]) -> None:
    for component in sorted(GUEST_IMAGE_NAMES):
        verify_guest_components_image_component(lock, component)


def verify_trustee_image_publication(lock: dict[str, Any], component: str) -> None:
    if component not in lock["trustee_images"]:
        raise MaterialError(f"unknown Trustee image component: {component}")
    image = lock["trustee_images"][component]
    repository, expected_digest = image["reference"].split("@", 1)
    tag_reference = f"{repository}:{image['published_tag']}"
    actual_digest = run_skopeo(
        "inspect", "--format", "{{.Digest}}", f"docker://{tag_reference}"
    )
    if actual_digest != expected_digest:
        raise MaterialError(
            f"Trustee image {component} tag digest mismatch: "
            f"expected {expected_digest}, got {actual_digest}"
        )

    index = skopeo_raw(image["reference"])
    manifests = index.get("manifests")
    if not isinstance(manifests, list):
        raise MaterialError(f"Trustee image {component} is not a manifest index")
    platform_matches = [
        manifest
        for manifest in manifests
        if isinstance(manifest, dict)
        and manifest.get("platform") == {"architecture": "amd64", "os": "linux"}
    ]
    if len(platform_matches) != 1:
        raise MaterialError(
            f"Trustee image {component} does not have one linux/amd64 manifest"
        )
    if platform_matches[0].get("digest") != image["platform_manifest"]:
        raise MaterialError(f"Trustee image {component} platform manifest drifted")

    if component not in COMBINED_TRUSTEE_IMAGE_NAMES:
        return
    attestation_manifest = image["attestations"]["manifest"]
    if not any(
        isinstance(manifest, dict)
        and manifest.get("digest") == attestation_manifest
        and manifest.get("annotations", {}).get("vnd.docker.reference.type")
        == "attestation-manifest"
        for manifest in manifests
    ):
        raise MaterialError(
            f"Trustee image {component} lacks its locked attestation manifest"
        )
    attestation = skopeo_raw(f"{repository}@{attestation_manifest}")
    layers = attestation.get("layers")
    if not isinstance(layers, list):
        raise MaterialError(
            f"Trustee image {component} attestation manifest lacks layers"
        )
    predicates = {
        layer.get("annotations", {}).get("in-toto.io/predicate-type"): layer.get(
            "digest"
        )
        for layer in layers
        if isinstance(layer, dict)
    }
    if predicates.get("https://spdx.dev/Document") != image["attestations"]["sbom"]:
        raise MaterialError(f"Trustee image {component} SBOM attestation drifted")
    if (
        predicates.get("https://slsa.dev/provenance/v1")
        != image["attestations"]["provenance"]
    ):
        raise MaterialError(f"Trustee image {component} provenance attestation drifted")

    source = lock["sources"][image["source"]]
    statement = oras_blob(f"{repository}@{image['attestations']['provenance']}")
    if statement.get("predicateType") != "https://slsa.dev/provenance/v1":
        raise MaterialError(
            f"Trustee image {component} provenance predicate is not SLSA v1"
        )
    subjects = statement.get("subject")
    expected_platform_digest = image["platform_manifest"].removeprefix("sha256:")
    if not isinstance(subjects, list) or not any(
        isinstance(subject, dict)
        and subject.get("digest", {}).get("sha256") == expected_platform_digest
        for subject in subjects
    ):
        raise MaterialError(
            f"Trustee image {component} provenance does not bind its platform manifest"
        )
    try:
        build_definition = statement["predicate"]["buildDefinition"]
        request = build_definition["externalParameters"]["request"]["root"]["request"][
            "args"
        ]
        internal = build_definition["internalParameters"]
    except (KeyError, TypeError) as error:
        raise MaterialError(
            f"Trustee image {component} provenance lacks build identity"
        ) from error
    expected_slug = source["repository"].removeprefix("https://github.com/")
    expected_workflow = (
        f"{expected_slug}/.github/workflows/downstream-kbs-grpc-as.yml@"
        "refs/heads/downstream/confidential-storage"
    )
    if (
        request.get("vcs:revision") != source["revision"]
        or request.get("vcs:source") != source["repository"]
        or request.get("vcs:localdir:dockerfile")
        != os.fspath(Path(image["dockerfile"]).parent)
        or internal.get("github_repository") != expected_slug
        or internal.get("github_workflow_sha") != source["revision"]
        or internal.get("github_workflow_ref") != expected_workflow
        or internal.get("github_ref") != "refs/heads/downstream/confidential-storage"
        or internal.get("github_event_name") != "push"
    ):
        raise MaterialError(
            f"Trustee image {component} provenance source identity drifted"
        )


def clone_exact(
    lock: dict[str, Any], source_name: str, repo: Path, output: Path
) -> None:
    if output.exists():
        raise MaterialError(f"output path already exists: {output}")
    source = lock["sources"][source_name]
    try:
        subprocess.run(
            [
                "git",
                "clone",
                "--quiet",
                "--no-local",
                os.fspath(repo),
                os.fspath(output),
            ],
            check=True,
        )
    except subprocess.CalledProcessError as error:
        raise MaterialError(f"failed to clone {source_name} source") from error
    run_git(output, "fetch", "--quiet", "--depth=1", "origin", source["revision"])
    run_git(output, "checkout", "--quiet", "--detach", "FETCH_HEAD")
    verify_git_source(lock, source_name, output)


def replace_once(path: Path, old: str, new: str, description: str) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise MaterialError(f"{description} anchor count is {count}, expected 1")
    before = hashlib.sha256(text.encode()).hexdigest()
    updated = text.replace(old, new)
    path.write_text(updated, encoding="utf-8")
    return {
        "path": os.fspath(path),
        "description": description,
        "before_sha256": before,
        "after_sha256": hashlib.sha256(updated.encode()).hexdigest(),
    }


def bind_yaml_asset_source(
    path: Path,
    asset: str,
    fields: dict[str, str],
    description: str,
) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    block_pattern = re.compile(
        rf"(?ms)^  {re.escape(asset)}:\n.*?(?=^  [A-Za-z0-9][A-Za-z0-9_.-]*:\n|\Z)"
    )
    blocks = list(block_pattern.finditer(text))
    if len(blocks) != 1:
        raise MaterialError(
            f"{description} component block count is {len(blocks)}, expected 1"
        )

    updated_block = blocks[0].group(0)
    counts: dict[str, int] = {}
    for field, value in fields.items():
        field_pattern = re.compile(
            rf'^    {re.escape(field)}: "[^"\n]+"$', re.MULTILINE
        )
        counts[field] = len(field_pattern.findall(updated_block))
        if counts[field] == 1:
            updated_block = field_pattern.sub(
                f'    {field}: "{value}"', updated_block, count=1
            )
    if any(count != 1 for count in counts.values()):
        detail = ", ".join(f"{field}={count}" for field, count in counts.items())
        raise MaterialError(
            f"{description} requires one of every bound field; found {detail}"
        )

    updated = text[: blocks[0].start()] + updated_block + text[blocks[0].end() :]
    before = hashlib.sha256(text.encode()).hexdigest()
    path.write_text(updated, encoding="utf-8")

    return {
        "path": os.fspath(path),
        "description": description,
        "before_sha256": before,
        "after_sha256": hashlib.sha256(updated.encode()).hexdigest(),
    }


def guest_component_bindings(
    source: dict[str, Any], artifact_variant: str, platform: str
) -> dict[str, str]:
    repository = source["repository"].rstrip("/")
    slug = urlparse(repository).path.strip("/").lower()
    registry_root = f"ghcr.io/{slug}"
    if platform != "linux/amd64":
        raise MaterialError(f"unsupported guest artifact platform: {platform!r}")
    return {
        "url": f"{repository}/",
        "version": source["revision"],
        "variant": artifact_variant,
        "container_image": f"{registry_root}/coco-extension",
        "extension_image": f"{registry_root}/coco-extension-disk",
    }


def prepared_receipt(
    lock_path: Path,
    lock: dict[str, Any],
    source_name: str,
    patches: list[dict[str, str]],
) -> dict[str, Any]:
    source = lock["sources"][source_name]
    receipt = {
        "schema": "codewire.confidential-storage.prepared-source/v1",
        "source_lock_sha256": lock_digest(lock_path),
        "source": source_name,
        "revision": source["revision"],
        "tree": source["tree"],
        "source_date_epoch": lock["source_date_epoch"],
        "patches": patches,
    }
    for patch in receipt["patches"]:
        patch["path"] = Path(patch["path"]).name
    return receipt


def prepare_kata(
    lock_path: Path, lock: dict[str, Any], repo: Path, output: Path
) -> Path:
    clone_exact(lock, "kata_containers", repo, output)
    contract = lock["kata_build_contract"]
    guest_variant = contract["guest_artifact_variant"]
    platform = lock["platforms"][0]
    verify_file_contract(output, contract["input_files"], "Kata build contract")
    guest = lock["sources"]["guest_components"]
    ca_bootstrap = lock["base_images"]["ubuntu_apt_ca_bootstrap"]
    packaging = output / "tools/packaging/kata-deploy/local-build/kata-deploy-binaries.sh"
    patches = [
        bind_yaml_asset_source(
            output / "versions.yaml",
            "coco-guest-components",
            guest_component_bindings(guest, guest_variant, platform),
            "bind the accepted guest-components source",
        ),
        replace_once(
            packaging,
            'echo "${image}:${version}-${variant}"',
            'echo "${image}:${version}-${variant}-$(get_coco_extension_oci_arch)"',
            "select the architecture-qualified guest-components container tag",
        ),
        replace_once(
            output / "tools/osbuilder/rootfs-builder/ubuntu/config.sh",
            'PACKAGES+=" cryptsetup-bin e2fsprogs"',
            'PACKAGES+=" cryptsetup-bin dmsetup e2fsprogs"',
            "add the device-mapper userspace tool to the measured guest rootfs",
        ),
        replace_once(
            output / "tools/osbuilder/rootfs-builder/ubuntu/config.sh",
            "http://archive.ubuntu.com/ubuntu",
            "https://archive.ubuntu.com/ubuntu",
            "use HTTPS for the x86 Ubuntu rootfs package source",
        ),
        replace_once(
            output / "tools/osbuilder/rootfs-builder/ubuntu/config.sh",
            "http://ports.ubuntu.com",
            "https://ports.ubuntu.com",
            "use HTTPS for the non-x86 Ubuntu rootfs package source",
        ),
        replace_once(
            output / "tools/osbuilder/rootfs-builder/ubuntu/Dockerfile.in",
            "ARG IMAGE_REGISTRY=docker.io\n"
            "FROM ${IMAGE_REGISTRY}/ubuntu:@OS_VERSION@\n"
            "@SET_PROXY@\n",
            "ARG IMAGE_REGISTRY=docker.io\n"
            f"FROM {ca_bootstrap} AS codewire-ubuntu-apt-ca\n"
            "FROM ${IMAGE_REGISTRY}/ubuntu:@OS_VERSION@\n"
            "@SET_PROXY@\n"
            "COPY --from=codewire-ubuntu-apt-ca "
            "/etc/ssl/certs/ca-certificates.crt "
            "/etc/ssl/certs/ca-certificates.crt\n",
            "seed Ubuntu APT trust from the locked CA bootstrap image",
        ),
        replace_once(
            output / "tools/osbuilder/rootfs-builder/ubuntu/Dockerfile.in",
            "# hadolint ignore=DL3009,SC2046\nRUN apt-get update && \\\n",
            "# hadolint ignore=DL3009,SC2046\n"
            "RUN ca_bundle=/etc/ssl/certs/ca-certificates.crt && \\\n"
            "    source_file=/etc/apt/sources.list.d/ubuntu.sources && \\\n"
            "    test -s \"${ca_bundle}\" && \\\n"
            "    test -f \"${source_file}\" && \\\n"
            "    sed -E -i \\\n"
            "        -e 's#http://(([[:alnum:]-]+\\.)*archive[.]ubuntu[.]com|security[.]ubuntu[.]com|ports[.]ubuntu[.]com)(/|[[:space:]]|$)#https://\\1\\3#g' \\\n"
            "        \"${source_file}\" && \\\n"
            "    ! grep -Eq 'http://(([[:alnum:]-]+\\.)*archive[.]ubuntu[.]com|security[.]ubuntu[.]com|ports[.]ubuntu[.]com)(/|[[:space:]]|$)' \"${source_file}\" && \\\n"
            "    grep -Eq 'https://(([[:alnum:]-]+\\.)*archive[.]ubuntu[.]com|security[.]ubuntu[.]com|ports[.]ubuntu[.]com)(/|[[:space:]]|$)' \"${source_file}\" && \\\n"
            "    apt-get -o Acquire::https::CaInfo=\"${ca_bundle}\" update && \\\n",
            "require HTTPS for the Ubuntu rootfs builder package sources",
        ),
        replace_once(
            output / "tools/osbuilder/rootfs-builder/ubuntu/Dockerfile.in",
            "    DEBIAN_FRONTEND=noninteractive \\\n"
            "    apt-get --no-install-recommends -y install \\\n",
            "    DEBIAN_FRONTEND=noninteractive \\\n"
            "    apt-get -o Acquire::https::CaInfo=\"${ca_bundle}\" "
            "--no-install-recommends -y install \\\n",
            "keep pinned CA trust through the initial Ubuntu package download",
        ),
    ]
    verify_prepared_kata(lock, output)
    receipt_path = output.parent / f"{output.name}-materials.json"
    write_json(
        receipt_path, prepared_receipt(lock_path, lock, "kata_containers", patches)
    )
    return receipt_path


def verify_prepared_kata(lock: dict[str, Any], repo: Path) -> None:
    guest = lock["sources"]["guest_components"]
    guest_variant = lock["kata_build_contract"]["guest_artifact_variant"]
    platform = lock["platforms"][0]
    versions = (repo / "versions.yaml").read_text(encoding="utf-8")
    for field, value in guest_component_bindings(
        guest, guest_variant, platform
    ).items():
        expected = f'    {field}: "{value}"'
        if versions.count(expected) != 1:
            raise MaterialError(
                "prepared Kata source does not bind the accepted "
                f"guest-components {field}"
            )
    config = (repo / "tools/osbuilder/rootfs-builder/ubuntu/config.sh").read_text(
        encoding="utf-8"
    )
    package_line = 'PACKAGES+=" cryptsetup-bin dmsetup e2fsprogs"'
    if config.count(package_line) != 1:
        raise MaterialError(
            "prepared Kata source lacks the fixed storage-tool package closure"
        )
    for package in lock["kata_build_contract"]["required_packages"]:
        if package not in package_line:
            raise MaterialError(
                f"prepared Kata source lacks required package {package}"
            )
    ubuntu_http = re.compile(
        r"http://((?:[a-z0-9-]+\.)*archive\.ubuntu\.com|"
        r"security\.ubuntu\.com|ports\.ubuntu\.com)(?:/|\s|$)"
    )
    if ubuntu_http.search(config):
        raise MaterialError(
            "prepared Kata rootfs configuration retains a cleartext Ubuntu source"
        )
    for expected in (
        "https://archive.ubuntu.com/ubuntu",
        "https://ports.ubuntu.com",
    ):
        if config.count(expected) != 1:
            raise MaterialError(
                f"prepared Kata rootfs configuration lacks exact source {expected}"
            )
    dockerfile = (
        repo / "tools/osbuilder/rootfs-builder/ubuntu/Dockerfile.in"
    ).read_text(encoding="utf-8")
    ca_reference = lock["base_images"]["ubuntu_apt_ca_bootstrap"]
    ca_stage = f"FROM {ca_reference} AS codewire-ubuntu-apt-ca"
    ca_copy = (
        "COPY --from=codewire-ubuntu-apt-ca "
        "/etc/ssl/certs/ca-certificates.crt "
        "/etc/ssl/certs/ca-certificates.crt"
    )
    if dockerfile.count(ca_stage) != 1:
        raise MaterialError(
            "prepared Kata rootfs builder lacks the pinned CA bootstrap stage"
        )
    certificate_imports = [
        line.strip()
        for line in dockerfile.splitlines()
        if line.lstrip().startswith(("COPY ", "ADD "))
        and "ca-certificates.crt" in line
    ]
    if certificate_imports != [ca_copy]:
        raise MaterialError(
            "prepared Kata rootfs builder lacks the exact pinned CA bundle import"
        )
    target_stage = "FROM ${IMAGE_REGISTRY}/ubuntu:@OS_VERSION@"
    source_gate = "source_file=/etc/apt/sources.list.d/ubuntu.sources"
    ca_assignment = "ca_bundle=/etc/ssl/certs/ca-certificates.crt"
    if (
        dockerfile.count(target_stage) != 1
        or dockerfile.count(ca_assignment) != 1
        or dockerfile.count('test -s "${ca_bundle}"') != 1
        or dockerfile.find(ca_stage) > dockerfile.find(target_stage)
        or dockerfile.find(target_stage) > dockerfile.find(ca_copy)
        or dockerfile.find(ca_copy) > dockerfile.find(ca_assignment)
        or dockerfile.find(ca_assignment) > dockerfile.find(source_gate)
    ):
        raise MaterialError(
            "prepared Kata rootfs builder does not establish CA trust before HTTPS"
        )
    ca_info = 'Acquire::https::CaInfo="${ca_bundle}"'
    if (
        dockerfile.count(ca_info) != 2
        or dockerfile.count(f"apt-get -o {ca_info} update") != 1
        or dockerfile.count(
            f"apt-get -o {ca_info} --no-install-recommends -y install"
        )
        != 1
    ):
        raise MaterialError(
            "prepared Kata rootfs builder does not use the pinned CA bundle "
            "for every bootstrap APT transaction"
        )
    tls_bypasses = (
        r"Acquire::https::Verify-(?:Peer|Host)[^\n]*(?:false|0)",
        r"(?:curl|wget)[^\n]*(?:--insecure|--no-check-certificate|(?:^|\s)-k(?:\s|$))",
        r"GIT_SSL_NO_VERIFY",
    )
    if any(re.search(pattern, dockerfile, re.IGNORECASE) for pattern in tls_bypasses):
        raise MaterialError(
            "prepared Kata rootfs builder contains a TLS verification bypass"
        )
    if ubuntu_http.search(dockerfile):
        raise MaterialError(
            "prepared Kata rootfs builder retains a cleartext Ubuntu source"
        )
    if dockerfile.count("source_file=/etc/apt/sources.list.d/ubuntu.sources") != 1:
        raise MaterialError(
            "prepared Kata rootfs builder lacks the fail-closed HTTPS source gate"
        )
    rootfs_builder = (repo / "tools/osbuilder/rootfs-builder/rootfs.sh").read_text(
        encoding="utf-8"
    )
    if rootfs_builder.count(': > "${dns_file}"') != 1:
        raise MaterialError(
            "prepared Kata source does not clear the guest resolver before image creation"
        )
    if 'touch "${dns_file}"' in rootfs_builder:
        raise MaterialError(
            "prepared Kata source retains the build-host guest resolver"
        )
    libseccomp_installer = repo / "ci/install_libseccomp.sh"
    execute_mask = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    if libseccomp_installer.stat().st_mode & execute_mask != execute_mask:
        raise MaterialError(
            "prepared Kata libseccomp installer must be executable by the builder UID"
        )
    packaging = (
        repo / "tools/packaging/kata-deploy/local-build/kata-deploy-binaries.sh"
    ).read_text(encoding="utf-8")
    container_reference = (
        'echo "${image}:${version}-${variant}-$(get_coco_extension_oci_arch)"'
    )
    if packaging.count(container_reference) != 1:
        raise MaterialError(
            "prepared Kata source does not select the architecture-qualified "
            "CoCo container tag"
        )
    if 'echo "${image}:${version}-${variant}"' in packaging:
        raise MaterialError(
            "prepared Kata source retains the unqualified CoCo container tag"
        )
    resolver_call = (
        'digest="$(resolve_oci_artifact_manifest "${disk_image_ref}" "${go_arch}")"'
    )
    if packaging.count(resolver_call) != 1:
        raise MaterialError(
            "prepared Kata source does not select the CoCo disk manifest explicitly"
        )
    if 'oras resolve --platform "linux/${go_arch}" "${disk_image_ref}"' in packaging:
        raise MaterialError(
            "prepared Kata source asks ORAS to infer a platform from an artifact config"
        )


def iso_time(epoch: int) -> str:
    return (
        dt.datetime.fromtimestamp(epoch, tz=dt.UTC).isoformat().replace("+00:00", "Z")
    )


def spdx_id(name: str) -> str:
    return "SPDXRef-" + re.sub(r"[^A-Za-z0-9.-]", "-", name)


def emit_materials(
    lock_path: Path,
    lock: dict[str, Any],
    output_dir: Path,
    artifacts: list[tuple[str, Path]],
    oci_artifacts: list[tuple[str, Path]] | None = None,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    source_lock_sha = lock_digest(lock_path)
    artifact_subjects = []
    for name, path in sorted(artifacts):
        if not path.is_file():
            raise MaterialError(f"artifact does not exist: {path}")
        artifact_subjects.append(
            {"name": name, "digest": {"sha256": digest_file(path, "sha256")}}
        )
    for component, path in sorted(oci_artifacts or []):
        artifact_subjects.append(verify_oci_image(lock_path, lock, component, path))

    packages = []
    relationships = []
    resolved = []
    for name, source in sorted(lock["sources"].items()):
        package_id = spdx_id(name)
        packages.append(
            {
                "SPDXID": package_id,
                "name": name.replace("_", "-"),
                "versionInfo": source["revision"],
                "downloadLocation": source["archive"]["url"],
                "filesAnalyzed": False,
                "checksums": [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": source["archive"]["sha256"],
                    },
                    {
                        "algorithm": "SHA512",
                        "checksumValue": source["archive"]["sha512"],
                    },
                ],
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:github/{urlparse(source['repository']).path.strip('/')}@{source['revision']}",
                    },
                    {
                        "referenceCategory": "OTHER",
                        "referenceType": "vcs",
                        "referenceLocator": f"git+{source['repository']}.git@{source['revision']}",
                    },
                ],
                "primaryPackagePurpose": "SOURCE",
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": package_id,
            }
        )
        resolved.append(
            {
                "uri": f"git+{source['repository']}.git@{source['revision']}",
                "digest": {
                    "gitCommit": source["revision"],
                    "gitTree": source["tree"],
                    "sha256": source["archive"]["sha256"],
                    "sha512": source["archive"]["sha512"],
                },
            }
        )

    builder = lock["builder"]
    builder_source = lock["sources"][builder["source"]]
    for relative, digest in sorted(builder["input_files"].items()):
        resolved.append(
            {
                "uri": f"https://codewire.sh/build/confidential-storage/inputs/{relative}",
                "digest": {"sha256": digest},
                "annotations": {
                    "component": "extension-builder",
                    "role": "build-recipe",
                    "baseSourceRepository": builder_source["repository"],
                    "baseSourceRevision": builder_source["revision"],
                },
            }
        )

    guest_source = lock["sources"]["guest_components"]
    for component, guest_image in sorted(lock["guest_components_images"].items()):
        guest_annotations = {
            "component": f"guest-components-{component}-image",
            "source": guest_image["source"],
            "sourceRepository": guest_source["repository"],
            "sourceRevision": guest_source["revision"],
            "sourceTree": guest_source["tree"],
            "publishedTag": guest_image["published_tag"],
            "platform": guest_image["platform"],
            "dockerfile": guest_image["dockerfile"],
        }
        for name, attestation in sorted(guest_image["attestations"].items()):
            for kind, digest in sorted(attestation.items()):
                guest_annotations[f"{name}{kind.title()}Attestation"] = digest
        resolved.append(
            {
                "uri": guest_image["reference"].split("@", 1)[0],
                "digest": {"sha256": guest_image["reference"].rsplit(":", 1)[1]},
                "annotations": guest_annotations,
            }
        )
        for relative, digest in sorted(guest_image["build_files"].items()):
            resolved.append(
                {
                    "uri": (
                        f"git+{guest_source['repository']}.git@"
                        f"{guest_source['revision']}#{relative}"
                    ),
                    "digest": {"sha256": digest},
                    "annotations": {
                        "component": f"guest-components-{component}-image",
                        "role": "build-recipe",
                    },
                }
            )

    for name, image in sorted(lock["trustee_images"].items()):
        source = lock["sources"][image["source"]]
        annotations = {
            "component": f"trustee-{name}",
            "source": image["source"],
            "sourceRepository": source["repository"],
            "sourceRevision": source["revision"],
            "sourceTree": source["tree"],
            "publishedTag": image["published_tag"],
            "platform": image["platform"],
            "platformManifest": image["platform_manifest"],
            "dockerfile": image["dockerfile"],
        }
        for attestation_name, digest in sorted(image["attestations"].items()):
            annotations[f"{attestation_name}Attestation"] = digest
        resolved.append(
            {
                "uri": image["reference"].split("@", 1)[0],
                "digest": {"sha256": image["reference"].rsplit(":", 1)[1]},
                "annotations": annotations,
            }
        )
        for relative, digest in sorted(image["build_files"].items()):
            resolved.append(
                {
                    "uri": (
                        f"git+{source['repository']}.git@"
                        f"{source['revision']}#{relative}"
                    ),
                    "digest": {"sha256": digest},
                    "annotations": {
                        "component": f"trustee-{name}",
                        "role": "build-recipe",
                    },
                }
            )
    for name, reference in sorted(lock["base_images"].items()):
        resolved.append(
            {
                "uri": reference.split("@", 1)[0],
                "digest": {"sha256": reference.rsplit(":", 1)[1]},
                "annotations": {"component": name.replace("_", "-")},
            }
        )

    spdx = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "codewire-confidential-storage-build-materials",
        "documentNamespace": f"https://codewire.sh/spdx/confidential-storage/{source_lock_sha}",
        "creationInfo": {
            "created": iso_time(lock["source_date_epoch"]),
            "creators": ["Tool: codewire-confidential-storage-materials-v1"],
        },
        "packages": packages,
        "relationships": relationships,
    }
    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": artifact_subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://codewire.sh/build/confidential-storage/v1",
                "externalParameters": {"platforms": lock["platforms"]},
                "internalParameters": {"sourceLockSha256": source_lock_sha},
                "resolvedDependencies": resolved,
            },
            "runDetails": {
                "builder": {
                    "id": (
                        "https://codewire.sh/builders/confidential-storage/"
                        f"sha256:{builder['input_tree_sha256']}"
                    )
                },
                "metadata": {
                    "invocationId": source_lock_sha,
                    "startedOn": iso_time(lock["source_date_epoch"]),
                    "finishedOn": iso_time(lock["source_date_epoch"]),
                },
            },
        },
    }
    write_json(output_dir / "materials.spdx.json", spdx)
    write_json(output_dir / "provenance.in-toto.json", provenance)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def verify_extension_manifest_version(data: bytes, expected_version: str) -> None:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise MaterialError("Kata extension manifest.yaml is not UTF-8") from error
    if lines.count("version: v1alpha1") != 1:
        raise MaterialError("Kata extension manifest schema is not v1alpha1")
    metadata = [index for index, line in enumerate(lines) if line == "metadata:"]
    if len(metadata) != 1:
        raise MaterialError("Kata extension manifest metadata block is invalid")
    metadata_start = metadata[0]
    metadata_end = next(
        (
            index
            for index in range(metadata_start + 1, len(lines))
            if lines[index] and not lines[index].startswith(" ")
        ),
        len(lines),
    )
    version_lines = [
        line
        for line in lines[metadata_start + 1 : metadata_end]
        if line.startswith("  version:")
    ]
    if version_lines != [f'  version: "{expected_version}"']:
        raise MaterialError(
            "Kata extension metadata version differs from the locked Kata version"
        )


def verify_talos_extension_tree(root: Path, expected_kata_version: str) -> None:
    if not root.is_dir():
        raise MaterialError(f"Talos extension tree does not exist: {root}")
    entries = {entry.name for entry in root.iterdir()}
    expected = {"manifest.yaml", "rootfs"}
    if entries != expected:
        unexpected = sorted(entries - expected)
        missing = sorted(expected - entries)
        detail = []
        if unexpected:
            detail.append(f"unexpected entries {unexpected}")
        if missing:
            detail.append(f"missing entries {missing}")
        raise MaterialError("invalid Talos extension tree: " + "; ".join(detail))

    manifest = root / "manifest.yaml"
    payload = root / "rootfs"
    if manifest.is_symlink() or not manifest.is_file():
        raise MaterialError("Talos extension manifest.yaml must be a regular file")
    verify_extension_manifest_version(manifest.read_bytes(), expected_kata_version)
    if payload.is_symlink() or not payload.is_dir():
        raise MaterialError("Talos extension rootfs must be a directory")


def verify_talos_runtime_elf(data: bytes) -> None:
    """Reject host runtime binaries that require a userspace ABI Talos lacks."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise MaterialError("Kata runtime shim is not an ELF executable")
    if data[4] != 2 or data[5] != 1:
        raise MaterialError("Kata runtime shim is not little-endian ELF64")
    if struct.unpack_from("<H", data, 18)[0] != 62:
        raise MaterialError("Kata runtime shim is not amd64 ELF")

    program_offset = struct.unpack_from("<Q", data, 32)[0]
    program_entry_size = struct.unpack_from("<H", data, 54)[0]
    program_count = struct.unpack_from("<H", data, 56)[0]
    if program_count and program_entry_size < 56:
        raise MaterialError("Kata runtime shim has invalid program headers")

    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        if offset + 56 > len(data):
            raise MaterialError("Kata runtime shim has truncated program headers")
        program_type, _, file_offset, _, _, file_size, _, _ = struct.unpack_from(
            "<IIQQQQQQ", data, offset
        )
        if program_type == 3:  # PT_INTERP
            raise MaterialError("Kata runtime shim contains PT_INTERP")
        if program_type != 2:  # PT_DYNAMIC
            continue
        if file_offset + file_size > len(data) or file_size % 16:
            raise MaterialError("Kata runtime shim has an invalid dynamic section")
        for dynamic_offset in range(file_offset, file_offset + file_size, 16):
            dynamic_tag, _ = struct.unpack_from("<QQ", data, dynamic_offset)
            if dynamic_tag == 1:  # DT_NEEDED
                raise MaterialError("Kata runtime shim contains DT_NEEDED")


def verify_kata_extension_layer(data: bytes, expected_kata_version: str) -> None:
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as layer:
            members = layer.getmembers()
    except (OSError, tarfile.TarError) as error:
        raise MaterialError(
            f"Kata extension layer is not a readable tar: {error}"
        ) from error

    normalized = []
    for member in members:
        name = member.name.rstrip("/")
        while name.startswith("./"):
            name = name[2:]
        if name.startswith("/") or ".." in name.split("/"):
            raise MaterialError(
                f"Kata extension layer contains unsafe path {member.name!r}"
            )
        normalized.append(name)
    if len(normalized) != len(set(normalized)):
        raise MaterialError("Kata extension layer contains duplicate paths")
    top_level = {name.split("/", 1)[0] for name in normalized if name}
    expected = {"manifest.yaml", "rootfs"}
    if top_level != expected:
        unexpected = sorted(top_level - expected)
        missing = sorted(expected - top_level)
        detail = []
        if unexpected:
            detail.append(f"unexpected entries {unexpected}")
        if missing:
            detail.append(f"missing entries {missing}")
        raise MaterialError("invalid Kata Talos extension layer: " + "; ".join(detail))

    by_name = {name: member for name, member in zip(normalized, members)}
    manifest = by_name.get("manifest.yaml")
    payload = by_name.get("rootfs")
    if manifest is None or not manifest.isfile():
        raise MaterialError("Kata extension manifest.yaml must be a regular file")
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as layer:
            stream = layer.extractfile(manifest)
            if stream is None:
                raise MaterialError("Kata extension manifest.yaml is unreadable")
            verify_extension_manifest_version(stream.read(), expected_kata_version)
    except (OSError, tarfile.TarError) as error:
        raise MaterialError(
            f"Kata extension manifest.yaml is unreadable: {error}"
        ) from error
    if payload is None or not payload.isdir():
        raise MaterialError("Kata extension rootfs must be a directory")

    required = {
        "rootfs/usr/local/bin/containerd-shim-kata-v2",
        "rootfs/usr/local/bin/containerd-shim-kata-qemu-snp-v2",
        "rootfs/usr/local/bin/kata-ctl",
        "rootfs/usr/local/bin/qemu-system-x86_64-snp-experimental",
        "rootfs/usr/local/libexec/qemu-system-x86_64-snp-experimental",
        "rootfs/usr/local/lib/kata-qemu-snp-experimental/libfdt.a",
        "rootfs/usr/local/share/kata-qemu-snp-experimental/qemu/bios.bin",
        "rootfs/usr/local/share/ovmf/AMDSEV.fd",
        "rootfs/usr/local/share/codewire/confidential-storage/materials.spdx.json",
        "rootfs/usr/local/share/codewire/confidential-storage/provenance.in-toto.json",
        "rootfs/usr/local/share/kata-containers/configuration.toml",
        "rootfs/usr/local/share/kata-containers/configuration-qemu-snp.toml",
        "rootfs/usr/local/share/kata-containers/kata-containers.img",
        "rootfs/usr/local/share/kata-containers/kata-containers-confidential.img",
        "rootfs/usr/local/share/kata-containers/kata-containers-coco-extension.img",
        "rootfs/usr/local/share/kata-containers/kata-containers-initrd-confidential.img",
        "rootfs/usr/local/share/kata-containers/root_hash_coco-extension.txt",
        "rootfs/usr/local/share/kata-containers/root_hash_confidential.txt",
    }
    missing_payload = sorted(required - set(normalized))
    if missing_payload:
        raise MaterialError(
            f"Kata extension layer lacks required payload {missing_payload}"
        )
    kernel_pattern = re.compile(
        r"rootfs/usr/local/share/kata-containers/"
        r"vmlinuz-[0-9]+(?:\.[0-9]+)*-[0-9]+"
    )
    versioned_kernels = [
        name
        for name, member in by_name.items()
        if kernel_pattern.fullmatch(name) and member.isfile()
    ]
    if len(versioned_kernels) != 1:
        raise MaterialError(
            "Kata extension must contain exactly one versioned kernel, "
            f"found {len(versioned_kernels)}"
        )
    kernel_link_name = "rootfs/usr/local/share/kata-containers/vmlinuz.container"
    kernel_link = by_name.get(kernel_link_name)
    if kernel_link is None or not kernel_link.issym():
        raise MaterialError("Kata extension vmlinuz.container must be a symbolic link")
    if kernel_link.linkname != Path(versioned_kernels[0]).name:
        raise MaterialError(
            "Kata extension vmlinuz.container does not select its exact versioned kernel"
        )
    for executable_name in (
        "rootfs/usr/local/bin/qemu-system-x86_64-snp-experimental",
        "rootfs/usr/local/libexec/qemu-system-x86_64-snp-experimental",
    ):
        executable = by_name[executable_name]
        if not executable.isfile() or not executable.mode & 0o111:
            raise MaterialError(
                f"Kata extension executable payload is invalid: {executable_name}"
            )
    for nonempty_name in (
        "rootfs/usr/local/share/ovmf/AMDSEV.fd",
        versioned_kernels[0],
    ):
        payload_member = by_name[nonempty_name]
        if not payload_member.isfile() or payload_member.size <= 0:
            raise MaterialError(f"Kata extension payload is empty: {nonempty_name}")
    shim = by_name["rootfs/usr/local/bin/containerd-shim-kata-v2"]
    if not shim.isfile() or not shim.mode & 0o111:
        raise MaterialError("Kata runtime shim is not an executable regular file")
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as layer:
            stream = layer.extractfile(shim)
            if stream is None:
                raise MaterialError("Kata runtime shim data is unavailable")
            verify_talos_runtime_elf(stream.read())
    except (OSError, tarfile.TarError) as error:
        raise MaterialError(f"Kata runtime shim is unreadable: {error}") from error

    config_name = "rootfs/usr/local/share/kata-containers/configuration.toml"
    config_member = by_name.get(config_name)
    if config_member is None or not config_member.isfile():
        raise MaterialError("Kata extension commodity runtime config is not a file")
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as layer:
            stream = layer.extractfile(config_member.name)
            if stream is None:
                raise MaterialError(
                    "Kata extension commodity runtime config is unreadable"
                )
            config = tomllib.loads(stream.read().decode("utf-8"))
    except (
        OSError,
        UnicodeDecodeError,
        tarfile.TarError,
        tomllib.TOMLDecodeError,
    ) as error:
        raise MaterialError(
            f"Kata extension commodity runtime config is not valid TOML: {error}"
        ) from error

    hypervisor = config.get("hypervisor")
    clh = hypervisor.get("clh") if isinstance(hypervisor, dict) else None
    if not isinstance(clh, dict):
        raise MaterialError("Kata extension commodity config lacks hypervisor.clh")
    if clh.get("path") != "/usr/local/bin/cloud-hypervisor" or clh.get(
        "valid_hypervisor_paths"
    ) != ["/usr/local/bin/cloud-hypervisor"]:
        raise MaterialError("Kata extension commodity config has invalid CLH paths")
    if clh.get("image") != "/usr/local/share/kata-containers/kata-containers.img":
        raise MaterialError(
            "Kata extension commodity config does not use its dedicated root image"
        )
    annotations = clh.get("enable_annotations")
    if not isinstance(annotations, list) or not {
        "cc_init_data",
        "kernel_params",
    }.issubset(annotations):
        raise MaterialError(
            "Kata extension commodity config lacks required annotations"
        )
    if any(value in {"*", ".*"} for value in annotations):
        raise MaterialError(
            "Kata extension commodity config contains a wildcard annotation"
        )

    agent = config.get("agent", {}).get("kata")
    if not isinstance(agent, dict):
        raise MaterialError("Kata extension commodity config lacks agent.kata")
    if "dial_timeout" in agent:
        raise MaterialError(
            "Kata extension commodity config contains a legacy Go-runtime dial timeout"
        )
    dial_timeout_ms = agent.get("dial_timeout_ms")
    if not isinstance(dial_timeout_ms, int) or dial_timeout_ms <= 0:
        raise MaterialError(
            "Kata extension commodity config lacks a runtime-rs dial timeout"
        )

    runtime = config.get("runtime")
    if (
        not isinstance(runtime, dict)
        or runtime.get("hypervisor_name") != "clh"
        or runtime.get("agent_name") != "kata"
    ):
        raise MaterialError(
            "Kata extension commodity config is not bound to runtime-rs CLH"
        )

    qemu_config_name = (
        "rootfs/usr/local/share/kata-containers/configuration-qemu-snp.toml"
    )
    qemu_config_member = by_name[qemu_config_name]
    if not qemu_config_member.isfile():
        raise MaterialError("Kata extension QEMU-SNP runtime config is not a file")
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as layer:
            stream = layer.extractfile(qemu_config_member.name)
            if stream is None:
                raise MaterialError(
                    "Kata extension QEMU-SNP runtime config is unreadable"
                )
            qemu_config = tomllib.loads(stream.read().decode("utf-8"))
    except (
        OSError,
        UnicodeDecodeError,
        tarfile.TarError,
        tomllib.TOMLDecodeError,
    ) as error:
        raise MaterialError(
            f"Kata extension QEMU-SNP runtime config is not valid TOML: {error}"
        ) from error

    qemu_hypervisors = qemu_config.get("hypervisor")
    qemu_hypervisor = (
        qemu_hypervisors.get("qemu") if isinstance(qemu_hypervisors, dict) else None
    )
    if not isinstance(qemu_hypervisor, dict):
        raise MaterialError("Kata extension QEMU-SNP config lacks hypervisor.qemu")
    if qemu_hypervisor.get("path") != (
        "/usr/local/bin/qemu-system-x86_64-snp-experimental"
    ) or qemu_hypervisor.get("valid_hypervisor_paths") != [
        "/usr/local/bin/qemu-system-x86_64-snp-experimental"
    ]:
        raise MaterialError("Kata extension QEMU-SNP config has invalid QEMU paths")
    if qemu_hypervisor.get("kernel") != (
        "/usr/local/share/kata-containers/vmlinuz.container"
    ):
        raise MaterialError("Kata extension QEMU-SNP config has an invalid kernel path")
    if qemu_hypervisor.get("firmware") != "/usr/local/share/ovmf/AMDSEV.fd":
        raise MaterialError("Kata extension QEMU-SNP config has an invalid firmware path")
    if qemu_hypervisor.get("image") != (
        "/usr/local/share/kata-containers/kata-containers-confidential.img"
    ):
        raise MaterialError(
            "Kata extension QEMU-SNP config does not use its dedicated confidential root image"
        )
    if qemu_hypervisor.get("confidential_guest") is not True:
        raise MaterialError("Kata extension QEMU-SNP config is not confidential")
    if qemu_hypervisor.get("shared_fs") != "none":
        raise MaterialError(
            "Kata extension QEMU-SNP config does not use shared_fs=none"
        )
    qemu_annotations = qemu_hypervisor.get("enable_annotations")
    required_qemu_annotations = {"cc_init_data", "kernel_params"}
    allowed_qemu_annotations = {
        "cc_init_data",
        "default_memory",
        "default_vcpus",
        "enable_iommu",
        "kernel_params",
        "kernel_verity_params",
    }
    if (
        not isinstance(qemu_annotations, list)
        or any(not isinstance(value, str) for value in qemu_annotations)
        or not required_qemu_annotations.issubset(qemu_annotations)
    ):
        raise MaterialError("Kata extension QEMU-SNP config lacks required annotations")
    if any(value not in allowed_qemu_annotations for value in qemu_annotations):
        raise MaterialError(
            "Kata extension QEMU-SNP config contains an unsafe annotation rule"
        )

    def read_verity_record(member_name: str, description: str) -> str:
        member = by_name[member_name]
        if not member.isfile():
            raise MaterialError(f"Kata extension {description} root hash is not a file")
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as layer:
                stream = layer.extractfile(member.name)
                if stream is None:
                    raise MaterialError(
                        f"Kata extension {description} root hash is unreadable"
                    )
                lines = [
                    line.strip()
                    for line in stream.read().decode("utf-8").splitlines()
                    if line.strip()
                ]
        except (OSError, UnicodeDecodeError, tarfile.TarError) as error:
            raise MaterialError(
                f"Kata extension {description} root hash is unreadable: {error}"
            ) from error
        if (
            len(lines) != 1
            or re.fullmatch(
                r"root_hash=[0-9a-f]{64},salt=[0-9a-f]{64},data_blocks=[1-9][0-9]*,"
                r"data_block_size=[1-9][0-9]*,hash_block_size=[1-9][0-9]*",
                lines[0],
            )
            is None
        ):
            raise MaterialError(
                f"Kata extension {description} root hash has an invalid format"
            )
        return lines[0]

    confidential_root_hash = read_verity_record(
        "rootfs/usr/local/share/kata-containers/root_hash_confidential.txt",
        "confidential",
    )
    if qemu_hypervisor.get("kernel_verity_params") != confidential_root_hash:
        raise MaterialError(
            "Kata extension confidential root verity params do not match its root hash"
        )
    coco_root_hash = read_verity_record(
        "rootfs/usr/local/share/kata-containers/root_hash_coco-extension.txt",
        "CoCo",
    )

    guest_images = qemu_hypervisor.get("guest_extension_images")
    if not isinstance(guest_images, list) or not guest_images:
        raise MaterialError(
            "Kata extension QEMU-SNP config has no guest extension images"
        )

    expected_coco_path = (
        "/usr/local/share/kata-containers/kata-containers-coco-extension.img"
    )
    found_coco = False
    for image in guest_images:
        if not isinstance(image, dict):
            raise MaterialError("Kata extension QEMU-SNP guest image is not an object")
        name = image.get("name")
        path = image.get("path")
        if not isinstance(name, str) or not name or not isinstance(path, str):
            raise MaterialError("Kata extension QEMU-SNP guest image is incomplete")
        if (
            not path.startswith("/usr/local/share/kata-containers/")
            or ".." in Path(path).parts
        ):
            raise MaterialError(
                f"Kata extension QEMU-SNP guest image has unsafe path {path!r}"
            )
        member_name = f"rootfs{path}"
        image_member = by_name.get(member_name)
        if image_member is None or not image_member.isfile() or image_member.size <= 0:
            raise MaterialError(
                f"Kata extension lacks non-empty configured guest image {path}"
            )
        if name == "coco" and path == expected_coco_path:
            if image.get("verity_params") != coco_root_hash:
                raise MaterialError(
                    "Kata extension CoCo verity params do not match its root hash"
                )
            found_coco = True
    if not found_coco:
        raise MaterialError(
            "Kata extension QEMU-SNP config lacks the canonical CoCo guest image"
        )


def verify_oci_image(
    lock_path: Path, lock: dict[str, Any], component: str, archive: Path
) -> dict[str, Any]:
    if component != "kata-extension":
        raise MaterialError(f"unsupported OCI component: {component}")
    if not archive.is_file():
        raise MaterialError(f"OCI archive does not exist: {archive}")

    digest_pattern = re.compile(r"^sha256:([0-9a-f]{64})$")
    with contextlib.ExitStack() as stack:
        try:
            oci = stack.enter_context(tarfile.open(archive, mode="r:*"))
        except (OSError, tarfile.TarError) as error:
            raise MaterialError(
                f"failed to open OCI archive {archive}: {error}"
            ) from error

        def read_json_member(name: str) -> dict[str, Any]:
            try:
                member = oci.getmember(name)
                stream = oci.extractfile(member)
            except (KeyError, tarfile.TarError) as error:
                raise MaterialError(f"OCI archive lacks {name}") from error
            if not member.isfile() or stream is None:
                raise MaterialError(f"OCI member is not a regular file: {name}")
            try:
                value = json.loads(
                    stream.read(), object_pairs_hook=reject_duplicate_keys
                )
            except (OSError, json.JSONDecodeError) as error:
                raise MaterialError(f"OCI member is not valid JSON: {name}") from error
            if not isinstance(value, dict):
                raise MaterialError(f"OCI JSON member is not an object: {name}")
            return value

        def read_json_blob(digest: str) -> dict[str, Any]:
            match = digest_pattern.fullmatch(digest)
            if match is None:
                raise MaterialError(f"OCI descriptor digest is invalid: {digest!r}")
            name = f"blobs/sha256/{match.group(1)}"
            try:
                member = oci.getmember(name)
                stream = oci.extractfile(member)
            except (KeyError, tarfile.TarError) as error:
                raise MaterialError(
                    f"OCI archive lacks descriptor blob {digest}"
                ) from error
            if not member.isfile() or stream is None:
                raise MaterialError(f"OCI descriptor blob is not a file: {digest}")
            data = stream.read()
            if hashlib.sha256(data).hexdigest() != match.group(1):
                raise MaterialError(f"OCI descriptor blob does not match {digest}")
            try:
                value = json.loads(data, object_pairs_hook=reject_duplicate_keys)
            except json.JSONDecodeError as error:
                raise MaterialError(
                    f"OCI descriptor blob is invalid JSON: {digest}"
                ) from error
            if not isinstance(value, dict):
                raise MaterialError(f"OCI descriptor blob is not an object: {digest}")
            return value

        index = read_json_member("index.json")
        manifests = index.get("manifests")
        if not isinstance(manifests, list):
            raise MaterialError("OCI index manifests must be a list")
        if (
            len(manifests) == 1
            and isinstance(manifests[0], dict)
            and manifests[0].get("mediaType")
            == "application/vnd.oci.image.index.v1+json"
            and isinstance(manifests[0].get("digest"), str)
        ):
            nested_index = read_json_blob(manifests[0]["digest"])
            manifests = nested_index.get("manifests")
            if not isinstance(manifests, list):
                raise MaterialError("nested OCI index manifests must be a list")
        image_descriptors = [
            descriptor
            for descriptor in manifests
            if isinstance(descriptor, dict)
            and descriptor.get("platform") == {"architecture": "amd64", "os": "linux"}
        ]
        if len(image_descriptors) != 1:
            raise MaterialError("OCI index must contain exactly one linux/amd64 image")
        image_descriptor = image_descriptors[0]
        image_digest = image_descriptor.get("digest")
        if not isinstance(image_digest, str):
            raise MaterialError("OCI image descriptor lacks a digest")

        attestation_descriptors = [
            descriptor
            for descriptor in manifests
            if isinstance(descriptor, dict)
            and descriptor.get("annotations", {}).get("vnd.docker.reference.type")
            == "attestation-manifest"
            and descriptor.get("annotations", {}).get("vnd.docker.reference.digest")
            == image_digest
        ]
        if len(attestation_descriptors) != 1:
            raise MaterialError(
                "OCI index must contain one matching attestation manifest"
            )

        image_manifest = read_json_blob(image_digest)
        image_layers = image_manifest.get("layers")
        if not isinstance(image_layers, list):
            raise MaterialError("OCI image manifest layers must be a list")
        if component == "kata-extension":
            if len(image_layers) != 1 or not isinstance(image_layers[0], dict):
                raise MaterialError(
                    "Kata extension must contain exactly one image layer"
                )
            layer_digest = image_layers[0].get("digest")
            if image_layers[0].get("mediaType") not in {
                "application/vnd.oci.image.layer.v1.tar",
                "application/vnd.oci.image.layer.v1.tar+gzip",
            }:
                raise MaterialError("Kata extension layer media type is unsupported")
            match = (
                digest_pattern.fullmatch(layer_digest)
                if isinstance(layer_digest, str)
                else None
            )
            if match is None:
                raise MaterialError("Kata extension layer digest is invalid")
            layer_name = f"blobs/sha256/{match.group(1)}"
            try:
                layer_member = oci.getmember(layer_name)
                layer_stream = oci.extractfile(layer_member)
            except (KeyError, tarfile.TarError) as error:
                raise MaterialError(
                    f"OCI archive lacks Kata extension layer {layer_digest}"
                ) from error
            if not layer_member.isfile() or layer_stream is None:
                raise MaterialError("Kata extension layer blob is not a file")
            layer_data = layer_stream.read()
            if hashlib.sha256(layer_data).hexdigest() != match.group(1):
                raise MaterialError(
                    f"Kata extension layer blob does not match {layer_digest}"
                )
            verify_kata_extension_layer(
                layer_data, lock["kata_build_contract"]["kata_version"]
            )

        config_descriptor = image_manifest.get("config")
        if not isinstance(config_descriptor, dict) or not isinstance(
            config_descriptor.get("digest"), str
        ):
            raise MaterialError("OCI image manifest lacks its config digest")
        config = read_json_blob(config_descriptor["digest"])
        if config.get("architecture") != "amd64" or config.get("os") != "linux":
            raise MaterialError("OCI config platform is not linux/amd64")
        if config.get("created") != iso_time(lock["source_date_epoch"]):
            raise MaterialError(
                "OCI config creation time differs from the source epoch"
            )
        labels = config.get("config", {}).get("Labels", {})
        if not isinstance(labels, dict):
            raise MaterialError("OCI config labels must be an object")
        if labels.get("io.codewire.source-lock.sha256") != lock_digest(lock_path):
            raise MaterialError("OCI image label does not bind the exact source lock")

        expected_labels = {
            "io.codewire.source.extensions": lock["sources"]["extensions"]["revision"],
            "io.codewire.source.guest-components": lock["sources"]["guest_components"][
                "revision"
            ],
            "io.codewire.source.kata-containers": lock["sources"]["kata_containers"][
                "revision"
            ],
        }
        for name, expected in expected_labels.items():
            if labels.get(name) != expected:
                raise MaterialError(f"OCI image label {name} differs from the lock")

        attestation_digest = attestation_descriptors[0].get("digest")
        if not isinstance(attestation_digest, str):
            raise MaterialError("OCI attestation descriptor lacks a digest")
        attestation_manifest = read_json_blob(attestation_digest)
        layers = attestation_manifest.get("layers")
        if not isinstance(layers, list):
            raise MaterialError("OCI attestation manifest layers must be a list")
        predicate_types = {
            layer.get("annotations", {}).get("in-toto.io/predicate-type")
            for layer in layers
            if isinstance(layer, dict)
        }
        if "https://spdx.dev/Document" not in predicate_types:
            raise MaterialError("OCI image lacks embedded SPDX/SLSA attestations")
        supported_slsa = {
            "https://slsa.dev/provenance/v0.2",
            "https://slsa.dev/provenance/v1",
        }
        if len(predicate_types & supported_slsa) != 1:
            raise MaterialError("OCI image lacks embedded SPDX/SLSA attestations")

    return {
        "name": f"{component}@linux-amd64",
        "digest": {"sha256": image_digest.removeprefix("sha256:")},
    }


def parse_artifact(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("artifact must use NAME=PATH")
    name, path = value.split("=", 1)
    if not name or not path or not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise argparse.ArgumentTypeError("artifact must use a safe non-empty NAME=PATH")
    return name, Path(path)


def parse_oci_artifact(value: str) -> tuple[str, Path]:
    component, path = parse_artifact(value)
    if component != "kata-extension":
        raise argparse.ArgumentTypeError(
            "OCI artifact component must be kata-extension"
        )
    return component, path


def default_lock_path() -> Path:
    return Path(__file__).with_name("sources.lock.json")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=default_lock_path())
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("validate")
    archives = subparsers.add_parser("verify-archives")
    archives.add_argument("--cache", required=True, type=Path)

    git_source = subparsers.add_parser("verify-git")
    git_source.add_argument("--source", required=True, choices=sorted(SOURCE_NAMES))
    git_source.add_argument("--repo", required=True, type=Path)

    verify_builder_parser = subparsers.add_parser("verify-builder")
    verify_builder_parser.add_argument("--repo", required=True, type=Path)

    guest_image_source = subparsers.add_parser("verify-guest-image-source")
    guest_image_source.add_argument("--repo", required=True, type=Path)

    subparsers.add_parser("verify-guest-image-publication")

    trustee_image_source = subparsers.add_parser("verify-trustee-image-source")
    trustee_image_source.add_argument(
        "--component", required=True, choices=sorted(TRUSTEE_IMAGE_NAMES)
    )
    trustee_image_source.add_argument("--repo", required=True, type=Path)

    trustee_image_publication = subparsers.add_parser(
        "verify-trustee-image-publication"
    )
    trustee_image_publication.add_argument(
        "--component", required=True, choices=sorted(TRUSTEE_IMAGE_NAMES)
    )

    prepare_kata_parser = subparsers.add_parser("prepare-kata")
    prepare_kata_parser.add_argument("--repo", required=True, type=Path)
    prepare_kata_parser.add_argument("--output", required=True, type=Path)

    verify_kata_parser = subparsers.add_parser("verify-prepared-kata")
    verify_kata_parser.add_argument("--repo", required=True, type=Path)

    verify_extension_parser = subparsers.add_parser("verify-extension-tree")
    verify_extension_parser.add_argument("--root", required=True, type=Path)

    emit = subparsers.add_parser("emit")
    emit.add_argument("--output-dir", required=True, type=Path)
    emit.add_argument("--artifact", action="append", default=[], type=parse_artifact)
    emit.add_argument(
        "--oci-artifact", action="append", default=[], type=parse_oci_artifact
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        lock = load_lock(args.lock)
        if args.command == "validate":
            print(f"source lock valid: sha256:{lock_digest(args.lock)}")
        elif args.command == "verify-archives":
            verify_archives(lock, args.cache)
            print("all locked archives match SHA-256 and SHA-512")
        elif args.command == "verify-git":
            verify_git_source(lock, args.source, args.repo)
            print(f"{args.source} Git commit and tree match the source lock")
        elif args.command == "verify-builder":
            verify_builder(lock, args.repo)
            print("extension builder checkout matches the locked input tree")
        elif args.command == "verify-guest-image-source":
            verify_guest_components_image_source(lock, args.repo)
            print("Guest Components image source and recipes match the lock")
        elif args.command == "verify-guest-image-publication":
            verify_guest_components_image_publication(lock)
            print("Guest Components image publication matches the lock")
        elif args.command == "verify-trustee-image-source":
            verify_trustee_image_source(lock, args.component, args.repo)
            print(f"Trustee image {args.component} source and recipes match the lock")
        elif args.command == "verify-trustee-image-publication":
            verify_trustee_image_publication(lock, args.component)
            print(f"Trustee image {args.component} publication matches the lock")
        elif args.command == "prepare-kata":
            receipt = prepare_kata(args.lock, lock, args.repo, args.output)
            print(receipt)
        elif args.command == "verify-prepared-kata":
            verify_prepared_kata(lock, args.repo)
            print("prepared Kata source matches the confidential-storage contract")
        elif args.command == "verify-extension-tree":
            verify_talos_extension_tree(
                args.root, lock["kata_build_contract"]["kata_version"]
            )
            print("Talos extension tree contains only manifest.yaml and rootfs")
        elif args.command == "emit":
            emit_materials(
                args.lock,
                lock,
                args.output_dir,
                args.artifact,
                args.oci_artifact,
            )
            print(args.output_dir)
        else:
            raise AssertionError(args.command)
    except MaterialError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
