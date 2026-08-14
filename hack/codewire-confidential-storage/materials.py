#!/usr/bin/env python3
"""Validate and materialize Codewire confidential-storage build inputs."""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

SCHEMA = "codewire.confidential-storage.sources/v1"
SOURCE_NAMES = {
    "extensions",
    "guest_components",
    "kata_containers",
    "longhorn_manager",
    "trustee",
}
TRUSTEE_IMAGE_NAMES = {"attestation_service", "kbs", "rvps"}
TALOS_EXTENSION_NAMES = ["iscsi-tools", "util-linux-tools"]
FULL_HASH = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SHA512 = re.compile(r"^[0-9a-f]{128}$")
OCI_DIGEST = re.compile(r"^(?:docker\.io|ghcr\.io)/[a-z0-9./_-]+@sha256:[0-9a-f]{64}$")
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


def validate_lock(lock: dict[str, Any]) -> None:
    validate_no_secret_fields(lock)
    require_keys(
        lock,
        {
            "schema",
            "platforms",
            "source_date_epoch",
            "sources",
            "base_images",
            "trustee_images",
            "talos_extensions",
            "kata_build_contract",
            "longhorn_build_contract",
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

    base_images = lock["base_images"]
    if not isinstance(base_images, dict):
        raise MaterialError("base_images must be an object")
    require_keys(
        base_images,
        {
            "buildkit_sbom_scanner",
            "kata_talos_extension",
            "longhorn_manager_runtime",
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
        r"docker\.io/longhornio/longhorn-manager@sha256:[0-9a-f]{64}",
        base_images["longhorn_manager_runtime"],
    ):
        raise MaterialError(
            "Longhorn runtime base image must be its exact Docker Hub digest"
        )

    trustee_images = lock["trustee_images"]
    if (
        not isinstance(trustee_images, dict)
        or set(trustee_images) != TRUSTEE_IMAGE_NAMES
    ):
        raise MaterialError(
            f"trustee_images must be exactly {sorted(TRUSTEE_IMAGE_NAMES)}"
        )
    for name, reference in trustee_images.items():
        if not isinstance(reference, str) or not OCI_DIGEST.fullmatch(reference):
            raise MaterialError(f"Trustee image {name} must be a GHCR digest reference")

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
        {"input_files", "required_packages", "required_guest_tools"},
        "kata_build_contract",
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

    longhorn = lock["longhorn_build_contract"]
    if not isinstance(longhorn, dict):
        raise MaterialError("longhorn_build_contract must be an object")
    require_keys(longhorn, {"input_files"}, "longhorn_build_contract")
    validate_input_files(longhorn["input_files"], "longhorn_build_contract")


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


def guest_component_bindings(source: dict[str, Any]) -> dict[str, str]:
    repository = source["repository"].rstrip("/")
    slug = urlparse(repository).path.strip("/").lower()
    registry_root = f"ghcr.io/{slug}"

    return {
        "url": f"{repository}/",
        "version": source["revision"],
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
    verify_file_contract(output, contract["input_files"], "Kata build contract")
    guest = lock["sources"]["guest_components"]
    patches = [
        bind_yaml_asset_source(
            output / "versions.yaml",
            "coco-guest-components",
            guest_component_bindings(guest),
            "bind the accepted guest-components source",
        ),
        replace_once(
            output / "tools/osbuilder/rootfs-builder/ubuntu/config.sh",
            'PACKAGES+=" cryptsetup-bin e2fsprogs"',
            'PACKAGES+=" cryptsetup-bin dmsetup e2fsprogs"',
            "add the device-mapper userspace tool to the measured guest rootfs",
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
    versions = (repo / "versions.yaml").read_text(encoding="utf-8")
    for field, value in guest_component_bindings(guest).items():
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


def prepare_longhorn(
    lock_path: Path, lock: dict[str, Any], repo: Path, output: Path
) -> Path:
    clone_exact(lock, "longhorn_manager", repo, output)
    contract = lock["longhorn_build_contract"]
    verify_file_contract(output, contract["input_files"], "Longhorn build contract")
    dockerfile = output / "package/Dockerfile"
    runtime_base = lock["base_images"]["longhorn_manager_runtime"]
    patches = [
        replace_once(
            output / "scripts/version",
            "BUILDDATE=$(date -u --rfc-3339=seconds)",
            ': "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH is required}"\n'
            'BUILDDATE=$(date -u --date="@${SOURCE_DATE_EPOCH}" --rfc-3339=seconds)',
            "derive the embedded build date from SOURCE_DATE_EPOCH",
        ),
        replace_once(
            dockerfile,
            "ARG LONGHORN_TWO_MINOR_UPGRADE_DISTROS\nENV LONGHORN_TWO_MINOR_UPGRADE_DISTROS=${LONGHORN_TWO_MINOR_UPGRADE_DISTROS}",
            "ARG LONGHORN_TWO_MINOR_UPGRADE_DISTROS\n"
            "ARG SOURCE_DATE_EPOCH\n\n"
            "ENV LONGHORN_TWO_MINOR_UPGRADE_DISTROS=${LONGHORN_TWO_MINOR_UPGRADE_DISTROS}\n"
            "ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}",
            "pass SOURCE_DATE_EPOCH into the deterministic builder",
        ),
        replace_once(
            dockerfile,
            "FROM registry.suse.com/bci/bci-base:15.7@sha256:c2b0859ac7ceaf22c2d75a05c931dd7976dc0ac75e1a3a5f3c14380fcc3fb029 AS release",
            f"FROM {runtime_base} AS release",
            "bind the immutable official v1.12.0 runtime package closure",
        ),
        replace_once(
            dockerfile,
            "RUN zypper -n ref && \\\n    zypper update -y\n\n",
            "",
            "remove the mutable runtime package-update step",
        ),
        replace_once(
            dockerfile,
            "RUN zypper -n install \\\n"
            "    iputils \\\n"
            "    iproute2 \\\n"
            "    nfs-client \\\n"
            "    cifs-utils \\\n"
            "    bind-utils \\\n"
            "    e2fsprogs \\\n"
            "    xfsprogs \\\n"
            "    zip \\\n"
            "    unzip \\\n"
            "    kmod \\\n"
            "    smartmontools \\\n"
            "    && zypper clean --all\n\n",
            "",
            "remove the mutable runtime package-install step",
        ),
    ]
    verify_prepared_longhorn(lock, output)
    run_git(
        output,
        "update-index",
        "--assume-unchanged",
        "scripts/version",
        "package/Dockerfile",
    )
    if run_git(output, "status", "--porcelain", "--untracked-files=no"):
        raise MaterialError(
            "prepared Longhorn source has unexpected tracked modifications"
        )
    receipt_path = output.parent / f"{output.name}-materials.json"
    write_json(
        receipt_path, prepared_receipt(lock_path, lock, "longhorn_manager", patches)
    )
    return receipt_path


def verify_prepared_longhorn(lock: dict[str, Any], repo: Path) -> None:
    version = (repo / "scripts/version").read_text(encoding="utf-8")
    if version.count("SOURCE_DATE_EPOCH is required") != 1:
        raise MaterialError("prepared Longhorn source lacks the fixed build epoch")
    dockerfile = (repo / "package/Dockerfile").read_text(encoding="utf-8")
    runtime_base = lock["base_images"]["longhorn_manager_runtime"]
    if dockerfile.count(f"FROM {runtime_base} AS release") != 1:
        raise MaterialError("prepared Longhorn source lacks the locked runtime base")
    if "zypper" in dockerfile:
        raise MaterialError(
            "prepared Longhorn release stage still uses mutable packages"
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

    for name, reference in sorted(lock["trustee_images"].items()):
        resolved.append(
            {
                "uri": reference.split("@", 1)[0],
                "digest": {"sha256": reference.rsplit(":", 1)[1]},
                "annotations": {"component": f"trustee-{name}"},
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
                    "id": "https://github.com/noeljackson/extensions/tree/"
                    + lock["sources"]["extensions"]["revision"]
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


def verify_talos_extension_tree(root: Path) -> None:
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
    if payload.is_symlink() or not payload.is_dir():
        raise MaterialError("Talos extension rootfs must be a directory")


def verify_kata_extension_layer(data: bytes) -> None:
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
    if payload is None or not payload.isdir():
        raise MaterialError("Kata extension rootfs must be a directory")

    required = {
        "rootfs/usr/local/bin/containerd-shim-kata-v2",
        "rootfs/usr/local/bin/containerd-shim-kata-qemu-snp-v2",
        "rootfs/usr/local/bin/kata-ctl",
        "rootfs/usr/local/share/codewire/confidential-storage/materials.spdx.json",
        "rootfs/usr/local/share/codewire/confidential-storage/provenance.in-toto.json",
        "rootfs/usr/local/share/kata-containers/configuration-qemu-snp.toml",
        "rootfs/usr/local/share/kata-containers/kata-containers-confidential.img",
        "rootfs/usr/local/share/kata-containers/kata-containers-initrd-confidential.img",
        "rootfs/usr/local/share/kata-containers/root_hash_confidential.txt",
    }
    missing_payload = sorted(required - set(normalized))
    if missing_payload:
        raise MaterialError(
            f"Kata extension layer lacks required payload {missing_payload}"
        )


def verify_oci_image(
    lock_path: Path, lock: dict[str, Any], component: str, archive: Path
) -> dict[str, Any]:
    if component not in {"kata-extension", "longhorn-manager"}:
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
            verify_kata_extension_layer(layer_data)

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

        if component == "longhorn-manager":
            expected_labels = {
                "org.opencontainers.image.revision": lock["sources"][
                    "longhorn_manager"
                ]["revision"],
                "org.opencontainers.image.source": lock["sources"]["longhorn_manager"][
                    "repository"
                ],
            }
        else:
            expected_labels = {
                "io.codewire.source.extensions": lock["sources"]["extensions"][
                    "revision"
                ],
                "io.codewire.source.guest-components": lock["sources"][
                    "guest_components"
                ]["revision"],
                "io.codewire.source.kata-containers": lock["sources"][
                    "kata_containers"
                ]["revision"],
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
    if component not in {"kata-extension", "longhorn-manager"}:
        raise argparse.ArgumentTypeError(
            "OCI artifact component must be kata-extension or longhorn-manager"
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

    prepare_kata_parser = subparsers.add_parser("prepare-kata")
    prepare_kata_parser.add_argument("--repo", required=True, type=Path)
    prepare_kata_parser.add_argument("--output", required=True, type=Path)

    verify_kata_parser = subparsers.add_parser("verify-prepared-kata")
    verify_kata_parser.add_argument("--repo", required=True, type=Path)

    verify_extension_parser = subparsers.add_parser("verify-extension-tree")
    verify_extension_parser.add_argument("--root", required=True, type=Path)

    prepare_longhorn_parser = subparsers.add_parser("prepare-longhorn")
    prepare_longhorn_parser.add_argument("--repo", required=True, type=Path)
    prepare_longhorn_parser.add_argument("--output", required=True, type=Path)

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
        elif args.command == "prepare-kata":
            receipt = prepare_kata(args.lock, lock, args.repo, args.output)
            print(receipt)
        elif args.command == "verify-prepared-kata":
            verify_prepared_kata(lock, args.repo)
            print("prepared Kata source matches the confidential-storage contract")
        elif args.command == "verify-extension-tree":
            verify_talos_extension_tree(args.root)
            print("Talos extension tree contains only manifest.yaml and rootfs")
        elif args.command == "prepare-longhorn":
            receipt = prepare_longhorn(args.lock, lock, args.repo, args.output)
            print(receipt)
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
