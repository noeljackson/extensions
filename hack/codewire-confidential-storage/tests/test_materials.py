from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1]
LOCK_PATH = SCRIPT_DIR / "sources.lock.json"
SPEC = importlib.util.spec_from_file_location(
    "codewire_materials", SCRIPT_DIR / "materials.py"
)
assert SPEC and SPEC.loader
materials = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(materials)


class MaterialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = materials.load_lock(LOCK_PATH)

    def test_canonical_lock_binds_accepted_sources(self) -> None:
        expected = {
            "guest_components": (
                "4f851920f568067ba6ad7542f986f69775f28ea3",
                "8468a2595cf7522e769ed33f62fb27e266137108",
            ),
            "kata_containers": (
                "387f4ebbfb787b8324fca1a00a2ff197fd2ff0a7",
                "fdb02e8f060bc7d75d57234069d6313dd01b48f1",
            ),
            "longhorn_manager": (
                "1cfcebd4ac6f7fc8c9b29158e126c36872eb4950",
                "bb48a40cc04bdffee4f68927ad2134ca71e36b4d",
            ),
            "trustee": (
                "258ea4acb7b9bd865fce5c63a539f2120dba8298",
                "1d4368226a1d95ff4f30d6e9c5496595632e29cf",
            ),
        }
        for name, (revision, tree) in expected.items():
            with self.subTest(name=name):
                self.assertEqual(self.lock["sources"][name]["revision"], revision)
                self.assertEqual(self.lock["sources"][name]["tree"], tree)
        self.assertEqual(self.lock["platforms"], ["linux/amd64"])
        self.assertEqual(
            self.lock["talos_extensions"]["installer_profile"],
            "servernet-confidential-storage-only",
        )

    def test_branch_archive_and_short_revision_are_rejected(self) -> None:
        changed = copy.deepcopy(self.lock)
        source = changed["sources"]["kata_containers"]
        source["revision"] = "main"
        source["archive"]["url"] = (
            "https://codeload.github.com/noeljackson/kata-containers/tar.gz/main"
        )
        with self.assertRaisesRegex(materials.MaterialError, "full Git hash"):
            materials.validate_lock(changed)

    def test_archive_url_must_resolve_exact_revision(self) -> None:
        changed = copy.deepcopy(self.lock)
        changed["sources"]["guest_components"]["archive"]["url"] = (
            "https://codeload.github.com/noeljackson/guest-components/tar.gz/main"
        )
        with self.assertRaisesRegex(materials.MaterialError, "bind the exact revision"):
            materials.validate_lock(changed)

    def test_digest_only_images_and_servernet_profile_are_required(self) -> None:
        changed = copy.deepcopy(self.lock)
        changed["trustee_images"]["kbs"] = (
            "ghcr.io/confidential-containers/staged-images/kbs-grpc-as:latest"
        )
        with self.assertRaisesRegex(materials.MaterialError, "digest reference"):
            materials.validate_lock(changed)
        changed = copy.deepcopy(self.lock)
        changed["talos_extensions"]["installer_profile"] = "all-nodes"
        with self.assertRaisesRegex(materials.MaterialError, "Server.net"):
            materials.validate_lock(changed)
        changed = copy.deepcopy(self.lock)
        changed["base_images"]["longhorn_manager_runtime"] = (
            "docker.io/longhornio/longhorn-manager:v1.12.0"
        )
        with self.assertRaisesRegex(materials.MaterialError, "exact Docker Hub digest"):
            materials.validate_lock(changed)
        changed = copy.deepcopy(self.lock)
        changed["base_images"]["buildkit_sbom_scanner"] = (
            "docker.io/docker/buildkit-syft-scanner:stable-1"
        )
        with self.assertRaisesRegex(materials.MaterialError, "exact Docker Hub digest"):
            materials.validate_lock(changed)

    def test_secret_named_fields_are_rejected(self) -> None:
        changed = copy.deepcopy(self.lock)
        changed["sources"]["trustee"]["admin_token"] = "redacted"
        with self.assertRaisesRegex(materials.MaterialError, "secret-bearing"):
            materials.validate_lock(changed)

    def test_archive_verification_fails_closed_on_mutation(self) -> None:
        changed = copy.deepcopy(self.lock)
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            for name, source in changed["sources"].items():
                data = f"archive:{name}".encode()
                path = cache / f"{name}.tar.gz"
                path.write_bytes(data)
                source["archive"]["sha256"] = hashlib.sha256(data).hexdigest()
                source["archive"]["sha512"] = hashlib.sha512(data).hexdigest()
            materials.verify_archives(changed, cache)
            (cache / "kata_containers.tar.gz").write_bytes(b"mutated")
            with self.assertRaisesRegex(materials.MaterialError, "mismatch"):
                materials.verify_archives(changed, cache)

    def test_prepare_kata_binds_structural_source_and_adds_tool_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            self._init_repo(source)
            files = {
                "versions.yaml": (
                    "  coco-guest-components:\n"
                    '    description: "test"\n'
                    '    url: "https://github.com/confidential-containers/guest-components/"\n'
                    '    version: "d4dce5ce62294cfa741225f7e5b4527ea276f326"\n'
                    '    container_image: "ghcr.io/confidential-containers/guest-components/coco-extension"\n'
                    '    extension_image: "ghcr.io/confidential-containers/guest-components/coco-extension-disk"\n'
                ),
                "tools/osbuilder/rootfs-builder/ubuntu/config.sh": (
                    'PACKAGES="base"\nPACKAGES+=" cryptsetup-bin e2fsprogs"\n'
                ),
                "tools/packaging/kata-deploy/local-build/Makefile": "all:\n\ttrue\n",
                "tools/packaging/kata-deploy/local-build/kata-deploy-binaries.sh": "test\n",
                "tools/packaging/static-build/coco-guest-components/Dockerfile": "FROM scratch\n",
                "tools/packaging/static-build/coco-guest-components/build-static-coco-guest-components.sh": "test\n",
                "tools/packaging/static-build/coco-guest-components/build.sh": "test\n",
            }
            for relative, content in files.items():
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            self._commit_all(source)

            lock = copy.deepcopy(self.lock)
            self._bind_test_repo(lock, "kata_containers", source)
            lock["kata_build_contract"]["input_files"] = {
                relative: hashlib.sha256(content.encode()).hexdigest()
                for relative, content in files.items()
            }
            lock_path = root / "lock.json"
            self._write_lock(lock_path, lock)
            output = root / "prepared"
            materials.prepare_kata(lock_path, lock, source, output)
            materials.verify_prepared_kata(lock, output)
            self.assertIn(
                self.lock["sources"]["guest_components"]["revision"],
                (output / "versions.yaml").read_text(encoding="utf-8"),
            )
            self.assertIn(
                f'url: "{self.lock["sources"]["guest_components"]["repository"]}/"',
                (output / "versions.yaml").read_text(encoding="utf-8"),
            )
            self.assertIn(
                'container_image: "ghcr.io/noeljackson/guest-components/coco-extension"',
                (output / "versions.yaml").read_text(encoding="utf-8"),
            )
            self.assertIn(
                'extension_image: "ghcr.io/noeljackson/guest-components/coco-extension-disk"',
                (output / "versions.yaml").read_text(encoding="utf-8"),
            )
            self.assertIn(
                'PACKAGES+=" cryptsetup-bin dmsetup e2fsprogs"',
                (output / "tools/osbuilder/rootfs-builder/ubuntu/config.sh").read_text(
                    encoding="utf-8"
                ),
            )

    def test_prepare_kata_refuses_unknown_base_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "config.sh"
            path.write_text("PACKAGES=unexpected\n", encoding="utf-8")
            with self.assertRaisesRegex(materials.MaterialError, "anchor count is 0"):
                materials.replace_once(
                    path,
                    'PACKAGES+=" cryptsetup-bin e2fsprogs"',
                    'PACKAGES+=" cryptsetup-bin dmsetup e2fsprogs"',
                    "guest tool closure",
                )

    def test_yaml_asset_binding_rejects_ambiguous_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "versions.yaml"
            path.write_text(
                "  coco-guest-components:\n"
                '    url: "https://example.invalid/one"\n'
                '    version: "0000000000000000000000000000000000000000"\n'
                '    version: "1111111111111111111111111111111111111111"\n'
                '    container_image: "ghcr.io/example/guest-components/coco-extension"\n'
                '    extension_image: "ghcr.io/example/guest-components/coco-extension-disk"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                materials.MaterialError, "found url=1, version=2"
            ):
                materials.bind_yaml_asset_source(
                    path,
                    "coco-guest-components",
                    {
                        "url": "https://github.com/example/guest-components/",
                        "version": "2" * 40,
                        "container_image": "ghcr.io/example/guest-components/coco-extension",
                        "extension_image": "ghcr.io/example/guest-components/coco-extension-disk",
                    },
                    "test binding",
                )

    def test_prepare_longhorn_keeps_accepted_git_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            self._init_repo(source)
            files = {
                "scripts/version": (
                    "#!/bin/bash\n"
                    'GITCOMMIT="$(git rev-parse HEAD)"\n'
                    "BUILDDATE=$(date -u --rfc-3339=seconds)\n"
                ),
                "package/Dockerfile": (
                    "FROM scratch AS builder\n"
                    "ARG LONGHORN_TWO_MINOR_UPGRADE_DISTROS\n"
                    "ENV LONGHORN_TWO_MINOR_UPGRADE_DISTROS=${LONGHORN_TWO_MINOR_UPGRADE_DISTROS}\n"
                    "FROM registry.suse.com/bci/bci-base:15.7@sha256:c2b0859ac7ceaf22c2d75a05c931dd7976dc0ac75e1a3a5f3c14380fcc3fb029 AS release\n"
                    "RUN zypper -n ref && \\\n"
                    "    zypper update -y\n\n"
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
                    "    && zypper clean --all\n\n"
                ),
                "package/nsmounter": "#!/bin/sh\nexit 0\n",
            }
            for relative, content in files.items():
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            self._commit_all(source)

            lock = copy.deepcopy(self.lock)
            self._bind_test_repo(lock, "longhorn_manager", source)
            lock["longhorn_build_contract"]["input_files"] = {
                relative: hashlib.sha256(content.encode()).hexdigest()
                for relative, content in files.items()
            }
            lock_path = root / "lock.json"
            self._write_lock(lock_path, lock)
            output = root / "prepared"
            materials.prepare_longhorn(lock_path, lock, source, output)
            materials.verify_prepared_longhorn(lock, output)
            self.assertIn("SOURCE_DATE_EPOCH", (output / "scripts/version").read_text())
            prepared_dockerfile = (output / "package/Dockerfile").read_text()
            self.assertIn(
                lock["base_images"]["longhorn_manager_runtime"], prepared_dockerfile
            )
            self.assertNotIn("zypper", prepared_dockerfile)
            self.assertEqual(
                self._git(output, "rev-parse", "HEAD"),
                lock["sources"]["longhorn_manager"]["revision"],
            )
            self.assertEqual(
                self._git(output, "status", "--porcelain", "--untracked-files=no"), ""
            )

    def test_material_receipts_are_deterministic_and_non_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second"
            artifact = root / "image.oci.tar"
            artifact.write_bytes(b"deterministic artifact")
            materials.emit_materials(
                LOCK_PATH, self.lock, first, [("image.oci.tar", artifact)]
            )
            materials.emit_materials(
                LOCK_PATH, self.lock, second, [("image.oci.tar", artifact)]
            )
            for name in ("materials.spdx.json", "provenance.in-toto.json"):
                self.assertEqual(
                    (first / name).read_bytes(), (second / name).read_bytes()
                )
                text = (first / name).read_text(encoding="utf-8")
                self.assertNotRegex(text.lower(), r"password|private_key|admin_token")
                self.assertIn("387f4ebbfb787b8324fca1a00a2ff197fd2ff0a7", text)

    def test_oci_subject_uses_platform_manifest_and_checks_attestations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive, image_digest = self._write_oci_archive(root / "valid")
            subject = materials.verify_oci_image(
                LOCK_PATH, self.lock, "longhorn-manager", archive
            )
            self.assertEqual(
                subject,
                {
                    "name": "longhorn-manager@linux-amd64",
                    "digest": {"sha256": image_digest},
                },
            )

            invalid, _ = self._write_oci_archive(
                root / "invalid", source_lock_label="0" * 64
            )
            with self.assertRaisesRegex(materials.MaterialError, "exact source lock"):
                materials.verify_oci_image(
                    LOCK_PATH, self.lock, "longhorn-manager", invalid
                )

            invalid_source, _ = self._write_oci_archive(
                root / "invalid-source",
                source_label="https://sources.suse.com/not-codewire",
            )
            with self.assertRaisesRegex(
                materials.MaterialError, "org.opencontainers.image.source"
            ):
                materials.verify_oci_image(
                    LOCK_PATH, self.lock, "longhorn-manager", invalid_source
                )

            invalid_attestation, _ = self._write_oci_archive(
                root / "invalid-attestation",
                slsa_predicate="https://example.invalid/provenance",
            )
            with self.assertRaisesRegex(materials.MaterialError, "SPDX/SLSA"):
                materials.verify_oci_image(
                    LOCK_PATH,
                    self.lock,
                    "longhorn-manager",
                    invalid_attestation,
                )

    def test_kata_extension_layout_rejects_runtime_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid, image_digest = self._write_oci_archive(
                root / "valid", component="kata-extension"
            )
            subject = materials.verify_oci_image(
                LOCK_PATH, self.lock, "kata-extension", valid
            )
            self.assertEqual(
                subject,
                {
                    "name": "kata-extension@linux-amd64",
                    "digest": {"sha256": image_digest},
                },
            )

            invalid_entries = self._kata_extension_entries()
            invalid_entries[".dockerenv"] = b""
            invalid, _ = self._write_oci_archive(
                root / "invalid",
                component="kata-extension",
                layer_entries=invalid_entries,
            )
            with self.assertRaisesRegex(
                materials.MaterialError, "unexpected entries.*dockerenv"
            ):
                materials.verify_oci_image(
                    LOCK_PATH, self.lock, "kata-extension", invalid
                )

            missing_helper_entries = self._kata_extension_entries()
            del missing_helper_entries["rootfs/usr/local/bin/kata-ctl"]
            missing_helper, _ = self._write_oci_archive(
                root / "missing-helper",
                component="kata-extension",
                layer_entries=missing_helper_entries,
            )
            with self.assertRaisesRegex(
                materials.MaterialError, "lacks required payload.*kata-ctl"
            ):
                materials.verify_oci_image(
                    LOCK_PATH, self.lock, "kata-extension", missing_helper
                )

    def test_talos_extension_tree_has_exact_top_level_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "manifest.yaml").write_text("version: v1alpha1\n")
            (root / "rootfs").mkdir()
            materials.verify_talos_extension_tree(root)
            (root / ".dockerenv").touch()
            with self.assertRaisesRegex(
                materials.MaterialError, "unexpected entries.*dockerenv"
            ):
                materials.verify_talos_extension_tree(root)

    def test_build_recipe_has_no_publication_path(self) -> None:
        recipe = (SCRIPT_DIR / "build.sh").read_text(encoding="utf-8")
        self.assertNotIn(" --push", recipe)
        self.assertNotIn("docker login", recipe)
        self.assertNotIn("GITHUB_TOKEN", recipe)
        self.assertNotIn("--sbom=true", recipe)
        self.assertIn(".base_images.buildkit_sbom_scanner", recipe)
        self.assertEqual(recipe.count("type=sbom,generator=$(lock_value"), 2)
        self.assertIn(
            '--label "org.opencontainers.image.source=$(lock_value '
            "'.sources.longhorn_manager.repository')\"",
            recipe,
        )
        self.assertIn('mode:"no-push"', recipe)
        self.assertNotIn("docker export", recipe)
        self.assertNotIn("docker create", recipe)
        self.assertIn("base-rootfs.Dockerfile", recipe)
        self.assertIn('"$work_dir/context/extension/rootfs"', recipe)
        self.assertIn(
            'built_tarball="$local_build/kata-static.tar.zst"',
            recipe,
        )
        self.assertIn("\\( -type f -o -type l \\)", recipe)
        self.assertIn("rootfs-image-confidential-tarball", recipe)
        self.assertIn("rootfs-initrd-confidential-tarball", recipe)
        self.assertIn("qemu-snp-experimental-tarball", recipe)
        self.assertIn("sfdisk --json", recipe)
        self.assertIn(".bootable == true", recipe)
        self.assertNotIn("rootfs-image-mariner-tarball", recipe)
        self.assertNotIn("qemu-tdx-experimental-tarball", recipe)

    def _init_repo(self, path: Path) -> None:
        path.mkdir()
        subprocess.run(["git", "init", "--quiet", path], check=True)
        self._git(path, "config", "user.name", "Codewire Test")
        self._git(path, "config", "user.email", "test@codewire.invalid")

    def _commit_all(self, path: Path) -> None:
        self._git(path, "add", ".")
        self._git(path, "commit", "--quiet", "-m", "test source")

    def _git(self, path: Path, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", path, *args],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()

    def _bind_test_repo(self, lock: dict, source_name: str, repo: Path) -> None:
        source = lock["sources"][source_name]
        source["revision"] = self._git(repo, "rev-parse", "HEAD")
        source["tree"] = self._git(repo, "rev-parse", "HEAD^{tree}")
        source["archive"]["url"] = (
            f"https://codeload.github.com/{source['repository'].removeprefix('https://github.com/')}/"
            f"tar.gz/{source['revision']}"
        )

    def _write_lock(self, path: Path, lock: dict) -> None:
        path.write_text(
            json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def _write_oci_archive(
        self,
        root: Path,
        source_lock_label: str | None = None,
        source_label: str | None = None,
        component: str = "longhorn-manager",
        layer_entries: dict[str, bytes | None] | None = None,
        slsa_predicate: str = "https://slsa.dev/provenance/v1",
    ) -> tuple[Path, str]:
        layout = root / "layout"
        blobs = layout / "blobs" / "sha256"
        blobs.mkdir(parents=True)

        def write_blob_bytes(data: bytes) -> tuple[str, int]:
            digest = hashlib.sha256(data).hexdigest()
            (blobs / digest).write_bytes(data)
            return digest, len(data)

        def write_blob(value: dict) -> tuple[str, int]:
            data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            return write_blob_bytes(data)

        if component == "kata-extension":
            layer_buffer = io.BytesIO()
            with tarfile.open(fileobj=layer_buffer, mode="w") as layer:
                for name, data in sorted(
                    (layer_entries or self._kata_extension_entries()).items()
                ):
                    member = tarfile.TarInfo(name)
                    if data is None:
                        member.type = tarfile.DIRTYPE
                        member.mode = 0o755
                        layer.addfile(member)
                    else:
                        member.size = len(data)
                        member.mode = 0o644
                        layer.addfile(member, io.BytesIO(data))
            layer_digest, layer_size = write_blob_bytes(layer_buffer.getvalue())
            image_layers = [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": f"sha256:{layer_digest}",
                    "size": layer_size,
                }
            ]
            labels = {
                "io.codewire.source-lock.sha256": source_lock_label
                or materials.lock_digest(LOCK_PATH),
                "io.codewire.source.extensions": self.lock["sources"]["extensions"][
                    "revision"
                ],
                "io.codewire.source.guest-components": self.lock["sources"][
                    "guest_components"
                ]["revision"],
                "io.codewire.source.kata-containers": self.lock["sources"][
                    "kata_containers"
                ]["revision"],
            }
        else:
            image_layers = []
            labels = {
                "io.codewire.source-lock.sha256": source_lock_label
                or materials.lock_digest(LOCK_PATH),
                "org.opencontainers.image.revision": self.lock["sources"][
                    "longhorn_manager"
                ]["revision"],
                "org.opencontainers.image.source": source_label
                or self.lock["sources"]["longhorn_manager"]["repository"],
            }

        config_digest, config_size = write_blob(
            {
                "architecture": "amd64",
                "os": "linux",
                "created": materials.iso_time(self.lock["source_date_epoch"]),
                "config": {"Labels": labels},
            }
        )
        image_digest, image_size = write_blob(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": f"sha256:{config_digest}",
                    "size": config_size,
                },
                "layers": image_layers,
            }
        )
        attestation_digest, attestation_size = write_blob(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": f"sha256:{'0' * 64}",
                    "size": 0,
                },
                "layers": [
                    {
                        "mediaType": "application/vnd.in-toto+json",
                        "digest": f"sha256:{'1' * 64}",
                        "size": 0,
                        "annotations": {
                            "in-toto.io/predicate-type": "https://spdx.dev/Document"
                        },
                    },
                    {
                        "mediaType": "application/vnd.in-toto+json",
                        "digest": f"sha256:{'2' * 64}",
                        "size": 0,
                        "annotations": {"in-toto.io/predicate-type": slsa_predicate},
                    },
                ],
            }
        )
        nested_digest, nested_size = write_blob(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": f"sha256:{image_digest}",
                        "size": image_size,
                        "platform": {"architecture": "amd64", "os": "linux"},
                    },
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": f"sha256:{attestation_digest}",
                        "size": attestation_size,
                        "platform": {"architecture": "unknown", "os": "unknown"},
                        "annotations": {
                            "vnd.docker.reference.digest": f"sha256:{image_digest}",
                            "vnd.docker.reference.type": "attestation-manifest",
                        },
                    },
                ],
            }
        )
        (layout / "index.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 2,
                    "manifests": [
                        {
                            "mediaType": "application/vnd.oci.image.index.v1+json",
                            "digest": f"sha256:{nested_digest}",
                            "size": nested_size,
                        }
                    ],
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        archive = root / "image.oci.tar"
        with tarfile.open(archive, "w") as output:
            for source in sorted(layout.rglob("*")):
                output.add(source, arcname=source.relative_to(layout), recursive=False)
        return archive, image_digest

    def _kata_extension_entries(self) -> dict[str, bytes | None]:
        return {
            "manifest.yaml": b"version: v1alpha1\n",
            "rootfs": None,
            "rootfs/usr/local/bin/containerd-shim-kata-qemu-snp-v2": b"shim",
            "rootfs/usr/local/bin/containerd-shim-kata-v2": b"shim",
            "rootfs/usr/local/bin/kata-ctl": b"kata-ctl",
            "rootfs/usr/local/share/codewire/confidential-storage/materials.spdx.json": b"{}\n",
            "rootfs/usr/local/share/codewire/confidential-storage/provenance.in-toto.json": b"{}\n",
            "rootfs/usr/local/share/kata-containers/configuration-qemu-snp.toml": b'shared_fs = "none"\n',
            "rootfs/usr/local/share/kata-containers/kata-containers-confidential.img": b"image",
            "rootfs/usr/local/share/kata-containers/kata-containers-initrd-confidential.img": b"initrd",
            "rootfs/usr/local/share/kata-containers/root_hash_confidential.txt": b"hash\n",
        }


if __name__ == "__main__":
    unittest.main()
