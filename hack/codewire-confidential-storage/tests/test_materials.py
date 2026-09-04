from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import io
import json
import struct
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
            "extensions": (
                "0a825ae60fef6838a98edb7bca661d285e0426d9",
                "3753e0b7b3a338587ee89b330abe486afad4b41b",
            ),
            "guest_components": (
                "a793932e8fc98a42f673d38dbb1981edacb61db6",
                "1c37325fcb48e6f1b04f94c0fa50f9f8afd91d60",
            ),
            "kata_containers": (
                "d40d8c27572803e787a061a01a2228b35b7246d3",
                "e7417e18fb7181d2296455363647e33cbf153cab",
            ),
            "trustee": (
                "bc76377e5a694d03a122ecf3f8272a0889dd9371",
                "621a0b2fb38f6e64526f4f1e5ba553718fb94039",
            ),
            "trustee_attestation_service": (
                "6bb2f94d534274489ce41e7023fdd0e559d9f80c",
                "df909a1c4fde58d0318ca699edaa2d6b9d7bcc6c",
            ),
        }
        for name, (revision, tree) in expected.items():
            with self.subTest(name=name):
                self.assertEqual(self.lock["sources"][name]["revision"], revision)
                self.assertEqual(self.lock["sources"][name]["tree"], tree)
        self.assertEqual(self.lock["platforms"], ["linux/amd64"])
        self.assertEqual(
            self.lock["schema"], "codewire.confidential-storage.sources/v2"
        )
        self.assertEqual(
            self.lock["kata_build_contract"]["guest_artifact_variant"],
            "ubuntu26.04",
        )
        self.assertEqual(
            self.lock["kata_build_contract"]["kata_version"],
            "4.1.0",
        )
        self.assertEqual(
            self.lock["kata_build_contract"]["qemu_snp_overhead_memory_mib"],
            2048,
        )
        self.assertEqual(
            self.lock["kata_build_contract"]["persistent_volume_max_gib"], 50
        )
        self.assertEqual(
            self.lock["kata_build_contract"]["cdh_api_timeout_seconds"], 1200
        )
        self.assertEqual(
            self.lock["kata_build_contract"]["create_container_timeout_seconds"],
            1350,
        )
        self.assertEqual(
            self.lock["talos_extensions"]["installer_profile"],
            "servernet-confidential-storage-only",
        )
        self.assertEqual(
            self.lock["trustee_images"]["kbs"],
            self.lock["trustee_images"]["rvps"],
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

    def test_legacy_lock_and_incomplete_builder_contract_are_rejected(self) -> None:
        changed = copy.deepcopy(self.lock)
        changed["schema"] = "codewire.confidential-storage.sources/v1"
        with self.assertRaisesRegex(materials.MaterialError, "unsupported schema"):
            materials.validate_lock(changed)

        changed = copy.deepcopy(self.lock)
        changed["builder"]["input_files"].pop(
            "hack/codewire-confidential-storage/materials.py"
        )
        with self.assertRaisesRegex(materials.MaterialError, "must be exactly"):
            materials.validate_lock(changed)

        changed = copy.deepcopy(self.lock)
        changed["builder"]["source"] = "guest_components"
        with self.assertRaisesRegex(materials.MaterialError, "extensions source"):
            materials.validate_lock(changed)

        changed = copy.deepcopy(self.lock)
        changed["builder"]["input_tree_sha256"] = "0" * 64
        with self.assertRaisesRegex(materials.MaterialError, "tree digest"):
            materials.validate_lock(changed)

        changed = copy.deepcopy(self.lock)
        changed["base_images"]["ubuntu_apt_ca_bootstrap"] = (
            "docker.io/library/golang:1.26.7-alpine3.23"
        )
        with self.assertRaisesRegex(materials.MaterialError, "exact Docker Hub digest"):
            materials.validate_lock(changed)

    def test_archive_url_must_resolve_exact_revision(self) -> None:
        changed = copy.deepcopy(self.lock)
        changed["sources"]["guest_components"]["archive"]["url"] = (
            "https://codeload.github.com/noeljackson/guest-components/tar.gz/main"
        )
        with self.assertRaisesRegex(materials.MaterialError, "bind the exact revision"):
            materials.validate_lock(changed)

    def test_guest_artifact_variant_is_fixed(self) -> None:
        changed = copy.deepcopy(self.lock)
        changed["kata_build_contract"]["guest_artifact_variant"] = "latest"
        with self.assertRaisesRegex(materials.MaterialError, "Ubuntu 26.04"):
            materials.validate_lock(changed)

    def test_qemu_snp_guest_overhead_is_locked(self) -> None:
        changed = copy.deepcopy(self.lock)
        changed["kata_build_contract"]["qemu_snp_overhead_memory_mib"] = 128
        with self.assertRaisesRegex(materials.MaterialError, "2048 MiB"):
            materials.validate_lock(changed)

    def test_persistent_volume_deadlines_are_a_fixed_nested_contract(self) -> None:
        changed = copy.deepcopy(self.lock)
        changed["kata_build_contract"]["persistent_volume_max_gib"] = 51
        with self.assertRaisesRegex(materials.MaterialError, "bounded to 50 GiB"):
            materials.validate_lock(changed)

        changed = copy.deepcopy(self.lock)
        changed["kata_build_contract"]["cdh_api_timeout_seconds"] = 50
        with self.assertRaisesRegex(materials.MaterialError, "50 GiB initialization"):
            materials.validate_lock(changed)

        changed = copy.deepcopy(self.lock)
        changed["kata_build_contract"]["create_container_timeout_seconds"] = 1200
        with self.assertRaisesRegex(materials.MaterialError, "headroom above"):
            materials.validate_lock(changed)

    def test_provenanced_images_and_servernet_profile_are_required(self) -> None:
        changed = copy.deepcopy(self.lock)
        changed["guest_components_images"]["container"]["reference"] = (
            "ghcr.io/noeljackson/guest-components/coco-extension:latest"
        )
        with self.assertRaisesRegex(materials.MaterialError, "immutable digest"):
            materials.validate_lock(changed)
        changed = copy.deepcopy(self.lock)
        changed["guest_components_images"]["container"]["published_tag"] = "latest"
        with self.assertRaisesRegex(materials.MaterialError, "source revision"):
            materials.validate_lock(changed)
        changed = copy.deepcopy(self.lock)
        changed["guest_components_images"]["container"]["source"] = "trustee"
        with self.assertRaisesRegex(materials.MaterialError, "guest_components source"):
            materials.validate_lock(changed)
        changed = copy.deepcopy(self.lock)
        changed["guest_components_images"]["container"]["attestations"].pop("sbom")
        with self.assertRaisesRegex(
            materials.MaterialError, "attestations keys differ"
        ):
            materials.validate_lock(changed)
        changed = copy.deepcopy(self.lock)
        changed["guest_components_images"]["container"]["attestations"]["provenance"][
            "manifest"
        ] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(materials.MaterialError, "digest is invalid"):
            materials.validate_lock(changed)

        changed = copy.deepcopy(self.lock)
        changed["trustee_images"]["kbs"]["reference"] = (
            "ghcr.io/confidential-containers/staged-images/kbs-grpc-as:latest"
        )
        with self.assertRaisesRegex(materials.MaterialError, "immutable digest"):
            materials.validate_lock(changed)
        changed = copy.deepcopy(self.lock)
        changed["trustee_images"]["kbs"] = self.lock["trustee_images"]["kbs"][
            "reference"
        ]
        with self.assertRaisesRegex(
            materials.MaterialError, "source and build evidence"
        ):
            materials.validate_lock(changed)
        changed = copy.deepcopy(self.lock)
        changed["trustee_images"]["kbs"]["published_tag"] = "latest"
        with self.assertRaisesRegex(
            materials.MaterialError, "bind its source revision"
        ):
            materials.validate_lock(changed)
        changed = copy.deepcopy(self.lock)
        changed["trustee_images"]["kbs"]["source"] = "trustee_attestation_service"
        with self.assertRaisesRegex(materials.MaterialError, "must use source trustee"):
            materials.validate_lock(changed)
        changed = copy.deepcopy(self.lock)
        changed["trustee_images"]["kbs"]["attestations"].pop("provenance")
        with self.assertRaisesRegex(
            materials.MaterialError, "attestations keys differ"
        ):
            materials.validate_lock(changed)
        changed = copy.deepcopy(self.lock)
        changed["trustee_images"]["rvps"]["platform_manifest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(
            materials.MaterialError, "same combined downstream image"
        ):
            materials.validate_lock(changed)
        changed = copy.deepcopy(self.lock)
        changed["talos_extensions"]["installer_profile"] = "all-nodes"
        with self.assertRaisesRegex(materials.MaterialError, "Server.net"):
            materials.validate_lock(changed)
        changed = copy.deepcopy(self.lock)
        changed["base_images"]["buildkit_sbom_scanner"] = (
            "docker.io/docker/buildkit-syft-scanner:stable-1"
        )
        with self.assertRaisesRegex(materials.MaterialError, "exact Docker Hub digest"):
            materials.validate_lock(changed)

    def test_builder_checkout_is_bound_to_the_exact_input_tree(self) -> None:
        repo = SCRIPT_DIR.parents[1]
        materials.verify_builder(self.lock, repo)
        changed = copy.deepcopy(self.lock)
        changed["builder"]["input_files"][
            "hack/codewire-confidential-storage/build.sh"
        ] = "0" * 64
        with self.assertRaisesRegex(materials.MaterialError, "input drift"):
            materials.verify_builder(changed, repo)

    def test_trustee_publication_oracle_rejects_tag_or_attestation_drift(
        self,
    ) -> None:
        image = self.lock["trustee_images"]["kbs"]
        repository = image["reference"].split("@", 1)[0]
        index = {
            "manifests": [
                {
                    "digest": image["platform_manifest"],
                    "platform": {"architecture": "amd64", "os": "linux"},
                },
                {
                    "digest": image["attestations"]["manifest"],
                    "annotations": {
                        "vnd.docker.reference.type": "attestation-manifest"
                    },
                    "platform": {"architecture": "unknown", "os": "unknown"},
                },
            ]
        }
        attestation = {
            "layers": [
                {
                    "digest": image["attestations"]["sbom"],
                    "annotations": {
                        "in-toto.io/predicate-type": "https://spdx.dev/Document"
                    },
                },
                {
                    "digest": image["attestations"]["provenance"],
                    "annotations": {
                        "in-toto.io/predicate-type": "https://slsa.dev/provenance/v1"
                    },
                },
            ]
        }
        provenance = {
            "subject": [
                {
                    "digest": {
                        "sha256": image["platform_manifest"].removeprefix("sha256:")
                    }
                }
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "request": {
                            "root": {
                                "request": {
                                    "args": {
                                        "vcs:revision": self.lock["sources"]["trustee"][
                                            "revision"
                                        ],
                                        "vcs:source": self.lock["sources"]["trustee"][
                                            "repository"
                                        ],
                                        "vcs:localdir:dockerfile": "kbs/docker/coco-as-grpc",
                                    }
                                }
                            }
                        }
                    },
                    "internalParameters": {
                        "github_repository": "noeljackson/trustee",
                        "github_workflow_sha": self.lock["sources"]["trustee"][
                            "revision"
                        ],
                        "github_workflow_ref": "noeljackson/trustee/.github/workflows/downstream-kbs-grpc-as.yml@refs/heads/downstream/confidential-storage",
                        "github_ref": "refs/heads/downstream/confidential-storage",
                        "github_event_name": "push",
                    },
                }
            },
        }

        def valid_skopeo(*arguments: str) -> str:
            if "--format" in arguments:
                return image["reference"].split("@", 1)[1]
            reference = arguments[-1].removeprefix("docker://")
            if reference == image["reference"]:
                return json.dumps(index)
            if reference == f"{repository}@{image['attestations']['manifest']}":
                return json.dumps(attestation)
            raise AssertionError(reference)

        with (
            mock.patch.object(materials, "run_skopeo", side_effect=valid_skopeo),
            mock.patch.object(materials, "oras_blob", return_value=provenance),
        ):
            for component in ("kbs", "rvps"):
                with self.subTest(component=component):
                    materials.verify_trustee_image_publication(self.lock, component)

        with mock.patch.object(
            materials, "run_skopeo", return_value="sha256:" + "0" * 64
        ):
            with self.assertRaisesRegex(materials.MaterialError, "tag digest mismatch"):
                materials.verify_trustee_image_publication(self.lock, "kbs")

        drifted_attestation = copy.deepcopy(attestation)
        drifted_attestation["layers"][1]["digest"] = "sha256:" + "0" * 64

        def drifted_skopeo(*arguments: str) -> str:
            value = valid_skopeo(*arguments)
            reference = arguments[-1].removeprefix("docker://")
            if reference == f"{repository}@{image['attestations']['manifest']}":
                return json.dumps(drifted_attestation)
            return value

        with (
            mock.patch.object(materials, "run_skopeo", side_effect=drifted_skopeo),
            mock.patch.object(materials, "oras_blob", return_value=provenance),
        ):
            with self.assertRaisesRegex(materials.MaterialError, "provenance.*drifted"):
                materials.verify_trustee_image_publication(self.lock, "kbs")

        drifted_provenance = copy.deepcopy(provenance)
        drifted_provenance["predicate"]["buildDefinition"]["internalParameters"][
            "github_workflow_sha"
        ] = "0" * 40
        with (
            mock.patch.object(materials, "run_skopeo", side_effect=valid_skopeo),
            mock.patch.object(materials, "oras_blob", return_value=drifted_provenance),
        ):
            with self.assertRaisesRegex(
                materials.MaterialError, "source identity drifted"
            ):
                materials.verify_trustee_image_publication(self.lock, "kbs")

    def test_guest_publication_oracle_rejects_tag_source_or_attestation_drift(
        self,
    ) -> None:
        lock = copy.deepcopy(self.lock)
        image = lock["guest_components_images"]["container"]
        repository = image["reference"].split("@", 1)[0]
        source = lock["sources"]["guest_components"]
        subject_digest = "sha256:" + "5" * 64
        config_digest = "sha256:" + "6" * 64
        image["reference"] = f"{repository}@{subject_digest}"
        image["attestations"] = {
            "provenance": {
                "manifest": "sha256:" + "1" * 64,
                "bundle": "sha256:" + "2" * 64,
            },
            "sbom": {
                "manifest": "sha256:" + "3" * 64,
                "bundle": "sha256:" + "4" * 64,
            },
        }
        manifest = {
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "digest": config_digest,
            },
            "layers": [
                {
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "digest": "sha256:" + "c" * 64,
                }
            ],
        }
        config = {
            "architecture": "amd64",
            "os": "linux",
            "config": {
                "Labels": {
                    "org.opencontainers.image.source": source["repository"],
                    "org.opencontainers.image.revision": source["revision"],
                }
            },
        }
        statement_subject = [
            {
                "name": repository,
                "digest": {"sha256": subject_digest.removeprefix("sha256:")},
            }
        ]
        branch = "refs/heads/downstream/confidential-storage"
        provenance = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": statement_subject,
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                    "externalParameters": {
                        "workflow": {
                            "ref": branch,
                            "repository": source["repository"],
                            "path": ".github/workflows/coco-extension-image.yml",
                        }
                    },
                    "internalParameters": {
                        "github": {
                            "event_name": "push",
                            "runner_environment": "github-hosted",
                        }
                    },
                    "resolvedDependencies": [
                        {
                            "uri": f"git+{source['repository']}@{branch}",
                            "digest": {"gitCommit": source["revision"]},
                        }
                    ],
                },
                "runDetails": {
                    "builder": {
                        "id": (
                            f"{source['repository']}/.github/workflows/"
                            f"coco-extension-image.yml@{branch}"
                        )
                    }
                },
            },
        }
        sbom = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": statement_subject,
            "predicateType": "https://spdx.dev/Document/v2.3",
            "predicate": {"SPDXID": "SPDXRef-DOCUMENT"},
        }

        def attestation_manifest(name: str) -> dict:
            locked = image["attestations"][name]
            return {
                "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "subject": {"digest": subject_digest},
                "layers": [
                    {
                        "mediaType": ("application/vnd.dev.sigstore.bundle.v0.3+json"),
                        "digest": locked["bundle"],
                    }
                ],
                "annotations": {
                    "dev.sigstore.bundle.predicateType": (
                        materials.GUEST_IMAGE_ATTESTATION_PREDICATES["container"][name]
                    )
                },
            }

        def sigstore_bundle(statement: dict) -> dict:
            payload = base64.b64encode(
                json.dumps(statement, sort_keys=True).encode()
            ).decode()
            return {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "dsseEnvelope": {
                    "payloadType": "application/vnd.in-toto+json",
                    "payload": payload,
                    "signatures": [{"sig": "test"}],
                },
            }

        manifests = {
            image["reference"]: manifest,
            f"{repository}@{image['attestations']['provenance']['manifest']}": (
                attestation_manifest("provenance")
            ),
            f"{repository}@{image['attestations']['sbom']['manifest']}": (
                attestation_manifest("sbom")
            ),
        }
        blobs = {
            f"{repository}@{config_digest}": config,
            f"{repository}@{image['attestations']['provenance']['bundle']}": (
                sigstore_bundle(provenance)
            ),
            f"{repository}@{image['attestations']['sbom']['bundle']}": (
                sigstore_bundle(sbom)
            ),
        }

        def valid_skopeo(*arguments: str) -> str:
            if "--format" in arguments:
                return subject_digest
            reference = arguments[-1].removeprefix("docker://")
            return json.dumps(manifests[reference])

        def valid_blob(reference: str) -> dict:
            return blobs[reference]

        with (
            mock.patch.object(
                materials, "oras_manifest_digest", return_value=subject_digest
            ),
            mock.patch.object(materials, "run_skopeo", side_effect=valid_skopeo),
            mock.patch.object(materials, "oras_blob", side_effect=valid_blob),
        ):
            materials.verify_guest_components_image_component(lock, "container")

        with (
            mock.patch.object(
                materials, "oras_manifest_digest", return_value="sha256:" + "0" * 64
            ),
            self.assertRaisesRegex(materials.MaterialError, "tag digest mismatch"),
        ):
            materials.verify_guest_components_image_component(lock, "container")

        drifted_config = copy.deepcopy(config)
        drifted_config["config"]["Labels"]["org.opencontainers.image.revision"] = (
            "0" * 40
        )
        drifted_blobs = {**blobs, f"{repository}@{config_digest}": drifted_config}
        with (
            mock.patch.object(
                materials, "oras_manifest_digest", return_value=subject_digest
            ),
            mock.patch.object(materials, "run_skopeo", side_effect=valid_skopeo),
            mock.patch.object(
                materials, "oras_blob", side_effect=drifted_blobs.__getitem__
            ),
            self.assertRaisesRegex(materials.MaterialError, "source labels drifted"),
        ):
            materials.verify_guest_components_image_component(lock, "container")

        drifted_provenance = copy.deepcopy(provenance)
        drifted_provenance["predicate"]["buildDefinition"]["resolvedDependencies"][0][
            "digest"
        ]["gitCommit"] = "0" * 40
        drifted_blobs = {
            **blobs,
            f"{repository}@{image['attestations']['provenance']['bundle']}": (
                sigstore_bundle(drifted_provenance)
            ),
        }
        with (
            mock.patch.object(
                materials, "oras_manifest_digest", return_value=subject_digest
            ),
            mock.patch.object(materials, "run_skopeo", side_effect=valid_skopeo),
            mock.patch.object(
                materials, "oras_blob", side_effect=drifted_blobs.__getitem__
            ),
            self.assertRaisesRegex(
                materials.MaterialError, "provenance source identity drifted"
            ),
        ):
            materials.verify_guest_components_image_component(lock, "container")

        self_hosted_provenance = copy.deepcopy(provenance)
        self_hosted_provenance["predicate"]["buildDefinition"]["internalParameters"][
            "github"
        ]["runner_environment"] = "self-hosted"
        self_hosted_blobs = {
            **blobs,
            f"{repository}@{image['attestations']['provenance']['bundle']}": (
                sigstore_bundle(self_hosted_provenance)
            ),
        }
        with (
            mock.patch.object(
                materials, "oras_manifest_digest", return_value=subject_digest
            ),
            mock.patch.object(materials, "run_skopeo", side_effect=valid_skopeo),
            mock.patch.object(
                materials, "oras_blob", side_effect=self_hosted_blobs.__getitem__
            ),
            self.assertRaisesRegex(
                materials.MaterialError, "provenance source identity drifted"
            ),
        ):
            materials.verify_guest_components_image_component(lock, "container")

        disk = lock["guest_components_images"]["disk"]
        disk_repository = disk["reference"].split("@", 1)[0]
        disk_digest = "sha256:" + "7" * 64
        disk["reference"] = f"{disk_repository}@{disk_digest}"
        disk["attestations"]["provenance"] = {
            "manifest": "sha256:" + "8" * 64,
            "bundle": "sha256:" + "9" * 64,
        }
        disk_manifest = {
            "artifactType": (
                "application/vnd.confidential-containers.coco-extension.disk"
            ),
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": "sha256:" + "a" * 64,
                    "annotations": {
                        "org.opencontainers.image.title": (
                            "kata-containers-coco-extension.img"
                        )
                    },
                },
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": "sha256:" + "b" * 64,
                    "annotations": {
                        "org.opencontainers.image.title": (
                            "root_hash_coco-extension.txt"
                        )
                    },
                },
            ],
        }
        disk_provenance = copy.deepcopy(provenance)
        disk_provenance["subject"] = [
            {
                "name": disk_repository,
                "digest": {"sha256": disk_digest.removeprefix("sha256:")},
            }
        ]
        disk_attestation = {
            "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "subject": {"digest": disk_digest},
            "layers": [
                {
                    "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                    "digest": disk["attestations"]["provenance"]["bundle"],
                }
            ],
            "annotations": {
                "dev.sigstore.bundle.predicateType": ("https://slsa.dev/provenance/v1")
            },
        }
        disk_manifests = {
            disk["reference"]: disk_manifest,
            (
                f"{disk_repository}@{disk['attestations']['provenance']['manifest']}"
            ): disk_attestation,
        }
        disk_blobs = {
            (
                f"{disk_repository}@{disk['attestations']['provenance']['bundle']}"
            ): sigstore_bundle(disk_provenance)
        }

        def valid_disk_skopeo(*arguments: str) -> str:
            reference = arguments[-1].removeprefix("docker://")
            return json.dumps(disk_manifests[reference])

        with (
            mock.patch.object(
                materials, "oras_manifest_digest", return_value=disk_digest
            ),
            mock.patch.object(materials, "run_skopeo", side_effect=valid_disk_skopeo),
            mock.patch.object(
                materials, "oras_blob", side_effect=disk_blobs.__getitem__
            ),
        ):
            materials.verify_guest_components_image_component(lock, "disk")

        drifted_disk_manifests = copy.deepcopy(disk_manifests)
        drifted_disk_manifests[disk["reference"]]["layers"].pop()

        def drifted_disk_skopeo(*arguments: str) -> str:
            reference = arguments[-1].removeprefix("docker://")
            return json.dumps(drifted_disk_manifests[reference])

        with (
            mock.patch.object(
                materials, "oras_manifest_digest", return_value=disk_digest
            ),
            mock.patch.object(materials, "run_skopeo", side_effect=drifted_disk_skopeo),
            self.assertRaisesRegex(
                materials.MaterialError, "disk image payload contract drifted"
            ),
        ):
            materials.verify_guest_components_image_component(lock, "disk")

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
                "ci/install_libseccomp.sh": "#!/bin/sh\nexit 0\n",
                "versions.yaml": (
                    "  coco-guest-components:\n"
                    '    description: "test"\n'
                    '    url: "https://github.com/confidential-containers/guest-components/"\n'
                    '    version: "d4dce5ce62294cfa741225f7e5b4527ea276f326"\n'
                    '    variant: "ubuntu26.04"\n'
                    '    container_image: "ghcr.io/confidential-containers/guest-components/coco-extension"\n'
                    '    extension_image: "ghcr.io/confidential-containers/guest-components/coco-extension-disk"\n'
                ),
                "tools/osbuilder/rootfs-builder/ubuntu/config.sh": (
                    'PACKAGES="base"\n'
                    'PACKAGES+=" cryptsetup-bin e2fsprogs"\n'
                    'REPO_URL=${REPO_URL:-http://archive.ubuntu.com/ubuntu}\n'
                    'REPO_URL=${REPO_URL:-http://ports.ubuntu.com}\n'
                ),
                "tools/osbuilder/rootfs-builder/ubuntu/Dockerfile.in": (
                    "ARG IMAGE_REGISTRY=docker.io\n"
                    "FROM ${IMAGE_REGISTRY}/ubuntu:@OS_VERSION@\n"
                    "@SET_PROXY@\n"
                    "# hadolint ignore=DL3009,SC2046\n"
                    "RUN apt-get update && \\\n"
                    "    DEBIAN_FRONTEND=noninteractive \\\n"
                    "    apt-get --no-install-recommends -y install \\\n"
                    "    ca-certificates\n"
                ),
                "tools/osbuilder/rootfs-builder/rootfs.sh": (
                    'dns_file="${ROOTFS_DIR}/etc/resolv.conf"\n: > "${dns_file}"\n'
                ),
                "src/runtime-rs/crates/runtimes/common/src/types/trans_from_shim.rs": (
                    "// sandbox DNS formatter fixture\n"
                ),
                "tools/packaging/kata-deploy/local-build/Makefile": "all:\n\ttrue\n",
                "tools/packaging/kata-deploy/local-build/kata-deploy-binaries.sh": (
                    'echo "${image}:${version}-${variant}"\n'
                    'digest="$(resolve_oci_artifact_manifest '
                    '"${disk_image_ref}" "${go_arch}")"\n'
                ),
                "tools/packaging/static-build/coco-guest-components/Dockerfile": "FROM scratch\n",
                "tools/packaging/static-build/coco-guest-components/build-static-coco-guest-components.sh": "test\n",
                "tools/packaging/static-build/coco-guest-components/build.sh": "test\n",
            }
            for relative, content in files.items():
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            (source / "ci/install_libseccomp.sh").chmod(0o755)
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
            versions = (output / "versions.yaml").read_text(encoding="utf-8")
            self.assertIn(
                f'    version: "{self.lock["sources"]["guest_components"]["revision"]}"',
                versions,
            )
            self.assertIn('    variant: "ubuntu26.04"', versions)
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
            packaging = (
                output
                / "tools/packaging/kata-deploy/local-build/kata-deploy-binaries.sh"
            )
            self.assertIn(
                'echo "${image}:${version}-${variant}-$(get_coco_extension_oci_arch)"',
                packaging.read_text(encoding="utf-8"),
            )
            self.assertNotIn(
                'echo "${image}:${version}-${variant}"',
                packaging.read_text(encoding="utf-8"),
            )
            self.assertIn(
                'PACKAGES+=" cryptsetup-bin dmsetup e2fsprogs"',
                (output / "tools/osbuilder/rootfs-builder/ubuntu/config.sh").read_text(
                    encoding="utf-8"
                ),
            )
            config = (
                output / "tools/osbuilder/rootfs-builder/ubuntu/config.sh"
            ).read_text(encoding="utf-8")
            self.assertIn("https://archive.ubuntu.com/ubuntu", config)
            self.assertIn("https://ports.ubuntu.com", config)
            self.assertNotIn("http://archive.ubuntu.com", config)
            self.assertNotIn("http://ports.ubuntu.com", config)
            dockerfile = (
                output / "tools/osbuilder/rootfs-builder/ubuntu/Dockerfile.in"
            )
            ca_reference = self.lock["base_images"]["ubuntu_apt_ca_bootstrap"]
            ca_stage = f"FROM {ca_reference} AS codewire-ubuntu-apt-ca"
            ca_copy = (
                "COPY --from=codewire-ubuntu-apt-ca "
                "/etc/ssl/certs/ca-certificates.crt "
                "/etc/ssl/certs/ca-certificates.crt"
            )
            prepared_dockerfile = dockerfile.read_text(encoding="utf-8")
            self.assertEqual(prepared_dockerfile.count(ca_stage), 1)
            self.assertEqual(prepared_dockerfile.count(ca_copy), 1)
            self.assertEqual(
                prepared_dockerfile.count(
                    'Acquire::https::CaInfo="${ca_bundle}"'
                ),
                2,
            )
            self.assertLess(
                prepared_dockerfile.index(ca_copy),
                prepared_dockerfile.index(
                    "source_file=/etc/apt/sources.list.d/ubuntu.sources"
                ),
            )
            self.assertIn(
                "source_file=/etc/apt/sources.list.d/ubuntu.sources",
                prepared_dockerfile,
            )
            self.assertNotIn(
                "RUN apt-get update",
                prepared_dockerfile,
            )
            dockerfile.write_text(
                prepared_dockerfile.replace(
                    ca_stage,
                    "FROM docker.io/library/golang:1.26.7-alpine3.23 "
                    "AS codewire-ubuntu-apt-ca",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                materials.MaterialError, "pinned CA bootstrap stage"
            ):
                materials.verify_prepared_kata(lock, output)
            dockerfile.write_text(
                prepared_dockerfile.replace(
                    ca_copy,
                    "COPY ca-certificates.crt "
                    "/etc/ssl/certs/ca-certificates.crt",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                materials.MaterialError, "exact pinned CA bundle import"
            ):
                materials.verify_prepared_kata(lock, output)
            dockerfile.write_text(
                prepared_dockerfile.replace(
                    "source_file=/etc/apt/sources.list.d/ubuntu.sources",
                    "apt_option='Acquire::https::Verify-Peer=false' && \\\n"
                    "    source_file=/etc/apt/sources.list.d/ubuntu.sources",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                materials.MaterialError, "TLS verification bypass"
            ):
                materials.verify_prepared_kata(lock, output)
            dockerfile.write_text(prepared_dockerfile, encoding="utf-8")
            dockerfile.write_text(
                dockerfile.read_text(encoding="utf-8")
                + "# http://security.ubuntu.com/ubuntu\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                materials.MaterialError, "builder retains a cleartext Ubuntu source"
            ):
                materials.verify_prepared_kata(lock, output)
            dockerfile.write_text(
                dockerfile.read_text(encoding="utf-8").replace(
                    "# http://security.ubuntu.com/ubuntu\n", ""
                ),
                encoding="utf-8",
            )
            config_path = output / "tools/osbuilder/rootfs-builder/ubuntu/config.sh"
            config_path.write_text(
                config_path.read_text(encoding="utf-8").replace(
                    "https://archive.ubuntu.com/ubuntu",
                    "http://archive.ubuntu.com/ubuntu",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                materials.MaterialError,
                "configuration retains a cleartext Ubuntu source",
            ):
                materials.verify_prepared_kata(lock, output)
            config_path.write_text(config, encoding="utf-8")
            rootfs_builder = output / "tools/osbuilder/rootfs-builder/rootfs.sh"
            rootfs_builder.write_text(
                'dns_file="${ROOTFS_DIR}/etc/resolv.conf"\ntouch "${dns_file}"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                materials.MaterialError,
                "does not clear the guest resolver",
            ):
                materials.verify_prepared_kata(lock, output)
            rootfs_builder.write_text(
                'dns_file="${ROOTFS_DIR}/etc/resolv.conf"\n'
                ': > "${dns_file}"\n'
                'touch "${dns_file}"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                materials.MaterialError,
                "retains the build-host guest resolver",
            ):
                materials.verify_prepared_kata(lock, output)
            rootfs_builder.write_text(
                files["tools/osbuilder/rootfs-builder/rootfs.sh"],
                encoding="utf-8",
            )
            libseccomp_installer = output / "ci/install_libseccomp.sh"
            libseccomp_installer.chmod(0o700)
            with self.assertRaisesRegex(
                materials.MaterialError,
                "executable by the builder UID",
            ):
                materials.verify_prepared_kata(lock, output)
            libseccomp_installer.chmod(0o755)
            packaging = (
                output
                / "tools/packaging/kata-deploy/local-build/kata-deploy-binaries.sh"
            )
            packaging.write_text(
                'digest="$(oras resolve --platform "linux/${go_arch}" '
                '"${disk_image_ref}")"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                materials.MaterialError, "architecture-qualified CoCo container tag"
            ):
                materials.verify_prepared_kata(lock, output)

            packaging.write_text(
                'echo "${image}:${version}-${variant}-$(get_coco_extension_oci_arch)"\n'
                'digest="$(oras resolve --platform "linux/${go_arch}" '
                '"${disk_image_ref}")"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                materials.MaterialError, "select the CoCo disk manifest explicitly"
            ):
                materials.verify_prepared_kata(lock, output)

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
                self.assertIn("d40d8c27572803e787a061a01a2228b35b7246d3", text)
            provenance = json.loads(
                (first / "provenance.in-toto.json").read_text(encoding="utf-8")
            )
            dependencies = provenance["predicate"]["buildDefinition"][
                "resolvedDependencies"
            ]
            guest = next(
                dependency
                for dependency in dependencies
                if dependency.get("annotations", {}).get("component")
                == "guest-components-container-image"
                and dependency.get("annotations", {}).get("role") is None
            )
            self.assertEqual(
                guest["annotations"]["sourceRevision"],
                self.lock["sources"]["guest_components"]["revision"],
            )
            self.assertEqual(
                guest["annotations"]["provenanceBundleAttestation"],
                self.lock["guest_components_images"]["container"]["attestations"][
                    "provenance"
                ]["bundle"],
            )
            kbs = next(
                dependency
                for dependency in dependencies
                if dependency.get("annotations", {}).get("component") == "trustee-kbs"
                and dependency.get("annotations", {}).get("role") is None
            )
            self.assertEqual(
                kbs["annotations"]["sourceRevision"],
                "bc76377e5a694d03a122ecf3f8272a0889dd9371",
            )
            self.assertEqual(
                kbs["annotations"]["provenanceAttestation"],
                "sha256:3af3a1391a954a6554d9c1c9b391fdfb121eb76190c0510d6b1a56ba84411ff6",
            )
            self.assertTrue(
                any(
                    dependency.get("annotations", {}).get("role") == "build-recipe"
                    and dependency.get("annotations", {}).get("component")
                    == "trustee-kbs"
                    for dependency in dependencies
                )
            )

    def test_oci_subject_uses_platform_manifest_and_checks_attestations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive, image_digest = self._write_oci_archive(root / "valid")
            subject = materials.verify_oci_image(
                LOCK_PATH, self.lock, "kata-extension", archive
            )
            self.assertEqual(
                subject,
                {
                    "name": "kata-extension@linux-amd64",
                    "digest": {"sha256": image_digest},
                },
            )

            invalid, _ = self._write_oci_archive(
                root / "invalid", source_lock_label="0" * 64
            )
            with self.assertRaisesRegex(materials.MaterialError, "exact source lock"):
                materials.verify_oci_image(
                    LOCK_PATH, self.lock, "kata-extension", invalid
                )

            invalid_attestation, _ = self._write_oci_archive(
                root / "invalid-attestation",
                slsa_predicate="https://example.invalid/provenance",
            )
            with self.assertRaisesRegex(materials.MaterialError, "SPDX/SLSA"):
                materials.verify_oci_image(
                    LOCK_PATH,
                    self.lock,
                    "kata-extension",
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

    def test_kata_extension_rejects_stale_manifest_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            invalid_entries = self._kata_extension_entries()
            invalid_entries["manifest.yaml"] = b"""\
version: v1alpha1
metadata:
  name: kata-containers
  version: "4.0.0"
"""
            invalid, _ = self._write_oci_archive(
                root / "invalid",
                component="kata-extension",
                layer_entries=invalid_entries,
            )
            with self.assertRaisesRegex(materials.MaterialError, "locked Kata version"):
                materials.verify_oci_image(
                    LOCK_PATH, self.lock, "kata-extension", invalid
                )

    def test_kata_extension_rejects_non_talos_shim_abis(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, shim, expected in (
                (
                    "interp",
                    self._elf_with_program_segment(3, b"/lib64/ld-linux-x86-64.so.2\0"),
                    "PT_INTERP",
                ),
                (
                    "needed",
                    self._elf_with_program_segment(2, struct.pack("<QQQQ", 1, 0, 0, 0)),
                    "DT_NEEDED",
                ),
            ):
                with self.subTest(name=name):
                    entries = self._kata_extension_entries()
                    entries["rootfs/usr/local/bin/containerd-shim-kata-v2"] = shim
                    archive, _ = self._write_oci_archive(
                        root / name,
                        component="kata-extension",
                        layer_entries=entries,
                    )
                    with self.assertRaisesRegex(materials.MaterialError, expected):
                        materials.verify_oci_image(
                            LOCK_PATH, self.lock, "kata-extension", archive
                        )

    def test_kata_extension_requires_runtime_rs_helper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
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

    def test_kata_extension_rejects_mixed_host_boot_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = []

            missing_qemu = self._kata_extension_entries()
            del missing_qemu[
                "rootfs/usr/local/libexec/qemu-system-x86_64-snp-experimental"
            ]
            cases.append(("missing-qemu", missing_qemu, "lacks required payload"))

            stale_kernel = self._kata_extension_entries()
            stale_kernel[
                "rootfs/usr/local/share/kata-containers/vmlinuz-6.18.35-202"
            ] = b"stale-kernel"
            cases.append(
                ("stale-kernel", stale_kernel, "exactly one versioned kernel")
            )

            wrong_default = self._kata_extension_entries()
            wrong_default[
                "rootfs/usr/local/share/kata-containers/vmlinuz.container"
            ] = "vmlinuz-6.18.35-202"
            cases.append(
                (
                    "wrong-default",
                    wrong_default,
                    "does not select its exact versioned kernel",
                )
            )

            regular_default = self._kata_extension_entries()
            regular_default[
                "rootfs/usr/local/share/kata-containers/vmlinuz.container"
            ] = b"copied-kernel"
            cases.append(
                (
                    "regular-default",
                    regular_default,
                    "must be a symbolic link",
                )
            )

            for name, entries, expected in cases:
                with self.subTest(name=name):
                    archive, _ = self._write_oci_archive(
                        root / name,
                        component="kata-extension",
                        layer_entries=entries,
                    )
                    with self.assertRaisesRegex(materials.MaterialError, expected):
                        materials.verify_oci_image(
                            LOCK_PATH, self.lock, "kata-extension", archive
                        )

    def test_kata_extension_requires_every_configured_guest_image(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image_path = (
                "rootfs/usr/local/share/kata-containers/"
                "kata-containers-coco-extension.img"
            )
            for name, payload in (("missing", None), ("empty", b"")):
                with self.subTest(name=name):
                    entries = self._kata_extension_entries()
                    if payload is None:
                        del entries[image_path]
                    else:
                        entries[image_path] = payload
                    archive, _ = self._write_oci_archive(
                        root / name,
                        component="kata-extension",
                        layer_entries=entries,
                    )
                    with self.assertRaisesRegex(
                        materials.MaterialError,
                        "required payload|lacks non-empty configured guest image",
                    ):
                        materials.verify_oci_image(
                            LOCK_PATH, self.lock, "kata-extension", archive
                        )

            wrong_path_entries = self._kata_extension_entries()
            wrong_path_entries[
                "rootfs/usr/local/share/kata-containers/configuration-qemu-snp.toml"
            ] = b"""\
[hypervisor.qemu]
path = "/usr/local/bin/qemu-system-x86_64-snp-experimental"
valid_hypervisor_paths = ["/usr/local/bin/qemu-system-x86_64-snp-experimental"]
kernel = "/usr/local/share/kata-containers/vmlinuz.container"
firmware = "/usr/local/share/ovmf/AMDSEV.fd"
image = "/usr/local/share/kata-containers/kata-containers-confidential.img"
kernel_verity_params = "root_hash=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc,salt=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd,data_blocks=2,data_block_size=4096,hash_block_size=4096"
confidential_guest = true
shared_fs = "none"
enable_annotations = ["enable_iommu", "kernel_params", "kernel_verity_params", "default_vcpus", "default_memory", "cc_init_data"]
[[hypervisor.qemu.guest_extension_images]]
name = "coco"
path = "/usr/local/share/kata-containers/not-the-coco-image.img"
verity_params = "root_hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,salt=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,data_blocks=1,data_block_size=4096,hash_block_size=4096"
"""
            wrong_path, _ = self._write_oci_archive(
                root / "wrong-path",
                component="kata-extension",
                layer_entries=wrong_path_entries,
            )
            with self.assertRaisesRegex(
                materials.MaterialError,
                "lacks non-empty configured guest image",
            ):
                materials.verify_oci_image(
                    LOCK_PATH, self.lock, "kata-extension", wrong_path
                )

            shared_root_entries = self._kata_extension_entries()
            shared_root_entries[
                "rootfs/usr/local/share/kata-containers/configuration-qemu-snp.toml"
            ] = shared_root_entries[
                "rootfs/usr/local/share/kata-containers/configuration-qemu-snp.toml"
            ].replace(b"kata-containers-confidential.img", b"kata-containers.img")
            shared_root, _ = self._write_oci_archive(
                root / "shared-root",
                component="kata-extension",
                layer_entries=shared_root_entries,
            )
            with self.assertRaisesRegex(
                materials.MaterialError, "dedicated confidential root image"
            ):
                materials.verify_oci_image(
                    LOCK_PATH, self.lock, "kata-extension", shared_root
                )

    def test_kata_extension_requires_guest_only_confidential_mount_profile(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_name = (
                "rootfs/usr/local/share/kata-containers/configuration-qemu-snp.toml"
            )
            for name, replacement in (
                ("missing-shared-fs", b""),
                ("virtio-fs", b'shared_fs = "virtio-fs"'),
                ("inline-virtio-fs", b'shared_fs = "inline-virtio-fs"'),
                ("nydus-virtio-fs", b'shared_fs = "virtio-fs-nydus"'),
                ("9p", b'shared_fs = "9p"'),
            ):
                with self.subTest(name=name):
                    entries = self._kata_extension_entries()
                    entries[config_name] = entries[config_name].replace(
                        b'shared_fs = "none"', replacement
                    )
                    archive, _ = self._write_oci_archive(
                        root / name,
                        component="kata-extension",
                        layer_entries=entries,
                    )
                    with self.assertRaisesRegex(
                        materials.MaterialError, "does not use shared_fs=none"
                    ):
                        materials.verify_oci_image(
                            LOCK_PATH, self.lock, "kata-extension", archive
                        )

            annotation_line = (
                b'enable_annotations = ["enable_iommu", "kernel_params", '
                b'"kernel_verity_params", "default_vcpus", "default_memory", '
                b'"cc_init_data"]'
            )
            for name, replacement, expected in (
                ("missing-annotations", b"", "lacks required annotations"),
                (
                    "shared-fs-annotation",
                    annotation_line[:-1] + b', "shared_fs"]',
                    "unsafe annotation rule",
                ),
                (
                    "shared-fs-regex-annotation",
                    annotation_line[:-1] + b', "shared_.*"]',
                    "unsafe annotation rule",
                ),
                (
                    "wildcard-annotation",
                    annotation_line[:-1] + b', ".*"]',
                    "unsafe annotation rule",
                ),
            ):
                with self.subTest(name=name):
                    entries = self._kata_extension_entries()
                    entries[config_name] = entries[config_name].replace(
                        annotation_line, replacement
                    )
                    archive, _ = self._write_oci_archive(
                        root / name,
                        component="kata-extension",
                        layer_entries=entries,
                    )
                    with self.assertRaisesRegex(materials.MaterialError, expected):
                        materials.verify_oci_image(
                            LOCK_PATH, self.lock, "kata-extension", archive
                        )

    def test_kata_extension_binds_verity_params_to_root_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            coco_params = b'verity_params = "root_hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,salt=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,data_blocks=1,data_block_size=4096,hash_block_size=4096"'
            confidential_params = b'kernel_verity_params = "root_hash=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc,salt=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd,data_blocks=2,data_block_size=4096,hash_block_size=4096"'
            for name, needle, replacement, expected in (
                (
                    "coco-empty",
                    coco_params,
                    b'verity_params = ""',
                    "CoCo verity params do not match its root hash",
                ),
                (
                    "coco-mismatch",
                    coco_params,
                    b'verity_params = "root_hash=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc,salt=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,data_blocks=1,data_block_size=4096,hash_block_size=4096"',
                    "CoCo verity params do not match its root hash",
                ),
                (
                    "confidential-empty",
                    confidential_params,
                    b'kernel_verity_params = ""',
                    "confidential root verity params do not match its root hash",
                ),
                (
                    "confidential-mismatch",
                    confidential_params,
                    b'kernel_verity_params = "root_hash=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee,salt=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd,data_blocks=2,data_block_size=4096,hash_block_size=4096"',
                    "confidential root verity params do not match its root hash",
                ),
            ):
                with self.subTest(name=name):
                    entries = self._kata_extension_entries()
                    config_name = (
                        "rootfs/usr/local/share/kata-containers/"
                        "configuration-qemu-snp.toml"
                    )
                    entries[config_name] = entries[config_name].replace(
                        needle, replacement
                    )
                    archive, _ = self._write_oci_archive(
                        root / name,
                        component="kata-extension",
                        layer_entries=entries,
                    )
                    with self.assertRaisesRegex(materials.MaterialError, expected):
                        materials.verify_oci_image(
                            LOCK_PATH, self.lock, "kata-extension", archive
                        )

    def test_kata_extension_rejects_legacy_runtime_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            legacy_config_entries = self._kata_extension_entries()
            legacy_config_entries[
                "rootfs/usr/local/share/kata-containers/configuration.toml"
            ] = b"""\
[hypervisor.clh]
path = "/usr/local/bin/cloud-hypervisor"
valid_hypervisor_paths = ["/usr/local/bin/cloud-hypervisor"]
image = "/usr/local/share/kata-containers/kata-containers.img"
enable_annotations = ["kernel_params", "cc_init_data"]
[agent.kata]
dial_timeout = 45
[runtime]
hypervisor_name = "clh"
agent_name = "kata"
"""
            legacy_config, _ = self._write_oci_archive(
                root / "legacy-config",
                component="kata-extension",
                layer_entries=legacy_config_entries,
            )
            with self.assertRaisesRegex(
                materials.MaterialError, "legacy Go-runtime dial timeout"
            ):
                materials.verify_oci_image(
                    LOCK_PATH, self.lock, "kata-extension", legacy_config
                )

    def test_talos_extension_tree_has_exact_top_level_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid_manifest = """\
version: v1alpha1
metadata:
  name: kata-containers
  version: "4.1.0"
"""
            stale_manifest = valid_manifest.replace('"4.1.0"', '"4.0.0"')
            (root / "manifest.yaml").write_text(valid_manifest)
            (root / "rootfs").mkdir()
            materials.verify_talos_extension_tree(root, "4.1.0")
            (root / "manifest.yaml").write_text(stale_manifest)
            with self.assertRaisesRegex(materials.MaterialError, "locked Kata version"):
                materials.verify_talos_extension_tree(root, "4.1.0")
            (root / "manifest.yaml").write_text(valid_manifest)
            (root / ".dockerenv").touch()
            with self.assertRaisesRegex(
                materials.MaterialError, "unexpected entries.*dockerenv"
            ):
                materials.verify_talos_extension_tree(root, "4.1.0")

    def test_build_recipe_has_no_publication_path(self) -> None:
        recipe = (SCRIPT_DIR / "build.sh").read_text(encoding="utf-8")
        for command in (
            "fetch-archives",
            "verify-guest-source",
            "verify-guest-publication",
            "verify-trustee-sources",
            "verify-trustee-publications",
            "plan",
            "prepare-kata",
            "kata-static",
            "kata-guest-components",
            "verify-kata-static",
            "kata-extension",
        ):
            command_body = recipe.split(f"  {command})", 1)[1].split(";;", 1)[0]
            self.assertIn("verify_builder_checkout", command_body, command)
        self.assertNotIn(" --push", recipe)
        self.assertNotIn("docker login", recipe)
        self.assertNotIn("GITHUB_TOKEN", recipe)
        self.assertNotIn("--sbom=true", recipe)
        self.assertIn(".base_images.buildkit_sbom_scanner", recipe)
        self.assertEqual(recipe.count("type=sbom,generator=$(lock_value"), 1)
        self.assertNotIn("longhorn", recipe.lower())
        self.assertIn('mode:"no-push"', recipe)
        self.assertNotIn("docker export", recipe)
        self.assertNotIn("docker create", recipe)
        self.assertIn("base-rootfs.Dockerfile", recipe)
        self.assertIn('"$work_dir/context/extension/rootfs"', recipe)
        self.assertIn(
            'built_tarball="$local_build/kata-static.tar.zst"',
            recipe,
        )
        self.assertIn("kata-guest-components)", recipe)
        self.assertIn("BASE_TARBALLS=coco-guest-components-tarball", recipe)
        self.assertIn("verify_guest_components_artifact()", recipe)
        self.assertEqual(recipe.count("    verify_guest_components_artifact\n"), 3)
        self.assertIn("verify-guest-image-publication", recipe)
        self.assertIn("require_command oras", recipe)
        self.assertIn("require_command skopeo", recipe)
        self.assertLess(
            recipe.index("    verify_guest_components_artifact\n"),
            recipe.index('BASE_TARBALLS="$parallel_targets"'),
        )
        self.assertIn(
            'built_tarball="$local_build/build/kata-static-coco-guest-components.tar.zst"',
            recipe,
        )
        self.assertIn("failed build work directory retained", recipe)
        self.assertNotIn("trap 'remove_tree", recipe)
        self.assertIn("STATIC_RUNTIME=yes USE_CACHE=no", recipe)
        self.assertIn("readelf -l", recipe)
        self.assertIn("readelf -d", recipe)
        self.assertIn('runtime_abi:"static"', recipe)
        self.assertIn("\\( -type f -o -type l \\)", recipe)
        self.assertIn("rootfs-image-confidential-tarball", recipe)
        self.assertIn("rootfs-image-coco-extension-tarball", recipe)
        self.assertIn("kata-static-rootfs-image-coco-extension.tar.zst", recipe)
        self.assertIn("kata-containers-coco-extension.img", recipe)
        self.assertIn("root_hash_coco-extension.txt", recipe)
        self.assertIn('cmp -s "$source"', recipe)
        self.assertIn(
            'replace_exact_tree "$qemu_snp_libs" '
            '"$rootfs/usr/local/lib/kata-qemu-snp-experimental"',
            recipe,
        )
        self.assertIn(
            'replace_exact_tree "$qemu_snp_data" '
            '"$rootfs/usr/local/share/kata-qemu-snp-experimental/qemu"',
            recipe,
        )
        self.assertIn("final QEMU-SNP binary differs after copying", recipe)
        self.assertIn("final AMD SEV firmware differs after copying", recipe)
        self.assertIn("final Kata kernel differs after copying", recipe)
        self.assertIn("-name 'vmlinuz-*' -delete", recipe)
        self.assertIn("parsed kernel_verity_params does not match", recipe)
        self.assertNotIn(
            'find "$work_dir/context/extension" -exec touch',
            recipe,
        )
        self.assertIn("--no-cache", recipe)
        parallel_targets = recipe.split("kata_parallel_targets=(", 1)[1].split(")", 1)[
            0
        ]
        post_image_targets = recipe.split("kata_post_image_targets=(", 1)[1].split(
            ")", 1
        )[0]
        self.assertNotIn("shim-v2-rust-tarball", parallel_targets)
        self.assertIn("shim-v2-rust-tarball", post_image_targets)
        self.assertLess(
            recipe.index('BASE_TARBALLS="$parallel_targets"'),
            recipe.index('BASE_TARBALLS="$post_image_targets"'),
        )
        self.assertIn("has_executable_mode", recipe)
        self.assertNotIn('[[ -x "$shim" ]]', recipe)
        self.assertNotIn('[[ -x "$kata_ctl" ]]', recipe)
        self.assertIn("rootfs-initrd-confidential-tarball", recipe)
        self.assertIn("qemu-snp-experimental-tarball", recipe)
        self.assertIn("sfdisk --json", recipe)
        self.assertIn("QEMU-SNP annotation allowlist is not exact", recipe)
        self.assertIn("grep -Eq '^shared_fs = \"none\"$'", recipe)

        smoke = (SCRIPT_DIR / "qemu-tcg-boot-smoke").read_text(encoding="utf-8")
        self.assertIn("console=ttyS0,115200", smoke)
        self.assertIn("earlyprintk=serial,ttyS0,115200", smoke)
        self.assertIn("ignore_loglevel", smoke)
        self.assertIn('-serial "file:$raw_log"', smoke)
        self.assertNotIn("-serial stdio", smoke)
        self.assertIn(".bootable == true", recipe)
        self.assertNotIn("rootfs-image-mariner-tarball", recipe)
        self.assertNotIn("qemu-tdx-experimental-tarball", recipe)

    def test_downstream_publication_contract_is_separate_and_guarded(self) -> None:
        subprocess.run(
            [SCRIPT_DIR / "test-publication-contract.sh"],
            cwd=SCRIPT_DIR.parents[1],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        )

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
        component: str = "kata-extension",
        layer_entries: dict[str, bytes | str | None] | None = None,
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

        if component != "kata-extension":
            raise AssertionError(f"unsupported test component: {component}")
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
                elif isinstance(data, str):
                    member.type = tarfile.SYMTYPE
                    member.mode = 0o777
                    member.linkname = data
                    layer.addfile(member)
                else:
                    member.size = len(data)
                    member.mode = (
                        0o755
                        if name
                        in {
                            "rootfs/usr/local/bin/containerd-shim-kata-v2",
                            "rootfs/usr/local/bin/qemu-system-x86_64-snp-experimental",
                            "rootfs/usr/local/libexec/qemu-system-x86_64-snp-experimental",
                        }
                        else 0o644
                    )
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

    def _kata_extension_entries(self) -> dict[str, bytes | str | None]:
        return {
            "manifest.yaml": b"""\
version: v1alpha1
metadata:
  name: kata-containers
  version: "4.1.0"
""",
            "rootfs": None,
            "rootfs/usr/local/bin/containerd-shim-kata-qemu-snp-v2": b"shim",
            "rootfs/usr/local/bin/containerd-shim-kata-v2": self._static_amd64_elf(),
            "rootfs/usr/local/bin/kata-ctl": b"kata-ctl",
            "rootfs/usr/local/bin/qemu-system-x86_64-snp-experimental": b"qemu-wrapper",
            "rootfs/usr/local/libexec/qemu-system-x86_64-snp-experimental": b"qemu-binary",
            "rootfs/usr/local/lib/kata-qemu-snp-experimental/libfdt.a": b"qemu-library",
            "rootfs/usr/local/share/kata-qemu-snp-experimental/qemu/bios.bin": b"qemu-data",
            "rootfs/usr/local/share/ovmf/AMDSEV.fd": b"firmware",
            "rootfs/usr/local/share/codewire/confidential-storage/materials.spdx.json": b"{}\n",
            "rootfs/usr/local/share/codewire/confidential-storage/provenance.in-toto.json": b"{}\n",
            "rootfs/usr/local/share/kata-containers/configuration.toml": b"""\
[hypervisor.clh]
path = "/usr/local/bin/cloud-hypervisor"
valid_hypervisor_paths = ["/usr/local/bin/cloud-hypervisor"]
image = "/usr/local/share/kata-containers/kata-containers.img"
enable_annotations = ["kernel_params", "cc_init_data"]
[agent.kata]
dial_timeout_ms = 10
[runtime]
hypervisor_name = "clh"
agent_name = "kata"
""",
            "rootfs/usr/local/share/kata-containers/configuration-qemu-snp.toml": b"""\
[hypervisor.qemu]
path = "/usr/local/bin/qemu-system-x86_64-snp-experimental"
valid_hypervisor_paths = ["/usr/local/bin/qemu-system-x86_64-snp-experimental"]
kernel = "/usr/local/share/kata-containers/vmlinuz.container"
firmware = "/usr/local/share/ovmf/AMDSEV.fd"
image = "/usr/local/share/kata-containers/kata-containers-confidential.img"
kernel_verity_params = "root_hash=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc,salt=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd,data_blocks=2,data_block_size=4096,hash_block_size=4096"
confidential_guest = true
shared_fs = "none"
enable_annotations = ["enable_iommu", "kernel_params", "kernel_verity_params", "default_vcpus", "default_memory", "cc_init_data"]
[[hypervisor.qemu.guest_extension_images]]
name = "coco"
path = "/usr/local/share/kata-containers/kata-containers-coco-extension.img"
verity_params = "root_hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,salt=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,data_blocks=1,data_block_size=4096,hash_block_size=4096"
""",
            "rootfs/usr/local/share/kata-containers/kata-containers.img": b"commodity-image",
            "rootfs/usr/local/share/kata-containers/kata-containers-confidential.img": b"image",
            "rootfs/usr/local/share/kata-containers/kata-containers-coco-extension.img": b"coco-image",
            "rootfs/usr/local/share/kata-containers/kata-containers-initrd-confidential.img": b"initrd",
            "rootfs/usr/local/share/kata-containers/vmlinuz-7.2.2-202": b"kernel",
            "rootfs/usr/local/share/kata-containers/vmlinuz.container": "vmlinuz-7.2.2-202",
            "rootfs/usr/local/share/kata-containers/root_hash_coco-extension.txt": b"root_hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,salt=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,data_blocks=1,data_block_size=4096,hash_block_size=4096\n",
            "rootfs/usr/local/share/kata-containers/root_hash_confidential.txt": b"root_hash=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc,salt=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd,data_blocks=2,data_block_size=4096,hash_block_size=4096\n",
        }

    def _static_amd64_elf(self) -> bytes:
        data = bytearray(64)
        data[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
        struct.pack_into("<HHI", data, 16, 2, 62, 1)
        struct.pack_into("<HHH", data, 52, 64, 56, 0)
        return bytes(data)

    def _elf_with_program_segment(self, program_type: int, payload: bytes) -> bytes:
        data = bytearray(self._static_amd64_elf())
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<H", data, 56, 1)
        payload_offset = 64 + 56
        data.extend(
            struct.pack(
                "<IIQQQQQQ",
                program_type,
                4,
                payload_offset,
                0,
                0,
                len(payload),
                len(payload),
                8,
            )
        )
        data.extend(payload)
        return bytes(data)


if __name__ == "__main__":
    unittest.main()
