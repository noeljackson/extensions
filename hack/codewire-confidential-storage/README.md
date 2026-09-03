# Codewire confidential-storage build inputs

This directory owns the exact-source, non-publishing build boundary for the
single-node Dev confidential-storage milestone. `sources.lock.json` binds every
source by full Git commit, Git tree, codeload SHA-256/SHA-512, and immutable OCI
digest where an existing image is consumed. The builder itself is bound by an
exact SHA-256 input tree covering the two Dockerfiles, build/material tools, and
QEMU smoke oracle; validation rejects a checkout that differs from that tree.

The lock includes the accepted guest-components, Kata, downstream Trustee, and
Extensions sources; the exact historical upstream Trustee commit used by the
AS image; the existing Codewire Talos-extension base; the BuildKit SBOM
scanner; and the exact `iscsi-tools` and `util-linux-tools` package inputs. The
Guest container and disk images bind their commit-derived tags, immutable
manifests, workflow and recipe hashes, and available Sigstore-wrapped
attestations; the container additionally requires exact source labels and an
SPDX attestation. Each Trustee image binds its source commit/tree and dual-hashed
archive, commit-derived publication tag, Dockerfile and workflow hashes, amd64
platform manifest, and immutable index digest. KBS and RVPS are required to be
the same downstream combined image with the same embedded SBOM and SLSA
provenance attestations. The latter two Talos packages are restricted by
contract to the `servernet-confidential-storage-only` installer profile. Infra
owns actually selecting them on that profile.

The `extensions` source entry binds the accepted Talos-extension base, while the
separate builder input tree identifies the exact executable recipe even though
the lock is necessarily stored beside that recipe. Kata's upstream guest-image
recipe resolves distribution packages while it runs, so its final artifact
digest, SBOM, and provenance—not an assumption of future byte-for-byte
reproduction—form the immutable publication unit. Longhorn is intentionally
absent from this build boundary: the cluster consumes the stock CSI deployment
and this artifact supplies only the Kata guest/runtime contract above it.

`build.sh` has no registry login or push path. The deployment branch keeps that
source/build boundary separate from its checked-in GitHub Actions publication
overlay. It can:

- validate and download-check every source lock;
- prepare exact Kata source with the accepted guest-components revision;
- derive the immutable guest-components child tag from that revision, the
  locked Ubuntu variant, and the lock's single `linux/amd64` platform, avoiding
  a dependency on unrelated multi-architecture manifest assembly;
- add `dmsetup` beside the already required `cryptsetup-bin` and `e2fsprogs` in
  the measured guest rootfs, then prove `cryptsetup`, `dmsetup`, `mkfs.ext4`, and
  `resize2fs` exist in the resulting confidential image;
- export the accepted Kata Talos extension base through BuildKit without
  container-runtime pseudo-files, require exactly `manifest.yaml` plus
  `rootfs/`, and overlay the exact confidential payload inside that `rootfs/`;
- require runtime-rs to render OCI DNS fields as resolver directives and prove
  the built confidential guest starts with an empty `/etc/resolv.conf`, so the
  sandbox DNS supplied at launch is authoritative rather than appended to a
  build-host resolver;
- install the commodity Cloud Hypervisor config and shim from the same pinned
  runtime-rs archive, then parse the final OCI config and reject legacy
  Go-runtime fields before publication;
- bind the confidential runtime to the 50 GiB first-use storage contract:
  image-rs accepts a per-guest resource deadline (Codewire selects 300 seconds
  for fresh attestation), CDH receives 1200 seconds for the complete zero scan
  and journaled dm-integrity initialization, and runtime-rs receives 1350
  seconds for the containing image-pull and `CreateContainer` operation;
- build only the Dev SNP artifact closure (agent, CDH, kernel, SEV firmware,
  SNP QEMU, runtime-rs shim, `kata-ctl`, confidential image/initrd, and the
  composable CoCo guest-extension disk), excluding
  unrelated hypervisors and distro images from both failure scope and the final
  tarball; the verifier requires the runtime-rs shim, QEMU-SNP configuration,
  and every configured guest-extension image at their canonical archive paths
  and rejects a deprecated Go-runtime shim;
- build the host Kata shim with the static runtime profile and reject any
  static tarball or final extension layer whose shim contains `PT_INTERP` or
  `DT_NEEDED`, preserving the Talos host ABI;
- emit deterministic SPDX 2.3 material SBOM and SLSA/in-toto provenance JSON.

Run the source-only gates:

```bash
./hack/codewire-confidential-storage/build.sh verify
./hack/codewire-confidential-storage/build.sh plan
./hack/codewire-confidential-storage/build.sh verify-guest-source /path/to/guest-components
./hack/codewire-confidential-storage/build.sh verify-guest-publication
./hack/codewire-confidential-storage/build.sh verify-trustee-sources /path/to/trustee
./hack/codewire-confidential-storage/build.sh verify-trustee-publications
python3 -m unittest discover -s hack/codewire-confidential-storage/tests -p 'test_*.py'
shellcheck hack/codewire-confidential-storage/build.sh
```

To re-check the public immutable archives:

```bash
./hack/codewire-confidential-storage/build.sh fetch-archives /tmp/codewire-source-cache
```

`verify-guest-publication` resolves the source-derived tag to its locked
manifest, checks the exact source labels, and verifies the locked SPDX and SLSA
Sigstore bundles bind both that manifest and the downstream source commit.
`verify-trustee-publications` resolves every distinct source-derived tag back to
the locked index digest, selects the exact amd64 manifest, and checks the
combined KBS/RVPS image's SPDX and SLSA layers. They are the networked
counterparts to the local source/recipe oracles; none of these commands
publishes or mutates registry state.

The expensive amd64 recipe is deliberately separate from publication:

```bash
./hack/codewire-confidential-storage/build.sh \
  kata-static _out/confidential-storage/kata-static.tar.zst
./hack/codewire-confidential-storage/build.sh \
  kata-extension _out/confidential-storage/kata-static.tar.zst \
  _out/confidential-storage/kata-extension
```

When the guest-components target itself is the unresolved boundary, build only
that immutable input before starting the full Kata closure:

```bash
./hack/codewire-confidential-storage/build.sh \
  kata-guest-components _out/confidential-storage/kata-static-coco-guest-components.tar.zst
```

Successful builds remove their private scratch worktree. Failed builds retain
it and print the exact path so the target's local build log remains available.

The default scratch root is the ignored
`hack/codewire-confidential-storage/_out/scratch` directory. Set
`CODEWIRE_CONFIDENTIAL_STORAGE_SCRATCH_ROOT` to another absolute, dedicated
directory when needed. The root must permit execution because the Kata build
runs its checked-out helper scripts there; the wrapper probes that property and
fails before compilation with a direct diagnostic. The recipe only removes its
own `codewire-confidential-storage.*` children directly beneath that root. The
builder normalizes public source checkout modes independently of the invoking
shell umask and rejects a libseccomp installer that the unprivileged builder UID
cannot execute.

The outputs are local OCI archives plus non-secret material receipts. Only
`.github/workflows/downstream-confidential-storage.yml`, after an authorized
push to the exact deployment branch, may pass one of those archives to
`publish.sh`. Pull requests run the source-only and publication-contract gates;
they never publish or perform the expensive Kata build. The accepted PR head is
then built once by the deployment-branch push, booted under QEMU TCG, and copied
with all of its embedded BuildKit SPDX/SLSA attestations to
`ghcr.io/noeljackson/kata-containers`.

The immutable tag is
`<kata-version>-codewire-confidential-storage-<full-source-lock-sha256>`.
`publish.sh` rejects any other repository, event, ref, checkout head, or dirty
tracked checkout. It refuses to overwrite an existing tag with different
content, accepts an exact digest as an idempotent retry, verifies the published
index, platform, source labels, and matching embedded attestation descriptor,
and emits a non-secret receipt. GitHub OIDC adds a registry provenance
attestation for the exact deployment commit after the copy. There is no manual
dispatch, release, moving tag, or local publication mode.

Publication remains OP-1 and requires separate action-scoped authority for the
deployment push. Never replace a failed exact build with an upstream static
tarball, a branch/tag source, or a commodity/local-path fallback.

Before publication, directly boot the exact final OCI payload under local QEMU
TCG:

```bash
CODEWIRE_CONFIDENTIAL_STORAGE_SCRATCH_ROOT="$PWD/_out/scratch" \
  ./hack/codewire-confidential-storage/qemu-tcg-boot-smoke \
  _out/confidential-storage/kata-extension/kata-extension.oci.tar
```

The smoke parses both measured-disk bindings from the final runtime-rs config,
resolves the packaged kernel symlink inside the immutable payload, and boots
that kernel with the packaged confidential root and CoCo extension disks. It
also supplies a canonical minimal Init-Data block. The gate requires dm-verity
root activation, the extension mount, Kata Agent and Attestation Agent launch,
and the clean fail-closed shutdown produced when the TCG sample attester cannot
bind required Init-Data. It retains a bounded QEMU and serial-log directory on
failure and emits only fixed structural claims on success. This is a fast
guest-boot and non-TEE rejection contract test; it does not emulate `/dev/sev`,
produce an SNP report, authorize a workload, or replace live SNP attestation
and storage acceptance.

The source lock also binds the final QEMU-SNP guest-side `overhead_memory` to
2048 MiB. The downstream packaging overlay applies this deployment value
without modifying or rebuilding the immutable upstream Kata binaries and
measured guest disks. Runtime-rs static sizing launches the VM with the
workload memory limit plus this overhead, including the encrypted `/run`
workspace used by guest image pulling.

Kubernetes RuntimeClass overhead is a separate pod-cgroup budget. It must cover
the guest overhead plus the host QEMU margin; making it equal to the guest
overhead leaves no room for QEMU and causes a memory-cgroup OOM. Codewire
preserves the upstream SNP margin when changing the guest budget:
`2048 + (2048 - 128) = 3968 MiB`. Change these contracts coherently, and
require the final-archive smoke plus a live QEMU memory receipt before
acceptance.

The same lock owns the confidential first-use CDH/runtime-rs deadline pair. The
guest resource request selected by the product must remain below CDH, CDH must
remain below runtime-rs `CreateContainer`, and the Kubernetes kubelet and
product readiness deadlines must remain larger still. These are bounded caps
for an intentionally size-linear 50 GiB operation, not a substitute for
phase/progress evidence or permission for larger volumes.
