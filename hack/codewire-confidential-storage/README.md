# Codewire confidential-storage build inputs

This directory owns the exact-source, non-publishing build boundary for the
single-node Dev confidential-storage milestone. `sources.lock.json` binds every
source by full Git commit, Git tree, codeload SHA-256/SHA-512, and immutable OCI
digest where an existing image is consumed.

The lock includes the accepted guest-components, Kata, Longhorn, and Trustee
sources; the existing Codewire Talos-extension base; the official Longhorn
v1.12.0 amd64 manager runtime base; the BuildKit SBOM scanner; Trustee v0.21.0
images; and the exact `iscsi-tools` and `util-linux-tools` package inputs. Every
image is bound by
manifest digest. The latter two packages are restricted by contract to the
`servernet-confidential-storage-only` installer profile. Infra owns actually
selecting them on that profile.

The `extensions` source entry binds the accepted Talos-extension base. OP-1
must additionally record the exact merged WI-4 builder commit. Kata's upstream
guest-image recipe resolves distribution packages while it runs, so its final
artifact digest, SBOM, and provenance—not an assumption of future byte-for-byte
reproduction—form the immutable publication unit. The Longhorn runtime path
does not consult mutable operating-system repositories.

`build.sh` has no registry login or push path. It can:

- validate and download-check every source lock;
- prepare exact Kata source with the accepted guest-components revision;
- add `dmsetup` beside the already required `cryptsetup-bin` and `e2fsprogs` in
  the measured guest rootfs, then prove `cryptsetup`, `dmsetup`, `mkfs.ext4`, and
  `resize2fs` exist in the resulting confidential image;
- export the accepted Kata Talos extension base through BuildKit without
  container-runtime pseudo-files, require exactly `manifest.yaml` plus
  `rootfs/`, and overlay the exact confidential payload inside that `rootfs/`;
- build only the Dev SNP artifact closure (agent, CDH, kernel, SEV firmware,
  SNP QEMU, Go shim, and confidential image/initrd), excluding unrelated
  hypervisors and distro images from both failure scope and the final tarball;
- build the host Kata shim with the static runtime profile and reject any
  static tarball or final extension layer whose shim contains `PT_INTERP` or
  `DT_NEEDED`, preserving the Talos host ABI;
- build the exact Longhorn manager OCI image with a deterministic embedded
  build date, inheriting its runtime packages from the immutable official
  v1.12.0 image instead of consulting mutable OS repositories; and
- emit deterministic SPDX 2.3 material SBOM and SLSA/in-toto provenance JSON.

Run the source-only gates:

```bash
./hack/codewire-confidential-storage/build.sh verify
./hack/codewire-confidential-storage/build.sh plan
python3 -m unittest discover -s hack/codewire-confidential-storage/tests -p 'test_*.py'
shellcheck hack/codewire-confidential-storage/build.sh
```

To re-check the public immutable archives:

```bash
./hack/codewire-confidential-storage/build.sh fetch-archives /tmp/codewire-source-cache
```

The expensive amd64 recipe is deliberately separate from publication:

```bash
./hack/codewire-confidential-storage/build.sh \
  kata-static _out/confidential-storage/kata-static.tar.zst
./hack/codewire-confidential-storage/build.sh \
  kata-extension _out/confidential-storage/kata-static.tar.zst \
  _out/confidential-storage/kata-extension
./hack/codewire-confidential-storage/build.sh \
  longhorn-image _out/confidential-storage/longhorn-manager
```

Set `CODEWIRE_CONFIDENTIAL_STORAGE_SCRATCH_ROOT` to an absolute, dedicated
directory when `/tmp` is too small for the Kata source and build outputs. The
recipe only removes its own `codewire-confidential-storage.*` children directly
beneath that root.

The outputs are local OCI archives plus non-secret material receipts. Publishing
them is OP-1 and requires its separate action-scoped authority. Never replace a
failed exact build with an upstream static tarball, a branch/tag source, or a
commodity/local-path fallback.
