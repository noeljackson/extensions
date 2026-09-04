#!/usr/bin/env bash

set -euo pipefail

# This builder consumes and emits public source and artifacts. Normalize source
# checkout modes instead of inheriting a caller's private umask: several Kata
# builder containers run as the invoking UID and execute root-owned COPY inputs.
# mktemp still creates each scratch work directory as mode 0700.
umask 022

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
default_scratch_root="${script_dir}/_out/scratch"
lock_file="${script_dir}/sources.lock.json"
materials_tool="${script_dir}/materials.py"
source_names=(
  extensions
  guest_components
  kata_containers
  trustee
  trustee_attestation_service
)
kata_parallel_targets=(
  agent-tarball
  pause-image-tarball
  coco-guest-components-tarball
  kernel-tarball
  ovmf-sev-tarball
  qemu-snp-experimental-tarball
  kata-ctl-tarball
  serial-targets
)
kata_serial_targets=(
  rootfs-image-confidential-tarball
  rootfs-image-coco-extension-tarball
  rootfs-initrd-confidential-tarball
)
kata_post_image_targets=(
  shim-v2-rust-tarball
)
kata_final_inputs=(
  kata-static-kernel.tar.zst
  kata-static-ovmf-sev.tar.zst
  kata-static-qemu-snp-experimental.tar.zst
  kata-static-rootfs-image-confidential.tar.zst
  kata-static-rootfs-image-coco-extension.tar.zst
  kata-static-rootfs-initrd-confidential.tar.zst
  kata-static-shim-v2-rust.tar.zst
  kata-static-kata-ctl.tar.zst
)

usage() {
  cat <<'EOF'
Usage: build.sh COMMAND [OPTIONS]

Commands:
  verify
      Validate the source lock and emit deterministic source SBOM/provenance.
  fetch-archives CACHE_DIR
      Download every immutable source archive and verify SHA-256 plus SHA-512.
  verify-guest-source GUEST_COMPONENTS_REPOSITORY
      Verify the Guest image recipes against their exact source commit.
  verify-guest-publication
      Verify both Guest tags/manifests plus source labels, SBOM, and provenance.
  verify-trustee-sources TRUSTEE_REPOSITORY
      Verify every consumed Trustee image recipe against its exact source commit.
  verify-trustee-publications
      Verify each public Trustee tag, index, platform manifest, and attestation digest.
  plan
      Print the exact non-publishing build plan.
  prepare-kata KATA_REPOSITORY OUTPUT_DIRECTORY
      Copy and prepare the exact Kata source with the accepted guest/tool inputs.
  kata-static OUTPUT_TARBALL [KATA_REPOSITORY]
      Build the exact amd64 Kata static tarball. Registry caches and pushes are disabled.
  kata-guest-components OUTPUT_TARBALL [KATA_REPOSITORY]
      Build only the exact CoCo guest-components tarball for a focused local diagnostic loop.
  verify-kata-static KATA_TARBALL
      Prove the confidential image contains the required block-encryption/ext4 tools.
  kata-extension KATA_TARBALL OUTPUT_DIRECTORY
      Produce an attested amd64 OCI archive; never pushes.
Image publication is intentionally absent. OP-1 must use a separately reviewed wrapper
that preserves these exact inputs and records the resulting registry digests.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is missing: $1"
}

lock_value() {
  jq -er "$1" "$lock_file"
}

lock_sha256() {
  sha256sum "$lock_file" | awk '{print $1}'
}

verify_builder_checkout() {
  require_command python3
  python3 "$materials_tool" --lock "$lock_file" validate >/dev/null
  python3 "$materials_tool" --lock "$lock_file" verify-builder --repo "$repo_root" >/dev/null
}

verify_guest_components_artifact() {
  require_command oras
  require_command python3
  require_command skopeo
  python3 "$materials_tool" --lock "$lock_file" \
    verify-guest-image-publication
}

remove_tree() {
  local task_tree=$1
  local scratch_root=${CODEWIRE_CONFIDENTIAL_STORAGE_SCRATCH_ROOT:-$default_scratch_root}
  [[ -n "$task_tree" && -d "$task_tree" && "$scratch_root" == /* ]] || return 0
  scratch_root="$(cd "$scratch_root" && pwd -P)"
  [[ "$scratch_root" != / ]] || die "scratch root cannot be /"
  local task_parent task_name
  task_parent="$(cd "$(dirname "$task_tree")" && pwd -P)"
  task_name="$(basename "$task_tree")"
  if [[ "$task_parent" == "$scratch_root" && "$task_name" == codewire-confidential-storage.* ]]; then
    find "$task_tree" -depth -delete 2>/dev/null ||
      printf 'warning: root-owned scratch remains at %s\n' "$task_tree" >&2
  fi
}

cleanup_or_retain_work_dir() {
  local rc=$?
  local task_tree=$1
  if (( rc == 0 )); then
    remove_tree "$task_tree"
  elif [[ -n "$task_tree" && -d "$task_tree" ]]; then
    chmod 0700 "$task_tree" 2>/dev/null || true
    printf 'error: failed build work directory retained at %s\n' "$task_tree" >&2
  fi
  return "$rc"
}

new_work_dir() {
  local scratch_root=${CODEWIRE_CONFIDENTIAL_STORAGE_SCRATCH_ROOT:-$default_scratch_root}
  [[ "$scratch_root" == /* ]] || die "scratch root must be absolute"
  mkdir -p "$scratch_root"
  scratch_root="$(cd "$scratch_root" && pwd -P)"
  [[ "$scratch_root" != / ]] || die "scratch root cannot be /"
  local exec_probe
  exec_probe="$(mktemp "${scratch_root}/.codewire-exec-probe.XXXXXX")"
  printf '#!/bin/sh\nexit 0\n' >"$exec_probe"
  chmod 0700 "$exec_probe"
  if ! "$exec_probe"; then
    find "$exec_probe" -delete
    die "scratch root does not permit executing build helpers; set CODEWIRE_CONFIDENTIAL_STORAGE_SCRATCH_ROOT to an executable dedicated directory"
  fi
  find "$exec_probe" -delete
  mktemp -d "${scratch_root}/codewire-confidential-storage.XXXXXX"
}

checkout_locked_source() {
  local source_name=$1
  local output=$2
  local repository revision
  repository="$(lock_value ".sources.${source_name}.repository")"
  revision="$(lock_value ".sources.${source_name}.revision")"
  git init --quiet "$output"
  git -C "$output" remote add origin "${repository}.git"
  git -C "$output" fetch --quiet --depth=1 origin "$revision"
  git -C "$output" checkout --quiet --detach FETCH_HEAD
  python3 "$materials_tool" --lock "$lock_file" verify-git --source "$source_name" --repo "$output"
}

unique_file() {
  local root=$1
  local pattern=$2
  local -a matches
  mapfile -t matches < <(
    find "$root" \( -type f -o -type l \) -path "$pattern" -print
  )
  [[ ${#matches[@]} -eq 1 ]] || die "expected exactly one ${pattern}, found ${#matches[@]}"
  printf '%s\n' "${matches[0]}"
}

unique_directory() {
  local root=$1
  local pattern=$2
  local -a matches
  mapfile -t matches < <(
    find "$root" -type d -path "$pattern" -print
  )
  [[ ${#matches[@]} -eq 1 ]] || die "expected exactly one ${pattern}, found ${#matches[@]}"
  printf '%s\n' "${matches[0]}"
}

replace_exact_tree() {
  local source=$1
  local destination=$2
  [[ -d "$source" && ! -L "$source" ]] || die "exact source tree is missing: $source"
  [[ "$destination" == */rootfs/usr/local/* && "$destination" != */..* ]] ||
    die "refusing unsafe extension tree destination: $destination"
  if [[ -e "$destination" || -L "$destination" ]]; then
    find "$destination" -depth -delete
  fi
  mkdir -p "$(dirname "$destination")"
  cp -a "$source" "$destination"
  diff -qr --no-dereference "$source" "$destination" >/dev/null ||
    die "final extension tree differs after copying $source"
}

has_executable_mode() {
  local path=$1
  local mode
  [[ -f "$path" ]] || return 1
  mode="$(stat -c '%a' -- "$path")" || return 1
  (( (8#$mode & 0111) != 0 ))
}

debugfs_has_any() {
  local image=$1
  local name=$2
  shift 2
  local candidate output
  for candidate in "$@"; do
    output="$(debugfs -R "stat ${candidate}" "$image" 2>&1 || true)"
    if [[ "$output" != *'File not found'* && "$output" == *'Inode:'* ]]; then
      return 0
    fi
  done
  die "confidential guest image lacks ${name} at every allowed path"
}

verify_kata_static() (
  local tarball=$1
  [[ -f "$tarball" ]] || die "Kata static tarball is missing: $tarball"
  require_command tar
  require_command zstd
  require_command debugfs
  require_command dd
  require_command jq
  require_command python3
  require_command readelf
  require_command sfdisk

  local audit_dir image coco_extension_image coco_root_hash rootfs shim kata_ctl runtime_config commodity_runtime_config cdh_output resolver_output partition_json sector_size partition_start partition_size
  local qemu_snp qemu_snp_libs qemu_snp_data firmware kernel kernel_link
  local -a kernels
  local program_headers dynamic_tags
  audit_dir="$(new_work_dir)"
  trap 'cleanup_or_retain_work_dir "${audit_dir:-}"' EXIT
  tar --zstd -xf "$tarball" -C "$audit_dir"
  image="$(unique_file "$audit_dir" '*/opt/kata/share/kata-containers/kata-containers-confidential.img')"
  coco_extension_image="$(unique_file "$audit_dir" '*/opt/kata/share/kata-containers/kata-containers-coco-extension.img')"
  [[ -f "$coco_extension_image" && -s "$coco_extension_image" ]] || \
    die "Kata static tarball has no non-empty CoCo guest extension image"
  shim="$(unique_file "$audit_dir" '*/opt/kata/runtime-rs/bin/containerd-shim-kata-v2')"
  has_executable_mode "$shim" || die "exact Kata runtime-rs shim has no executable mode bit"
  program_headers="$(LC_ALL=C readelf -l "$shim")" \
    || die "exact Kata runtime shim has unreadable program headers"
  if grep -Eq 'INTERP|Requesting program interpreter' <<<"$program_headers"; then
    die "exact Kata runtime shim requires an ELF interpreter"
  fi
  dynamic_tags="$(LC_ALL=C readelf -d "$shim")" \
    || die "exact Kata runtime shim has an unreadable dynamic section"
  if grep -q '(NEEDED)' <<<"$dynamic_tags"; then
    die "exact Kata runtime shim has dynamic library dependencies"
  fi
  if find "$audit_dir" -type f -path '*/opt/kata/bin/containerd-shim-kata-v2' -print -quit | grep -q .; then
    die "Kata static tarball unexpectedly contains the deprecated Go runtime shim"
  fi
  kata_ctl="$(unique_file "$audit_dir" '*/opt/kata/bin/kata-ctl')"
  has_executable_mode "$kata_ctl" || die "exact Kata runtime-rs volume helper has no executable mode bit"
  qemu_snp="$(unique_file "$audit_dir" '*/opt/kata/bin/qemu-system-x86_64-snp-experimental')"
  has_executable_mode "$qemu_snp" || die "exact Kata QEMU-SNP binary has no executable mode bit"
  qemu_snp_libs="$(unique_directory "$audit_dir" '*/opt/kata/lib/kata-qemu-snp-experimental')"
  [[ -n "$(find "$qemu_snp_libs" -type f -print -quit)" ]] ||
    die "exact Kata QEMU-SNP library tree is empty"
  qemu_snp_data="$(unique_directory "$audit_dir" '*/opt/kata/share/kata-qemu-snp-experimental/qemu')"
  [[ -n "$(find "$qemu_snp_data" -type f -print -quit)" ]] ||
    die "exact Kata QEMU-SNP data tree is empty"
  firmware="$(unique_file "$audit_dir" '*/opt/kata/share/ovmf/AMDSEV.fd')"
  [[ -s "$firmware" ]] || die "exact Kata AMD SEV firmware is empty"
  mapfile -t kernels < <(
    find "$audit_dir" -regextype posix-extended -type f \
      -regex '.*/opt/kata/share/kata-containers/vmlinuz-[0-9]+(\.[0-9]+)*-[0-9]+' -print
  )
  [[ ${#kernels[@]} -eq 1 ]] ||
    die "expected exactly one versioned Kata kernel, found ${#kernels[@]}"
  kernel="${kernels[0]}"
  [[ -s "$kernel" ]] || die "exact Kata kernel is empty"
  kernel_link="$(unique_file "$audit_dir" '*/opt/kata/share/kata-containers/vmlinuz.container')"
  [[ -L "$kernel_link" ]] || die "exact Kata vmlinuz.container is not a symbolic link"
  [[ "$(readlink "$kernel_link")" == "$(basename "$kernel")" ]] ||
    die "exact Kata vmlinuz.container does not select the versioned kernel"
  runtime_config="$(unique_file "$audit_dir" '*/opt/kata/share/defaults/kata-containers/runtime-rs/configuration-qemu-snp-runtime-rs.toml')"
  grep -Fqx '[hypervisor.qemu]' "$runtime_config" \
    || die "runtime-rs QEMU-SNP configuration lacks its hypervisor table"
  grep -Fqx 'confidential_guest = true' "$runtime_config" \
    || die "runtime-rs QEMU-SNP configuration does not enable confidential guests"
  grep -Fqx 'shared_fs = "none"' "$runtime_config" \
    || die "runtime-rs QEMU-SNP configuration does not preserve shared_fs=none"
  grep -Fqx 'path = "/opt/kata/share/kata-containers/kata-containers-coco-extension.img"' "$runtime_config" \
    || die "runtime-rs QEMU-SNP configuration does not consume the built CoCo guest extension image"
  coco_root_hash="$(unique_file "$audit_dir" '*/opt/kata/share/kata-containers/root_hash_coco-extension.txt')"
  python3 - "$runtime_config" "$coco_root_hash" <<'PY' || \
    die "runtime-rs QEMU-SNP configuration is not bound to the built CoCo extension measurement"
import pathlib
import sys
import tomllib

config_path, root_hash_path = map(pathlib.Path, sys.argv[1:])
root_hash_lines = [line.strip() for line in root_hash_path.read_text().splitlines() if line.strip()]
if len(root_hash_lines) != 1:
    raise SystemExit("CoCo extension root hash must contain exactly one non-empty line")
config = tomllib.loads(config_path.read_text())
images = config.get("hypervisor", {}).get("qemu", {}).get("guest_extension_images", [])
coco = [image for image in images if image.get("name") == "coco"]
if len(coco) != 1 or coco[0].get("verity_params") != root_hash_lines[0]:
    raise SystemExit("CoCo extension verity params do not match its root hash")
PY
  commodity_runtime_config="$(unique_file "$audit_dir" '*/opt/kata/share/defaults/kata-containers/runtime-rs/configuration-clh-runtime-rs.toml')"
  grep -Fqx '[hypervisor.clh]' "$commodity_runtime_config" \
    || die "runtime-rs Cloud Hypervisor configuration lacks its hypervisor table"
  grep -Eq '^dial_timeout_ms = [1-9][0-9]*$' "$commodity_runtime_config" \
    || die "runtime-rs Cloud Hypervisor configuration lacks its millisecond dial timeout"
  ! grep -Eq '^dial_timeout[[:space:]]*=' "$commodity_runtime_config" \
    || die "runtime-rs Cloud Hypervisor configuration contains a legacy Go-runtime dial timeout"

  partition_json="$(sfdisk --json "$image")"
  sector_size="$(jq -er '.partitiontable.sectorsize | select(type == "number" and . > 0)' <<<"$partition_json")"
  partition_start="$(
    jq -er '[.partitiontable.partitions[] | select(.bootable == true and (.type == "83" or .type == "0x83"))]
      | if length == 1 then .[0].start else error("expected one bootable Linux root partition") end' \
      <<<"$partition_json"
  )"
  partition_size="$(
    jq -er '[.partitiontable.partitions[] | select(.bootable == true and (.type == "83" or .type == "0x83"))]
      | if length == 1 then .[0].size else error("expected one bootable Linux root partition") end' \
      <<<"$partition_json"
  )"
  rootfs="$audit_dir/rootfs.ext4"
  dd if="$image" of="$rootfs" bs="$sector_size" skip="$partition_start" count="$partition_size" \
    iflag=fullblock conv=sparse status=none

  while IFS=$'\t' read -r tool path_a path_b; do
    debugfs_has_any "$rootfs" "$tool" "$path_a" "$path_b"
  done < <(
    jq -r '.kata_build_contract.required_guest_tools | to_entries[] | [.key, .value[0], .value[1]] | @tsv' "$lock_file"
  )

  resolver_output="$(debugfs -R 'stat /etc/resolv.conf' "$rootfs" 2>&1 || true)"
  if [[ "$resolver_output" == *'File not found'* || "$resolver_output" != *'Inode:'* ]]; then
    die "confidential guest image lacks /etc/resolv.conf"
  fi
  grep -Eq '(^|[[:space:]])Size:[[:space:]]+0([[:space:]]|$)' <<<"$resolver_output" \
    || die "confidential guest image retains a non-empty build-host resolver"

  cdh_output="$(debugfs -R 'stat /usr/local/bin/confidential-data-hub' "$rootfs" 2>&1 || true)"
  if [[ "$cdh_output" == *'File not found'* || "$cdh_output" != *'Inode:'* ]]; then
    die "confidential guest image lacks confidential-data-hub"
  fi
  printf 'Kata static tarball contains the exact runtime, empty resolver, and required guest storage tools\n'
)

bind_extension_manifest_version() {
  local static_root=$1
  local manifest=$2
  local source
  local kata_version expected_kata_version

  source="$static_root/opt/kata/VERSION"
  [[ -f "$source" ]] || die "exact Kata archive lacks VERSION"
  [[ "$(grep -cve '^[[:space:]]*$' "$source")" -eq 1 ]] \
    || die "exact Kata archive VERSION must contain one non-empty line"
  kata_version="$(sed -n '/[^[:space:]]/ { s/[[:space:]]*$//; p; }' "$source")"
  expected_kata_version="$(lock_value '.kata_build_contract.kata_version')"
  [[ "$kata_version" == "$expected_kata_version" ]] \
    || die "exact Kata archive version does not match the source lock"
  python3 - "$manifest" "$kata_version" <<'PY' || \
    die "failed to bind the Talos extension manifest to the exact Kata version"
import pathlib
import re
import sys

manifest_path = pathlib.Path(sys.argv[1])
version = sys.argv[2]
lines = manifest_path.read_text().splitlines()
if lines.count("version: v1alpha1") != 1:
    raise SystemExit("expected the Talos v1alpha1 manifest schema")
metadata = [index for index, line in enumerate(lines) if line == "metadata:"]
if len(metadata) != 1:
    raise SystemExit("expected exactly one metadata block")
metadata_start = metadata[0]
metadata_end = next(
    (index for index in range(metadata_start + 1, len(lines)) if lines[index] and not lines[index].startswith(" ")),
    len(lines),
)
matches = [
    index
    for index in range(metadata_start + 1, metadata_end)
    if re.fullmatch(r"  version:\s*.*", lines[index])
]
if len(matches) != 1:
    raise SystemExit("expected exactly one metadata version")
lines[matches[0]] = f'  version: "{version}"'
manifest_path.write_text("\n".join(lines) + "\n")
PY
  grep -Fqx 'version: v1alpha1' "$manifest" \
    || die "Talos extension manifest schema changed"
  grep -Fqx "  version: \"${kata_version}\"" "$manifest" \
    || die "Talos extension metadata does not identify the exact Kata version"
}

overlay_confidential_payload() {
  local static_root=$1
  local rootfs=$2
  local source destination confidential_verity_params qemu_snp_config expected_overhead_memory
  local cdh_api_timeout_seconds cdh_api_timeout_ms create_container_timeout_seconds
  local qemu_snp_libs qemu_snp_data firmware kernel kernel_link kernel_dir
  local -a kernels

  source="$static_root/opt/kata/runtime-rs/bin/containerd-shim-kata-v2"
  has_executable_mode "$source" || die "exact Kata runtime-rs shim is missing or has no executable mode bit"
  install -D -m 0755 "$source" "$rootfs/usr/local/bin/containerd-shim-kata-v2"
  ln -sfn containerd-shim-kata-v2 "$rootfs/usr/local/bin/containerd-shim-kata-qemu-snp-v2"

  source="$static_root/opt/kata/bin/kata-ctl"
  has_executable_mode "$source" || die "exact kata-ctl is missing or has no executable mode bit"
  install -D -m 0755 "$source" "$rootfs/usr/local/bin/kata-ctl"

  source="$static_root/opt/kata/bin/qemu-system-x86_64-snp-experimental"
  has_executable_mode "$source" || die "exact QEMU-SNP binary is missing or has no executable mode bit"
  install -D -m 0755 "$source" "$rootfs/usr/local/libexec/qemu-system-x86_64-snp-experimental"
  cmp -s "$source" "$rootfs/usr/local/libexec/qemu-system-x86_64-snp-experimental" ||
    die "final QEMU-SNP binary differs after copying"

  qemu_snp_libs="$static_root/opt/kata/lib/kata-qemu-snp-experimental"
  replace_exact_tree "$qemu_snp_libs" "$rootfs/usr/local/lib/kata-qemu-snp-experimental"
  qemu_snp_data="$static_root/opt/kata/share/kata-qemu-snp-experimental/qemu"
  replace_exact_tree "$qemu_snp_data" "$rootfs/usr/local/share/kata-qemu-snp-experimental/qemu"

  firmware="$static_root/opt/kata/share/ovmf/AMDSEV.fd"
  [[ -s "$firmware" ]] || die "exact AMD SEV firmware is missing or empty"
  install -D -m 0644 "$firmware" "$rootfs/usr/local/share/ovmf/AMDSEV.fd"
  cmp -s "$firmware" "$rootfs/usr/local/share/ovmf/AMDSEV.fd" ||
    die "final AMD SEV firmware differs after copying"

  mapfile -t kernels < <(
    find "$static_root/opt/kata/share/kata-containers" -regextype posix-extended \
      -maxdepth 1 -type f -regex '.*/vmlinuz-[0-9]+(\.[0-9]+)*-[0-9]+' -print
  )
  [[ ${#kernels[@]} -eq 1 ]] ||
    die "expected exactly one versioned Kata kernel, found ${#kernels[@]}"
  kernel="${kernels[0]}"
  kernel_link="$static_root/opt/kata/share/kata-containers/vmlinuz.container"
  [[ -s "$kernel" && -L "$kernel_link" ]] ||
    die "exact Kata kernel payload is incomplete"
  [[ "$(readlink "$kernel_link")" == "$(basename "$kernel")" ]] ||
    die "exact Kata vmlinuz.container does not select the versioned kernel"
  kernel_dir="$rootfs/usr/local/share/kata-containers"
  find "$kernel_dir" -maxdepth 1 \( -type f -o -type l \) -name 'vmlinuz-*' -delete
  if [[ -e "$kernel_dir/vmlinuz.container" || -L "$kernel_dir/vmlinuz.container" ]]; then
    find "$kernel_dir/vmlinuz.container" -maxdepth 0 -delete
  fi
  install -D -m 0644 "$kernel" "$kernel_dir/$(basename "$kernel")"
  cp -a "$kernel_link" "$kernel_dir/vmlinuz.container"
  cmp -s "$kernel" "$kernel_dir/$(basename "$kernel")" ||
    die "final Kata kernel differs after copying"
  [[ "$(readlink "$kernel_dir/vmlinuz.container")" == "$(basename "$kernel")" ]] ||
    die "final vmlinuz.container does not select the exact Kata kernel"

  for destination in \
    kata-containers-confidential.img \
    kata-containers-coco-extension.img \
    kata-containers-initrd-confidential.img \
    root_hash_confidential.txt \
    root_hash_coco-extension.txt; do
    source="$(unique_file "$static_root" "*/opt/kata/share/kata-containers/${destination}")"
    install -D -m 0644 "$source" "$rootfs/usr/local/share/kata-containers/${destination}"
    cmp -s "$source" "$rootfs/usr/local/share/kata-containers/${destination}" \
      || die "final Kata payload differs after copying ${destination}"
  done

  source="$(unique_file "$static_root" '*/opt/kata/share/defaults/kata-containers/runtime-rs/configuration-clh-runtime-rs.toml')"
  install -D -m 0644 "$source" "$rootfs/usr/local/share/kata-containers/configuration.toml"
  sed -i \
    -e 's#/opt/kata#/usr/local#g' \
    "$rootfs/usr/local/share/kata-containers/configuration.toml"
  grep -Eq '^enable_annotations = .*"cc_init_data"' "$rootfs/usr/local/share/kata-containers/configuration.toml" \
    || sed -i '/^enable_annotations = / s/]$/, "cc_init_data"]/' \
      "$rootfs/usr/local/share/kata-containers/configuration.toml"

  grep -Fqx '[hypervisor.clh]' "$rootfs/usr/local/share/kata-containers/configuration.toml" \
    || die "final commodity configuration lacks its runtime-rs Cloud Hypervisor table"
  grep -Eq '^dial_timeout_ms = [1-9][0-9]*$' "$rootfs/usr/local/share/kata-containers/configuration.toml" \
    || die "final commodity configuration lacks its runtime-rs millisecond dial timeout"
  ! grep -Eq '^dial_timeout[[:space:]]*=' "$rootfs/usr/local/share/kata-containers/configuration.toml" \
    || die "final commodity configuration contains a legacy Go-runtime dial timeout"

  source="$(unique_file "$static_root" '*/opt/kata/share/defaults/kata-containers/runtime-rs/configuration-qemu-snp-runtime-rs.toml')"
  qemu_snp_config="$rootfs/usr/local/share/kata-containers/configuration-qemu-snp.toml"
  install -D -m 0644 "$source" "$qemu_snp_config"
  expected_overhead_memory="$(lock_value '.kata_build_contract.qemu_snp_overhead_memory_mib')"
  cdh_api_timeout_seconds="$(lock_value '.kata_build_contract.cdh_api_timeout_seconds')"
  cdh_api_timeout_ms="$((cdh_api_timeout_seconds * 1000))"
  create_container_timeout_seconds="$(lock_value '.kata_build_contract.create_container_timeout_seconds')"
  [[ "$(grep -Ec '^overhead_memory = [0-9]+$' "$qemu_snp_config")" -eq 1 ]] \
    || die "QEMU-SNP configuration does not have exactly one memory-overhead assignment"
  sed -i \
    -e 's#/opt/kata#/usr/local#g' \
    -e 's#^image = "/usr/local/share/kata-containers/kata-containers.img"$#image = "/usr/local/share/kata-containers/kata-containers-confidential.img"#' \
    -e 's#path = "/usr/local/bin/qemu-system-x86_64"#path = "/usr/local/bin/qemu-system-x86_64-snp-experimental"#' \
    -e 's#valid_hypervisor_paths = \["/usr/local/bin/qemu-system-x86_64"\]#valid_hypervisor_paths = ["/usr/local/bin/qemu-system-x86_64-snp-experimental"]#' \
    -e 's#shared_fs = "virtio-fs"#shared_fs = "none"#' \
    -e "s#create_container_timeout = [0-9][0-9]*#create_container_timeout = ${create_container_timeout_seconds}#" \
    -e "s#cdh_api_timeout_ms = [0-9][0-9]*#cdh_api_timeout_ms = ${cdh_api_timeout_ms}#" \
    -e "s#^overhead_memory = [0-9][0-9]*\$#overhead_memory = ${expected_overhead_memory}#" \
    "$qemu_snp_config"
  IFS= read -r confidential_verity_params < \
    "$rootfs/usr/local/share/kata-containers/root_hash_confidential.txt"
  [[ -n "$confidential_verity_params" ]] || \
    die "confidential root image has no verity params"
  python3 - \
    "$rootfs/usr/local/share/kata-containers/configuration-qemu-snp.toml" \
    "$confidential_verity_params" <<'PY' || \
    die "failed to bind the QEMU-SNP configuration to the confidential root measurement"
import pathlib
import sys
import tomllib

config_path = pathlib.Path(sys.argv[1])
verity_params = sys.argv[2]
lines = config_path.read_text().splitlines()
matches = [index for index, line in enumerate(lines) if line.startswith("kernel_verity_params = ")]
if len(matches) != 1:
    raise SystemExit("expected exactly one kernel_verity_params assignment")
lines[matches[0]] = f'kernel_verity_params = "{verity_params}"'
config_path.write_text("\n".join(lines) + "\n")
config = tomllib.loads(config_path.read_text())
if config.get("hypervisor", {}).get("qemu", {}).get("kernel_verity_params") != verity_params:
    raise SystemExit("parsed kernel_verity_params does not match the confidential root hash")
PY
  grep -Eq '^enable_annotations = .*"cc_init_data"' "$rootfs/usr/local/share/kata-containers/configuration-qemu-snp.toml" \
    || sed -i '/^enable_annotations = / s/]$/, "cc_init_data"]/' \
      "$rootfs/usr/local/share/kata-containers/configuration-qemu-snp.toml"

  local annotations
  annotations="$(sed -nE 's/^enable_annotations = (.*)$/\1/p' "$rootfs/usr/local/share/kata-containers/configuration-qemu-snp.toml")"
  [[ -n "$annotations" ]] || die "QEMU-SNP configuration lacks enable_annotations"
  grep -Fq '"cc_init_data"' <<<"$annotations" || die "QEMU-SNP configuration rejects cc_init_data"
  grep -Fq '"kernel_params"' <<<"$annotations" || die "QEMU-SNP configuration rejects kernel_params"
  if grep -Eq '"(\.\*|\*)"' <<<"$annotations"; then
    die "QEMU-SNP configuration contains a wildcard annotation rule"
  fi
  python3 - "$qemu_snp_config" <<'PY' || \
    die "QEMU-SNP configuration admits an unsafe hypervisor annotation"
import pathlib
import sys
import tomllib

config = tomllib.loads(pathlib.Path(sys.argv[1]).read_text())
annotations = config.get("hypervisor", {}).get("qemu", {}).get("enable_annotations")
required = {"cc_init_data", "kernel_params"}
allowed = {
    "cc_init_data",
    "default_memory",
    "default_vcpus",
    "enable_iommu",
    "kernel_params",
    "kernel_verity_params",
}
if (
    not isinstance(annotations, list)
    or any(not isinstance(value, str) for value in annotations)
    or not required.issubset(annotations)
):
    raise SystemExit("required QEMU-SNP annotations are absent")
if any(value not in allowed for value in annotations):
    raise SystemExit("QEMU-SNP annotation allowlist is not exact")
PY
  grep -Eq '^shared_fs = "none"$' "$rootfs/usr/local/share/kata-containers/configuration-qemu-snp.toml" \
    || die "QEMU-SNP configuration does not preserve shared_fs=none"
  grep -Fqx "overhead_memory = ${expected_overhead_memory}" "$qemu_snp_config" \
    || die "QEMU-SNP configuration does not match the locked guest memory overhead"
  grep -Fqx "create_container_timeout = ${create_container_timeout_seconds}" "$qemu_snp_config" \
    || die "QEMU-SNP configuration does not match the bounded persistent-volume CreateContainer timeout"
  grep -Fqx "cdh_api_timeout_ms = ${cdh_api_timeout_ms}" "$qemu_snp_config" \
    || die "QEMU-SNP configuration does not match the bounded persistent-volume CDH timeout"
  grep -Fqx 'image = "/usr/local/share/kata-containers/kata-containers-confidential.img"' \
    "$rootfs/usr/local/share/kata-containers/configuration-qemu-snp.toml" \
    || die "QEMU-SNP configuration does not use its dedicated confidential root image"
  grep -Fqx "kernel_verity_params = \"$confidential_verity_params\"" \
    "$rootfs/usr/local/share/kata-containers/configuration-qemu-snp.toml" \
    || die "QEMU-SNP configuration does not use its confidential root measurement"
  grep -Fqx 'path = "/usr/local/share/kata-containers/kata-containers-coco-extension.img"' \
    "$rootfs/usr/local/share/kata-containers/configuration-qemu-snp.toml" \
    || die "QEMU-SNP configuration does not consume the overlaid CoCo guest extension image"
}

command=${1:-}
case "$command" in
  verify)
    require_command python3
    python3 "$materials_tool" --lock "$lock_file" validate
    python3 "$materials_tool" --lock "$lock_file" verify-builder --repo "$repo_root"
    python3 "$materials_tool" --lock "$lock_file" emit --output-dir "${script_dir}/_out"
    ;;

  fetch-archives)
    [[ $# -eq 2 ]] || die "fetch-archives requires CACHE_DIR"
    verify_builder_checkout
    require_command curl
    require_command jq
    cache_dir=$2
    mkdir -p "$cache_dir"
    for source_name in "${source_names[@]}"; do
      url="$(lock_value ".sources.${source_name}.archive.url")"
      curl --proto '=https' --tlsv1.2 --fail --location --retry 3 \
        --output "${cache_dir}/${source_name}.tar.gz" "$url"
    done
    python3 "$materials_tool" --lock "$lock_file" verify-archives --cache "$cache_dir"
    ;;

  verify-guest-source)
    [[ $# -eq 2 ]] || die "verify-guest-source requires GUEST_COMPONENTS_REPOSITORY"
    verify_builder_checkout
    python3 "$materials_tool" --lock "$lock_file" verify-guest-image-source \
      --repo "$2"
    ;;

  verify-guest-publication)
    [[ $# -eq 1 ]] || die "verify-guest-publication takes no arguments"
    verify_builder_checkout
    verify_guest_components_artifact
    ;;

  verify-trustee-sources)
    [[ $# -eq 2 ]] || die "verify-trustee-sources requires TRUSTEE_REPOSITORY"
    verify_builder_checkout
    # KBS and RVPS are two entrypoints in the same locked combined image.
    for component in attestation_service kbs; do
      python3 "$materials_tool" --lock "$lock_file" verify-trustee-image-source \
        --component "$component" --repo "$2"
    done
    ;;

  verify-trustee-publications)
    [[ $# -eq 1 ]] || die "verify-trustee-publications takes no arguments"
    verify_builder_checkout
    require_command oras
    require_command skopeo
    # Lock validation requires RVPS to be byte-for-byte identical to KBS.
    for component in attestation_service kbs; do
      python3 "$materials_tool" --lock "$lock_file" \
        verify-trustee-image-publication --component "$component"
    done
    ;;

  plan)
    require_command jq
    verify_builder_checkout
    jq -n \
      --arg platform "$(lock_value '.platforms[0]')" \
      --arg guest "$(lock_value '.sources.guest_components.revision')" \
      --arg kata "$(lock_value '.sources.kata_containers.revision')" \
      --arg trustee "$(lock_value '.sources.trustee.revision')" \
      --arg source_lock "$(lock_sha256)" \
      '{schema:"codewire.confidential-storage.build-plan/v1", mode:"no-push", platform:$platform, runtime_abi:"static", source_lock_sha256:$source_lock, sources:{guest_components:$guest,kata_containers:$kata,trustee:$trustee}, outputs:["kata-static.tar.zst","kata-extension.oci.tar","materials.spdx.json","provenance.in-toto.json"]}'
    ;;

  prepare-kata)
    [[ $# -eq 3 ]] || die "prepare-kata requires KATA_REPOSITORY OUTPUT_DIRECTORY"
    verify_builder_checkout
    python3 "$materials_tool" --lock "$lock_file" prepare-kata --repo "$2" --output "$3"
    ;;

  kata-static)
    [[ $# -eq 2 || $# -eq 3 ]] || die "kata-static requires OUTPUT_TARBALL [KATA_REPOSITORY]"
    verify_builder_checkout
    require_command docker
    require_command git
    require_command make
    require_command python3
    output_tarball=$2
    work_dir="$(new_work_dir)"
    trap 'cleanup_or_retain_work_dir "${work_dir:-}"' EXIT
    source_repo=${3:-}
    if [[ -z "$source_repo" ]]; then
      checkout_locked_source kata_containers "$work_dir/kata-source"
      source_repo="$work_dir/kata-source"
    else
      python3 "$materials_tool" --lock "$lock_file" verify-git --source kata_containers --repo "$source_repo"
    fi
    python3 "$materials_tool" --lock "$lock_file" prepare-kata \
      --repo "$source_repo" --output "$work_dir/kata-prepared"
    verify_guest_components_artifact
    local_build="$work_dir/kata-prepared/tools/packaging/kata-deploy/local-build"
    parallel_targets="${kata_parallel_targets[*]}"
    serial_targets="${kata_serial_targets[*]}"
    post_image_targets="${kata_post_image_targets[*]}"
    final_inputs="${kata_final_inputs[*]}"
    STATIC_RUNTIME=yes USE_CACHE=no PUSH_TO_REGISTRY=no RELEASE=yes \
      make -C "$local_build" -f "$local_build/Makefile" all \
      -j "$(nproc)" --output-sync=target V= \
      BASE_TARBALLS="$parallel_targets" \
      BASE_SERIAL_TARBALLS="$serial_targets" \
      DEPS=
    STATIC_RUNTIME=yes USE_CACHE=no PUSH_TO_REGISTRY=no RELEASE=yes \
      make -C "$local_build" -f "$local_build/Makefile" all \
      -j "$(nproc)" --output-sync=target V= \
      BASE_TARBALLS="$post_image_targets" \
      DEPS=
    RELEASE=yes make -C "$local_build" -f "$local_build/Makefile" merge-builds \
      FINAL_TARBALL_INPUTS="$final_inputs" \
      FINAL_TARBALL_MERGE_MODE=merge
    built_tarball="$local_build/kata-static.tar.zst"
    [[ -f "$built_tarball" ]] || die "Kata build did not produce kata-static.tar.zst"
    mkdir -p "$(dirname "$output_tarball")"
    cp "$built_tarball" "$output_tarball"
    verify_kata_static "$output_tarball"
    python3 "$materials_tool" --lock "$lock_file" emit \
      --output-dir "$(dirname "$output_tarball")/materials" \
      --artifact "kata-static.tar.zst=${output_tarball}"
    ;;

  kata-guest-components)
    [[ $# -eq 2 || $# -eq 3 ]] || \
      die "kata-guest-components requires OUTPUT_TARBALL [KATA_REPOSITORY]"
    verify_builder_checkout
    require_command docker
    require_command git
    require_command make
    require_command python3
    output_tarball=$2
    work_dir="$(new_work_dir)"
    trap 'cleanup_or_retain_work_dir "${work_dir:-}"' EXIT
    source_repo=${3:-}
    if [[ -z "$source_repo" ]]; then
      checkout_locked_source kata_containers "$work_dir/kata-source"
      source_repo="$work_dir/kata-source"
    else
      python3 "$materials_tool" --lock "$lock_file" verify-git --source kata_containers --repo "$source_repo"
    fi
    python3 "$materials_tool" --lock "$lock_file" prepare-kata \
      --repo "$source_repo" --output "$work_dir/kata-prepared"
    verify_guest_components_artifact
    local_build="$work_dir/kata-prepared/tools/packaging/kata-deploy/local-build"
    STATIC_RUNTIME=yes USE_CACHE=no PUSH_TO_REGISTRY=no RELEASE=yes \
      make -C "$local_build" -f "$local_build/Makefile" all \
      --output-sync=target V= \
      BASE_TARBALLS=coco-guest-components-tarball \
      DEPS=
    built_tarball="$local_build/build/kata-static-coco-guest-components.tar.zst"
    [[ -f "$built_tarball" ]] || die "Kata build did not produce the CoCo guest-components tarball"
    mkdir -p "$(dirname "$output_tarball")"
    cp "$built_tarball" "$output_tarball"
    ;;

  verify-kata-static)
    [[ $# -eq 2 ]] || die "verify-kata-static requires KATA_TARBALL"
    verify_builder_checkout
    verify_kata_static "$2"
    ;;

  kata-extension)
    [[ $# -eq 3 ]] || die "kata-extension requires KATA_TARBALL OUTPUT_DIRECTORY"
    verify_builder_checkout
    require_command docker
    require_command diff
    require_command jq
    require_command python3
    require_command tar
    require_command zstd
    kata_tarball=$2
    output_dir=$3
    verify_kata_static "$kata_tarball"
    mkdir -p "$output_dir"
    work_dir="$(new_work_dir)"
    trap 'cleanup_or_retain_work_dir "${work_dir:-}"' EXIT
    mkdir -p "$work_dir/context/extension" "$work_dir/static"
    base_image="$(lock_value '.base_images.kata_talos_extension')"
    docker buildx build \
      --file "$script_dir/base-rootfs.Dockerfile" \
      --platform linux/amd64 \
      --build-arg "BASE_IMAGE=${base_image}" \
      --output "type=local,dest=$work_dir/context/extension" \
      "$script_dir"
    tar --zstd -xf "$kata_tarball" -C "$work_dir/static"
    bind_extension_manifest_version \
      "$work_dir/static" \
      "$work_dir/context/extension/manifest.yaml"
    python3 "$materials_tool" --lock "$lock_file" verify-extension-tree \
      --root "$work_dir/context/extension"
    overlay_confidential_payload \
      "$work_dir/static" \
      "$work_dir/context/extension/rootfs"
    python3 "$materials_tool" --lock "$lock_file" emit \
      --output-dir "$work_dir/context/extension/rootfs/usr/local/share/codewire/confidential-storage"
    python3 "$materials_tool" --lock "$lock_file" verify-extension-tree \
      --root "$work_dir/context/extension"
    # Let BuildKit observe real source mtimes so equal-sized measured images
    # cannot reuse stale local-context content. The OCI exporter rewrites every
    # output timestamp to SOURCE_DATE_EPOCH after content ingestion.
    docker buildx build \
      --no-cache \
      --file "$script_dir/extension.Dockerfile" \
      --platform linux/amd64 \
      --provenance=mode=max \
      --attest "type=sbom,generator=$(lock_value '.base_images.buildkit_sbom_scanner')" \
      --build-arg "EXTENSIONS_REVISION=$(lock_value '.sources.extensions.revision')" \
      --build-arg "GUEST_COMPONENTS_REVISION=$(lock_value '.sources.guest_components.revision')" \
      --build-arg "KATA_CONTAINERS_REVISION=$(lock_value '.sources.kata_containers.revision')" \
      --build-arg "SOURCE_DATE_EPOCH=$(lock_value '.source_date_epoch')" \
      --build-arg "SOURCE_LOCK_SHA256=$(lock_sha256)" \
      --metadata-file "$output_dir/kata-extension.metadata.json" \
      --output "type=oci,dest=$output_dir/kata-extension.oci.tar,rewrite-timestamp=true" \
      "$work_dir/context"
    python3 "$materials_tool" --lock "$lock_file" emit \
      --output-dir "$output_dir/materials" \
      --oci-artifact "kata-extension=$output_dir/kata-extension.oci.tar"
    ;;

  -h|--help|help)
    usage
    ;;

  *)
    usage >&2
    exit 2
    ;;
esac
