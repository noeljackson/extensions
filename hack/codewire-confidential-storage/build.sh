#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lock_file="${script_dir}/sources.lock.json"
materials_tool="${script_dir}/materials.py"
source_names=(extensions guest_components kata_containers longhorn_manager trustee)
kata_parallel_targets=(
  agent-tarball
  pause-image-tarball
  coco-guest-components-tarball
  kernel-tarball
  ovmf-sev-tarball
  qemu-snp-experimental-tarball
  shim-v2-go-tarball
  serial-targets
)
kata_serial_targets=(
  rootfs-image-confidential-tarball
  rootfs-initrd-confidential-tarball
)
kata_final_inputs=(
  kata-static-kernel.tar.zst
  kata-static-ovmf-sev.tar.zst
  kata-static-qemu-snp-experimental.tar.zst
  kata-static-rootfs-image-confidential.tar.zst
  kata-static-rootfs-initrd-confidential.tar.zst
  kata-static-shim-v2-go.tar.zst
)

usage() {
  cat <<'EOF'
Usage: build.sh COMMAND [OPTIONS]

Commands:
  verify
      Validate the source lock and emit deterministic source SBOM/provenance.
  fetch-archives CACHE_DIR
      Download every immutable source archive and verify SHA-256 plus SHA-512.
  plan
      Print the exact non-publishing build plan.
  prepare-kata KATA_REPOSITORY OUTPUT_DIRECTORY
      Copy and prepare the exact Kata source with the accepted guest/tool inputs.
  kata-static OUTPUT_TARBALL [KATA_REPOSITORY]
      Build the exact amd64 Kata static tarball. Registry caches and pushes are disabled.
  verify-kata-static KATA_TARBALL
      Prove the confidential image contains the required block-encryption/ext4 tools.
  kata-extension KATA_TARBALL OUTPUT_DIRECTORY
      Produce an attested amd64 OCI archive; never pushes.
  longhorn-image OUTPUT_DIRECTORY [LONGHORN_REPOSITORY]
      Produce an attested amd64 OCI archive from the exact Longhorn source; never pushes.

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

remove_tree() {
  local task_tree=$1
  local scratch_root=${CODEWIRE_CONFIDENTIAL_STORAGE_SCRATCH_ROOT:-/tmp}
  [[ -n "$task_tree" && -d "$task_tree" && "$scratch_root" == /* ]] || return 0
  scratch_root="$(cd "$scratch_root" && pwd -P)"
  [[ "$scratch_root" != / ]] || die "scratch root cannot be /"
  local task_parent task_name
  task_parent="$(cd "$(dirname "$task_tree")" && pwd -P)"
  task_name="$(basename "$task_tree")"
  if [[ "$task_parent" == "$scratch_root" && "$task_name" == codewire-confidential-storage.* ]]; then
    if ! find "$task_tree" -depth -delete 2>/dev/null; then
      if command -v docker >/dev/null 2>&1; then
        cleanup_image="$(lock_value '.base_images.longhorn_manager_runtime')"
        docker run --rm \
          --mount "type=bind,src=${task_tree},dst=/task" \
          --entrypoint /bin/sh \
          "$cleanup_image" \
          -c 'find /task -mindepth 1 -depth -delete' >/dev/null
        find "$task_tree" -depth -delete
      else
        printf 'warning: root-owned scratch remains at %s\n' "$task_tree" >&2
      fi
    fi
  fi
}

new_work_dir() {
  local scratch_root=${CODEWIRE_CONFIDENTIAL_STORAGE_SCRATCH_ROOT:-/tmp}
  [[ "$scratch_root" == /* ]] || die "scratch root must be absolute"
  mkdir -p "$scratch_root"
  scratch_root="$(cd "$scratch_root" && pwd -P)"
  [[ "$scratch_root" != / ]] || die "scratch root cannot be /"
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
  require_command readelf
  require_command sfdisk

  local audit_dir image rootfs shim cdh_output partition_json sector_size partition_start partition_size
  local program_headers dynamic_tags
  audit_dir="$(new_work_dir)"
  trap 'remove_tree "${audit_dir:-}"' EXIT
  tar --zstd -xf "$tarball" -C "$audit_dir"
  image="$(unique_file "$audit_dir" '*/opt/kata/share/kata-containers/kata-containers-confidential.img')"
  shim="$(unique_file "$audit_dir" '*/opt/kata/bin/containerd-shim-kata-v2')"
  [[ -x "$shim" ]] || die "exact Kata runtime shim is not executable"
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

  cdh_output="$(debugfs -R 'stat /usr/local/bin/confidential-data-hub' "$rootfs" 2>&1 || true)"
  if [[ "$cdh_output" == *'File not found'* || "$cdh_output" != *'Inode:'* ]]; then
    die "confidential guest image lacks confidential-data-hub"
  fi
  printf 'Kata static tarball contains the exact runtime and required guest storage tools\n'
)

overlay_confidential_payload() {
  local static_root=$1
  local rootfs=$2
  local source destination

  source="$(unique_file "$static_root" '*/opt/kata/bin/containerd-shim-kata-v2')"
  install -D -m 0755 "$source" "$rootfs/usr/local/bin/containerd-shim-kata-v2"
  ln -sfn containerd-shim-kata-v2 "$rootfs/usr/local/bin/containerd-shim-kata-qemu-snp-v2"

  for destination in \
    kata-containers-confidential.img \
    kata-containers-initrd-confidential.img \
    root_hash_confidential.txt; do
    source="$(unique_file "$static_root" "*/opt/kata/share/kata-containers/${destination}")"
    install -D -m 0644 "$source" "$rootfs/usr/local/share/kata-containers/${destination}"
  done

  source="$(unique_file "$static_root" '*/opt/kata/share/defaults/kata-containers/configuration-qemu-snp.toml')"
  install -D -m 0644 "$source" "$rootfs/usr/local/share/kata-containers/configuration-qemu-snp.toml"
  sed -i \
    -e 's#/opt/kata#/usr/local#g' \
    -e 's#path = "/usr/local/bin/qemu-system-x86_64"#path = "/usr/local/bin/qemu-system-x86_64-snp-experimental"#' \
    -e 's#valid_hypervisor_paths = \["/usr/local/bin/qemu-system-x86_64"\]#valid_hypervisor_paths = ["/usr/local/bin/qemu-system-x86_64-snp-experimental"]#' \
    -e 's#shared_fs = "virtio-fs"#shared_fs = "none"#' \
    -e 's#create_container_timeout = 60#create_container_timeout = 180#' \
    "$rootfs/usr/local/share/kata-containers/configuration-qemu-snp.toml"

  local annotations
  annotations="$(sed -nE 's/^enable_annotations = (.*)$/\1/p' "$rootfs/usr/local/share/kata-containers/configuration-qemu-snp.toml")"
  [[ -n "$annotations" ]] || die "QEMU-SNP configuration lacks enable_annotations"
  grep -Fq '"cc_init_data"' <<<"$annotations" || die "QEMU-SNP configuration rejects cc_init_data"
  grep -Fq '"kernel_params"' <<<"$annotations" || die "QEMU-SNP configuration rejects kernel_params"
  if grep -Eq '"(\.\*|\*)"' <<<"$annotations"; then
    die "QEMU-SNP configuration contains a wildcard annotation rule"
  fi
  grep -Eq '^shared_fs = "none"$' "$rootfs/usr/local/share/kata-containers/configuration-qemu-snp.toml" \
    || die "QEMU-SNP configuration does not preserve shared_fs=none"
}

command=${1:-}
case "$command" in
  verify)
    require_command python3
    python3 "$materials_tool" --lock "$lock_file" validate
    python3 "$materials_tool" --lock "$lock_file" emit --output-dir "${script_dir}/_out"
    ;;

  fetch-archives)
    [[ $# -eq 2 ]] || die "fetch-archives requires CACHE_DIR"
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

  plan)
    require_command jq
    python3 "$materials_tool" --lock "$lock_file" validate >/dev/null
    jq -n \
      --arg platform "$(lock_value '.platforms[0]')" \
      --arg guest "$(lock_value '.sources.guest_components.revision')" \
      --arg kata "$(lock_value '.sources.kata_containers.revision')" \
      --arg longhorn "$(lock_value '.sources.longhorn_manager.revision')" \
      --arg trustee "$(lock_value '.sources.trustee.revision')" \
      --arg source_lock "$(lock_sha256)" \
      '{schema:"codewire.confidential-storage.build-plan/v1", mode:"no-push", platform:$platform, runtime_abi:"static", source_lock_sha256:$source_lock, sources:{guest_components:$guest,kata_containers:$kata,longhorn_manager:$longhorn,trustee:$trustee}, outputs:["kata-static.tar.zst","kata-extension.oci.tar","longhorn-manager.oci.tar","materials.spdx.json","provenance.in-toto.json"]}'
    ;;

  prepare-kata)
    [[ $# -eq 3 ]] || die "prepare-kata requires KATA_REPOSITORY OUTPUT_DIRECTORY"
    python3 "$materials_tool" --lock "$lock_file" prepare-kata --repo "$2" --output "$3"
    ;;

  kata-static)
    [[ $# -eq 2 || $# -eq 3 ]] || die "kata-static requires OUTPUT_TARBALL [KATA_REPOSITORY]"
    require_command docker
    require_command git
    require_command make
    require_command python3
    output_tarball=$2
    work_dir="$(new_work_dir)"
    trap 'remove_tree "${work_dir:-}"' EXIT
    source_repo=${3:-}
    if [[ -z "$source_repo" ]]; then
      checkout_locked_source kata_containers "$work_dir/kata-source"
      source_repo="$work_dir/kata-source"
    else
      python3 "$materials_tool" --lock "$lock_file" verify-git --source kata_containers --repo "$source_repo"
    fi
    python3 "$materials_tool" --lock "$lock_file" prepare-kata \
      --repo "$source_repo" --output "$work_dir/kata-prepared"
    local_build="$work_dir/kata-prepared/tools/packaging/kata-deploy/local-build"
    parallel_targets="${kata_parallel_targets[*]}"
    serial_targets="${kata_serial_targets[*]}"
    final_inputs="${kata_final_inputs[*]}"
    STATIC_RUNTIME=yes USE_CACHE=no PUSH_TO_REGISTRY=no RELEASE=yes \
      make -C "$local_build" -f "$local_build/Makefile" all \
      -j "$(nproc)" --output-sync=target V= \
      BASE_TARBALLS="$parallel_targets" \
      BASE_SERIAL_TARBALLS="$serial_targets" \
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

  verify-kata-static)
    [[ $# -eq 2 ]] || die "verify-kata-static requires KATA_TARBALL"
    verify_kata_static "$2"
    ;;

  kata-extension)
    [[ $# -eq 3 ]] || die "kata-extension requires KATA_TARBALL OUTPUT_DIRECTORY"
    require_command docker
    require_command jq
    require_command python3
    require_command tar
    require_command zstd
    kata_tarball=$2
    output_dir=$3
    verify_kata_static "$kata_tarball"
    mkdir -p "$output_dir"
    work_dir="$(new_work_dir)"
    cleanup_extension() {
      remove_tree "$work_dir"
    }
    trap cleanup_extension EXIT
    mkdir -p "$work_dir/context/extension" "$work_dir/static"
    base_image="$(lock_value '.base_images.kata_talos_extension')"
    docker buildx build \
      --file "$script_dir/base-rootfs.Dockerfile" \
      --platform linux/amd64 \
      --build-arg "BASE_IMAGE=${base_image}" \
      --output "type=local,dest=$work_dir/context/extension" \
      "$script_dir"
    python3 "$materials_tool" --lock "$lock_file" verify-extension-tree \
      --root "$work_dir/context/extension"
    tar --zstd -xf "$kata_tarball" -C "$work_dir/static"
    overlay_confidential_payload "$work_dir/static" "$work_dir/context/extension/rootfs"
    python3 "$materials_tool" --lock "$lock_file" emit \
      --output-dir "$work_dir/context/extension/rootfs/usr/local/share/codewire/confidential-storage"
    python3 "$materials_tool" --lock "$lock_file" verify-extension-tree \
      --root "$work_dir/context/extension"
    epoch="$(lock_value '.source_date_epoch')"
    find "$work_dir/context/extension" -exec touch -h --date="@${epoch}" {} +
    docker buildx build \
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

  longhorn-image)
    [[ $# -eq 2 || $# -eq 3 ]] || die "longhorn-image requires OUTPUT_DIRECTORY [LONGHORN_REPOSITORY]"
    require_command docker
    require_command git
    require_command jq
    require_command python3
    output_dir=$2
    mkdir -p "$output_dir"
    work_dir="$(new_work_dir)"
    trap 'remove_tree "${work_dir:-}"' EXIT
    source_repo=${3:-}
    if [[ -z "$source_repo" ]]; then
      checkout_locked_source longhorn_manager "$work_dir/longhorn-source"
      source_repo="$work_dir/longhorn-source"
    else
      python3 "$materials_tool" --lock "$lock_file" verify-git --source longhorn_manager --repo "$source_repo"
    fi
    python3 "$materials_tool" --lock "$lock_file" prepare-longhorn \
      --repo "$source_repo" --output "$work_dir/longhorn-prepared"
    docker buildx build \
      --file "$work_dir/longhorn-prepared/package/Dockerfile" \
      --platform linux/amd64 \
      --no-cache \
      --provenance=mode=max \
      --attest "type=sbom,generator=$(lock_value '.base_images.buildkit_sbom_scanner')" \
      --build-arg "SOURCE_DATE_EPOCH=$(lock_value '.source_date_epoch')" \
      --label "org.opencontainers.image.revision=$(lock_value '.sources.longhorn_manager.revision')" \
      --label "org.opencontainers.image.source=$(lock_value '.sources.longhorn_manager.repository')" \
      --label "io.codewire.source-lock.sha256=$(lock_sha256)" \
      --metadata-file "$output_dir/longhorn-manager.metadata.json" \
      --output "type=oci,dest=$output_dir/longhorn-manager.oci.tar,rewrite-timestamp=true" \
      "$work_dir/longhorn-prepared"
    python3 "$materials_tool" --lock "$lock_file" emit \
      --output-dir "$output_dir/materials" \
      --oci-artifact "longhorn-manager=$output_dir/longhorn-manager.oci.tar"
    ;;

  -h|--help|help)
    usage
    ;;

  *)
    usage >&2
    exit 2
    ;;
esac
