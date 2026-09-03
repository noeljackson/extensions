#!/usr/bin/env bash

set -euo pipefail
umask 077

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
smoke="$script_dir/qemu-tcg-boot-smoke"
test_base="$repo_root/_out"
mkdir -p "$test_base"
test_root="$(mktemp -d "$test_base/qemu-tcg-boot-smoke-test.XXXXXX")"
bin_dir="$test_root/bin"

cleanup() {
  find "$test_root" -xdev -depth -delete 2>/dev/null || true
}
trap cleanup EXIT INT TERM

mkdir -p "$bin_dir"

write_fixture() {
  local fixture_root=$1 kernel_target=$2 include_target=$3
  local layer_root payload layer_digest

  layer_root="$fixture_root/layer-root"
  payload="$layer_root/rootfs/usr/local/share/kata-containers"
  mkdir -p "$payload" "$fixture_root/image-source"
  cat >"$payload/configuration-qemu-snp.toml" <<'EOF'
[hypervisor.qemu]
overhead_memory = 2048
kernel_verity_params = "root_hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,salt=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,data_blocks=1,data_block_size=4096,hash_block_size=4096"
guest_extension_images = [
  { name = "coco", path = "/usr/local/share/kata-containers/kata-containers-coco-extension.img", verity_params = "root_hash=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc,salt=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd,data_blocks=1,data_block_size=4096,hash_block_size=4096" },
]
EOF
  printf '%s\n' 'root_hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,salt=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,data_blocks=1,data_block_size=4096,hash_block_size=4096' >"$payload/root_hash_confidential.txt"
  printf '%s\n' 'root_hash=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc,salt=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd,data_blocks=1,data_block_size=4096,hash_block_size=4096' >"$payload/root_hash_coco-extension.txt"
  : >"$payload/kata-containers-confidential.img"
  : >"$payload/kata-containers-coco-extension.img"
  ln -s "$kernel_target" "$payload/vmlinuz.container"
  if [[ "$include_target" == true ]]; then
    printf 'fixture kernel\n' >"$payload/$kernel_target"
  fi

  tar -czf "$fixture_root/layer.tar.gz" -C "$layer_root" rootfs
  layer_digest="$(sha256sum "$fixture_root/layer.tar.gz" | awk '{print $1}')"
  cp "$fixture_root/layer.tar.gz" "$fixture_root/image-source/$layer_digest"
  jq -n --arg digest "sha256:$layer_digest" '{
    layers: [{
      mediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
      digest: $digest
    }]
  }' >"$fixture_root/image-source/manifest.json"
  : >"$fixture_root/input.oci.tar"
}

cat >"$bin_dir/skopeo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
destination="${*: -1}"
[[ "$destination" == dir:* ]]
destination="${destination#dir:}"
mkdir -p "$destination"
cp -a "$TEST_SMOKE_IMAGE_SOURCE/." "$destination/"
EOF

cat >"$bin_dir/qemu-system-x86_64" <<'EOF'
#!/usr/bin/env bash
exit 99
EOF

cat >"$bin_dir/timeout" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == '--signal=TERM' ]]
shift
[[ "${1:-}" == '30s' ]]
shift
[[ "${1:-}" == 'qemu-system-x86_64' ]]
shift

kernel=''
serial=''
initdata=''
initdata_device=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    -kernel)
      kernel=${2:-}
      shift 2
      ;;
    -serial)
      serial=${2:-}
      shift 2
      ;;
    -drive)
      if [[ "${2:-}" == *',id=initdata,'* ]]; then
        [[ "${2:-}" == *',readonly=on'* ]]
        initdata=${2#*file=}
        initdata=${initdata%%,*}
      fi
      shift 2
      ;;
    -device)
      if [[ "${2:-}" == 'virtio-blk-pci,drive=initdata,serial=initdata' ]]; then
        initdata_device=true
      fi
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

[[ -f "$kernel" ]]
[[ -f "$initdata" ]]
[[ "$initdata_device" == true ]]
[[ "$serial" == file:* ]]
python3 - "$initdata" <<'PY'
import gzip
import pathlib
import struct
import sys

image = pathlib.Path(sys.argv[1]).read_bytes()
assert image[:8] == b"initdata"
length = struct.unpack("<Q", image[8:16])[0]
raw = gzip.decompress(image[16:16 + length])
assert raw == b'algorithm = "sha256"\nversion = "0.1.0"\n\n[data]\n'
assert len(image) % 512 == 0
PY
serial=${serial#file:}
cat >"$serial" <<'MARKERS'
dm-0 (dm-verity) is ready
Finished kata-extension-mount@coco
Started kata-agent.service
Reached target kata-containers.target
Initdata version: 0.1.0
Welcome to Confidential Containers Attestation Agent (ttRPC version)
Error: the selected attester does not support required Init-Data binding
kata-agent.service: Main process exited, code=exited, status=1/FAILURE
Powering off: unit kata-agent.service failed
MARKERS

if [[ "${TEST_TCG_TIMEOUT_MODE:-timeout}" == early-exit ]]; then
  printf '%s\n' 'fixture early exit diagnostic' >>"$serial"
  exit 1
fi
exit 0
EOF

chmod +x "$bin_dir/skopeo" "$bin_dir/qemu-system-x86_64" "$bin_dir/timeout"

safe_fixture="$test_root/safe"
write_fixture "$safe_fixture" vmlinuz-7.2.2-202 true
safe_stdout="$test_root/safe.stdout"
safe_stderr="$test_root/safe.stderr"
mkdir "$test_root/safe-scratch"
if ! env \
  PATH="$bin_dir:$PATH" \
  TEST_SMOKE_IMAGE_SOURCE="$safe_fixture/image-source" \
  CODEWIRE_CONFIDENTIAL_STORAGE_SCRATCH_ROOT="$test_root/safe-scratch" \
  CODEWIRE_KATA_TCG_BOOT_HORIZON_SECONDS=30 \
  "$smoke" "$safe_fixture/input.oci.tar" >"$safe_stdout" 2>"$safe_stderr"; then
  cat "$safe_stderr" >&2
  printf '%s\n' 'safe packaged kernel symlink fixture failed the TCG gate' >&2
  exit 1
fi
grep -Fq 'required Init-Data fail-closed path' "$safe_stdout"

early_stdout="$test_root/early.stdout"
early_stderr="$test_root/early.stderr"
mkdir "$test_root/early-scratch"
if env \
  PATH="$bin_dir:$PATH" \
  TEST_SMOKE_IMAGE_SOURCE="$safe_fixture/image-source" \
  TEST_TCG_TIMEOUT_MODE=early-exit \
  CODEWIRE_CONFIDENTIAL_STORAGE_SCRATCH_ROOT="$test_root/early-scratch" \
  CODEWIRE_KATA_TCG_BOOT_HORIZON_SECONDS=30 \
  "$smoke" "$safe_fixture/input.oci.tar" >"$early_stdout" 2>"$early_stderr"; then
  printf '%s\n' 'early guest exit unexpectedly passed the TCG gate' >&2
  exit 1
fi
grep -Fq 'bounded guest serial failure output follows' "$early_stderr"
grep -Fq 'fixture early exit diagnostic' "$early_stderr"
grep -Fq 'guest did not take the required TCG fail-closed path (status 1)' "$early_stderr"

unsafe_fixture="$test_root/unsafe"
write_fixture "$unsafe_fixture" ../outside false
unsafe_stdout="$test_root/unsafe.stdout"
unsafe_stderr="$test_root/unsafe.stderr"
mkdir "$test_root/unsafe-scratch"
if env \
  PATH="$bin_dir:$PATH" \
  TEST_SMOKE_IMAGE_SOURCE="$unsafe_fixture/image-source" \
  CODEWIRE_CONFIDENTIAL_STORAGE_SCRATCH_ROOT="$test_root/unsafe-scratch" \
  CODEWIRE_KATA_TCG_BOOT_HORIZON_SECONDS=30 \
  "$smoke" "$unsafe_fixture/input.oci.tar" >"$unsafe_stdout" 2>"$unsafe_stderr"; then
  printf '%s\n' 'unsafe packaged kernel symlink unexpectedly passed the TCG gate' >&2
  exit 1
fi
grep -Fq 'packaged kernel symlink target is not a safe in-package kernel name' "$unsafe_stderr"

printf '%s\n' 'QEMU TCG boot smoke extraction and failure-evidence fixtures: PASS'
