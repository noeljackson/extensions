#!/usr/bin/env bash
# shellcheck disable=SC2016 # Contract literals intentionally contain workflow expressions.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
workflow="${repo_root}/.github/workflows/downstream-confidential-storage.yml"
publisher="${script_dir}/publish.sh"
apt_source_guard="${script_dir}/secure-ubuntu-apt-sources"
test_root="$(mktemp -d)"

cleanup() {
	rm -f -- "${test_root}/candidate.yml" "${test_root}/guard.stderr"
	rm -rf -- "${test_root}/apt-root" "${test_root}/nonubuntu-root"
	rmdir -- "${test_root}" 2>/dev/null || true
}
trap cleanup EXIT

require_line() {
	local file=$1 line=$2 description=$3
	grep -Fqx -- "${line}" "${file}" || {
		printf 'missing %s in %s\n' "${description}" "${file}" >&2
		return 1
	}
}

require_text() {
	local file=$1 value=$2 description=$3
	grep -Fq -- "${value}" "${file}" || {
		printf 'missing %s in %s\n' "${description}" "${file}" >&2
		return 1
	}
}

require_count() {
	local file=$1 value=$2 expected=$3 description=$4 actual
	actual="$(grep -Fxc -- "${value}" "${file}" || true)"
	[[ "${actual}" -eq "${expected}" ]] || {
		printf 'expected %s %s in %s, found %s\n' \
			"${expected}" "${description}" "${file}" "${actual}" >&2
		return 1
	}
}

require_order() {
	local file=$1 first=$2 second=$3 description=$4 first_line second_line
	first_line="$(grep -nF -- "${first}" "${file}" | head -n 1 | cut -d: -f1)"
	second_line="$(grep -nF -- "${second}" "${file}" | head -n 1 | cut -d: -f1)"
	[[ "${first_line}" =~ ^[0-9]+$ && "${second_line}" =~ ^[0-9]+$ && \
		"${first_line}" -lt "${second_line}" ]] || {
		printf 'workflow does not preserve %s\n' "${description}" >&2
		return 1
	}
}

verify_workflow() {
	local candidate=$1
	[[ "$(grep -Fxc '      - downstream/confidential-storage' "${candidate}")" -eq 2 ]] || {
		printf 'workflow must select the deployment branch once for PRs and once for pushes\n' >&2
		return 1
	}
	! grep -Fq 'downstream/confidential-storage-source' "${candidate}" || {
		printf 'upstreamable source branch must never publish\n' >&2
		return 1
	}
	! grep -Eq 'workflow_dispatch:|^[[:space:]]+release:|^[[:space:]]+tags:' "${candidate}" || {
		printf 'workflow must not expose manual, release, or tag publication\n' >&2
		return 1
	}
	! grep -Eq '^[[:space:]]+ref:' "${candidate}" || {
		printf 'checkout must consume the exact event commit\n' >&2
		return 1
	}
	require_count "${candidate}" \
		'    if: github.event_name == '\''push'\'' && github.ref == '\''refs/heads/downstream/confidential-storage'\'' && github.repository == '\''noeljackson/extensions'\''' \
		2 'exact build and publication job guards' || return 1
	require_count "${candidate}" \
		'        run: ./hack/codewire-confidential-storage/publish.sh preflight' \
		2 'exact build and publication preflights' || return 1
	require_count "${candidate}" \
		'          sudo ./hack/codewire-confidential-storage/secure-ubuntu-apt-sources /' \
		3 'Ubuntu apt HTTPS source gates' || return 1
	require_text "${candidate}" \
		'./hack/codewire-confidential-storage/qemu-tcg-boot-smoke' \
		'exact archive boot gate' || return 1
	require_line "${candidate}" \
		'    needs: build' \
		'publication dependency on the verified build' || return 1
	require_text "${candidate}" \
		'name: confidential-storage-payload-${{ github.sha }}' \
		'deployment-head-scoped publication payload' || return 1
	require_count "${candidate}" \
		'          name: confidential-storage-payload-${{ github.sha }}' \
		2 'matching publication payload upload and download names' || return 1
	require_count "${candidate}" \
		'        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1' \
		2 'pinned payload and receipt uploads' || return 1
	require_text "${candidate}" \
		'publication-payload.sha256' \
		'exact payload digest manifest' || return 1
	require_line "${candidate}" \
		'            _out/confidential-storage/kata-extension/publication-payload.sha256' \
		'durable payload digest receipt' || return 1
	require_text "${candidate}" \
		'find kata-extension.oci.tar kata-extension.metadata.json materials' \
		'complete payload digest inputs' || return 1
	require_line "${candidate}" \
		'        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1' \
		'pinned publication payload download' || return 1
	require_line "${candidate}" \
		'          path: ${{ env.OUTPUT_ROOT }}/kata-extension' \
		'exact publication payload restore path' || return 1
	require_line "${candidate}" \
		'          compression-level: 0' \
		'non-recompressing OCI payload preservation' || return 1
	require_line "${candidate}" \
		'          retention-days: 7' \
		'bounded publication payload retention' || return 1
	require_text "${candidate}" \
		'sha256sum --check' \
		'publication payload digest verification' || return 1
	require_order "${candidate}" \
		'./hack/codewire-confidential-storage/qemu-tcg-boot-smoke' \
		'- name: Preserve the verified publication payload' \
		'QEMU gate before payload preservation' || return 1
	require_order "${candidate}" \
		'sha256sum --check' \
		'- name: Log in to GHCR for the immutable copy' \
		'payload verification before registry authentication' || return 1
	require_text "${candidate}" \
		'./hack/codewire-confidential-storage/publish.sh publish' \
		'separate publication wrapper' || return 1
	require_count "${candidate}" \
		'      packages: write' \
		1 'single publish-job registry permission' || return 1
	require_count "${candidate}" \
		'      id-token: write' \
		1 'single publish-job OIDC attestation permission' || return 1
	require_count "${candidate}" \
		'      attestations: write' \
		1 'single publish-job GitHub attestation permission' || return 1
}

verify_publisher() {
	require_line "${publisher}" \
		'registry_repository="ghcr.io/noeljackson/kata-containers"' \
		'fixed destination repository' || return 1
	require_text "${publisher}" \
		'${kata_version}-codewire-confidential-storage-${lock_digest}' \
		'full-lock immutable tag' || return 1
	require_text "${publisher}" \
		'[[ "${GITHUB_EVENT_NAME:-}" == "push" ]]' \
		'push event guard' || return 1
	require_text "${publisher}" \
		'[[ "${GITHUB_REF:-}" == "refs/heads/downstream/confidential-storage" ]]' \
		'exact ref guard' || return 1
	require_text "${publisher}" \
		'[[ "${GITHUB_REPOSITORY:-}" == "noeljackson/extensions" ]]' \
		'exact repository guard' || return 1
	require_text "${publisher}" \
		'[[ "$(git -C "${repo_root}" rev-parse HEAD)" == "${GITHUB_SHA}" ]]' \
		'exact checkout guard' || return 1
	require_text "${publisher}" \
		'[[ "${existing_digest}" == "${source_digest}" ]]' \
		'immutable collision guard' || return 1
	require_text "${publisher}" \
		'skopeo copy --all --format oci' \
		'all-manifest copy' || return 1
	! grep -Fq 'docker login' "${publisher}" || {
		printf 'publisher must consume workflow-provided registry authentication\n' >&2
		return 1
	}
}

verify_workflow "${workflow}"
verify_publisher
"${script_dir}/test-qemu-tcg-boot-smoke.sh"

mkdir -p "${test_root}/apt-root/etc/apt/sources.list.d"
cat >"${test_root}/apt-root/etc/apt/sources.list" <<'EOF'
deb http://ports.ubuntu.com/ubuntu-ports resolute main
deb http://example.invalid/ubuntu resolute main
EOF
cat >"${test_root}/apt-root/etc/apt/apt-mirrors.txt" <<'EOF'
http://azure.archive.ubuntu.com/ubuntu/	priority:1
https://archive.ubuntu.com/ubuntu/	priority:2
https://security.ubuntu.com/ubuntu/	priority:3
EOF
cat >"${test_root}/apt-root/etc/apt/sources.list.d/ubuntu.sources" <<'EOF'
Types: deb
URIs: mirror+file:/etc/apt/apt-mirrors.txt
Suites: resolute resolute-updates resolute-security
Components: main
EOF
"${apt_source_guard}" "${test_root}/apt-root"
require_text "${test_root}/apt-root/etc/apt/apt-mirrors.txt" \
	'https://archive.ubuntu.com/ubuntu/' \
	'canonical Ubuntu HTTPS archive source' || exit 1
if grep -Eq 'https?://azure[.]archive[.]ubuntu[.]com' \
	"${test_root}/apt-root/etc/apt/apt-mirrors.txt"; then
	printf 'unreachable regional Ubuntu archive survived normalization\n' >&2
	exit 1
fi
require_text "${test_root}/apt-root/etc/apt/sources.list" \
	'https://ports.ubuntu.com/ubuntu-ports' \
	'Ubuntu ports HTTPS source' || exit 1
require_text "${test_root}/apt-root/etc/apt/sources.list" \
	'http://example.invalid/ubuntu' \
	'untouched non-Ubuntu source' || exit 1
if grep -ERq \
	'http://(([[:alnum:]-]+\.)*archive[.]ubuntu[.]com|security[.]ubuntu[.]com|ports[.]ubuntu[.]com)(/|[[:space:]]|$)' \
	"${test_root}/apt-root/etc/apt"; then
	printf 'Ubuntu cleartext apt source survived HTTPS normalization\n' >&2
	exit 1
fi

mkdir -p "${test_root}/nonubuntu-root/etc/apt"
printf 'deb http://example.invalid/ubuntu resolute main\n' \
	>"${test_root}/nonubuntu-root/etc/apt/sources.list"
if "${apt_source_guard}" "${test_root}/nonubuntu-root" >/dev/null 2>&1; then
	printf 'apt source set without an official Ubuntu HTTPS source unexpectedly passed\n' >&2
	exit 1
fi

# The previous source-only/main-only shape cannot satisfy this deployment contract.
sed 's/downstream\/confidential-storage/main/g' "${workflow}" >"${test_root}/candidate.yml"
if verify_workflow "${test_root}/candidate.yml" >/dev/null 2>&1; then
	printf 'main-only publication fixture unexpectedly satisfied the contract\n' >&2
	exit 1
fi

# Every runner package installation must remain downstream of the HTTPS guard.
sed '/secure-ubuntu-apt-sources/d' "${workflow}" >"${test_root}/candidate.yml"
if verify_workflow "${test_root}/candidate.yml" >/dev/null 2>&1; then
	printf 'workflow without Ubuntu apt HTTPS guards unexpectedly satisfied the contract\n' >&2
	exit 1
fi

# The upstreamable source branch remains inert even if someone adds it beside the deploy branch.
sed '/      - downstream\/confidential-storage$/a\      - downstream/confidential-storage-source' \
	"${workflow}" >"${test_root}/candidate.yml"
if verify_workflow "${test_root}/candidate.yml" >/dev/null 2>&1; then
	printf 'source-branch publication fixture unexpectedly satisfied the contract\n' >&2
	exit 1
fi

# Publication must remain downstream of the successful exact build/QEMU job.
sed '/^    needs: build$/d' "${workflow}" >"${test_root}/candidate.yml"
if verify_workflow "${test_root}/candidate.yml" >/dev/null 2>&1; then
	printf 'publication without the exact build dependency unexpectedly satisfied the contract\n' >&2
	exit 1
fi

# A downloaded artifact is not authority unless its archive digest is checked.
sed 's/sha256sum --check/sha256sum --version/' \
	"${workflow}" >"${test_root}/candidate.yml"
if verify_workflow "${test_root}/candidate.yml" >/dev/null 2>&1; then
	printf 'unverified publication payload unexpectedly satisfied the contract\n' >&2
	exit 1
fi

# Runtime guards must stop before looking at an artifact or registry credentials.
if env \
	GITHUB_ACTIONS=true \
	GITHUB_EVENT_NAME=pull_request \
	GITHUB_REF=refs/heads/downstream/confidential-storage \
	GITHUB_REPOSITORY=noeljackson/extensions \
	GITHUB_SHA="$(git -C "${repo_root}" rev-parse HEAD)" \
	"${publisher}" preflight 2>"${test_root}/guard.stderr"; then
	printf 'non-push publication context unexpectedly passed preflight\n' >&2
	exit 1
fi
grep -Fq 'publication requires a push event' "${test_root}/guard.stderr"

printf 'downstream confidential-storage publication contract: PASS\n'
