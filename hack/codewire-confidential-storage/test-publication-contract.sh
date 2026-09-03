#!/usr/bin/env bash
# shellcheck disable=SC2016 # Contract literals intentionally contain workflow expressions.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
workflow="${repo_root}/.github/workflows/downstream-confidential-storage.yml"
publisher="${script_dir}/publish.sh"
test_root="$(mktemp -d)"

cleanup() {
	rm -f -- "${test_root}/candidate.yml" "${test_root}/guard.stderr"
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
	require_line "${candidate}" \
		'    if: github.event_name == '\''push'\'' && github.ref == '\''refs/heads/downstream/confidential-storage'\'' && github.repository == '\''noeljackson/extensions'\''' \
		'exact publication job guard'
	require_line "${candidate}" \
		'        run: ./hack/codewire-confidential-storage/publish.sh preflight' \
		'pre-build publication preflight'
	require_text "${candidate}" \
		'./hack/codewire-confidential-storage/qemu-tcg-boot-smoke' \
		'exact archive boot gate'
	require_text "${candidate}" \
		'./hack/codewire-confidential-storage/publish.sh publish' \
		'separate publication wrapper'
	require_line "${candidate}" \
		'      packages: write' \
		'narrow registry permission'
	require_line "${candidate}" \
		'      id-token: write' \
		'OIDC attestation permission'
	require_line "${candidate}" \
		'      attestations: write' \
		'GitHub attestation permission'
}

verify_publisher() {
	require_line "${publisher}" \
		'registry_repository="ghcr.io/noeljackson/kata-containers"' \
		'fixed destination repository'
	require_text "${publisher}" \
		'${kata_version}-codewire-confidential-storage-${lock_digest}' \
		'full-lock immutable tag'
	require_text "${publisher}" \
		'[[ "${GITHUB_EVENT_NAME:-}" == "push" ]]' \
		'push event guard'
	require_text "${publisher}" \
		'[[ "${GITHUB_REF:-}" == "refs/heads/downstream/confidential-storage" ]]' \
		'exact ref guard'
	require_text "${publisher}" \
		'[[ "${GITHUB_REPOSITORY:-}" == "noeljackson/extensions" ]]' \
		'exact repository guard'
	require_text "${publisher}" \
		'[[ "$(git -C "${repo_root}" rev-parse HEAD)" == "${GITHUB_SHA}" ]]' \
		'exact checkout guard'
	require_text "${publisher}" \
		'[[ "${existing_digest}" == "${source_digest}" ]]' \
		'immutable collision guard'
	require_text "${publisher}" \
		'skopeo copy --all --format oci' \
		'all-manifest copy'
	! grep -Fq 'docker login' "${publisher}" || {
		printf 'publisher must consume workflow-provided registry authentication\n' >&2
		return 1
	}
}

verify_workflow "${workflow}"
verify_publisher
"${script_dir}/test-qemu-tcg-boot-smoke.sh"

# The previous source-only/main-only shape cannot satisfy this deployment contract.
sed 's/downstream\/confidential-storage/main/g' "${workflow}" >"${test_root}/candidate.yml"
if verify_workflow "${test_root}/candidate.yml" >/dev/null 2>&1; then
	printf 'main-only publication fixture unexpectedly satisfied the contract\n' >&2
	exit 1
fi

# The upstreamable source branch remains inert even if someone adds it beside the deploy branch.
sed '/      - downstream\/confidential-storage$/a\      - downstream/confidential-storage-source' \
	"${workflow}" >"${test_root}/candidate.yml"
if verify_workflow "${test_root}/candidate.yml" >/dev/null 2>&1; then
	printf 'source-branch publication fixture unexpectedly satisfied the contract\n' >&2
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
