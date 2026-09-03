#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
lock_file="${script_dir}/sources.lock.json"
registry_repository="ghcr.io/noeljackson/kata-containers"

usage() {
	cat <<'EOF'
Usage: publish.sh preflight
       publish.sh publish OCI_ARCHIVE RECEIPT

This wrapper is intentionally usable only by a push of the exact checked-out
downstream/confidential-storage commit in noeljackson/extensions GitHub Actions.
EOF
}

die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

require_command() {
	command -v "$1" >/dev/null 2>&1 || die "required command is missing: $1"
}

require_publication_context() {
	[[ "${GITHUB_ACTIONS:-}" == "true" ]] || die "publication requires GitHub Actions"
	[[ "${GITHUB_EVENT_NAME:-}" == "push" ]] || die "publication requires a push event"
	[[ "${GITHUB_REF:-}" == "refs/heads/downstream/confidential-storage" ]] \
		|| die "publication requires the downstream/confidential-storage ref"
	[[ "${GITHUB_REPOSITORY:-}" == "noeljackson/extensions" ]] \
		|| die "publication requires the noeljackson/extensions repository"
	[[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]] \
		|| die "publication requires a full lowercase GitHub event commit"
	[[ "$(git -C "${repo_root}" rev-parse HEAD)" == "${GITHUB_SHA}" ]] \
		|| die "checkout HEAD does not match the GitHub event commit"
	[[ -z "$(git -C "${repo_root}" status --porcelain --untracked-files=no)" ]] \
		|| die "tracked checkout changed after the event commit"
}

publication_identity() {
	require_command jq
	require_command sha256sum
	local kata_version lock_digest
	kata_version="$(jq -er '.kata_build_contract.kata_version' "${lock_file}")"
	lock_digest="$(sha256sum "${lock_file}" | awk '{print $1}')"
	[[ "${kata_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
		|| die "locked Kata version is not a stable numeric version"
	[[ "${lock_digest}" =~ ^[0-9a-f]{64}$ ]] || die "source lock digest is invalid"
	printf '%s\t%s\t%s\n' \
		"${kata_version}-codewire-confidential-storage-${lock_digest}" \
		"${lock_digest}" \
		"${kata_version}"
}

verify_registry_copy() {
	local reference=$1 expected_digest=$2 raw_file=$3 config_file=$4
	local extensions_revision guest_revision kata_revision actual_digest

	skopeo inspect --raw "docker://${reference}" >"${raw_file}"
	actual_digest="sha256:$(sha256sum "${raw_file}" | awk '{print $1}')"
	[[ "${actual_digest}" == "${expected_digest}" ]] \
		|| die "published index digest differs from the local OCI archive"

	jq -e '
		.mediaType == "application/vnd.oci.image.index.v1+json" and
		([.manifests[] |
			select(.platform.os == "linux" and
			       .platform.architecture == "amd64" and
			       (.annotations["vnd.docker.reference.type"] // "") != "attestation-manifest")
		] | length == 1) and
		([.manifests[] |
			select(.annotations["vnd.docker.reference.type"] == "attestation-manifest")
		] | length == 1) and
		(([.manifests[] |
			select(.annotations["vnd.docker.reference.type"] == "attestation-manifest") |
			.annotations["vnd.docker.reference.digest"]][0]) ==
		 ([.manifests[] |
			select(.platform.os == "linux" and
			       .platform.architecture == "amd64" and
			       (.annotations["vnd.docker.reference.type"] // "") != "attestation-manifest") |
			.digest][0]))
	' "${raw_file}" >/dev/null || die "published index lacks one matched amd64 image and attestation"

	skopeo inspect --config --override-os linux --override-arch amd64 \
		"docker://${reference}" >"${config_file}"
	extensions_revision="$(jq -er '.sources.extensions.revision' "${lock_file}")"
	guest_revision="$(jq -er '.sources.guest_components.revision' "${lock_file}")"
	kata_revision="$(jq -er '.sources.kata_containers.revision' "${lock_file}")"
	jq -e \
		--arg lock "$(sha256sum "${lock_file}" | awk '{print $1}')" \
		--arg extensions "${extensions_revision}" \
		--arg guest "${guest_revision}" \
		--arg kata "${kata_revision}" '
		.architecture == "amd64" and
		.os == "linux" and
		.config.Labels["io.codewire.source-lock.sha256"] == $lock and
		.config.Labels["io.codewire.source.extensions"] == $extensions and
		.config.Labels["io.codewire.source.guest-components"] == $guest and
		.config.Labels["io.codewire.source.kata-containers"] == $kata
	' "${config_file}" >/dev/null || die "published image platform or source labels drifted"
}

command=${1:-}
case "${command}" in
	preflight)
		[[ $# -eq 1 ]] || die "preflight takes no arguments"
		require_command git
		require_publication_context
		IFS=$'\t' read -r tag lock_digest kata_version < <(publication_identity)
		printf 'authorized immutable publication: %s:%s (lock sha256:%s, Kata %s)\n' \
			"${registry_repository}" "${tag}" "${lock_digest}" "${kata_version}"
		;;

	publish)
		[[ $# -eq 3 ]] || die "publish requires OCI_ARCHIVE RECEIPT"
		require_command git
		require_publication_context
		require_command jq
		require_command mkdir
		require_command sha256sum
		require_command skopeo

		archive=$2
		receipt=$3
		[[ -f "${archive}" ]] || die "OCI archive does not exist: ${archive}"
		IFS=$'\t' read -r tag lock_digest kata_version < <(publication_identity)
		reference="${registry_repository}:${tag}"
		source_digest="$(skopeo inspect --format '{{.Digest}}' "oci-archive:${archive}")"
		[[ "${source_digest}" =~ ^sha256:[0-9a-f]{64}$ ]] \
			|| die "local OCI archive digest is invalid"

		temporary_dir="$(mktemp -d)"
		cleanup() {
			rm -f -- \
				"${temporary_dir}/existing.raw" \
				"${temporary_dir}/existing.stderr" \
				"${temporary_dir}/published.raw" \
				"${temporary_dir}/published.config"
			rmdir -- "${temporary_dir}" 2>/dev/null || true
		}
		trap cleanup EXIT

		publication_state=published
		if skopeo inspect --raw "docker://${reference}" \
			>"${temporary_dir}/existing.raw" 2>"${temporary_dir}/existing.stderr"; then
			existing_digest="sha256:$(sha256sum "${temporary_dir}/existing.raw" | awk '{print $1}')"
			[[ "${existing_digest}" == "${source_digest}" ]] \
				|| die "immutable tag already exists with a different digest"
			publication_state=reused
		else
			grep -Eqi 'manifest unknown|manifest_unknown' "${temporary_dir}/existing.stderr" \
				|| die "could not prove that the immutable tag is absent"
			skopeo copy --all --format oci \
				"oci-archive:${archive}" "docker://${reference}"
		fi

		verify_registry_copy \
			"${reference}" "${source_digest}" \
			"${temporary_dir}/published.raw" \
			"${temporary_dir}/published.config"
		platform_manifest="$(jq -er '.manifests[] |
			select(.platform.os == "linux" and
			       .platform.architecture == "amd64" and
			       (.annotations["vnd.docker.reference.type"] // "") != "attestation-manifest") |
			.digest' "${temporary_dir}/published.raw")"

		mkdir -p "$(dirname "${receipt}")"
		jq -n \
			--arg repository "${registry_repository}" \
			--arg tag "${tag}" \
			--arg reference "${reference}" \
			--arg digest "${source_digest}" \
			--arg platform_manifest "${platform_manifest}" \
			--arg source_lock_sha256 "${lock_digest}" \
			--arg deployment_revision "${GITHUB_SHA}" \
			--arg state "${publication_state}" \
			'{schema:"codewire.confidential-storage.publication/v1",
			  repository:$repository, tag:$tag, reference:$reference, digest:$digest,
			  platform:"linux/amd64", platformManifest:$platform_manifest,
			  sourceLockSha256:$source_lock_sha256,
			  deploymentRevision:$deployment_revision, state:$state}' \
			>"${receipt}"

		[[ -n "${GITHUB_OUTPUT:-}" ]] || die "GitHub output file is unavailable"
		printf 'image=%s\ndigest=%s\nreference=%s@%s\ntag=%s\n' \
			"${registry_repository}" "${source_digest}" \
			"${registry_repository}" "${source_digest}" "${tag}" >>"${GITHUB_OUTPUT}"
		printf 'immutable publication %s: %s@%s\n' \
			"${publication_state}" "${registry_repository}" "${source_digest}"
		;;

	-h|--help|help)
		usage
		;;

	*)
		usage >&2
		exit 2
		;;
esac
