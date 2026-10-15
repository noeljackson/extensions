# Matching DRBD for the AMS/FRA kernel candidate

The existing fleet kernel and official DRBD extension share a module-signing
identity. A rebuilt kernel needs DRBD from that same build. `package.lock.json`
binds the qualified public kernel/DRBD package pair, full source revision,
module signing metadata and all 18 module-tree file hashes. The new recipe
copies that tree unchanged and runs the upstream extension validator. It does
not rebuild or re-sign any module or include a private signing key.

`extension.Dockerfile` is a deployment overlay; the upstreamable source branch
and the existing Kata publisher are unchanged. The workflow builds only DRBD
on the exact deployment push. Its repository-scoped token publishes to the
source-owned `ghcr.io/noeljackson/drbd` package and produces a deployment
attestation. New publication needs the admitted transaction before landing.

For source verification and local qualification, use a clean signed composition
with the current deployment head first and accepted source head second:

```sh
python3 hack/wireguard-drbd/test_verify.py
python3 hack/wireguard-drbd/build.py build /new/private/output
python3 hack/wireguard-drbd/build.py verify /new/private/output
```

Select an already-running task-owned Docker-container builder with Buildx
v0.36.1 and BuildKit
`moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8`.
Use an anonymous Docker configuration with explicit empty entries for
`ghcr.io` and `https://index.docker.io/v1/`; an entirely empty `auths` map can
activate Docker's host credential-helper discovery. Bound local builder CPU,
memory and runtime. The wrapper bounds its build to ten minutes and never
publishes in `build` or `verify` mode. Outputs must be new, private, and outside
the checkout. Remove owned temporary rules and builder/cache after qualification.

The verifier checks the complete OCI blob/descriptor chain, one AMD64 payload
and matched provenance/SBOM attestation, source/package labels, exact manifest
and every module-tree file, ownership, modes and path closure. Negative fixtures
cover changed/missing/extra payload, wrong source/kernel identity, permissions,
platform, broken attestations and hostile archive entries. No extracted root
ownership is needed by the registry transport.

Tags contain the full extension deployment revision. A retry retains an
existing index only when its independently inspected payload, source and
attestations match; a changed platform manifest is an immutable collision.
The receipt distinguishes retained and rebuilt indexes. Verify anonymous reads,
repository linkage and deployment attestation before Infra consumes the digest.
Module byte/signing-metadata equality is not kernel acceptance: the exact
enforcing Talos boot and staged-upgrade fixtures must load DRBD before the
serial AMS/FRA rollout. No other worker's profile changes with this artifact.
## Reproducible extension payload

The final filesystem is normalized to the exact deployment commit epoch before
the scratch copy. BuildKit timestamp rewriting alone preserves older cached or
local checkout mtimes. The archive verifier rejects every file or directory
with another timestamp, and requires the matching rewritten-timestamp layer
annotation before any registry write.
The final COPY also selects an epoch-qualified source directory: its cache
otherwise ignores mtime-only changes and can reuse an older payload layer.

For a new candidate, build once to populate the pinned builder, then compare
`build OUTPUT` with `build --no-cache OTHER_OUTPUT`. Independently verify both
archives and require equal platform manifests. After workflow publication,
require the same platform manifest from an anonymous pull and verify the
deployment attestation before consumption. The earlier
`a008cb037a4825ccb109655fe989733cd34dfb9e` image is unconsumed: its local and
hosted manifest-file timestamps differed. Keep its immutable tag intact.
