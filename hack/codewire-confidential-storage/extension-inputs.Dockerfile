# syntax=docker/dockerfile:1.23.0@sha256:2780b5c3bab67f1f76c781860de469442999ed1a0d7992a5efdf2cffc0e3d769
# Assemble the non-Kata inputs of the Talos extension tree from digest-pinned
# images only. build.sh passes every reference from sources.lock.json and adds
# the exact Kata closure, the manifest, and the containerd configuration after
# exporting this stage with the BuildKit local exporter.
ARG GO_WRAPPER_BUILDER_IMAGE=scratch
ARG TALOS_GLIBC_IMAGE=scratch
ARG TALOS_FUSE3_IMAGE=scratch

FROM ${TALOS_GLIBC_IMAGE} AS talos-glibc
FROM ${TALOS_FUSE3_IMAGE} AS talos-fuse3

# Talos has no /bin/sh, so the QEMU-SNP data-directory selector and the
# nydus mount.fuse helper are static Go executables built from repository
# source with the standard library only. The module proxy is disabled so the
# build cannot resolve anything outside the pinned toolchain image.
FROM ${GO_WRAPPER_BUILDER_IMAGE} AS go-wrappers
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    GOFLAGS=-buildvcs=false \
    GOPROXY=off \
    GOTOOLCHAIN=local
WORKDIR /src
COPY qemu-snp-wrapper.go mount-fuse-nydus-wrapper.go ./
RUN mkdir -p /out && \
    go build -trimpath -ldflags='-s -w -buildid=' \
      -o /out/qemu-system-x86_64-snp-experimental ./qemu-snp-wrapper.go && \
    go build -trimpath -ldflags='-s -w -buildid=' \
      -o /out/mount.fuse ./mount-fuse-nydus-wrapper.go

FROM scratch
# The fuse3 userspace (libfuse3, fusermount3, mount.fuse3) is installed at
# the extension root exactly as the official Talos fuse3 extension ships it.
COPY --from=talos-fuse3 /rootfs/ /rootfs/
# The nydus-for-kata-tee extension service runs inside its own container
# rootfs, whose entrypoint is the official Talos glibc dynamic loader.
COPY --from=talos-glibc /rootfs/ /rootfs/usr/local/lib/containers/nydus-for-kata-tee/
COPY --from=go-wrappers /out/ /rootfs/usr/local/bin/
