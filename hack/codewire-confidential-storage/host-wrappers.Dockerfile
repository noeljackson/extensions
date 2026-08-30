# syntax=docker/dockerfile:1.23.0@sha256:2780b5c3bab67f1f76c781860de469442999ed1a0d7992a5efdf2cffc0e3d769
ARG GO_IMAGE=scratch
FROM ${GO_IMAGE} AS build

ARG GO_VERSION
WORKDIR /src
COPY qemu-snp-wrapper.go mount-fuse-nydus-wrapper.go ./

RUN --network=none \
    test "$(go env GOVERSION)" = "${GO_VERSION}" && \
    mkdir -p /out && \
    GOTOOLCHAIN=local GO111MODULE=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -trimpath -ldflags='-s -w' \
      -o /out/qemu-system-x86_64-snp-experimental ./qemu-snp-wrapper.go && \
    GOTOOLCHAIN=local GO111MODULE=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -trimpath -ldflags='-s -w' \
      -o /out/mount.fuse ./mount-fuse-nydus-wrapper.go && \
    go version -m /out/qemu-system-x86_64-snp-experimental | grep -Fq ": ${GO_VERSION}" && \
    go version -m /out/mount.fuse | grep -Fq ": ${GO_VERSION}"

FROM scratch
COPY --from=build /out/ /
