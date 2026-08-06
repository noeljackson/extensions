# syntax=docker/dockerfile:1.23.0@sha256:2780b5c3bab67f1f76c781860de469442999ed1a0d7992a5efdf2cffc0e3d769
FROM scratch

ARG EXTENSIONS_REVISION
ARG GUEST_COMPONENTS_REVISION
ARG KATA_CONTAINERS_REVISION
ARG SOURCE_LOCK_SHA256

LABEL org.opencontainers.image.source="https://github.com/noeljackson/extensions" \
      io.codewire.source.extensions="${EXTENSIONS_REVISION}" \
      io.codewire.source.guest-components="${GUEST_COMPONENTS_REVISION}" \
      io.codewire.source.kata-containers="${KATA_CONTAINERS_REVISION}" \
      io.codewire.source-lock.sha256="${SOURCE_LOCK_SHA256}"

COPY --chown=0:0 rootfs/ /
