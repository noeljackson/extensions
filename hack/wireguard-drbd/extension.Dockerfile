# syntax=docker/dockerfile:1.23.0@sha256:2780b5c3bab67f1f76c781860de469442999ed1a0d7992a5efdf2cffc0e3d769
FROM ghcr.io/noeljackson/drbd-pkg@sha256:005b414a6095acfa384ce4faa60ad42246350123b57d20f09d8fcf543c1f1444 AS package

# release-1.14 validator c0c37e7, immutable linux/amd64 manifest.
FROM ghcr.io/siderolabs/extensions-validator@sha256:140d3e64a6ee7cea55fc8df7be7fe45695427e532a72e156d9e5c157a46877e9 AS validated
COPY --from=package /usr/lib/modules/ /extension/rootfs/usr/lib/modules/
COPY manifest.yaml /extension/manifest.yaml
RUN ["/extensions-validator", "validate", "--rootfs=/extension", "--pkg-name=drbd"]

FROM scratch
ARG REVISION
LABEL org.opencontainers.image.source="https://github.com/noeljackson/extensions" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.title="drbd" \
      org.opencontainers.image.version="9.3.3-v1.14.0-wg-f6afafe3f382" \
      io.codewire.kernel.package="ghcr.io/noeljackson/kernel@sha256:229c04e313d7a90cb8ddf5767a965472a8b53d554e1215c36fbd3f5e95815e43" \
      io.codewire.drbd.package="ghcr.io/noeljackson/drbd-pkg@sha256:005b414a6095acfa384ce4faa60ad42246350123b57d20f09d8fcf543c1f1444" \
      io.codewire.pkgs.revision="f6afafe3f382f47262cbef11e8c76a973476e9c2"
COPY --from=validated /extension/ /
