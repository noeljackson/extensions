# syntax=docker/dockerfile:1.23.0@sha256:2780b5c3bab67f1f76c781860de469442999ed1a0d7992a5efdf2cffc0e3d769
FROM ghcr.io/noeljackson/drbd-pkg@sha256:294edc95a4d74137b18a0def286dff7a509754ed0258d1c9bc6ec6c63d97dd3e AS package

# release-1.14 validator c0c37e7, immutable linux/amd64 manifest.
FROM ghcr.io/siderolabs/extensions-validator@sha256:140d3e64a6ee7cea55fc8df7be7fe45695427e532a72e156d9e5c157a46877e9 AS validated
COPY --from=package /usr/lib/modules/ /extension/rootfs/usr/lib/modules/
COPY manifest.yaml /extension/manifest.yaml
RUN ["/extensions-validator", "validate", "--rootfs=/extension", "--pkg-name=drbd"]

# The OCI exporter only clamps newer mtimes. Normalize older local checkout
# and cache mtimes too, without changing any module or manifest bytes.
FROM ghcr.io/siderolabs/tools@sha256:7dd7d86b652694fe5bf8954759e3bf414ff486a30023267fd2e78ccb925fc2ca AS normalized
COPY --from=validated /extension/ /extension/
ARG SOURCE_DATE_EPOCH
RUN find /extension -print0 \
    | xargs -0r touch --no-dereference --date="@${SOURCE_DATE_EPOCH}"
# COPY cache keys ignore mtimes. Bind its source path to the epoch as well,
# preventing reuse of a layer copied before normalization or for another epoch.
RUN mv /extension "/normalized-${SOURCE_DATE_EPOCH}"

FROM scratch
ARG REVISION
ARG SOURCE_DATE_EPOCH
LABEL org.opencontainers.image.source="https://github.com/noeljackson/extensions" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.title="drbd" \
      org.opencontainers.image.version="9.3.3-v1.14.0-wg-cdd772fe6e46" \
      io.codewire.kernel.package="ghcr.io/noeljackson/kernel@sha256:4ac13f223f1a1600e92c8464fce1317e2d553344c9f8e607340f8d171700664b" \
      io.codewire.drbd.package="ghcr.io/noeljackson/drbd-pkg@sha256:294edc95a4d74137b18a0def286dff7a509754ed0258d1c9bc6ec6c63d97dd3e" \
      io.codewire.pkgs.revision="cdd772fe6e4696d265303a9e2b0cdb9cd8bea211"
COPY --from=normalized /normalized-${SOURCE_DATE_EPOCH}/ /
