# syntax=docker/dockerfile:1.23.0@sha256:2780b5c3bab67f1f76c781860de469442999ed1a0d7992a5efdf2cffc0e3d769
FROM ghcr.io/noeljackson/drbd-pkg@sha256:6e9d254b3cc3da96f270efa4f1452a3fd6700a9fc3d4b5d68ed08da0f7800bff AS package

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
      org.opencontainers.image.version="9.3.3-v1.14.0-wg-63f8953b22ca" \
      io.codewire.kernel.package="ghcr.io/noeljackson/kernel@sha256:236481b2c6fdc4f1dec17ba5b1e0bcdc3f467401c4eab1d490af4a26bf82d646" \
      io.codewire.drbd.package="ghcr.io/noeljackson/drbd-pkg@sha256:6e9d254b3cc3da96f270efa4f1452a3fd6700a9fc3d4b5d68ed08da0f7800bff" \
      io.codewire.pkgs.revision="63f8953b22ca4bff1dcf9cc95bb9a99dfcd1cfc3"
COPY --from=normalized /normalized-${SOURCE_DATE_EPOCH}/ /
