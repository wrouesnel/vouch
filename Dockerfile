# Builds on the host platform and cross-compiles for the target, so multi-arch
# builds don't run the Go toolchain under emulation.
FROM --platform=$BUILDPLATFORM golang:1.27 AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go run mage.go releaseBin "${TARGETOS}-${TARGETARCH}" \
    && mkdir /out /audit \
    && cp bin/*_"${TARGETOS}-${TARGETARCH}"/* /out/

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/ /app/
# An example configuration. Mount the real one over it.
COPY vouch.yml /app/vouch.yml
# Where the example configuration's file audit sink writes. The distroless image has no shell,
# so the directory is made in the build stage and handed to the nonroot user (65532). Mount a
# volume here so the audit trail outlives the container.
COPY --from=build --chown=65532:65532 /audit /var/log/vouch
VOLUME ["/var/log/vouch"]

# Container log collectors want one JSON object per line rather than coloured console output.
ENV VOUCH_LOG_FORMAT=json

WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["/app/vouch"]
