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
    && mkdir /out \
    && cp bin/*_"${TARGETOS}-${TARGETARCH}"/* /out/

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/ /app/
# An example configuration. Mount the real one over it.
COPY vouch.yml /app/vouch.yml

# Container log collectors want one JSON object per line rather than coloured console output.
ENV VOUCH_LOG_FORMAT=json

WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["/app/vouch"]
