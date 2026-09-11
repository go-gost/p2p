# p2p container image. Native cross-compile: the build stage runs on the
# builder's architecture (BUILDPLATFORM) and produces a TARGETOS/TARGETARCH
# binary, so CI does not pay for QEMU-emulated Go compilation -- only the
# lightweight alpine runtime stage runs under QEMU.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine3.23 AS build
# No defaults: BuildKit populates these from the target platform (both for
# `buildx --platform` and plain `docker build`). A default SHADOWS that value --
# `ARG TARGETARCH=amd64` silently put an amd64 binary inside the arm64 image,
# which then failed at startup with "exec format error".
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -ldflags="-s -w" -o /p2p .

# Runtime environment. Non-root (uid 10001) by default.
#
# No device or capability is needed: this host only bridges tunnels and, for a
# datagram channel, binds a loopback UDP endpoint. tun/tap belongs to GOST --
# the tun listener creates and configures the device and needs
# CAP_NET_ADMIN + /dev/net/tun in *its* container, not in this one.
FROM alpine:3.23
RUN apk add --no-cache ca-certificates \
 && adduser -D -u 10001 p2p
COPY --from=build /p2p /usr/local/bin/p2p
USER p2p
# gRPC control plane (stub mode). DERP mode is outbound, no port to expose.
EXPOSE 8003
ENTRYPOINT ["/usr/local/bin/p2p"]
